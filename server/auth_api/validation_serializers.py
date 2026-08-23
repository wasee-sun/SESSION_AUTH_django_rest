from rest_framework import serializers
from django.conf import settings
from django.core.cache import cache
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from server.utils.exception import (
    BadRequestValidationError,
    ForbiddenValidationError,
    NotFoundValidationError,
)
from server.utils.encryption import generate_hash_key
from .utils import validate_user_attributes


class ValidUserLoginSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Validates an authenticated user object provided via context against rules.
    Also handles failed login attempt accounting and brute-force lockouts.
    """

    def validate(self, attrs):  # pylint: disable=R0912
        user = self.context.get("user")
        request = self.context.get("request")

        if not user:  # Wrong Password
            user_obj = (
                getattr(request, "authenticated_user_obj", None) if request else None
            )

            if user_obj:
                error = validate_user_attributes(user_obj, "login")

                if error:
                    raise ForbiddenValidationError({"error": error})

                hashed_user_key = generate_hash_key(user_obj.id)
                failed_attempts_key = f"login-failures:{hashed_user_key}"

                failed_attempts = cache.get(failed_attempts_key)

                if failed_attempts is not None:
                    failed_attempts = cache.incr(failed_attempts_key)
                else:
                    failed_attempts = 1
                    cache.set(
                        failed_attempts_key,
                        failed_attempts,
                        timeout=settings.LOGIN_FAILURE_ATTEMPT_TTL,
                    )  # 1 hour

                # Lock account
                if failed_attempts >= settings.MAX_LOGIN_FAILURE_LIMIT:
                    if user_obj.is_superuser:
                        user_obj.is_email_verified = False
                        user_obj.save()
                    else:
                        user_obj.is_active = False
                        user_obj.save()

                    cache.delete(failed_attempts_key)

                    raise BadRequestValidationError(
                        {
                            "error": (
                                "Invalid credentials. Your account has been deactivated."
                                " Contact an admin."
                            )
                        },
                    )

                # Warn user
                if failed_attempts >= 3:
                    remaining_attempts = (
                        settings.MAX_LOGIN_FAILURE_LIMIT - failed_attempts
                    )
                    raise BadRequestValidationError(
                        {
                            "error": (
                                f"Invalid credentials. You have {remaining_attempts}"
                                " more attempt(s) before your account is deactivated."
                            )
                        },
                    )
            else:
                # Dummy key for burning expected CPU cycles to neutralize timing attacks
                dummy_hash_key = generate_hash_key("ghost_user")
                dummy_key = f"ghost-failures:{dummy_hash_key}"

                dummy_attempts = cache.get(dummy_key)
                if dummy_attempts is not None:
                    _ = cache.incr(dummy_key)
                else:
                    cache.set(dummy_key, 1, timeout=settings.DUMMY_COOLDOWN_TTL)

            raise BadRequestValidationError({"error": "Invalid credentials"})

        error = validate_user_attributes(user, "login")

        if error:
            raise ForbiddenValidationError({"error": error})

        attrs["user"] = user
        return attrs


class ValidUserIDSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Gets a user using user_id and validates if provided via context against rules.
    """

    def validate(self, attrs):
        user_id = self.context.get("user_id")
        endpoint = self.context.get("endpoint")

        User = get_user_model()

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist as exc:
            raise NotFoundValidationError({"error": "User does not exist"}) from exc

        error = validate_user_attributes(user, endpoint)

        if error:
            raise ForbiddenValidationError({"error": error})

        attrs["user"] = user
        return attrs


class ValidUserSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Validates an user object provided via context against rules.
    """

    def validate(self, attrs):
        user = None
        endpoint = self.context.get("endpoint")

        User = get_user_model()

        try:
            if endpoint == "change-password":
                email_or_username = self.context.get("email_or_username")
                user = (
                    get_user_model()
                    .objects.only("id")
                    .get(
                        Q(email__exact=email_or_username.lower())
                        | Q(username__exact=email_or_username)
                    )
                )

            if endpoint == "verify-email":
                email = self.context.get("email")
                user = (
                    get_user_model().objects.only("id").get(email__exact=email.lower())
                )
        except User.DoesNotExist as exc:
            raise NotFoundValidationError({"error": "User does not exist"}) from exc

        error = validate_user_attributes(user, endpoint)

        if error:
            raise ForbiddenValidationError({"error": error})

        attrs["user"] = user
        return attrs


class ValidPasswordSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Validate password that matches both password and checks Django AUTH_PASSWORD_VALIDATORS.
    """

    password = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        style={"input_type": "password"},
        help_text="New password of the user",
        error_messages={
            "required": "Password is required.",
            "blank": "Password is required.",
            "null": "Password is required.",
        },
    )
    c_password = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        style={"input_type": "password"},
        help_text="Confirm new password of the user",
        error_messages={
            "required": "Confirm password is required.",
            "blank": "Confirm password is required.",
            "null": "Confirm password is required.",
        },
    )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        password = attrs.get("password")
        c_password = attrs.get("c_password")

        if password != c_password:
            raise serializers.ValidationError({"c_password": "Passwords do not match."})

        user = self.context.get("user") or getattr(self, "user", None)

        try:
            validate_password(password=password, user=user)
        except DjangoValidationError as error:
            raise serializers.ValidationError({"password": list(error.messages)})

        return attrs
