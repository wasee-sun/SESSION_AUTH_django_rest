from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Q
from django.conf import settings
from rest_framework.throttling import BaseThrottle
from server.utils.redis import get_cache_data
from server.utils.encryption import generate_hash_key

User = get_user_model()


def calculate_remaining_ttl(cache_key):
    """
    Calculate the remaining TTL for the cache key.
    """
    ttl = None
    if hasattr(cache, "ttl"):
        ttl = cache.ttl(cache_key)
    if ttl and ttl > 0:
        return max(ttl, 1)

    return 60


class OTPCooldownThrottle(BaseThrottle):
    def __init__(self):
        self.remaining_ttl = settings.OTP_COOLDOWN_TTL

    def allow_request(self, request, view):  # pylint: disable=R0911
        """
        Return `True` if the request should be allowed, `False` otherwise.
        """
        user_id = None

        login_input = (
            request.data.get("email_or_username")
            if isinstance(request.data, dict)
            else None
        )

        if login_input:
            try:
                clean_input = str(login_input).strip()
                user = User.objects.only("id").get(
                    Q(email__exact=clean_input.lower()) | Q(username__exact=clean_input)
                )
                user_id = user.id
            except User.DoesNotExist:
                # Dummy key for burning expected CPU cycles to neutralize timing attacks
                dummy_hash_key = generate_hash_key("ghost_user")
                dummy_key = f"ghost-failures:{dummy_hash_key}"

                _ = cache.get(dummy_key)

                return True  # reCAPTCHA will handle this

        pre_auth_token = (
            request.data.get("pre_auth_token")
            if isinstance(request.data, dict)
            else None
        )

        if pre_auth_token:
            clean_input = str(pre_auth_token).strip()
            cache_data = get_cache_data("pre-auth-otp", clean_input)

            if cache_data.get("error"):
                return True  # reCAPTCHA will handle this

            user_id = cache_data["decrypted_data"]["user_id"]

        if user_id:
            user_lock_key = generate_hash_key(user_id)
            user_cache_key = f"pre-auth-otp-cooldown:{user_lock_key}"

            if cache.get(user_cache_key):
                self.remaining_ttl = calculate_remaining_ttl(user_cache_key)
                return False

        return True

    def wait(self):
        """
        Return the number of seconds to wait for the next request.
        """
        return self.remaining_ttl


class TwoFACooldownThrottle(BaseThrottle):
    def __init__(self):
        self.remaining_ttl = settings.INVALID_OTP_COOLDOWN_TTL

    def allow_request(self, request, view):  # pylint: disable=R0911
        """
        Return `True` if the request should be allowed, `False` otherwise.
        """

        pre_auth_token = (
            request.data.get("pre_auth_token")
            if isinstance(request.data, dict)
            else None
        )

        if pre_auth_token:
            clean_input = str(pre_auth_token).strip()
            hashed_pre_auth_key = generate_hash_key(clean_input)
            invalid_otp_key = f"invalid-otp:{hashed_pre_auth_key}"
            invalid_otp_times = cache.get(invalid_otp_key)

            if (
                invalid_otp_times
                and invalid_otp_times >= settings.MAX_OTP_FAILURE_LIMIT
            ):
                self.remaining_ttl = calculate_remaining_ttl(invalid_otp_key)
                return False

        return True

    def wait(self):
        """
        Return the number of seconds to wait for the next request.
        """
        return self.remaining_ttl


class ResetPasswordCooldownThrottle(BaseThrottle):
    def __init__(self):
        self.remaining_ttl = settings.LINK_COOLDOWN_TTL

    def allow_request(self, request, view):  # pylint: disable=R0911
        """
        Return `True` if the request should be allowed, `False` otherwise.
        """

        password_change_input = (
            request.data.get("email_or_username")
            if isinstance(request.data, dict)
            else None
        )

        if password_change_input:
            try:
                clean_input = str(password_change_input).strip()
                user = User.objects.only("id").get(
                    Q(email__exact=clean_input.lower()) | Q(username__exact=clean_input)
                )
            except User.DoesNotExist:
                return True  # reCAPTCHA will handle this

            user_lock_key = generate_hash_key(user.id)
            user_cache_key = f"change-password-cooldown:{user_lock_key}"

            if cache.get(user_cache_key):
                self.remaining_ttl = calculate_remaining_ttl(user_cache_key)
                return False

        return True

    def wait(self):
        """
        Return the number of seconds to wait for the next request.
        """
        return self.remaining_ttl
