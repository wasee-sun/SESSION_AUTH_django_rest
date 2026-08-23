from rest_framework import serializers
from server.schema_serializers import BaseRecaptchaSerializer
from .validation_serializers import ValidPasswordSerializer


class RecaptchaRequestSerializer(BaseRecaptchaSerializer):  # pylint: disable=W0223
    """
    Extends the base reCAPTCHA serializer to include the expected_action field.
    """

    expected_action = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="Client's action in the frontend to be used in subsequent requests.",
        error_messages={
            "required": "Action is required.",
            "blank": "Action is required.",
            "null": "Action is required.",
        },
    )


class LoginRequestSerializer(BaseRecaptchaSerializer):  # pylint: disable=W0223
    """
    Handles Login credentials AND inherits the base reCAPTCHA validations/fields.
    """

    email_or_username = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The email or username of the user to log in.",
        error_messages={
            "required": "Email or username is required.",
            "blank": "Email or username is required.",
            "null": "Email or username is required.",
        },
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        allow_null=False,
        allow_blank=False,
        help_text="The password of the user to log in.",
        error_messages={
            "required": "Password is required.",
            "blank": "Password is required.",
            "null": "Password is required.",
        },
    )


class TwoFARequestSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Handles 2FA credentials.
    """

    # pylint: disable=R0801
    pre_auth_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The raw pre-auth token to be used in subsequent requests.",
        error_messages={
            "required": "Token is required.",
            "blank": "Token is required.",
            "null": "Token is required.",
        },
    )
    # pylint: enable=R0801

    otp = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The One Time Password to be used in subsequent requests.",
        error_messages={
            "required": "OTP is required.",
            "blank": "OTP is required.",
            "null": "OTP is required.",
        },
    )


class SocialLoginRequestSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Handles Social Login credentials.
    """

    provider = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The social provider name",
        error_messages={
            "required": "Provider is required.",
            "blank": "Provider is required.",
            "null": "Provider is required.",
        },
    )

    social_auth_code = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="Authorization code received from the SDK client",
        error_messages={
            "required": "Code is required.",
            "blank": "Code is required.",
            "null": "Code is required.",
        },
    )

    redirect_uri = serializers.URLField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The exact redirect_uri used during the authorization request",
        error_messages={
            "required": "Redirect URI is required.",
            "blank": "Redirect URI is required.",
            "null": "Redirect URI is required.",
        },
    )


class FCMTokenRequestSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Handles FCM Token credentials.
    """

    fcm_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The FCM token to be used in subsequent requests.",
        error_messages={
            "required": "Token is required.",
            "blank": "Token is required.",
            "null": "Token is required.",
        },
    )


class ResendOTPRequestSerializer(BaseRecaptchaSerializer):  # pylint: disable=W0223
    """
    Handles Resend OTP credentials AND inherits the base reCAPTCHA validations/fields.
    """

    # pylint: disable=R0801
    pre_auth_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The raw pre-auth token to be used in subsequent requests.",
        error_messages={
            "required": "Token is required.",
            "blank": "Token is required.",
            "null": "Token is required.",
        },
    )
    # pylint: enable=R0801


class ReqChangePassRequestSerializer(BaseRecaptchaSerializer):  # pylint: disable=W0223
    """
    Request Change Password email or username AND inherits the base reCAPTCHA validations/fields.
    """

    # pylint: disable=R0801
    email_or_username = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The email or username of the user to log in.",
        error_messages={
            "required": "Email or username is required.",
            "blank": "Email or username is required.",
            "null": "Email or username is required.",
        },
    )
    # pylint: enable=R0801


class ChangePassRequestSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Handles Change Password credentials.
    """

    # pylint: disable=R0801
    pass_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The raw password token to be used in subsequent requests.",
        error_messages={
            "required": "Token is required.",
            "blank": "Token is required.",
            "null": "Token is required.",
        },
    )
    # pylint: enable=R0801


class ChangePassOpenAPIRequestSerializer(
    ChangePassRequestSerializer, ValidPasswordSerializer
):  # pylint: disable=W0223
    """Combined serializer for OpenAPI request body documentation."""
