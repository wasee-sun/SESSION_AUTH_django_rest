from rest_framework import serializers
from server.schema_serializers import SuccessBoolResponseSerializer


class CSRFTokenResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard CSRF token structure."""

    csrf_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The CSRF token to be used in subsequent requests.",
        error_messages={
            "required": "CSRF token is required.",
            "blank": "CSRF token is required.",
            "null": "CSRF token is required.",
        },
    )

    csrf_token_expiry = serializers.DateTimeField(
        required=True,
        allow_null=False,
        help_text="CSRF Token Expiry in ISO 8601 format",
        error_messages={
            "required": "CSRF expiration timestamp is required.",
            "null": "CSRF expiration timestamp is required.",
            "invalid": "CSRF expiration timestamp is invalid.",
        },
    )


class OTPResponseSerializer(SuccessBoolResponseSerializer):  # pylint: disable=W0223
    """OTP response structure."""

    pre_auth_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The raw pre-auth token to be used in subsequent requests.",
        error_messages={
            "required": "Raw pre-auth token is required.",
            "blank": "Raw pre-auth token is required.",
            "null": "Raw pre-auth token is required.",
        },
    )


class SessionResponseSerializer(CSRFTokenResponseSerializer):  # pylint: disable=W0223
    """Session response structure."""

    sessionid = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="A unique identifier for the user's session.",
        error_messages={
            "required": "Session ID is required.",
            "blank": "Session ID is required.",
            "null": "Session ID is required.",
        },
    )

    session_expiry = serializers.DateTimeField(
        required=True,
        allow_null=False,
        help_text="Session token expiry in ISO 8601 format.",
        error_messages={
            "required": "Session token expiry is required.",
            "null": "Session token expiry is required.",
            "invalid": "Session token expiry is invalid.",
        },
    )

    user_role = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The role of the user in the system.",
        error_messages={
            "required": "User role is required.",
            "blank": "User role is required.",
            "null": "User role is required.",
        },
    )

    user_id = serializers.IntegerField(
        required=True,
        allow_null=False,
        help_text="A unique identifier for the user.",
        error_messages={
            "required": "User ID is required.",
            "null": "User ID is required.",
            "invalid": "User ID is invalid.",
        },
    )


class ReqChangePassResponseSerializer(
    SuccessBoolResponseSerializer
):  # pylint: disable=W0223
    """Request Change Password response structure."""

    pass_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The raw password token to be used in subsequent requests.",
        error_messages={
            "required": "Raw password token is required.",
            "blank": "Raw password token is required.",
            "null": "Raw password token is required.",
        },
    )
