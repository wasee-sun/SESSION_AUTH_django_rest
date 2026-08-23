from rest_framework import serializers
from server.utils.exception import BadRequestValidationError


class SuccessResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard Success Response structure."""

    success = serializers.CharField(
        help_text="A descriptive message indicating the success of the operation.",
    )


class ErrorResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard Error Response structure."""

    errors = serializers.CharField(
        help_text="A descriptive error message explaining the failure or status.",
    )


class SuccessBoolResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Boolean success response structure."""

    success = serializers.BooleanField(
        required=True,
        allow_null=False,
        help_text="A boolean value indicating the success of the operation.",
        error_messages={
            "required": "Success value is required.",
            "null": "Success value is required.",
            "invalid": "Success value is invalid.",
        },
    )


class BaseRecaptchaSerializer(serializers.Serializer):  # pylint: disable=W0223
    """
    Base serializer for handling reCAPTCHA tokens and request context validation.
    """

    recaptcha_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The Recaptcha token to be used in subsequent requests.",
        error_messages={
            "required": "Missing reCAPTCHA token.",
            "blank": "Missing reCAPTCHA token.",
            "null": "Missing reCAPTCHA token.",
        },
    )
    recaptcha_version = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The Recaptcha version to be used in subsequent requests.",
        error_messages={
            "required": "Missing reCAPTCHA version.",
            "blank": "Missing reCAPTCHA version.",
            "null": "Missing reCAPTCHA version.",
        },
    )

    def validate(self, attrs):
        request = self.context.get("request")
        if not request:
            raise BadRequestValidationError({"error": "Internal server context error."})

        user_agent = request.META.get("HTTP_USER_AGENT", "")
        if not user_agent:
            raise BadRequestValidationError(
                {"user_agent": "Missing User Agent Header."}
            )

        user_ip = request.META.get("HTTP_CF_CONNECTING_IP")

        if not user_ip:
            user_ip = request.META.get(
                "HTTP_X_FORWARDED_FOR", request.META.get("HTTP_X_REAL_IP", "")
            )

        if not user_ip:
            raise BadRequestValidationError({"user_ip": "Missing User IP Address."})

        if "," in user_ip:
            user_ip = user_ip.split(",")[0].strip()

        attrs["user_agent"] = user_agent
        attrs["user_ip"] = user_ip

        return attrs
