"""Views for Auth API."""  # pylint: disable=C0302

import logging
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.middleware.csrf import get_token
from django.core.cache import cache
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.exceptions import ValidationError, Throttled
from social_core.exceptions import AuthException
from social_django.utils import load_backend, load_strategy
from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    OpenApiExample,
    PolymorphicProxySerializer,
)

from server.renderers import ViewRenderer
from server.utils.exception import (
    BadRequestValidationError,
    ForbiddenValidationError,
    NotFoundValidationError,
)
from server.utils.email import Email
from server.utils.recaptcha import verify_recaptcha_token
from server.utils.redis import get_cache_data
from server.utils.encryption import generate_hash_key
from server.schema_serializers import (
    SuccessResponseSerializer,
    ErrorResponseSerializer,
)
from .utils import get_user_role
from .throttles import (
    OTPCooldownThrottle,
    TwoFACooldownThrottle,
    ResetPasswordCooldownThrottle,
)
from .serializers import FCMTokenSerializer
from .validation_serializers import ValidUserLoginSerializer, ValidUserSerializer
from .request_serializers import (
    RecaptchaRequestSerializer,
    LoginRequestSerializer,
    TwoFARequestSerializer,
    SocialLoginRequestSerializer,
    FCMTokenRequestSerializer,
    ResendOTPRequestSerializer,
    ReqChangePassRequestSerializer,
)
from .response_serializers import (
    CSRFTokenResponseSerializer,
    OTPResponseSerializer,
    SessionResponseSerializer,
    ReqChangePassResponseSerializer,
)

logger = logging.getLogger(__name__)


class CSRFTokenView(APIView):
    """CSRF Token View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Get CSRF Token",
        description="Returns a CSRF token along with its expiration time.",
        tags=["Authentication"],
        request=None,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=CSRFTokenResponseSerializer,
                description="CSRF token returned",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error",
            ),
        },
        examples=[
            OpenApiExample(
                name="Success",
                response_only=True,
                status_codes=["200"],
                value={
                    "csrf_token": "abc123def456ghi789-CSRFToken",
                    "csrf_token_expiry": "2024-07-01T12:00:00Z",
                },
            ),
            OpenApiExample(
                name="Bad Request",
                response_only=True,
                status_codes=["400"],
                value={"error": "Invalid request parameters"},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        """Get Method for CSRF Token."""
        try:
            csrf_token = get_token(request)
            csrf_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                - timedelta(seconds=10)
            )

            raw_data = {
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry,
            }

            serializer = CSRFTokenResponseSerializer(data=raw_data)

            serializer.is_valid(raise_exception=True)

            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            logger.error("Error getting CSRF token: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RecaptchaValidationView(APIView):
    """Recaptcha Validation View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Validate reCAPTCHA",
        description="Validates the provided reCAPTCHA token with Google's reCAPTCHA service.",
        tags=["Authentication"],
        request=RecaptchaRequestSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=SuccessResponseSerializer,
                description="reCAPTCHA validation successful",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - reCAPTCHA validation failed",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error",
            ),
        },
        examples=[
            OpenApiExample(
                name="reCAPTCHA Request Example",
                request_only=True,
                value={
                    "recaptcha_token": "03AFcWeA7V_u-R8N_m7N1wXzO3K7L-reCAPTCHA-TOKEN",
                    "recaptcha_version": "v3",
                    "expected_action": "login",
                },
            ),
            OpenApiExample(
                name="Success",
                response_only=True,
                status_codes=["200"],
                value={
                    "success": "reCAPTCHA validation successful",
                },
            ),
            OpenApiExample(
                name="Action Missing",
                response_only=True,
                status_codes=["400"],
                value={"error": {"expected_action": ["Action is required."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Token",
                response_only=True,
                status_codes=["400"],
                value={"error": {"recaptcha_token": ["Missing reCAPTCHA token."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Version",
                response_only=True,
                status_codes=["400"],
                value={"error": {"recaptcha_version": ["Missing reCAPTCHA version."]}},
            ),
            OpenApiExample(
                name="Missing User Agent",
                response_only=True,
                status_codes=["400"],
                value={"error": {"user_agent": ["Missing User Agent Header."]}},
            ),
            OpenApiExample(
                name="Missing User IP Address",
                response_only=True,
                status_codes=["400"],
                value={"error": {"user_ip": ["Missing User IP Address."]}},
            ),
            OpenApiExample(
                name="Invalid reCAPTCHA Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid token reason: Reason"},
            ),
            OpenApiExample(
                name="Action Mismatch",
                response_only=True,
                status_codes=["403"],
                value={"error": "Action mismatch. Expected 'login', got 'signup'"},
            ),
            OpenApiExample(
                name="Low Score",
                response_only=True,
                status_codes=["403"],
                value={"error": "reCAPTCHA validation failed."},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Post a request to validate reCAPTCHA.
        Returns a response with success or error message."""
        try:
            req_serializer = RecaptchaRequestSerializer(
                data=request.data, context={"request": request}
            )

            req_serializer.is_valid(raise_exception=True)

            validated_data = req_serializer.validated_data

            is_human, message = verify_recaptcha_token(
                token=validated_data["recaptcha_token"],
                expected_action=validated_data["expected_action"],
                recaptcha_version=validated_data["recaptcha_version"],
                user_ip_address=validated_data["user_ip"],
                user_agent=validated_data["user_agent"],
            )

            if not is_human:
                raise ForbiddenValidationError({"error": message})

            return Response(
                {"success": message},
                status=status.HTTP_200_OK,
            )
        except Exception as e:  # pylint: disable=W0718
            if isinstance(
                e,
                (ValidationError, BadRequestValidationError, ForbiddenValidationError),
            ):
                raise e
            logger.error("Error validating reCAPTCHA: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginView(APIView):
    """Login View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [OTPCooldownThrottle]

    def handle_exception(self, exc):
        if isinstance(exc, Throttled):
            return Response(
                {
                    "error": (
                        f"Please wait {exc.wait} seconds before"
                        " requesting another OTP."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        return super().handle_exception(exc)

    @extend_schema(
        summary="Login to get an OTP or Session ID",
        description=(
            "Authenticates a user via credentials. Handles reCAPTCHA mitigation, "
            "brute-force account tracking thresholds, and multi-factor conditional logic. "
            "If 2FA is enabled, issues an active temporary pre-authentication state payload. "
            "Otherwise, updates explicit anti-CSRF infrastructure and maps active session tokens."
        ),
        request=LoginRequestSerializer,
        tags=["Authentication"],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=PolymorphicProxySerializer(
                    component_name="LoginResponse",
                    serializers=[OTPResponseSerializer, SessionResponseSerializer],
                    resource_type_field_name=None,
                ),
                description=(
                    "Success Branch Outcomes:\n"
                    "1. OTP Response (User has 2FA enabled)\n"
                    "2. Token Response (User has 2FA disabled)"
                ),
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - reCAPTCHA validation failed",
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Too Many Requests",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="Superuser Login Request Example",
                request_only=True,
                value={
                    "email_or_username": "superuser@example.com",
                    "password": "Django@123",
                    "recaptcha_token": "03AFcWeA7V_u-R8N_m7N1wXzO3K7L-reCAPTCHA-TOKEN",
                    "recaptcha_version": "v3",
                },
            ),
            OpenApiExample(
                name="Staff Login Request Example",
                request_only=True,
                value={
                    "email_or_username": "staffuser@example.com",
                    "password": "Django@123",
                    "recaptcha_token": "03AFcWeA7V_u-R8N_m7N1wXzO3K7L-reCAPTCHA-TOKEN",
                    "recaptcha_version": "v3",
                },
            ),
            OpenApiExample(
                name="Default User Login Request Example",
                request_only=True,
                value={
                    "email_or_username": "defaultuser@example.com",
                    "password": "Django@123",
                    "recaptcha_token": "03AFcWeA7V_u-R8N_m7N1wXzO3K7L-reCAPTCHA-TOKEN",
                    "recaptcha_version": "v3",
                },
            ),
            OpenApiExample(
                name="OTP Success (2FA Enabled)",
                response_only=True,
                status_codes=["200"],
                value={
                    "success": "True",
                    "pre_auth_token": "kdslfjs0f9ujse8fhse8fs-PRE-AUTH-TOKEN",
                },
            ),
            OpenApiExample(
                name="Token Success (2FA Disabled)",
                response_only=True,
                status_codes=["200"],
                value={
                    "sessionid": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-SESSIONID",
                    "session_expiry": "2026-06-17T12:34:56.789Z",
                    "user_id": 42,
                    "user_role": "Default",
                    "csrf_token": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-CSRFTOKEN",
                    "csrf_token_expiry": "2026-06-18T12:34:56.789Z",
                },
            ),
            OpenApiExample(
                name="Missing email or username",
                response_only=True,
                status_codes=["400"],
                value={
                    "error": {"email_or_username": ["Email or username is required."]}
                },
            ),
            OpenApiExample(
                name="Missing Password",
                response_only=True,
                status_codes=["400"],
                value={"error": {"password": ["Password is required."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Token",
                response_only=True,
                status_codes=["400"],
                value={"error": {"recaptcha_token": ["Missing reCAPTCHA token."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Version",
                response_only=True,
                status_codes=["400"],
                value={"error": {"recaptcha_version": ["Missing reCAPTCHA version."]}},
            ),
            OpenApiExample(
                name="Missing User Agent",
                response_only=True,
                status_codes=["400"],
                value={"error": {"user_agent": ["Missing User Agent Header."]}},
            ),
            OpenApiExample(
                name="Missing User IP Address",
                response_only=True,
                status_codes=["400"],
                value={"error": {"user_ip": ["Missing User IP Address."]}},
            ),
            OpenApiExample(
                name="Invalid Credentials",
                response_only=True,
                status_codes=["400"],
                value={"error": "Invalid credentials"},
            ),
            OpenApiExample(
                name="Account Warning Limit (Attempts 3 or 4)",
                response_only=True,
                status_codes=["400"],
                value={
                    "error": (
                        "Invalid credentials. You have 2 more "
                        "attempt(s) before your account is deactivated."
                    )
                },
            ),
            OpenApiExample(
                name="Max Attempts Hit (Lockout)",
                response_only=True,
                status_codes=["400"],
                value={
                    "error": (
                        "Invalid credentials. Your account has "
                        "been deactivated. Contact an admin."
                    )
                },
            ),
            OpenApiExample(
                name="Invalid reCAPTCHA Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid token reason: Invalid"},
            ),
            OpenApiExample(
                name="Action Mismatch",
                response_only=True,
                status_codes=["403"],
                value={"error": "Action mismatch. Expected 'login', got 'signup'"},
            ),
            OpenApiExample(
                name="Low Score",
                response_only=True,
                status_codes=["403"],
                value={"error": "reCAPTCHA validation failed."},
            ),
            OpenApiExample(
                name="Deactivated Account Check",
                response_only=True,
                status_codes=["403"],
                value={"error": "Account has been deactivated. Contact your admin"},
            ),
            OpenApiExample(
                name="Unverified Email Check",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": "Email is not verified. You must verify your email first"
                },
            ),
            OpenApiExample(
                name="OAuth Provider Mismatch",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": (
                        "This account uses social login. Please set a"
                        "password first to log in with an email."
                    )
                },
            ),
            OpenApiExample(
                name="Throttled Wait Penalty",
                response_only=True,
                status_codes=["429"],
                value={
                    "error": "Please wait 45 seconds before requesting another OTP."
                },
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):  # pylint: disable=R0911, R0914
        """Post a request to login. Returns an OTP or SessionID to the registered email."""
        try:
            req_serializer = LoginRequestSerializer(
                data=request.data, context={"request": request}
            )

            req_serializer.is_valid(raise_exception=True)

            req_validated_data = req_serializer.validated_data

            is_human, message = verify_recaptcha_token(
                token=req_validated_data["recaptcha_token"],
                expected_action="login",
                recaptcha_version=req_validated_data["recaptcha_version"],
                user_ip_address=req_validated_data["user_ip"],
                user_agent=req_validated_data["user_agent"],
            )

            if not is_human:
                raise ForbiddenValidationError({"error": message})

            user = authenticate(
                request=request,
                username=req_validated_data["email_or_username"],
                password=req_validated_data["password"],
            )

            valid_serializer = ValidUserLoginSerializer(
                data={}, context={"user": user, "request": request}
            )

            valid_serializer.is_valid(raise_exception=True)

            validated_user = valid_serializer.validated_data["user"]

            hashed_user_key = generate_hash_key(validated_user.id)
            cache.delete(f"login-failures:{hashed_user_key}")

            if validated_user.is_two_fa:
                otp_email = Email(
                    user,
                    f"{settings.APP_NAME} account verification code",
                    "Confirm that it's you",
                    "We recieved a request to log in to your account. Your verification code is:",
                )

                pre_auth_token = otp_email.send_otp_email("pre-auth-otp")

                otp_res_serializer = OTPResponseSerializer(
                    data={"success": True, "pre_auth_token": pre_auth_token}
                )

                otp_res_serializer.is_valid(raise_exception=True)

                return Response(otp_res_serializer.data, status=status.HTTP_200_OK)

            login(request, validated_user)
            sessionid = request.session.session_key
            session_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.SESSION_COOKIE_TTL)
                - timedelta(seconds=10)
            ).isoformat()

            csrf_token = get_token(request)
            csrf_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                - timedelta(seconds=10)
            )

            raw_data = {
                "sessionid": sessionid,
                "session_expiry": session_expiry,
                "user_id": validated_user.id,
                "user_role": get_user_role(validated_user),
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry,
            }

            token_res_serializer = SessionResponseSerializer(data=raw_data)

            token_res_serializer.is_valid(raise_exception=True)

            return Response(token_res_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(
                e,
                (ValidationError, BadRequestValidationError, ForbiddenValidationError),
            ):
                raise e
            logger.error("Login failed: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TwoFAView(APIView):
    """2FA view."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [TwoFACooldownThrottle]

    def handle_exception(self, exc):
        if isinstance(exc, Throttled):
            return Response(
                {
                    "error": (
                        f"Please wait {exc.wait} seconds before"
                        " submitting another OTP."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        return super().handle_exception(exc)

    @extend_schema(
        summary="Generate Session ID",
        description=(
            "Verifies OTP and generates Session ID " "for the authenticated user."
        ),
        request=TwoFARequestSerializer,
        tags=["Authentication"],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=SessionResponseSerializer,
                description="Return Session ID",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - reCAPTCHA validation failed",
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Too Many Requests",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="2FA Request Example",
                request_only=True,
                value={
                    "pre-auth-token": "kdslfjs0f9ujse8fhse8fs-PRE-AUTH-TOKEN",
                    "otp": "000000",
                },
            ),
            OpenApiExample(
                name="Session ID Success",
                response_only=True,
                status_codes=["200"],
                value={
                    "sessionid": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-SESSIONID",
                    "session_expiry": "2026-06-17T12:34:56.789Z",
                    "user_id": 42,
                    "user_role": "Default",
                    "csrf_token": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-CSRFTOKEN",
                    "csrf_token_expiry": "2026-06-18T12:34:56.789Z",
                },
            ),
            OpenApiExample(
                name="Missing Pre Auth Token",
                response_only=True,
                status_codes=["400"],
                value={"error": {"pre_auth_token": ["Token is required."]}},
            ),
            OpenApiExample(
                name="Missing OTP",
                response_only=True,
                status_codes=["400"],
                value={"error": {"otp": ["OTP is required."]}},
            ),
            OpenApiExample(
                name="Invalid OTP",
                response_only=True,
                status_codes=["400"],
                value={"error": {"otp": ["OTP is invalid."]}},
            ),
            OpenApiExample(
                name="Invalid Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid Token"},
            ),
            OpenApiExample(
                name="Invalid OTP",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid OTP"},
            ),
            OpenApiExample(
                name="Throttled Wait Penalty",
                response_only=True,
                status_codes=["429"],
                value={
                    "error": "Please wait 45 seconds before submitting another OTP."
                },
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):  # pylint: disable=R0911, R0914
        """Post a request to TwoFA. Returns SessionID to the registered email."""
        try:
            req_serializer = TwoFARequestSerializer(data=request.data)

            req_serializer.is_valid(raise_exception=True)

            req_validated_data = req_serializer.validated_data

            otp_verification = Email.verification(
                prefix="pre-auth-otp",
                token=req_validated_data["pre_auth_token"],
                user_otp=req_validated_data["otp"],
            )

            if otp_verification.get("error"):
                raise ForbiddenValidationError({"error": otp_verification["error"]})

            user_id = otp_verification["user_id"]

            user = get_user_model().objects.get(id=user_id)

            login(request, user, backend="server.backends.CustomAuthBackend")
            sessionid = request.session.session_key
            session_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.SESSION_COOKIE_TTL)
                - timedelta(seconds=10)
            ).isoformat()

            csrf_token = get_token(request)
            csrf_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                - timedelta(seconds=10)
            )

            raw_data = {
                "sessionid": sessionid,
                "session_expiry": session_expiry,
                "user_id": user.id,
                "user_role": get_user_role(user),
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry,
            }

            token_res_serializer = SessionResponseSerializer(data=raw_data)

            token_res_serializer.is_valid(raise_exception=True)

            cache.delete(f"pre-auth-otp:{otp_verification["hashed_key"]}")

            return Response(token_res_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, (ValidationError, ForbiddenValidationError)):
                raise e
            logger.error("TwoFA failed: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RefreshSessionView(APIView):
    """Refresh and Rotate Session."""

    permission_classes = [IsAuthenticated]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Refresh and Rotate Session",
        description=(
            "Rotates the existing session ID cookie and "
            "generates a fresh CSRF token to prevent token expiration."
        ),
        tags=["Authentication"],
        request=None,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=SessionResponseSerializer,
                description="Session and CSRF tokens successfully refreshed.",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - Authentication failed",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error",
            ),
        },
        examples=[
            OpenApiExample(
                name="Success Response",
                response_only=True,
                status_codes=["200"],
                value={
                    "sessionid": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-SESSIONID",
                    "session_expiry": "2026-06-17T12:34:56.789Z",
                    "user_id": 42,
                    "user_role": "Default",
                    "csrf_token": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-CSRFTOKEN",
                    "csrf_token_expiry": "2026-06-18T12:34:56.789Z",
                },
            ),
            OpenApiExample(
                name="Authentication Failed",
                response_only=True,
                status_codes=["403"],
                value={"error": "Authentication credentials were not provided."},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Failed to refresh session."},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Rotates the session key and returns fresh session and CSRF details."""
        try:
            # Issue a new session key by deleting old key from cache and db
            request.session.cycle_key()

            sessionid = request.session.session_key
            session_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.SESSION_COOKIE_TTL)
                - timedelta(seconds=10)
            ).isoformat()

            user = request.user

            csrf_token = get_token(request)
            csrf_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                - timedelta(seconds=10)
            )

            raw_data = {
                "sessionid": sessionid,
                "session_expiry": session_expiry,
                "user_id": user.id,
                "user_role": get_user_role(user),
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry,
            }

            token_res_serializer = SessionResponseSerializer(data=raw_data)

            token_res_serializer.is_valid(raise_exception=True)

            return Response(token_res_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, ValidationError):
                raise e
            logger.error("Session refresh failed: %s", str(e))
            return Response(
                {"error": "Failed to refresh session."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class SocialLoginView(APIView):
    """
    Unified Social Login View. Validates authorization code payload forwarded
    from Custom SDK and executes custom social auth pipelines.
    """

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Social Authentication",
        description=(
            "Accepts a social auth provider code verified by the SDK, executes the"
            "social login or signup backend pipeline, and returns a Session ID."
        ),
        request=SocialLoginRequestSerializer,
        tags=["Authentication"],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=SessionResponseSerializer,
                description="Success - Session ID returned",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Unauthorized - Social authentication failed",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - Social authentication failed due to user",
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Not Found - User not found in backend DB",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="Social Login Request Example",
                request_only=True,
                value={
                    "provider": "google-oauth2",
                    "social_auth_code": "ya29.a0AfH6SMC-EXAMPLE-CODE-FROM-SDK",
                    "redirect_uri": "http://localhost:8000/",
                },
            ),
            OpenApiExample(
                name="Session ID Success Response",
                response_only=True,
                status_codes=["200"],
                value={
                    "sessionid": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-SESSIONID",
                    "session_expiry": "2026-06-17T12:34:56.789Z",
                    "user_id": 42,
                    "user_role": "Default",
                    "csrf_token": "ABcDeFgHiJkLmNoPqRsTuVwXyZ123456-CSRFTOKEN",
                    "csrf_token_expiry": "2026-06-18T12:34:56.789Z",
                },
            ),
            OpenApiExample(
                name="Missing Provider Name",
                response_only=True,
                status_codes=["400"],
                value={"error": {"provider": ["Provider is required."]}},
            ),
            OpenApiExample(
                name="Missing Social Code",
                response_only=True,
                status_codes=["400"],
                value={"error": {"social_auth_code": ["Code is required."]}},
            ),
            OpenApiExample(
                name="Missing Redirect URI",
                response_only=True,
                status_codes=["400"],
                value={"error": {"redirect_uri": ["Redirect URI is required."]}},
            ),
            OpenApiExample(
                name="Social Provider Auth Failed",
                response_only=True,
                status_codes=["401"],
                value={"error": "Social authentication failed. Something went wrong."},
            ),
            OpenApiExample(
                name="Amazon Login Linkup Fails",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": (
                        "You cannot log into an existing account using Amazon. "
                        "Please log in using your original method."
                    )
                },
            ),
            OpenApiExample(
                name="Unverified Email Check (Provider)",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": (
                        "Sorry your email is not verified by the "
                        "provider. Please verify your email first."
                    )
                },
            ),
            OpenApiExample(
                name="Staff Account Check",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": (
                        "Authentication failed. Please verify your credentials "
                        "or try a different login method."
                    )
                },
            ),
            OpenApiExample(
                name="Deactivated Account Check",
                response_only=True,
                status_codes=["403"],
                value={"error": "Account has been deactivated. Contact your admin"},
            ),
            OpenApiExample(
                name="Unverified Email Check (Local)",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": "Email is not verified. You must verify your email first"
                },
            ),
            OpenApiExample(
                name="Resolved User Not Found",
                response_only=True,
                status_codes=["404"],
                value={"error": "Authentication error. User not found"},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):  # pylint: disable=R0914
        """Post a request to social login. Returns SessionID to the registered email."""
        try:
            req_serializer = SocialLoginRequestSerializer(data=request.data)

            req_serializer.is_valid(raise_exception=True)

            validated_data = req_serializer.validated_data

            provider_name = validated_data["provider"]
            social_auth_code = validated_data["social_auth_code"]
            redirect_uri = validated_data["redirect_uri"]

            strategy = load_strategy(request)
            backend = load_backend(
                strategy=strategy, name=provider_name, redirect_uri=redirect_uri
            )

            # Disable state params (Handled by Server Side SDK)
            backend.REDIRECT_STATE = False
            backend.STATE_PARAMETER = False

            # Set the code and redirect_uri in the request
            backend.data = {
                "code": social_auth_code,
                "redirect_uri": redirect_uri,
                **request.data,
            }

            user = backend.auth_complete()

            if not user:
                raise NotFoundValidationError(
                    {"error": "Authentication error. User not found"}
                )

            hashed_user_key = generate_hash_key(user.id)
            cache.delete(f"login-failures:{hashed_user_key}")

            login(request, user, backend=user.backend)
            sessionid = request.session.session_key
            session_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.SESSION_COOKIE_TTL)
                - timedelta(seconds=10)
            ).isoformat()

            csrf_token = get_token(request)
            csrf_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                - timedelta(seconds=10)
            )

            raw_data = {
                "sessionid": sessionid,
                "session_expiry": session_expiry,
                "user_id": user.id,
                "user_role": get_user_role(user),
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry,
            }

            token_res_serializer = SessionResponseSerializer(data=raw_data)

            token_res_serializer.is_valid(raise_exception=True)

            return Response(token_res_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(
                e, (ValidationError, ForbiddenValidationError, NotFoundValidationError)
            ):
                raise e
            logger.error("Social authentication failed: %s", str(e))
            if isinstance(e, AuthException):
                return Response(
                    {"error": "Social authentication failed. Something went wrong."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LogoutView(APIView):
    """Logout View."""

    permission_classes = [IsAuthenticated]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Logout and invalidate session",
        description=(
            "Logs out the authenticated user. This flushes the active session, "
            "clears backend caches associated with the session state, and instructs "
            "the infrastructure to clear active anti-CSRF cookies and session headers."
        ),
        request=None,
        tags=["Authentication"],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=SuccessResponseSerializer,
                description="Success - Successfully logged out",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - Missing or invalid session/credentials",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="Logout Success Example",
                response_only=True,
                status_codes=["200"],
                value={"success": "Logged out successfully"},
            ),
            OpenApiExample(
                name="Logout Failure Example",
                response_only=True,
                status_codes=["403"],
                value={"error": "Authentication credentials were not provided."},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Post a request to logout. Flushes session details cleanly."""
        try:
            session_key = request.session.session_key

            if session_key and hasattr(request.session, "delete"):
                try:
                    request.session.delete(session_key)
                except Exception:  # pylint: disable=W0718
                    pass  # Fail silently if session does not exist

            logout(request)

            return Response(
                {"success": "Logged out successfully"}, status=status.HTTP_200_OK
            )
        except Exception as e:  # pylint: disable=W0718
            logger.error("Logout failed: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FCMTokenView(APIView):
    """FCM Token View."""

    permission_classes = [IsAuthenticated]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Register FCM Token",
        description="Register a FCM token in the database.",
        request=FCMTokenRequestSerializer,
        tags=["Authentication"],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=SuccessResponseSerializer,
                description="Success - FCM token registered",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - Authentication failed",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="FCMToken Request Example",
                request_only=True,
                value={
                    "fcm_token": "f3X8kPzQ6xE:APA91bHwM1C7eXzR-FCM-TOKEN",
                },
            ),
            OpenApiExample(
                name="FCMToken Success Example",
                response_only=True,
                status_codes=["200"],
                value={"success": "FCM token registered successfully"},
            ),
            OpenApiExample(
                name="Missing FCM Token",
                response_only=True,
                status_codes=["400"],
                value={"error": {"fcm_token": ["Token is required."]}},
            ),
            OpenApiExample(
                name="Authentication Failed",
                response_only=True,
                status_codes=["403"],
                value={"error": "Authentication credentials were not provided."},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Register a FCM token in the database."""
        try:
            req_serializer = FCMTokenRequestSerializer(data=request.data)

            req_serializer.is_valid(raise_exception=True)

            validated_data = req_serializer.validated_data

            fcm_token = validated_data["fcm_token"]

            res_serializer = FCMTokenSerializer(
                data={"token": fcm_token}, context={"user": request.user}
            )

            res_serializer.is_valid(raise_exception=True)
            res_serializer.save()

            return Response(
                {"success": "FCM token registered successfully"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, ValidationError):
                raise e
            logger.error("FCM token registration failed: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ResendOTPView(APIView):
    """Resend OTP View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [OTPCooldownThrottle]

    def handle_exception(self, exc):
        if isinstance(exc, Throttled):
            return Response(
                {
                    "error": (
                        f"Please wait {exc.wait} seconds before"
                        " requesting another OTP."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        return super().handle_exception(exc)

    @extend_schema(
        summary="Resend OTP",
        description=(
            "Gives access to a user via pre_auth_token. Handles reCAPTCHA mitigation, "
            "brute-force account tracking thresholds, and multi-factor conditional logic. "
            "Issues an new active temporary pre-authentication state payload. "
            "Deletes any existing active temporary pre-authentication state payload. "
        ),
        request=ResendOTPRequestSerializer,
        tags=["Authentication"],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=OTPResponseSerializer,
                description="Return Pre-Auth Token",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - reCAPTCHA or data validations failed",
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Too Many Requests",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="Resend OTP Request Example",
                request_only=True,
                value={
                    "pre-auth-token": "kdslfjs0f9ujse8fhse8fs-PRE-AUTH-TOKEN",
                    "recaptcha_token": "03AFcWeA7V_u-R8N_m7N1wXzO3K7L-reCAPTCHA-TOKEN",
                    "recaptcha_version": "v3",
                },
            ),
            OpenApiExample(
                name="Resend OTP Success",
                response_only=True,
                status_codes=["200"],
                value={
                    "success": "True",
                    "pre_auth_token": "kdslfjs0f9ujse8fhse8fs-PRE-AUTH-TOKEN",
                },
            ),
            OpenApiExample(
                name="Missing Pre Auth Token",
                response_only=True,
                status_codes=["400"],
                value={"error": {"pre_auth_token": ["Token is required."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Token",
                response_only=True,
                status_codes=["400"],
                value={"error": {"recaptcha_token": ["Missing reCAPTCHA token."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Version",
                response_only=True,
                status_codes=["400"],
                value={"error": {"recaptcha_version": ["Missing reCAPTCHA version."]}},
            ),
            OpenApiExample(
                name="Missing User Agent",
                response_only=True,
                status_codes=["400"],
                value={"error": {"user_agent": ["Missing User Agent Header."]}},
            ),
            OpenApiExample(
                name="Missing User IP Address",
                response_only=True,
                status_codes=["400"],
                value={"error": {"user_ip": ["Missing User IP Address."]}},
            ),
            OpenApiExample(
                name="Invalid reCAPTCHA Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid token reason: Invalid"},
            ),
            OpenApiExample(
                name="Action Mismatch",
                response_only=True,
                status_codes=["403"],
                value={"error": "Action mismatch. Expected 'login', got 'signup'"},
            ),
            OpenApiExample(
                name="Low Score",
                response_only=True,
                status_codes=["403"],
                value={"error": "reCAPTCHA validation failed."},
            ),
            OpenApiExample(
                name="Invalid Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid Token"},
            ),
            OpenApiExample(
                name="Throttled Wait Penalty",
                response_only=True,
                status_codes=["429"],
                value={
                    "error": "Please wait 45 seconds before requesting another OTP."
                },
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):  # pylint: disable=R0914
        """Resend OTP to the registered email."""
        try:
            req_serializer = ResendOTPRequestSerializer(
                data=request.data, context={"request": request}
            )

            req_serializer.is_valid(raise_exception=True)

            req_validated_data = req_serializer.validated_data

            is_human, message = verify_recaptcha_token(
                token=req_validated_data["recaptcha_token"],
                expected_action="resend-otp",
                recaptcha_version=req_validated_data["recaptcha_version"],
                user_ip_address=req_validated_data["user_ip"],
                user_agent=req_validated_data["user_agent"],
            )

            if not is_human:
                raise ForbiddenValidationError({"error": message})

            cache_data = get_cache_data(
                "pre-auth-otp", req_validated_data["pre_auth_token"]
            )

            if cache_data.get("error"):
                raise ForbiddenValidationError({"error": cache_data["error"]})

            hashed_key = cache_data["hashed_key"]
            decrypted_data = cache_data["decrypted_data"]

            user = get_user_model().objects.get(id=decrypted_data["user_id"])

            otp_email = Email(
                user,
                f"{settings.APP_NAME} account verification code",
                "Confirm that it's you",
                "We recieved a request to log in to your account. Your verification code is:",
            )

            new_pre_auth_token = otp_email.send_otp_email("pre-auth-otp")

            otp_res_serializer = OTPResponseSerializer(
                data={"success": True, "pre_auth_token": new_pre_auth_token}
            )

            otp_res_serializer.is_valid(raise_exception=True)
            cache.delete(f"pre-auth-otp:{hashed_key}")

            return Response(otp_res_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(
                e,
                (ValidationError, BadRequestValidationError, ForbiddenValidationError),
            ):
                raise e
            logger.error("Resend OTP failed: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RequestChangePasswordView(APIView):
    """Request Change Password View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ResetPasswordCooldownThrottle]

    def handle_exception(self, exc):
        if isinstance(exc, Throttled):
            return Response(
                {
                    "error": (
                        f"Please wait {exc.wait} seconds before"
                        " requesting another OTP."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        return super().handle_exception(exc)

    @extend_schema(
        summary="Request Change Password",
        description=(
            "Request to change password granted by email or username. Handles reCAPTCHA mitigation,"
            " brute-force account tracking thresholds, and multi-factor conditional logic. "
            "Issues an new active temporary pass_token state payload. "
        ),
        request=ReqChangePassRequestSerializer,
        tags=["Authentication"],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=ReqChangePassResponseSerializer,
                description="Return Password Token",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Bad Request - Invalid request parameters",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Forbidden - reCAPTCHA or user validations failed",
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Not Found - User not found",
            ),
            status.HTTP_429_TOO_MANY_REQUESTS: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Too Many Requests",
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="Request Change Password Example",
                request_only=True,
                value={
                    "email_or_username": "defaultuser@example.com",
                    "recaptcha_token": "03AFcWeA7V_u-R8N_m7N1wXzO3K7L-reCAPTCHA-TOKEN",
                    "recaptcha_version": "v3",
                },
            ),
            OpenApiExample(
                name="Request Password Change Success",
                response_only=True,
                status_codes=["200"],
                value={
                    "success": "True",
                    "pass_token": "kdslfjs0f9ujse8fhse8fs-PRE-AUTH-TOKEN",
                },
            ),
            OpenApiExample(
                name="Missing email or username",
                response_only=True,
                status_codes=["400"],
                value={
                    "error": {"email_or_username": ["Email or username is required."]}
                },
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Token",
                response_only=True,
                status_codes=["400"],
                value={"error": {"recaptcha_token": ["Missing reCAPTCHA token."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Version",
                response_only=True,
                status_codes=["400"],
                value={"error": {"recaptcha_version": ["Missing reCAPTCHA version."]}},
            ),
            OpenApiExample(
                name="Missing User Agent",
                response_only=True,
                status_codes=["400"],
                value={"error": {"user_agent": ["Missing User Agent Header."]}},
            ),
            OpenApiExample(
                name="Missing User IP Address",
                response_only=True,
                status_codes=["400"],
                value={"error": {"user_ip": ["Missing User IP Address."]}},
            ),
            OpenApiExample(
                name="Invalid reCAPTCHA Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid token reason: Invalid"},
            ),
            OpenApiExample(
                name="Action Mismatch",
                response_only=True,
                status_codes=["403"],
                value={"error": "Action mismatch. Expected 'login', got 'signup'"},
            ),
            OpenApiExample(
                name="Low Score",
                response_only=True,
                status_codes=["403"],
                value={"error": "reCAPTCHA validation failed."},
            ),
            OpenApiExample(
                name="Deactivated Account Check",
                response_only=True,
                status_codes=["403"],
                value={"error": "Account has been deactivated. Contact your admin"},
            ),
            OpenApiExample(
                name="Unverified Email Check",
                response_only=True,
                status_codes=["403"],
                value={
                    "error": "Email is not verified. You must verify your email first"
                },
            ),
            OpenApiExample(
                name="User not found",
                response_only=True,
                status_codes=["404"],
                value={"error": "User does not exist"},
            ),
            OpenApiExample(
                name="Throttled Wait Penalty",
                response_only=True,
                status_codes=["429"],
                value={
                    "error": "Please wait 45 seconds before requesting another OTP."
                },
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Post a request to change password. Sends a link to the registered email."""
        try:
            req_serializer = ReqChangePassRequestSerializer(
                data=request.data, context={"request": request}
            )

            req_serializer.is_valid(raise_exception=True)

            req_validated_data = req_serializer.validated_data

            is_human, message = verify_recaptcha_token(
                token=req_validated_data["recaptcha_token"],
                expected_action="request-password-change",
                recaptcha_version=req_validated_data["recaptcha_version"],
                user_ip_address=req_validated_data["user_ip"],
                user_agent=req_validated_data["user_agent"],
            )

            if not is_human:
                raise ForbiddenValidationError({"error": message})

            valid_serializer = ValidUserSerializer(
                data={},
                context={
                    "email_or_username": req_validated_data["email_or_username"],
                    "endpoint": "change-password",
                },
            )

            valid_serializer.is_valid(raise_exception=True)

            validated_user = valid_serializer.validated_data["user"]

            password_change_email = Email(
                validated_user,
                f"{settings.APP_NAME} password change request",
                "Change Your Password",
                (
                    "We received a request to change your password. "
                    "Click the link below to set a new password:"
                ),
            )

            pass_token = password_change_email.send_security_link_email(
                "change-password"
            )

            res_serializer = ReqChangePassResponseSerializer(
                data={"success": True, "pass_token": pass_token}
            )

            res_serializer.is_valid(raise_exception=True)

            return Response(res_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(
                e,
                (
                    ValidationError,
                    BadRequestValidationError,
                    ForbiddenValidationError,
                    NotFoundValidationError,
                ),
            ):
                raise e
            logger.error("Login failed: %s", str(e))
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
