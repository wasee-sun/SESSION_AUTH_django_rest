from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from server.utils.encryption import generate_hash_key

User = get_user_model()


class ReqChangePasswordViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("req-change-password")

        self.valid_payload = {
            "email_or_username": "defaultuser@example.com",
            "recaptcha_token": "mock_token_123",
            "recaptcha_version": "v3",
        }

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": token,
        }

    def tearDown(self):
        cache.clear()

    def create_mock_recaptcha_response(
        self, valid=True, reason=0, action="request-password-change", score=0.9
    ):
        """Helper to build a mock Google reCAPTCHA Enterprise response object."""
        mock_response = MagicMock()

        mock_response.token_properties.valid = valid
        mock_response.token_properties.invalid_reason = reason
        mock_response.token_properties.action = action
        mock_response.risk_analysis.score = score

        return mock_response

    # ==========================================
    # REQUEST SERIALIZER VALIDATION FAILURE (400)
    # ==========================================

    def test_missing_email_or_username(self):
        """Test 400 bad request when email or username is missing."""
        payload = self.valid_payload.copy()
        del payload["email_or_username"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email_or_username", response.data)
        self.assertEqual(
            response.data["email_or_username"][0], "Email or username is required."
        )

        payload["email_or_username"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email_or_username", response.data)
        self.assertEqual(
            response.data["email_or_username"][0], "Email or username is required."
        )

        payload["email_or_username"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email_or_username", response.data)
        self.assertEqual(
            response.data["email_or_username"][0], "Email or username is required."
        )

    def test_missing_recaptcha_token(self):
        """Test 400 bad request when recaptcha_token is missing."""
        payload = self.valid_payload.copy()
        del payload["recaptcha_token"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_token", response.data)
        self.assertEqual(
            response.data["recaptcha_token"][0], "Missing reCAPTCHA token."
        )

        payload["recaptcha_token"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_token", response.data)
        self.assertEqual(
            response.data["recaptcha_token"][0], "Missing reCAPTCHA token."
        )

        payload["recaptcha_token"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_token", response.data)
        self.assertEqual(
            response.data["recaptcha_token"][0], "Missing reCAPTCHA token."
        )

    def test_missing_recaptcha_version(self):
        """Test 400 bad request when recaptcha_version is missing."""
        payload = self.valid_payload.copy()
        del payload["recaptcha_version"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_version", response.data)
        self.assertEqual(
            response.data["recaptcha_version"][0], "Missing reCAPTCHA version."
        )

        payload["recaptcha_version"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_version", response.data)
        self.assertEqual(
            response.data["recaptcha_version"][0], "Missing reCAPTCHA version."
        )

        payload["recaptcha_version"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recaptcha_version", response.data)
        self.assertEqual(
            response.data["recaptcha_version"][0], "Missing reCAPTCHA version."
        )

    def test_missing_user_agent_header(self):
        """Test 400 bad request when HTTP_USER_AGENT header is missing."""
        headers = self.headers.copy()
        del headers["HTTP_USER_AGENT"]

        response = self.client.post(
            self.url, self.valid_payload, format="json", **headers
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("user_agent", response.data)
        self.assertEqual(response.data["user_agent"], "Missing User Agent Header.")

    def test_missing_user_ip_header(self):
        """Test 400 bad request when IP headers are missing."""
        headers = self.headers.copy()
        del headers["HTTP_X_REAL_IP"]

        response = self.client.post(
            self.url, self.valid_payload, format="json", **headers
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("user_ip", response.data)
        self.assertEqual(response.data["user_ip"], "Missing User IP Address.")

    # ==========================================
    # RECAPTCHA FAILURE TESTS (403)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_invalid_recaptcha_token_rejected(self, mock_client_class):
        """Test 403 when Google returns token validity as False."""
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(
            valid=False, reason="EXPIRED"
        )
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["error"], "Invalid token reason: EXPIRED")

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_action_mismatch_rejected(self, mock_client_class):
        """Test 403 when action in token doesn't match expected action."""
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(valid=True, action="signup")
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("Action mismatch", response.data["error"])

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_low_score_blocked(self, mock_client_class):
        """Test 403 when Google score is below the 0.7 threshold."""
        mock_client_instance = mock_client_class.return_value
        mock_response = self.create_mock_recaptcha_response(
            valid=True, action="request-password-change", score=0.3
        )
        mock_client_instance.create_assessment.return_value = mock_response

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("reCAPTCHA validation failed.", response.data["error"])

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_internal_server_error_on_google_exception(self, mock_client_class):
        """Test 500 block when Google's SDK raises an unhandled exception."""
        mock_client_instance = mock_client_class.return_value

        # Raise exception when the method is executed
        mock_client_instance.create_assessment.side_effect = Exception(
            "Google service unavailable"
        )

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data["error"], "Google service unavailable")

    # ==========================================
    # CSRFTOKEN FAILURE TEST
    # ==========================================

    def test_request_change_password_fails_when_csrf_token_is_missing(self):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **csrf_less_headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class ReqChangePasswordViewDBTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("req-change-password")

        self.valid_payload = {
            "email_or_username": "defaultuser@example.com",
            "recaptcha_token": "mock_token_123",
            "recaptcha_version": "v3",
        }

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": token,
        }

        self.user = User.objects.create_user(
            email="defaultuser@example.com",
            username="defaultuser",
            password="SecurePassword123!",
            auth_provider="email",
            is_email_verified=True,
            is_active=True,
        )

    def tearDown(self):
        User.objects.all().delete()
        cache.clear()

    def create_mock_recaptcha_response(
        self, valid=True, reason=0, action="request-password-change", score=0.9
    ):
        """Helper to build a mock Google reCAPTCHA Enterprise response object."""
        mock_response = MagicMock()

        mock_response.token_properties.valid = valid
        mock_response.token_properties.invalid_reason = reason
        mock_response.token_properties.action = action
        mock_response.risk_analysis.score = score

        return mock_response

    # ==========================================
    # SUCCESS TESTS (200)
    # ==========================================

    @patch("server.utils.email.dispatch_email.delay")
    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_request_change_password_success(self, mock_recaptcha, mock_dispatch_email):
        """Test that a user with 2FA enabled receives an OTP payload and resets failure cache."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        user_lock_hash = generate_hash_key(self.user.id)
        user_lock_key = f"change-password-cooldown:{user_lock_hash}"

        response1 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        pass_token_hash = generate_hash_key(response1.data["pass_token"])
        pass_token_key = f"change-password:{pass_token_hash}"
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        self.assertIn("pass_token", response1.data)
        self.assertTrue(cache.get(pass_token_key))
        self.assertTrue(cache.get(user_lock_key))

        self.assertTrue(mock_dispatch_email.called)
        self.assertEqual(mock_dispatch_email.call_count, 1)
        called_args, _ = mock_dispatch_email.call_args
        email_context = called_args[0]
        self.assertEqual(email_context["user_email"], self.user.email)
        self.assertEqual(email_context["username"], self.user.username)
        self.assertIsNotNone(email_context["action_url"])
        self.assertIsNotNone(email_context["action_button_text"])

        cache.delete(user_lock_key)

        self.valid_payload["email_or_username"] = "defaultuser"

        response2 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertIn("pass_token", response2.data)
        self.assertTrue(cache.get(user_lock_key))

    # ==========================================
    # AUTHENTICATED USER STATE VALIDATION (403)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_request_change_password_unverified_email_fails(self, mock_recaptcha):
        """Test 403 forbidden when user has not verified their email address."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        self.user.is_email_verified = False
        self.user.save()

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        error_msg = str(response.data["error"])
        self.assertEqual(
            error_msg,
            "Email is not verified. You must verify your email first",
        )

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_request_change_password_deactivated_user_fails(self, mock_recaptcha):
        """Test 403 forbidden when an explicitly deactivated user tries to log in."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        self.user.is_active = False
        self.user.save()

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        error_msg = str(response.data["error"])
        self.assertEqual(
            error_msg,
            "Account has been deactivated. Contact your admin",
        )

    # ==========================================
    # NOT FOUND VALIDATION (404)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_request_change_password_missing_user_fails(self, mock_recaptcha):
        """Test 404 not found when the user does not exist."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        self.valid_payload["email_or_username"] = "nonexistentuser"

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        error_msg = str(response.data["error"])
        self.assertEqual(error_msg, "User does not exist")

    # ==========================================
    # THROTTLING & RATE LIMIT WORKFLOW TESTS (429)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_request_change_password_link_cooldown_throttle_returns_429(
        self, mock_recaptcha
    ):
        """Test that OTPCooldownThrottle blocks a rapid subsequent login attempt with a custom 429 message."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        user_lock_hash = generate_hash_key(self.user.id)
        user_lock_key = f"change-password-cooldown:{user_lock_hash}"
        cache.set(user_lock_key, True, timeout=settings.OTP_COOLDOWN_TTL)

        with patch("django.core.cache.cache.ttl", return_value=45, create=True):
            response = self.client.post(
                self.url, self.valid_payload, format="json", **self.headers
            )

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn("error", response.data)
        self.assertEqual(
            response.data["error"],
            "Please wait 45 seconds before requesting another OTP.",
        )
        self.assertTrue(cache.get(user_lock_key))
