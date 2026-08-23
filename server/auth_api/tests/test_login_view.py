from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from server.utils.encryption import generate_hash_key

User = get_user_model()


class LoginViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("login")

        self.valid_payload = {
            "email_or_username": "defaultuser@example.com",
            "password": "SecurePassword123!",
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
        self, valid=True, reason=0, action="login", score=0.9
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

    def test_missing_password(self):
        """Test 400 bad request when password is missing."""
        payload = self.valid_payload.copy()
        del payload["password"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertEqual(response.data["password"][0], "Password is required.")

        payload["password"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertEqual(response.data["password"][0], "Password is required.")

        payload["password"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertEqual(response.data["password"][0], "Password is required.")

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
            valid=True, action="login", score=0.3
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

    def test_login_fails_when_csrf_token_is_missing(self):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **csrf_less_headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class LoginViewDBTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("login")

        self.valid_payload = {
            "email_or_username": "defaultuser@example.com",
            "password": "SecurePassword123!",
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
            is_two_fa=True,
        )

    def tearDown(self):
        User.objects.all().delete()
        cache.clear()

    def create_mock_recaptcha_response(
        self, valid=True, reason=0, action="login", score=0.9
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
    def test_login_with_2fa_enabled_success(self, mock_recaptcha, mock_dispatch_email):
        """Test that a user with 2FA enabled receives an OTP payload and resets failure cache."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        login_hashed_key = generate_hash_key(self.user.id)
        login_failure_key = f"login-failures:{login_hashed_key}"
        cache.set(login_failure_key, 2, timeout=settings.LOGIN_FAILURE_ATTEMPT_TTL)

        dummy_hash_key = generate_hash_key("ghost_user")
        dummy_key = f"ghost-failures:{dummy_hash_key}"

        user_lock_hash = generate_hash_key(self.user.id)
        user_lock_key = f"pre-auth-otp-cooldown:{user_lock_hash}"

        response1 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        self.assertIn("pre_auth_token", response1.data)
        self.assertTrue(cache.get(user_lock_key))
        self.assertIsNone(cache.get(login_failure_key))
        self.assertIsNone(cache.get(dummy_key))

        self.assertTrue(mock_dispatch_email.called)
        self.assertEqual(mock_dispatch_email.call_count, 1)
        called_args, _ = mock_dispatch_email.call_args
        email_context = called_args[0]
        self.assertEqual(email_context["user_email"], self.user.email)
        self.assertEqual(email_context["username"], self.user.username)
        self.assertIsNotNone(email_context["otp_code"])

        cache.delete(user_lock_key)

        self.valid_payload["email_or_username"] = "defaultuser"

        response2 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertIn("pre_auth_token", response2.data)
        self.assertTrue(cache.get(user_lock_key))

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_login_with_2fa_disabled_success(self, mock_recaptcha):
        """Test that a user with 2FA disabled directly receives Session tokens and resets failure cache."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        self.user.is_two_fa = False
        self.user.save()

        login_hashed_key = generate_hash_key(self.user.id)
        login_failure_key = f"login-failures:{login_hashed_key}"
        cache.set(login_failure_key, 3, timeout=settings.LOGIN_FAILURE_ATTEMPT_TTL)

        dummy_hash_key = generate_hash_key("ghost_user")
        dummy_key = f"ghost-failures:{dummy_hash_key}"

        user_lock_hash = generate_hash_key(self.user.id)
        user_lock_key = f"pre-auth-otp-cooldown:{user_lock_hash}"

        response1 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        expected_keys = [
            "sessionid",
            "session_expiry",
            "user_id",
            "user_role",
            "csrf_token",
            "csrf_token_expiry",
        ]
        for key in expected_keys:
            self.assertIn(key, response1.data)
            self.assertIsNotNone(response1.data[key])

        self.assertEqual(response1.data["user_id"], self.user.id)
        self.assertIsNone(cache.get(login_failure_key))
        self.assertIsNone(cache.get(user_lock_key))
        self.assertIsNone(cache.get(dummy_key))

        cache.delete(user_lock_key)

        self.valid_payload["email_or_username"] = "defaultuser"
        self.headers["HTTP_X_CSRFTOKEN"] = response1.data["csrf_token"]

        response2 = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertIn("user_id", response2.data)
        self.assertIsNone(cache.get(user_lock_key))

    # ==========================================
    # AUTHENTICATED USER STATE VALIDATION (403)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_login_wrong_auth_provider_fails(self, mock_recaptcha):
        """Test 403 forbidden request when an OAuth user (e.g., Google) attempts a password login."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        self.user.auth_provider = "google"
        self.user.save()

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        error_msg = str(response.data["error"])
        self.assertEqual(
            error_msg,
            "This account uses social login. Please set a password first to log in with an email.",
        )

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_login_unverified_email_fails(self, mock_recaptcha):
        """Test 403 forbidden request when user has not verified their email address."""
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
    def test_login_deactivated_user_fails(self, mock_recaptcha):
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
    # BRUTE-FORCE LOCKOUT & TRACKING TESTS (400)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_failed_login_uses_dummy_hash_for_invalid_user(self, mock_recaptcha):
        """Test cache counts increment on sequential email failures and increments dummy key."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        payload = self.valid_payload.copy()
        payload["email_or_username"] = "wrongemail@example.com"

        login_hashed_key = generate_hash_key(self.user.id)
        login_failure_key = f"login-failures:{login_hashed_key}"

        dummy_hash_key = generate_hash_key("ghost_user")
        dummy_key = f"ghost-failures:{dummy_hash_key}"

        # 3 attempts
        self.client.post(self.url, payload, format="json", **self.headers)
        self.client.post(self.url, payload, format="json", **self.headers)
        response3 = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response3.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(cache.get(dummy_key), 3)
        self.assertIsNone(cache.get(login_failure_key))

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_failed_login_increments_cache_and_warns(self, mock_recaptcha):
        """Test cache counts increment on sequential password failures and issue warning at 3 hits."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        payload = self.valid_payload.copy()
        payload["password"] = "WrongPassword111!"

        login_hashed_key = generate_hash_key(self.user.id)
        login_failure_key = f"login-failures:{login_hashed_key}"

        dummy_hash_key = generate_hash_key("ghost_user")
        dummy_key = f"ghost-failures:{dummy_hash_key}"

        # Attempt 1: First wrong password entry
        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        error_msg = str(response.data["error"])
        self.assertEqual(error_msg, "Invalid credentials")
        self.assertEqual(cache.get(login_failure_key), 1)

        # Attempt 2 & 3: Sequential incorrect submissions to trigger warning thresholds
        self.client.post(self.url, payload, format="json", **self.headers)
        response3 = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response3.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(cache.get(login_failure_key), 3)

        # Confirms warnings evaluate correctly
        error_msg3 = str(response3.data["error"])
        self.assertIn("You have 2 more attempt(s)", error_msg3)
        self.assertIsNone(cache.get(dummy_key))

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_account_lockout_deactivates_user(self, mock_recaptcha):
        """Test account gets fully deactivated when failure counter matches maximum limit settings."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        payload = self.valid_payload.copy()
        payload["password"] = "WrongPassword111!"

        login_hashed_key = generate_hash_key(self.user.id)
        login_failure_key = f"login-failures:{login_hashed_key}"

        dummy_hash_key = generate_hash_key("ghost_user")
        dummy_key = f"ghost-failures:{dummy_hash_key}"

        cache.set(login_failure_key, 4, timeout=settings.LOGIN_FAILURE_ATTEMPT_TTL)

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        error_msg = str(response.data["error"])
        self.assertIn("Your account has been deactivated", error_msg)

        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

        response2 = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response2.status_code, status.HTTP_403_FORBIDDEN)

        error_msg2 = str(response2.data["error"])
        self.assertIn("Account has been deactivated.", error_msg2)
        self.assertIsNone(cache.get(dummy_key))

    # ==========================================
    # THROTTLING & RATE LIMIT WORKFLOW TESTS (429)
    # ==========================================

    @patch(
        "server.utils.recaptcha.recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient"
    )
    def test_login_otp_cooldown_throttle_returns_429(self, mock_recaptcha):
        """Test that OTPCooldownThrottle blocks a rapid subsequent login attempt with a custom 429 message."""
        mock_recaptcha.return_value.create_assessment.return_value = (
            self.create_mock_recaptcha_response()
        )

        user_lock_hash = generate_hash_key(self.user.id)
        user_lock_key = f"pre-auth-otp-cooldown:{user_lock_hash}"
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
