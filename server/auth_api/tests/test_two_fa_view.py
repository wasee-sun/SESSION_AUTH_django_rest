from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from server.utils.redis import set_cache_data
from server.utils.encryption import generate_hash_key

User = get_user_model()


class TwoFAViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("two-fa-login")

        self.valid_payload = {
            "pre_auth_token": "mock_pre_auth_token",
            "otp": "123456",
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

    # ==========================================
    # REQUEST SERIALIZER VALIDATION FAILURE (400)
    # ==========================================

    def test_missing_pre_auth_token(self):
        """Test 400 bad request when pre auth token is missing."""
        payload = self.valid_payload.copy()
        del payload["pre_auth_token"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pre_auth_token", response.data)
        self.assertEqual(response.data["pre_auth_token"][0], "Token is required.")

        payload["pre_auth_token"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pre_auth_token", response.data)
        self.assertEqual(response.data["pre_auth_token"][0], "Token is required.")

        payload["pre_auth_token"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pre_auth_token", response.data)
        self.assertEqual(response.data["pre_auth_token"][0], "Token is required.")

    def test_missing_otp(self):
        """Test 400 bad request when otp is missing."""
        payload = self.valid_payload.copy()
        del payload["otp"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("otp", response.data)
        self.assertEqual(response.data["otp"][0], "OTP is required.")

        payload["otp"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("otp", response.data)
        self.assertEqual(response.data["otp"][0], "OTP is required.")

        payload["otp"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("otp", response.data)
        self.assertEqual(response.data["otp"][0], "OTP is required.")

    # ==========================================
    # CSRFTOKEN FAILURE TEST
    # ==========================================

    def test_2fa_fails_when_csrf_token_is_missing(self):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **csrf_less_headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class TwoFAViewDBTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("two-fa-login")

        self.user = User.objects.create_user(
            email="defaultuser@example.com",
            password="SecurePassword123!",
        )

        prefix = "pre-auth-otp"
        self.cache_obj = {
            "user_id": self.user.id,
            "otp": "123456",
        }

        token = set_cache_data(
            prefix,
            self.cache_obj,
            True,
            settings.PRE_AUTH_OTP_TTL,
            self.user.id,
            settings.OTP_COOLDOWN_TTL,
        )

        self.valid_payload = {
            "pre_auth_token": token,
            "otp": "123456",
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
        User.objects.all().delete()
        cache.clear()

    # ==========================================
    # SUCCESS TESTS (200)
    # ==========================================

    def test_2fa_login_success(self):
        """Test that a user with 2FA enabled receives JWT access/refresh tokens after successful otp verification."""

        self.user.is_two_fa = False
        self.user.save()

        otp_lock_hash = generate_hash_key(self.user.id)
        otp_lock_key = f"pre-auth-otp-cooldown:{otp_lock_hash}"

        pre_auth_hashed_key = generate_hash_key(self.valid_payload["pre_auth_token"])
        pre_auth_key = f"pre-auth-otp:{pre_auth_hashed_key}"

        invalid_otp_key = f"invalid-otp:{pre_auth_hashed_key}"
        cache.set(invalid_otp_key, 2, timeout=settings.INVALID_OTP_COOLDOWN_TTL)

        response = self.client.post(
            self.url, self.valid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        expected_keys = [
            "sessionid",
            "session_expiry",
            "user_id",
            "user_role",
            "csrf_token",
            "csrf_token_expiry",
        ]
        for key in expected_keys:
            self.assertIn(key, response.data)
            self.assertIsNotNone(response.data[key])

        self.assertEqual(response.data["user_id"], self.user.id)
        self.assertIsNone(cache.get(pre_auth_key))
        self.assertIsNone(cache.get(otp_lock_key))
        self.assertIsNone(cache.get(invalid_otp_key))

    # ==========================================
    # INVALID TESTS (403)
    # ==========================================

    def test_2fa_login_invalid_pre_auth_token_fails(self):
        """Test that an invalid/malformed pre-auth token returns 403 Forbidden."""
        invalid_payload = {
            "pre_auth_token": "completely_invalid_or_expired_token",
            "otp": 123456,
        }

        response = self.client.post(
            self.url, invalid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["error"], "Invalid Token")

    def test_2fa_login_invalid_otp_increments_cache_counter(self):
        """Test that an incorrect OTP returns 403 and initializes/increments the tracking cache."""
        invalid_payload = {
            "pre_auth_token": self.valid_payload["pre_auth_token"],
            "otp": 999999,
        }

        hashed_pre_auth_key = generate_hash_key(self.valid_payload["pre_auth_token"])
        invalid_otp_key = f"invalid-otp:{hashed_pre_auth_key}"

        response = self.client.post(
            self.url, invalid_payload, format="json", **self.headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["error"], "Invalid OTP")
        self.assertEqual(cache.get(invalid_otp_key), 1)

        response = self.client.post(
            self.url, invalid_payload, format="json", **self.headers
        )
        self.assertEqual(cache.get(invalid_otp_key), 2)

    # ==========================================
    # THROTTLING & COOLDOWN TESTS (429)
    # ==========================================

    def test_throttle_blocks_request_after_three_invalid_attempts(self):
        """Test that reaching 3 invalid OTP attempts triggers the Throttle class and returns 429."""
        invalid_payload = {
            "pre_auth_token": self.valid_payload["pre_auth_token"],
            "otp": 999999,
        }

        hashed_pre_auth_key = generate_hash_key(self.valid_payload["pre_auth_token"])
        invalid_otp_key = f"invalid-otp:{hashed_pre_auth_key}"

        cache.set(invalid_otp_key, 3, timeout=settings.INVALID_OTP_COOLDOWN_TTL)

        response = self.client.post(
            self.url, invalid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn("Please wait", response.data["error"])
        self.assertIn("seconds before submitting another OTP.", response.data["error"])

    def test_throttle_ignored_if_no_pre_auth_token_provided(self):
        """Test that the throttle passes through if pre_auth_token is missing (allowing normal validation to catch it)."""
        payload_missing_token = {"otp": 123456}

        response = self.client.post(
            self.url, payload_missing_token, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
