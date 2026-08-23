import time
from django.conf import settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from server.utils.redis import set_cache_data
from server.utils.encryption import generate_hash_key

User = get_user_model()


class ChangePasswordViewTestCase(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.url = reverse("change-password")

        self.user = User.objects.create_user(
            username="testuser", email="user@example.com", password="OldPassword123!"
        )

        self.prefix = "change-password"

        self.cache_obj = {
            "user_id": self.user.id,
            "created_at": time.time(),
        }

        self.token = set_cache_data(
            self.prefix,
            self.cache_obj,
            True,
            settings.LINK_EXPIRY_TTL,
            self.user.id,
            settings.LINK_COOLDOWN_TTL,
        )

        self.payload = {
            "pass_token": self.token,
            "password": "ValidPassword123!",
            "c_password": "ValidPassword123!",
        }

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        csrf_token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": csrf_token,
        }

    # ==========================================
    # SUCCESS TESTS (200)
    # ==========================================

    def test_change_password_success(self):
        """Test successful password change updates user password and clears cache."""
        link_lock_hash = generate_hash_key(self.user.id)
        link_lock_key = f"change-password-cooldown:{link_lock_hash}"

        pass_token_hashed_key = generate_hash_key(self.token)
        pass_token_key = f"change-password:{pass_token_hashed_key}"

        response = self.client.post(
            self.url, self.payload, format="json", **self.headers
        )

        import logging

        logger = logging.getLogger(__name__)
        logger.info("response.data: %s", response.data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["success"], "Your password has been changed successfully."
        )

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("ValidPassword123!"))
        self.assertFalse(self.user.check_password("OldPassword123!"))
        self.assertIsNone(cache.get(pass_token_key))
        self.assertIsNone(cache.get(link_lock_key))

    # ==========================================
    # REQUEST SERIALIZER VALIDATION FAILURE (400)
    # ==========================================

    # Missing fields

    def test_missing_pass_token(self):
        """Test 400 bad request when pass_token is missing."""
        payload = self.payload.copy()
        del payload["pass_token"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pass_token", response.data)
        self.assertEqual(response.data["pass_token"][0], "Token is required.")

        payload["pass_token"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pass_token", response.data)
        self.assertEqual(response.data["pass_token"][0], "Token is required.")

        payload["pass_token"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("pass_token", response.data)
        self.assertEqual(response.data["pass_token"][0], "Token is required.")

    def test_missing_password(self):
        """Test 400 bad request when password is missing."""
        payload = self.payload.copy()
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

    def test_missing_c_password(self):
        """Test 400 bad request when c_password is missing."""
        payload = self.payload.copy()
        del payload["c_password"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("c_password", response.data)
        self.assertEqual(
            response.data["c_password"][0], "Confirm password is required."
        )

        payload["c_password"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("c_password", response.data)
        self.assertEqual(
            response.data["c_password"][0], "Confirm password is required."
        )

        payload["c_password"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("c_password", response.data)
        self.assertEqual(
            response.data["c_password"][0], "Confirm password is required."
        )

    # Password Validations

    def test_password_mismatch(self):
        """Test 400 bad request when password and c_password do not match."""
        payload = self.payload.copy()
        payload["c_password"] = "DifferentPassword123!"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("c_password", response.data)
        self.assertEqual(response.data["c_password"][0], "Passwords do not match.")

    def test_password_too_short(self):
        """Test password fails when less than 8 characters."""
        payload = self.payload.copy()
        payload["password"] = "Ab1!"
        payload["c_password"] = "Ab1!"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertIn(
            "Password must be at least 8 characters.", response.data["password"]
        )

    def test_password_missing_uppercase(self):
        """Test password fails when missing an uppercase letter."""
        payload = self.payload.copy()
        payload["password"] = "password123!"
        payload["c_password"] = "password123!"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertIn(
            "Password must contain at least one uppercase letter.",
            response.data["password"],
        )

    def test_password_missing_lowercase(self):
        """Test password fails when missing a lowercase letter."""
        payload = self.payload.copy()
        payload["password"] = "PASSWORD123!"
        payload["c_password"] = "PASSWORD123!"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertIn(
            "Password must contain at least one lowercase letter.",
            response.data["password"],
        )

    def test_password_missing_number(self):
        """Test password fails when missing a digit."""
        payload = self.payload.copy()
        payload["password"] = "Password!"
        payload["c_password"] = "Password!"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertIn(
            "Password must contain at least one number.", response.data["password"]
        )

    def test_password_missing_special_char(self):
        """Test password fails when missing a special character."""
        payload = self.payload.copy()
        payload["password"] = "Password123"
        payload["c_password"] = "Password123"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertIn(
            "Password must contain at least one special character.",
            response.data["password"],
        )

    def test_password_multiple_complexity_failures(self):
        """Test multiple complexity failures returned together in list."""
        payload = self.payload.copy()
        payload["password"] = "pass"
        payload["c_password"] = "pass"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)

        errors = response.data["password"]
        self.assertIn("Password must be at least 8 characters.", errors)
        self.assertIn("Password must contain at least one uppercase letter.", errors)
        self.assertIn("Password must contain at least one number.", errors)
        self.assertIn("Password must contain at least one special character.", errors)

    def test_password_too_similar_to_username(self):
        """Test UserAttributeSimilarityValidator triggers 400 when password matches username."""
        payload = self.payload.copy()
        payload["password"] = f"{self.user.username}123!"
        payload["c_password"] = f"{self.user.username}123!"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertTrue(any("too similar" in err for err in response.data["password"]))

    def test_password_too_common(self):
        """Test MinimumLength/CommonPasswordValidator triggers 400 when using common passwords."""
        payload = self.payload.copy()
        payload["password"] = "password"
        payload["c_password"] = "password"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertTrue(
            any("common" in err.lower() for err in response.data["password"])
        )

    def test_password_entirely_numeric(self):
        """Test NumericPasswordValidator triggers 400 when password is only digits."""
        payload = self.payload.copy()
        payload["password"] = "123456789012"
        payload["c_password"] = "123456789012"

        response = self.client.post(self.url, payload, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertTrue(
            any("numeric" in err.lower() for err in response.data["password"])
        )

    # ==========================================
    # Forbidden TESTS (403)
    # ==========================================

    def test_change_password_with_invalid_pass_token_fails(self):
        """Test that an invalid/malformed pre-auth token returns 403 Forbidden."""
        invalid_payload = {
            "pass_token": "completely_invalid_or_expired_token",
            "password": "Django@123",
            "c_password": "Django@123",
        }

        response = self.client.post(
            self.url, invalid_payload, format="json", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["error"], "Invalid Token")

    def test_change_password_with_expired_link_fails(self):
        """Test that an expired security link token returns 403 Forbidden."""
        expired_cache_obj = {
            "user_id": self.user.id,
            "created_at": time.time() - (settings.LINK_EXPIRY_TTL + 10),
        }

        expired_token = set_cache_data(
            self.prefix,
            expired_cache_obj,
            True,
            settings.LINK_EXPIRY_TTL,
            self.user.id,
            settings.LINK_COOLDOWN_TTL,
        )

        payload = self.payload.copy()
        payload["pass_token"] = expired_token

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"], "The link has expired. Please request a new one."
        )

    # ==========================================
    # CSRFTOKEN FAILURE TEST
    # ==========================================

    def test_change_password_fails_when_csrf_token_is_missing(self):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        response = self.client.post(
            self.url, self.payload, format="json", **csrf_less_headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
