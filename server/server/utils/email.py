import random
import time
from django.conf import settings
from django.core.cache import cache
from server.tasks import dispatch_email
from .redis import get_cache_data, set_cache_data
from .encryption import generate_hash_key


class Email:
    def __init__(
        self,
        user,
        subject,
        title,
        body_text,
    ):
        self.user = user
        self.subject = subject
        self.title = title
        self.body_text = body_text
        self.app_name = settings.APP_NAME
        self.logo_url = settings.LOGO_URL
        self.contact_email = settings.CONTACT_EMAIL

    @classmethod
    def __verify_otp(cls, user_otp, invalid_otp_key, decrypted_data):
        """Verify the OTP or security link given by the user."""

        if user_otp != decrypted_data["otp"]:
            invalid_otp_cache_key = cache.get(invalid_otp_key)

            if invalid_otp_cache_key is not None:
                _ = cache.incr(invalid_otp_key)
            else:
                cache.set(
                    invalid_otp_key,
                    1,
                    timeout=settings.INVALID_OTP_COOLDOWN_TTL,
                )

            return {"error": "Invalid OTP"}

        cache.delete(invalid_otp_key)

        return {"error": None}

    @classmethod
    def __verify_security_link(cls, decrypted_data):
        """Verify the security link given by the user."""
        if time.time() - decrypted_data["created_at"] > settings.LINK_EXPIRY_TTL:
            return {"error": "The link has expired. Please request a new one."}

        return {"error": None}

    def __send_security_email(
        self, otp_code=None, action_url=None, action_button_text=None
    ):
        if not otp_code and not action_url:
            raise Exception("Either otp_code or action_url is required")

        email_context = {
            "username": self.user.username,
            "user_email": self.user.email,
            "app_name": self.app_name,
            "logo_url": self.logo_url,
            "contact_email": self.contact_email,
            "subject": self.subject,
            "title": self.title,
            "body_text": self.body_text,
            "otp_code": otp_code,
            "action_url": action_url,
            "action_button_text": action_button_text,
        }

        dispatch_email.delay(email_context, "emails/security_email.html")

    def send_otp_email(self, prefix):
        """
        Generates an 8 digit OTP and send it to the user's email.
        Returns the raw token to the client.
        """
        otp_code = str(random.randint(10000000, 99999999))

        self.__send_security_email(otp_code=otp_code)

        raw_cache_obj = {
            "user_id": self.user.id,
            "otp": otp_code,
        }

        return set_cache_data(
            prefix,
            raw_cache_obj,
            True,
            settings.PRE_AUTH_OTP_TTL,
            self.user.id,
            settings.OTP_COOLDOWN_TTL,
        )

    def send_security_link_email(self, prefix):
        """
        Generates a security link and send it to the user's email.
        Returns the raw token to the client.
        """
        raw_cache_obj = {
            "user_id": self.user.id,
            "created_at": time.time(),
        }

        token = set_cache_data(
            prefix,
            raw_cache_obj,
            True,
            settings.LINK_EXPIRY_TTL,
            self.user.id,
            settings.LINK_COOLDOWN_TTL,
        )

        if prefix == "email-verification":
            action_url = f"{settings.FRONTEND_URL}/auth/verify-email/?{token}"
            action_button_text = "Verify Email"
        elif prefix == "change-password":
            action_url = f"{settings.FRONTEND_URL}/auth/change-password/?{token}"
            action_button_text = "Change Password"
        else:
            return "Invalid prefix"

        self.__send_security_email(
            action_url=action_url, action_button_text=action_button_text
        )

        return token

    @classmethod
    def verification(cls, prefix, token, user_otp=None):
        """
        Verify the OTP or security link given by the user.
        Decrypts the minimal cache payload using a custom key.
        Returns user id.
        """
        cache_data = get_cache_data(prefix, token)

        if cache_data.get("error"):
            return cache_data

        hashed_key = cache_data["hashed_key"]
        decrypted_data = cache_data["decrypted_data"]

        if user_otp:
            invalid_otp_key = f"invalid-otp:{hashed_key}"
            verify_obj = cls.__verify_otp(user_otp, invalid_otp_key, decrypted_data)
        else:
            verify_obj = cls.__verify_security_link(decrypted_data)

        if verify_obj["error"]:
            return verify_obj

        user_lock_key = generate_hash_key(decrypted_data["user_id"])
        cache.delete(f"{prefix}-cooldown:{user_lock_key}")

        return {
            "hashed_key": hashed_key,
            "user_id": decrypted_data["user_id"],
        }
