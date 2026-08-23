import logging
import time
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from django.conf import settings
from server.tasks import dispatch_twilio_sms
from .redis import set_cache_data

logger = logging.getLogger(__name__)


class TwilioSMS:
    def __init__(self, phone_no, message=None):
        self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        self.verify_sid = settings.TWILIO_VERIFY_SERVICE_SID
        self.phone_no = phone_no
        self.message = message

    def send_message(self):
        """Sends custom SMS messages using Twilio Programmable Messaging."""
        if not self.message:
            return {
                "status": "error",
                "message": "Message body is required to send an SMS.",
            }

        dispatch_twilio_sms.delay(self.phone_no, self.message)

        return {
            "status": "success",
            "message": "Message task has been queued.",
        }

    def send_verification(self, prefix, channel="sms"):
        """Triggers Twilio Verify to send a managed 6-digit OTP."""
        try:
            verification = self.client.verify.v2.services(
                self.verify_sid
            ).verifications.create(to=self.phone_no, channel=channel)
        except TwilioRestException as e:
            logger.error("Phone no: %s. Twilio error: %s", self.phone_no, e.msg)
            if e.code == 60203:
                return {
                    "status": "error",
                    "message": "Too many requests. Please wait before trying again.",
                }
            elif e.code == 60200:
                return {"status": "error", "message": "Invalid phone number format."}
            else:
                return {
                    "status": "error",
                    "message": "Failed to send OTP code.",
                }

        raw_cache_obj = {
            "phone_no": self.phone_no,
            "created_at": time.time(),
        }

        phone_token = set_cache_data(
            prefix,
            raw_cache_obj,
            True,
            settings.TWILIO_OTP_COOLDOWN_TTL,
        )

        logger.info(
            "OTP code sent successfully to %s. SID: %s, Status: %s",
            verification.to,
            verification.sid,
            verification.status,
        )

        return {
            "status": "success",
            "phone_token": phone_token,
        }

    def check_verification(self, code):
        """Checks the OTP submitted by the user against Twilio Verify."""
        try:
            check = self.client.verify.v2.services(
                self.verify_sid
            ).verification_checks.create(to=self.phone_no, code=code)
        except TwilioRestException as e:
            logger.error("Phone no: %s. Twilio error: %s", self.phone_no, e.msg)
            if e.status == 404 or e.code == 20404:
                return {
                    "status": "error",
                    "message": "OTP code expired. Please request a new code.",
                }
            elif e.code == 60202:
                return {
                    "status": "error",
                    "message": "Too many failed attempts. Please request a new code.",
                }
            elif e.code == 60200:
                return {
                    "status": "error",
                    "message": "OTP code was invalid.",
                }
            else:
                return {
                    "status": "error",
                    "message": "Failed to check OTP code.",
                }

        if check.status == "approved":
            logger.info(
                "OTP code sent successfully to %s. SID: %s, Status: %s",
                check.to,
                check.sid,
                check.status,
            )

            return {
                "status": "success",
                "phone_no": self.phone_no,
            }

        return {
            "status": "error",
            "message": "Incorrect OTP code. Please try again.",
        }
