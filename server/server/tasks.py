import logging
from firebase_admin import messaging
from twilio.rest import Client
from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from core_db.models import FCMToken

logger = logging.getLogger(__name__)

User = get_user_model()


@shared_task(bind=True, max_retries=3, default_retry_delay=5)
def dispatch_fcm_notification(self, user_id, title, body, data=None):
    """
    Directly sends FCM push notifications to all active device tokens of a user.
    Handles automatic cleanup of expired/invalid registration tokens.
    """
    try:
        user = User.objects.get(id=user_id)

        tokens = list(
            FCMToken.objects.filter(user=user)
            .order_by("id")
            .values_list("token", flat=True)
        )

        if not tokens:
            return {
                "status": "success",
                "fcm_delivered_devices": 0,
            }

        # FCM object to string conversion
        string_data = {k: str(v) for k, v in (data or {}).items()}

        message = messaging.MulticastMessage(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            data=string_data,
            tokens=tokens,
        )

        response = messaging.send_each_for_multicast(message)

        # Cleanup invalid/unregistered tokens in responses
        tokens_to_delete = []
        for idx, resp in enumerate(response.responses):
            if not resp.success and resp.exception:
                if isinstance(
                    resp.exception,
                    (messaging.UnregisteredError, messaging.SenderIdMismatchError),
                ):
                    tokens_to_delete.append(tokens[idx])
                elif getattr(resp.exception, "code", None) in [
                    "UNREGISTERED",
                    "INVALID_ARGUMENT",
                ]:
                    tokens_to_delete.append(tokens[idx])

        if tokens_to_delete:
            FCMToken.objects.filter(token__in=tokens_to_delete).delete()
    except User.DoesNotExist:
        logger.error("FCM Multicast error for user %s: User not found", user_id)
        return {"status": "failed", "reason": "User not found"}
    except Exception as exc:  # pylint: disable=W0718
        logger.warning(
            "Attempt %s/%s failed. FCM Multicast error: %s. Retrying again",
            self.request.retries,
            self.max_retries,
            exc,
        )
        try:
            raise self.retry(exc=exc)
        except MaxRetriesExceededError as err:
            logger.error("FCM Multicast error for user %s: %s", user_id, str(err))
            return {"status": "failed", "reason": str(err)}

    return {
        "status": "success",
        "fcm_delivered_devices": response.success_count,
    }


@shared_task(bind=True, max_retries=3, default_retry_delay=5)
def dispatch_email(self, email_context, email_template):
    """
    Accepts a plain dictionary containing email context data.
    Send HTML emails asynchronously.
    """
    try:
        html_content = render_to_string(email_template, email_context)
        text_content = strip_tags(html_content)

        msg = EmailMultiAlternatives(
            subject=email_context["subject"],
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email_context["user_email"]],
        )

        msg.attach_alternative(html_content, "text/html")
        msg.send()
    except Exception as exc:  # pylint: disable=W0718
        logger.warning(
            "Attempt %s/%s failed. Email error: %s. Retrying again",
            self.request.retries,
            self.max_retries,
            exc,
        )
        try:
            raise self.retry(exc=exc)
        except MaxRetriesExceededError as err:
            logger.error(
                "Email error for user %s: %s", email_context["user_email"], str(err)
            )
            return {"status": "failed", "reason": str(err)}

    return {"status": "success"}


@shared_task(bind=True, max_retries=3, default_retry_delay=10)
def dispatch_twilio_sms(self, phone_no, message):
    """
    Accepts phone number and message. Send SMS asynchronously.
    """
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        sms = client.messages.create(
            to=phone_no, from_=settings.TWILIO_PHONE_NUMBER, body=message
        )
        logger.info("SMS sent successfully to %s. SID: %s", phone_no, sms.sid)
    except Exception as exc:  # pylint: disable=W0718
        logger.warning(
            "Attempt %s/%s failed. Twilio error: %s. Retrying again",
            self.request.retries,
            self.max_retries,
            exc,
        )
        try:
            raise self.retry(exc=exc)
        except MaxRetriesExceededError as err:
            logger.error("Twilio error for phone number %s: %s", phone_no, str(err))
            return {"status": "failed", "reason": str(err)}

    return {"status": "success", "sid": sms.sid}
