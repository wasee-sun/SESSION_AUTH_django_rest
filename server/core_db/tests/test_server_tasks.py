from unittest.mock import MagicMock, patch
from django.conf import settings
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from celery.exceptions import MaxRetriesExceededError, Retry
from firebase_admin import messaging
from core_db.models import FCMToken
from server.tasks import dispatch_fcm_notification, dispatch_email, dispatch_twilio_sms

User = get_user_model()


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
class FCMNotificationTaskTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", email="test@example.com", password="P@ssword123"
        )
        self.token_1 = FCMToken.objects.create(user=self.user, token="valid_token_123")
        self.token_2 = FCMToken.objects.create(
            user=self.user, token="invalid_token_456"
        )

    @patch("server.tasks.messaging.send_each_for_multicast")
    def test_dispatch_fcm_notification_success_and_cleanup(self, mock_send_multicast):
        """
        Tests successful multicast delivery and automatic deletion of invalid tokens.
        """
        # Mock individual Firebase responses
        success_response = MagicMock(success=True, exception=None)

        failure_exception = messaging.UnregisteredError("App instance unregistered")
        failure_response = MagicMock(success=False, exception=failure_exception)

        # Mock the BatchResponse object
        mock_batch_response = MagicMock()
        mock_batch_response.responses = [success_response, failure_response]
        mock_batch_response.success_count = 1

        mock_send_multicast.return_value = mock_batch_response

        result = dispatch_fcm_notification.delay(
            user_id=self.user.id,
            title="Test Title",
            body="Test Body",
            data={"key": "value"},
        ).get()

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["fcm_delivered_devices"], 1)

        # Verify messaging API call parameters
        self.assertTrue(mock_send_multicast.called)
        called_message = mock_send_multicast.call_args[0][0]
        self.assertListEqual(
            called_message.tokens, ["valid_token_123", "invalid_token_456"]
        )
        self.assertEqual(called_message.data, {"key": "value"})

        # Verify invalid token cleanup in database
        self.assertTrue(FCMToken.objects.filter(token="valid_token_123").exists())
        self.assertFalse(FCMToken.objects.filter(token="invalid_token_456").exists())

    def test_dispatch_fcm_notification_no_tokens(self):
        """
        Tests that task handles users with no FCM tokens gracefully.
        """
        user_without_tokens = User.objects.create_user(
            username="notokens", email="notokens@example.com", password="P@ssword123"
        )

        result = dispatch_fcm_notification.delay(
            user_id=user_without_tokens.id, title="Test", body="Test"
        ).get()

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["fcm_delivered_devices"], 0)

    def test_dispatch_fcm_notification_user_not_found(self):
        """
        Tests task behavior when user ID does not exist.
        """
        result = dispatch_fcm_notification.delay(
            user_id=99999, title="Test", body="Test"
        ).get()

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "User not found")


class FCMNotificationRetryTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="retryuser", email="retry@example.com", password="P@ssword123"
        )
        FCMToken.objects.create(user=self.user, token="retry_token_123")

    @patch("server.tasks.messaging.send_each_for_multicast")
    @patch("celery.app.task.Task.retry")
    def test_dispatch_fcm_notification_triggers_retry_on_exception(
        self, mock_retry, mock_send_multicast
    ):
        """
        Tests that task attempts to retry when Firebase raises a network or server exception.
        """
        # 1. Force Firebase to throw a network error
        mock_send_multicast.side_effect = Exception(
            "Firebase server connection timeout"
        )

        # 2. Make mock_retry raise Celery's standard Retry exception to break execution cleanly
        mock_retry.side_effect = Retry("Retrying task...")

        # 3. Execute the task directly (without .delay() since testing self.retry logic)
        with self.assertRaises(Retry):
            dispatch_fcm_notification(
                user_id=self.user.id, title="Retry Test", body="Testing Retries"
            )

        # 4. Assert that self.retry was called
        self.assertTrue(mock_retry.called)

    @patch("server.tasks.messaging.send_each_for_multicast")
    @patch("celery.app.task.Task.retry")
    def test_dispatch_fcm_notification_max_retries_exceeded(
        self, mock_retry, mock_send_multicast
    ):
        """
        Tests that exceeding max_retries catches MaxRetriesExceededError and returns the failure dictionary.
        """
        # 1. Force Firebase to throw an exception
        mock_send_multicast.side_effect = Exception("Persistent Firebase outage")

        # 2. Simulate Celery throwing MaxRetriesExceededError when retry() is called
        mock_retry.side_effect = MaxRetriesExceededError("Can't retry anymore")

        # 3. Execute task and assert output payload matching your updated exception block
        result = dispatch_fcm_notification(
            user_id=self.user.id,
            title="Max Retries Test",
            body="Testing Exceeded Retries",
        )

        self.assertEqual(result, {"status": "failed", "reason": "Can't retry anymore"})
        self.assertTrue(mock_retry.called)


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
class DispatchEmailTaskTestCase(TestCase):
    """Tests for normal task execution using Celery eager execution."""

    def setUp(self):
        self.valid_email_context = {
            "username": "johndoe",
            "user_email": "john@example.com",
            "app_name": "My App",
            "logo_url": "http://testserver/media/logo/myapp.png",
            "contact_email": "support@example.com",
            "subject": "12345678 is your security code",
            "title": "Confirm your identity",
            "body_text": "Here is your verification code:",
            "otp_code": 12345678,
            "action_url": None,
            "action_button_text": None,
        }

    @patch("server.tasks.EmailMultiAlternatives")
    def test_dispatch_email_success(self, mock_email_class):
        """Tests that HTML and plain text emails are constructed and sent correctly."""
        mock_msg_instance = MagicMock()
        mock_email_class.return_value = mock_msg_instance

        # Execute task eagerly
        result = dispatch_email.delay(
            self.valid_email_context, "emails/security_email.html"
        ).get()

        # Assert status
        self.assertEqual(result, {"status": "success"})

        # Assert email instantiation parameters
        mock_email_class.assert_called_once_with(
            subject=self.valid_email_context["subject"],
            body=mock_email_class.call_args[1]["body"],  # Checked via strip_tags output
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[self.valid_email_context["user_email"]],
        )

        # Verify alternative HTML attachment and sending
        self.assertTrue(mock_msg_instance.attach_alternative.called)
        self.assertTrue(mock_msg_instance.send.called)


class DispatchEmailRetryTestCase(TestCase):
    """Tests for task retries and failure handling without eager execution interfering."""

    def setUp(self):
        self.valid_email_context = {
            "user_email": "john@example.com",
            "subject": "Security Code",
            "title": "Title",
            "body_text": "Body",
        }

    @patch("server.tasks.EmailMultiAlternatives")
    @patch("celery.app.task.Task.retry")
    def test_dispatch_email_triggers_retry_on_smtp_error(
        self, mock_retry, mock_email_class
    ):
        """Tests that an SMTP exception triggers self.retry()."""
        # Force SMTP / socket error on send()
        mock_msg_instance = MagicMock()
        mock_msg_instance.send.side_effect = Exception(
            "SMTP Server connection timed out"
        )
        mock_email_class.return_value = mock_msg_instance

        # Raise Celery's Retry exception when task calls self.retry()
        mock_retry.side_effect = Retry("Retrying email delivery...")

        # Call the task function directly
        with self.assertRaises(Retry):
            dispatch_email(self.valid_email_context, "emails/security_email.html")

        self.assertTrue(mock_retry.called)

    @patch("server.tasks.EmailMultiAlternatives")
    @patch("celery.app.task.Task.retry")
    def test_dispatch_email_max_retries_exceeded(self, mock_retry, mock_email_class):
        """Tests that exceeding max retries returns the expected error dictionary."""
        mock_msg_instance = MagicMock()
        mock_msg_instance.send.side_effect = Exception("Persistent SMTP error")
        mock_email_class.return_value = mock_msg_instance

        # Force self.retry to throw MaxRetriesExceededError
        mock_retry.side_effect = MaxRetriesExceededError("SMTP failure limits exceeded")

        # Call task function directly
        result = dispatch_email(self.valid_email_context, "emails/security_email.html")

        self.assertEqual(
            result, {"status": "failed", "reason": "SMTP failure limits exceeded"}
        )
        self.assertTrue(mock_retry.called)


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
class DispatchTwilioSMSTaskTestCase(TestCase):
    """Tests for normal task execution using Celery eager execution."""

    def setUp(self):
        self.phone_no = "+1234567890"
        self.message = "Hello! This is a test SMS."

    @patch("server.tasks.Client")
    def test_dispatch_sms_success(self, mock_twilio_client):
        """Tests that SMS is instantiated and sent via Twilio API correctly."""
        # Setup mock Twilio client and returned message instance
        mock_client_instance = MagicMock()
        mock_sms_instance = MagicMock()
        mock_sms_instance.sid = "SMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

        mock_client_instance.messages.create.return_value = mock_sms_instance
        mock_twilio_client.return_value = mock_client_instance

        # Execute task eagerly
        result = dispatch_twilio_sms.delay(self.phone_no, self.message).get()

        # Assert returned status and SID
        self.assertEqual(
            result, {"status": "success", "sid": "SMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
        )

        # Assert Twilio Client instantiation
        mock_twilio_client.assert_called_once_with(
            settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN
        )

        # Assert message.create API parameters
        mock_client_instance.messages.create.assert_called_once_with(
            to=self.phone_no,
            from_=settings.TWILIO_PHONE_NUMBER,
            body=self.message,
        )


class DispatchTwilioSMSRetryTestCase(TestCase):
    """Tests for task retries and failure handling without eager execution interfering."""

    def setUp(self):
        self.phone_no = "+1234567890"
        self.message = "Hello! Retry test."

    @patch("server.tasks.Client")
    @patch("celery.app.task.Task.retry")
    def test_dispatch_sms_triggers_retry_on_exception(
        self, mock_retry, mock_twilio_client
    ):
        """Tests that a Twilio exception triggers self.retry()."""
        # Force exception on messages.create
        mock_client_instance = MagicMock()
        mock_client_instance.messages.create.side_effect = Exception(
            "Twilio API Unreachable"
        )
        mock_twilio_client.return_value = mock_client_instance

        # Raise Celery's Retry exception when task calls self.retry()
        mock_retry.side_effect = Retry("Retrying SMS delivery...")

        # Call the task function directly
        with self.assertRaises(Retry):
            dispatch_twilio_sms(self.phone_no, self.message)

        self.assertTrue(mock_retry.called)

    @patch("server.tasks.Client")
    @patch("celery.app.task.Task.retry")
    def test_dispatch_sms_max_retries_exceeded(self, mock_retry, mock_twilio_client):
        """Tests that exceeding max retries returns the expected failure dictionary."""
        # Force exception on messages.create
        mock_client_instance = MagicMock()
        mock_client_instance.messages.create.side_effect = Exception(
            "Persistent Twilio error"
        )
        mock_twilio_client.return_value = mock_client_instance

        # Force self.retry to throw MaxRetriesExceededError
        mock_retry.side_effect = MaxRetriesExceededError(
            "Twilio failure limits exceeded"
        )

        # Call task function directly
        result = dispatch_twilio_sms(self.phone_no, self.message)

        self.assertEqual(
            result, {"status": "failed", "reason": "Twilio failure limits exceeded"}
        )
        self.assertTrue(mock_retry.called)
