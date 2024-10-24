from __future__ import annotations

import io
import json
import typing
from base64 import b64decode

from django.http import HttpResponse
from django.utils.dateparse import parse_datetime

from ..exceptions import (
    AnymailAPIError,
    AnymailConfigurationError,
    AnymailImproperlyInstalled,
    AnymailWebhookValidationFailure,
    _LazyError,
)
from ..inbound import AnymailInboundMessage
from ..signals import (
    AnymailInboundEvent,
    AnymailTrackingEvent,
    EventType,
    RejectReason,
    inbound,
    tracking,
)
from ..utils import get_anymail_setting, getfirst
from .base import AnymailBaseWebhookView

try:
    import boto3
    from botocore.exceptions import ClientError

    from ..backends.amazon_ses import _get_anymail_boto3_params
except ImportError:
    # This module gets imported by anymail.urls, so don't complain about boto3 missing
    # unless one of the Amazon SES webhook views is actually used and needs it
    boto3 = _LazyError(
        AnymailImproperlyInstalled(missing_package="boto3", install_extra="amazon-ses")
    )
    ClientError = object
    _get_anymail_boto3_params = _LazyError(
        AnymailImproperlyInstalled(missing_package="boto3", install_extra="amazon-ses")
    )


class AmazonSESBaseWebhookView(AnymailBaseWebhookView):
    """Base view class for Amazon SES webhooks (SNS Notifications)"""

    esp_name = "Amazon SES"

    def __init__(self, **kwargs):
        # whether to automatically respond to SNS SubscriptionConfirmation requests;
        # default True. (Future: could also take a TopicArn or list to auto-confirm)
        self.auto_confirm_enabled = get_anymail_setting(
            "auto_confirm_sns_subscriptions",
            esp_name=self.esp_name,
            kwargs=kwargs,
            default=True,
        )
        # boto3 params for connecting to S3 (inbound downloads)
        # and SNS (auto-confirm subscriptions):
        self.session_params, self.client_params = _get_anymail_boto3_params(
            kwargs=kwargs
        )
        super().__init__(**kwargs)

    @staticmethod
    def _parse_sns_message(request):
        # cache so we don't have to parse the json multiple times
        if not hasattr(request, "_sns_message"):
            try:
                body = request.body.decode(request.encoding or "utf-8")
                request._sns_message = json.loads(body)
            except (TypeError, ValueError, UnicodeDecodeError) as err:
                raise AnymailAPIError(
                    "Malformed SNS message body %r" % request.body
                ) from err
        return request._sns_message

    def validate_request(self, request):
        # Block random posts that don't even have matching SNS headers
        sns_message = self._parse_sns_message(request)
        header_type = request.META.get("HTTP_X_AMZ_SNS_MESSAGE_TYPE", "<<missing>>")
        body_type = sns_message.get("Type", "<<missing>>")
        if header_type != body_type:
            raise AnymailWebhookValidationFailure(
                'SNS header "x-amz-sns-message-type: %s"'
                ' doesn\'t match body "Type": "%s"' % (header_type, body_type)
            )

        if header_type not in [
            "Notification",
            "SubscriptionConfirmation",
            "UnsubscribeConfirmation",
        ]:
            raise AnymailAPIError("Unknown SNS message type '%s'" % header_type)

        header_id = request.META.get("HTTP_X_AMZ_SNS_MESSAGE_ID", "<<missing>>")
        body_id = sns_message.get("MessageId", "<<missing>>")
        if header_id != body_id:
            raise AnymailWebhookValidationFailure(
                'SNS header "x-amz-sns-message-id: %s"'
                ' doesn\'t match body "MessageId": "%s"' % (header_id, body_id)
            )

        # Future: Verify SNS message signature
        # https://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.verify.signature.html

    def post(self, request, *args, **kwargs):
        # request has *not* yet been validated at this point
        if self.basic_auth and not request.META.get("HTTP_AUTHORIZATION"):
            # Amazon SNS requires a proper 401 response
            # before it will attempt to send basic auth
            response = HttpResponse(status=401)
            response["WWW-Authenticate"] = 'Basic realm="Anymail WEBHOOK_SECRET"'
            return response
        return super().post(request, *args, **kwargs)

    def parse_events(self, request):
        # request *has* been validated by now
        events = []
        sns_message = self._parse_sns_message(request)
        sns_type = sns_message.get("Type")
        if sns_type == "Notification":
            message_string = sns_message.get("Message")
            try:
                ses_event = json.loads(message_string)
            except (TypeError, ValueError) as err:
                if (
                    "Successfully validated SNS topic for Amazon SES event publishing."
                    == message_string
                ):
                    # this Notification is generated after SubscriptionConfirmation
                    pass
                else:
                    raise AnymailAPIError(
                        "Unparsable SNS Message %r" % message_string
                    ) from err
            else:
                events = self.esp_to_anymail_events(ses_event, sns_message)
        elif sns_type == "SubscriptionConfirmation":
            self.auto_confirm_sns_subscription(sns_message)
        # else: just ignore other SNS messages (e.g., "UnsubscribeConfirmation")
        return events

    def esp_to_anymail_events(self, ses_event, sns_message):
        raise NotImplementedError()

    def get_boto_client(self, service_name: str, **kwargs):
        """
        Return a boto3 client for service_name, using session_params and
        client_params from settings. Any kwargs are treated as additional
        client_params (overriding settings values).
        """
        if kwargs:
            client_params = self.client_params.copy()
            client_params.update(kwargs)
        else:
            client_params = self.client_params
        return boto3.session.Session(**self.session_params).client(
            service_name, **client_params
        )

    def auto_confirm_sns_subscription(self, sns_message):
        """
        Automatically accept a subscription to Amazon SNS topics,
        if the request is expected.

        If an SNS SubscriptionConfirmation arrives with HTTP basic auth proving it is
        meant for us, automatically load the SubscribeURL to confirm the subscription.
        """
        if not self.auto_confirm_enabled:
            return

        if not self.basic_auth:
            # basic_auth (shared secret) confirms the notification was meant for us.
            # If WEBHOOK_SECRET isn't set, Anymail logs a warning but allows the
            # request. (Also, verifying the SNS message signature would be insufficient
            # here: if someone else tried to point their own SNS topic at our webhook
            # url, SNS would send a SubscriptionConfirmation with a valid Amazon
            # signature.)
            raise AnymailWebhookValidationFailure(
                "Anymail received an unexpected SubscriptionConfirmation request for "
                "Amazon SNS topic '{topic_arn!s}'. (Anymail can automatically confirm "
                "SNS subscriptions if you set a WEBHOOK_SECRET and use that in your "
                "SNS notification url. Or you can manually confirm this subscription "
                "in the SNS dashboard with token '{token!s}'.)".format(
                    topic_arn=sns_message.get("TopicArn"),
                    token=sns_message.get("Token"),
                )
            )

        # WEBHOOK_SECRET *is* set, so the request's basic auth has been verified by now
        # (in run_validators). We're good to confirm...
        topic_arn = sns_message["TopicArn"]
        token = sns_message["Token"]

        # Must confirm in TopicArn's own region
        # (which may be different from the default)
        try:
            (
                _arn_tag,
                _partition,
                _service,
                region,
                _account,
                _resource,
            ) = topic_arn.split(":", maxsplit=6)
        except (TypeError, ValueError):
            raise ValueError(
                "Invalid ARN format '{topic_arn!s}'".format(topic_arn=topic_arn)
            )

        sns_client = self.get_boto_client("sns", region_name=region)
        try:
            sns_client.confirm_subscription(
                TopicArn=topic_arn, Token=token, AuthenticateOnUnsubscribe="true"
            )
        finally:
            sns_client.close()


class AmazonSESTrackingWebhookView(AmazonSESBaseWebhookView):
    """Handler for Amazon SES tracking notifications"""

    signal = tracking

    def esp_to_anymail_events(self, ses_event, sns_message):
        # Amazon SES has two notification formats, which are almost exactly the same:
        #   https://docs.aws.amazon.com/ses/latest/DeveloperGuide/event-publishing-retrieving-sns-contents.html
        #   https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notification-contents.html
        # This code should handle either.
        ses_event_type = getfirst(
            ses_event, ["eventType", "notificationType"], "<<type missing>>"
        )
        if ses_event_type == "Received":
            # This is an inbound event
            raise AnymailConfigurationError(
                "You seem to have set an Amazon SES *inbound* receipt rule to publish "
                "to an SNS Topic that posts to Anymail's *tracking* webhook URL. "
                "(SNS TopicArn %s)" % sns_message.get("TopicArn")
            )

        event_id = sns_message.get("MessageId")  # unique to the SNS notification
        try:
            timestamp = parse_datetime(sns_message["Timestamp"])
        except (KeyError, ValueError):
            timestamp = None

        mail_object = ses_event.get("mail", {})
        # same as MessageId in SendRawEmail response:
        message_id = mail_object.get("messageId")
        all_recipients = mail_object.get("destination", [])

        # Recover tags and metadata from custom headers
        metadata = {}
        tags = []
        for header in mail_object.get("headers", []):
            name = header["name"].lower()
            if name == "x-tag":
                tags.append(header["value"])
            elif name == "x-metadata":
                try:
                    metadata = json.loads(header["value"])
                except (ValueError, TypeError, KeyError):
                    pass

        # AnymailTrackingEvent props for all recipients:
        common_props = dict(
            esp_event=ses_event,
            event_id=event_id,
            message_id=message_id,
            metadata=metadata,
            tags=tags,
            timestamp=timestamp,
        )
        # generate individual events for each of these:
        per_recipient_props = [
            dict(recipient=email_address) for email_address in all_recipients
        ]

        # event-type-specific data (e.g., ses_event["bounce"]):
        event_object = ses_event.get(ses_event_type.lower(), {})

        if ses_event_type == "Bounce":
            common_props.update(
                event_type=EventType.BOUNCED,
                description="{bounceType}: {bounceSubType}".format(**event_object),
                reject_reason=RejectReason.BOUNCED,
            )
            per_recipient_props = [
                dict(
                    recipient=recipient["emailAddress"],
                    mta_response=recipient.get("diagnosticCode"),
                )
                for recipient in event_object["bouncedRecipients"]
            ]
        elif ses_event_type == "Complaint":
            common_props.update(
                event_type=EventType.COMPLAINED,
                description=event_object.get("complaintFeedbackType"),
                reject_reason=RejectReason.SPAM,
                user_agent=event_object.get("userAgent"),
            )
            per_recipient_props = [
                dict(recipient=recipient["emailAddress"])
                for recipient in event_object["complainedRecipients"]
            ]
        elif ses_event_type == "Delivery":
            common_props.update(
                event_type=EventType.DELIVERED,
                mta_response=event_object.get("smtpResponse"),
            )
            per_recipient_props = [
                dict(recipient=recipient) for recipient in event_object["recipients"]
            ]
        elif ses_event_type == "Send":
            common_props.update(
                event_type=EventType.SENT,
            )
        elif ses_event_type == "Reject":
            common_props.update(
                event_type=EventType.REJECTED,
                description=event_object["reason"],
                reject_reason=RejectReason.BLOCKED,
            )
        elif ses_event_type == "Open":
            # SES doesn't report which recipient opened the message (it doesn't
            # track them separately), so just report it for all_recipients
            common_props.update(
                event_type=EventType.OPENED,
                user_agent=event_object.get("userAgent"),
            )
        elif ses_event_type == "Click":
            # SES doesn't report which recipient clicked the message (it doesn't
            # track them separately), so just report it for all_recipients
            common_props.update(
                event_type=EventType.CLICKED,
                user_agent=event_object.get("userAgent"),
                click_url=event_object.get("link"),
            )
        elif ses_event_type == "Rendering Failure":
            # (this type doesn't follow usual event_object naming)
            event_object = ses_event["failure"]
            common_props.update(
                event_type=EventType.FAILED,
                description=event_object["errorMessage"],
            )
        else:
            # Umm... new event type?
            common_props.update(
                event_type=EventType.UNKNOWN,
                description="Unknown SES eventType '%s'" % ses_event_type,
            )

        return [
            AnymailTrackingEvent(**common_props, **recipient_props)
            for recipient_props in per_recipient_props
        ]


class AmazonSESInboundWebhookView(AmazonSESBaseWebhookView):
    """Handler for Amazon SES inbound notifications"""

    signal = inbound

    def esp_to_anymail_events(self, ses_event, sns_message):
        ses_event_type = ses_event.get("notificationType")
        if ses_event_type != "Received":
            # This is not an inbound event
            raise AnymailConfigurationError(
                "You seem to have set an Amazon SES *sending* event or notification "
                "to publish to an SNS Topic that posts to Anymail's *inbound* webhook "
                "URL. (SNS TopicArn %s)" % sns_message.get("TopicArn")
            )

        receipt_object = ses_event.get("receipt", {})
        action_object = receipt_object.get("action", {})
        mail_object = ses_event.get("mail", {})

        action_type = action_object.get("type")
        if action_type == "SNS":
            content = ses_event.get("content")
            if action_object.get("encoding") == "BASE64":
                content = b64decode(content.encode("ascii"))
                message = AnymailInboundMessage.parse_raw_mime_bytes(content)
            else:
                message = AnymailInboundMessage.parse_raw_mime(content)
        elif action_type == "S3":
            # Download message from s3 and parse. (SNS has 15s limit
            # for an http response; hope download doesn't take that long)
            fp = self.download_s3_object(
                bucket_name=action_object["bucketName"],
                object_key=action_object["objectKey"],
            )
            try:
                message = AnymailInboundMessage.parse_raw_mime_file(fp)
            finally:
                fp.close()
        else:
            raise AnymailConfigurationError(
                "Anymail's Amazon SES inbound webhook works only with 'SNS' or 'S3'"
                " receipt rule actions, not SNS notifications for {action_type!s}"
                " actions. (SNS TopicArn {topic_arn!s})"
                "".format(
                    action_type=action_type, topic_arn=sns_message.get("TopicArn")
                )
            )

        # "the envelope MAIL FROM address":
        message.envelope_sender = mail_object.get("source")
        try:
            # "recipients that were matched by the active receipt rule"
            message.envelope_recipient = receipt_object["recipients"][0]
        except (KeyError, TypeError, IndexError):
            pass
        spam_status = receipt_object.get("spamVerdict", {}).get("status", "").upper()
        # spam_detected = False if no spam, True if spam, or None if unsure:
        message.spam_detected = {"PASS": False, "FAIL": True}.get(spam_status)

        # "unique ID assigned to the email by Amazon SES":
        event_id = mail_object.get("messageId")
        try:
            # "time at which the email was received":
            timestamp = parse_datetime(mail_object["timestamp"])
        except (KeyError, ValueError):
            timestamp = None

        return [
            AnymailInboundEvent(
                event_type=EventType.INBOUND,
                event_id=event_id,
                message=message,
                timestamp=timestamp,
                esp_event=ses_event,
            )
        ]

    def download_s3_object(self, bucket_name: str, object_key: str) -> typing.IO:
        """
        Download bucket_name/object_key from S3. Must return a file-like object
        (bytes or text) opened for reading. Caller is responsible for closing it.
        """
        s3_client = self.get_boto_client("s3")
        bytesio = io.BytesIO()
        try:
            s3_client.download_fileobj(bucket_name, object_key, bytesio)
        except ClientError as err:
            bytesio.close()
            # improve the botocore error message
            raise AnymailBotoClientAPIError(
                "Anymail AmazonSESInboundWebhookView couldn't download"
                " S3 object '{bucket_name}:{object_key}'"
                "".format(bucket_name=bucket_name, object_key=object_key),
                client_error=err,
            ) from err
        else:
            bytesio.seek(0)
            return bytesio
        finally:
            s3_client.close()


class AnymailBotoClientAPIError(AnymailAPIError, ClientError):
    """An AnymailAPIError that is also a Boto ClientError"""

    def __init__(self, *args, client_error):
        assert isinstance(client_error, ClientError)
        # init self as boto ClientError (which doesn't cooperatively subclass):
        super().__init__(
            error_response=client_error.response,
            operation_name=client_error.operation_name,
        )
        # emulate AnymailError init:
        self.args = args