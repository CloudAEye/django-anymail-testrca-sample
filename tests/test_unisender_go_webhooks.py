from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import ANY

from django.test import override_settings, tag

from anymail.exceptions import AnymailConfigurationError
from anymail.signals import AnymailTrackingEvent
from anymail.webhooks.unisender_go import UnisenderGoTrackingWebhookView

from .utils import test_file_content
from .webhook_cases import WebhookBasicAuthTestCase, WebhookTestCase

TEST_API_KEY = "TEST_API_KEY"


def unisender_go_signed_payload(
    data: dict, api_key: str, json_options: dict | None = None
) -> bytes:
    """
    Return data serialized to JSON and signed with api_key, using Unisender Go's
    webhook signature in the top-level "auth" field:

        "MD5 hash of the string body of the message, with the auth value replaced
        by the api_key of the user/project whose handler is being called."
        https://godocs.unisender.ru/web-api-ref#callback-format

    Any json_options are passed to json.dumps as kwargs.

    This modifies data to add the "auth" field.
    """
    json_options = json_options or {"separators": (",", ":")}
    placeholder = "__PLACEHOLDER_FOR_SIGNATURE__"
    data["auth"] = placeholder
    serialized_data = json.dumps(data, **json_options)
    signature = hashlib.md5(
        serialized_data.replace(placeholder, api_key).encode()
    ).hexdigest()
    signed_data = serialized_data.replace(placeholder, signature)
    data["auth"] = signature  # make available to the caller
    return signed_data.encode()


class UnisenderGoWebhookTestCase(WebhookTestCase):
    def client_post_signed(
        self,
        url: str,
        data: dict,
        api_key: str = TEST_API_KEY,
        json_options: dict | None = None,
        **kwargs,
    ):
        """
        Return self.client.post(url, serialized json_data) signed with api_key
        using json_options.

        Additional kwargs are passed to self.client.post()
        """
        signed_data = unisender_go_signed_payload(data, api_key, json_options)
        return self.client.post(
            url, content_type="application/json", data=signed_data, **kwargs
        )


@tag("unisender_go")
class UnisenderGoWebhookSettingsTestCase(UnisenderGoWebhookTestCase):
    def test_requires_api_key(self):
        with self.assertRaisesMessage(
            AnymailConfigurationError, "UNISENDER_GO_API_KEY"
        ):
            self.client_post_signed("/anymail/unisender_go/tracking/", {})

    @override_settings(ANYMAIL={"UNISENDER_GO_API_KEY": "SETTINGS_API_KEY"})
    def test_view_params_api_key_override(self):
        """Webhook api_key can be provided as a view param"""
        view = UnisenderGoTrackingWebhookView.as_view(api_key="VIEW_API_KEY")
        view_instance = view.view_class(**view.view_initkwargs)
        self.assertEqual(view_instance.api_key_bytes, b"VIEW_API_KEY")


@tag("unisender_go")
@override_settings(
    # (Use expanded setting name because WebhookBasicAuthTestCase sets ANYMAIL={}.)
    ANYMAIL_UNISENDER_GO_API_KEY=TEST_API_KEY,
)
class UnisenderGoWebhookSecurityTestCase(
    UnisenderGoWebhookTestCase, WebhookBasicAuthTestCase
):
    should_warn_if_no_auth = False  # because we check webhook signature

    payload = {
        # "auth" is added by self.client_post_signed()
        "events_by_user": [
            {
                "user_id": 123456,
                "events": [
                    {
                        "event_name": "transactional_email_status",
                        "event_data": {
                            "job_id": "1sn15Z-0007Le-GtVN",
                            "email": "test@example.com",
                            "status": "sent",
                            "metadata": {"can_be_unicode": "Метаданные"},
                            "event_time": "2024-09-07 19:27:17",
                        },
                    }
                ],
            }
        ]
    }

    def call_webhook(self):
        return self.client_post_signed("/anymail/unisender_go/tracking/", self.payload)

    # Additional tests are in WebhookBasicAuthTestCase

    def test_verifies_correct_signature(self):
        response = self.client_post_signed(
            "/anymail/unisender_go/tracking/", self.payload
        )
        self.assertEqual(response.status_code, 200)

    def test_rejects_bad_signature(self):
        # This also verifies that the error log references the correct setting to check.
        with self.assertLogs() as logs:
            response = self.client_post_signed(
                "/anymail/unisender_go/tracking/",
                self.payload,
                api_key="OTHER_API_KEY",
            )
        # SuspiciousOperation causes 400 response (even in test client):
        self.assertEqual(response.status_code, 400)
        self.assertIn("check Anymail UNISENDER_GO_API_KEY", logs.output[0])
        self.assertNotIn("Project ID", logs.output[0])

    def test_rejects_missing_signature(self):
        payload = deepcopy(self.payload)
        del payload["auth"]
        # Post directly (without signing to add auth):
        response = self.client.post(
            "/anymail/unisender_go/tracking/",
            content_type="application/json",
            data=json.dumps(payload),
        )
        self.assertEqual(response.status_code, 400)

    def test_rejects_problem_signatures(self):
        # Make sure our `body.replace(auth, key)` approach can't be confused
        # by invalid payloads.
        for bad_auth in ["", " ", ":", "{", '"', 0, None, [], {}]:
            with self.subTest(auth=bad_auth):
                payload = deepcopy(self.payload)
                payload["auth"] = bad_auth
                response = self.client.post(
                    "/anymail/unisender_go/tracking/",
                    content_type="application/json",
                    data=json.dumps(payload),
                )
                self.assertEqual(response.status_code, 400)

    def test_error_includes_project_id(self):
        # If the webhook has a selected project, mention
        # its id in the validation error to assist in debugging.
        payload = deepcopy(self.payload)
        payload["events_by_user"][0].update(
            {"project_id": 999999, "project_name": "Test project"}
        )
        with self.assertLogs() as logs:
            response = self.client_post_signed(
                "/anymail/unisender_go/tracking/",
                payload,
                api_key="OTHER_API_KEY",
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "check Anymail UNISENDER_GO_API_KEY setting is for Project ID 999999",
            logs.output[0],
        )

    def test_error_includes_project_id_single_event(self):
        # Selected project works with "single event" option.
        payload = {
            "user_id": 123456,
            "project_id": 999999,
            "project_name": "Test project",
            "event_name": "transactional_email_status",
            "job_id": "1sn15Z-0007Le-GtVN",
            "email": "test@example.com",
            "status": "sent",
            "event_time": "2024-09-07 19:27:17",
        }
        with self.assertLogs() as logs:
            response = self.client_post_signed(
                "/anymail/unisender_go/tracking/",
                payload,
                api_key="OTHER_API_KEY",
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "check Anymail UNISENDER_GO_API_KEY setting is for Project ID 999999",
            logs.output[0],
        )

    def test_insensitive_to_json_serialization_options(self):
        # Our webhook signature verification must not depend on the exact
        # details of how Unisender Go serializes the JSON payload.
        for json_options in [
            {"separators": None},
            {"ensure_ascii": False},
            {"indent": 4},
            {"sort_keys": True},
        ]:
            with self.subTest(options=json_options):
                response = self.client_post_signed(
                    "/anymail/unisender_go/tracking/",
                    self.payload,
                    json_options=json_options,
                )
                self.assertEqual(response.status_code, 200)

    @override_settings(
        # noqa: secret-scanning: this API key has been disabled
        ANYMAIL={"UNISENDER_GO_API_KEY": "6mjstx9gwi7qj8eni6m77hfiiw6aifmss154y4ze"}
    )
    def test_actual_signed_payload(self):
        # Test our signature verification using an actual payload and API key.
        payload = test_file_content("unisender-go-tracking-test-payload.json.raw")
        # (If an editor or pre-commit forces a trailing newline, the test breaks.)
        assert payload[-1] != b"\n", "Test payload must not have end-of-file newline"
        response = self.client.post(
            "/anymail/unisender_go/tracking/",
            content_type="application/json",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)


@tag("unisender_go")
@override_settings(ANYMAIL={"UNISENDER_GO_API_KEY": TEST_API_KEY})
class UnisenderGoTestCase(UnisenderGoWebhookTestCase):
    # Most of these tests use Unisender Go's "single event" option for brevity.
    # Anymail also supports (and recommends) multiple event webhook option;
    # tests for that are toward the end.

    def test_sent_event(self):
        raw_event = {
            "event_name": "transactional_email_status",
            "user_id": 111111,
            "project_id": 999999,
            "project_name": "Testing",
            "job_id": "1smi9f-00057m-86zr",
            "metadata": {
                "anymail_id": "00001111-2222-3333-4444-555566667777",
                "cohort": "group a121",
            },
            "email": "recipient@example.com",
            "status": "sent",
            "event_time": "2024-09-06 23:14:19",
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=UnisenderGoTrackingWebhookView,
            event=ANY,
            esp_name="Unisender Go",
        )
        event = kwargs["event"]
        self.assertIsInstance(event, AnymailTrackingEvent)
        self.assertEqual(event.event_type, "sent")
        self.assertEqual(
            event.timestamp,
            datetime(2024, 9, 6, 23, 14, 19, tzinfo=timezone.utc),
        )
        # event.message_id matches the message.anymail_status.message_id
        # from when the message was sent. It comes from metadata.anymail_id
        # if present (added by UNISENDER_GO_GENERATE_MESSAGE_ID).
        self.assertEqual(event.message_id, "00001111-2222-3333-4444-555566667777")
        # Unisender Go does not include a useful event_id
        self.assertIsNone(event.event_id)
        self.assertEqual(event.recipient, "recipient@example.com")
        # Although Unisender Go's email-send docs claim tags are sent to webhooks,
        # its webhook docs don't show tags (and they aren't actually sent 9/2024).
        #   self.assertEqual(event.tags, ["tag1", "Tag 2"])
        # Our added "anymail_id" should be removed from metadata.
        self.assertEqual(event.metadata, {"cohort": "group a121"})
        self.assertEqual(event.esp_event, raw_event)

    def test_delivered_event(self):
        raw_event = {
            "event_name": "transactional_email_status",
            "user_id": 111111,
            "job_id": "1smi9f-00057m-86zr",
            "email": "recipient@example.com",
            "status": "delivered",
            "event_time": "2024-09-06 23:14:24",
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=UnisenderGoTrackingWebhookView,
            event=ANY,
            esp_name="Unisender Go",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "delivered")
        # If UNISENDER_GO_GENERATE_MESSAGE_ID not enabled, Unisender Go's
        # job_id becomes Anymail's message_id.
        self.assertEqual(event.message_id, "1smi9f-00057m-86zr")
        self.assertEqual(event.recipient, "recipient@example.com")

    def test_hard_bounced_event(self):
        raw_event = {
            "event_name": "transactional_email_status",
            "status": "hard_bounced",
            "email": "bounce@example.com",
            "delivery_info": {
                "delivery_status": "err_user_unknown",
                "destination_response": "555 5.7.1 User unknown 'bounce@example.com'.",
            },
            "event_time": "2024-09-06 23:22:40",
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=UnisenderGoTrackingWebhookView,
            event=ANY,
            esp_name="Unisender Go",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "bounced")
        self.assertEqual(event.recipient, "bounce@example.com")
        self.assertEqual(event.reject_reason, "bounced")
        self.assertEqual(event.description, "err_user_unknown")
        self.assertEqual(
            event.mta_response, "555 5.7.1 User unknown 'bounce@example.com'."
        )

    def test_soft_bounced_event(self):
        raw_event = {
            "event_name": "transactional_email_status",
            "status": "soft_bounced",
            "email": "full@example.com",
            "delivery_info": {
                "delivery_status": "err_mailbox_full",
                "destination_response": "554 5.2.2 Mailbox full 'full@example.com'.",
            },
            "event_time": "2024-09-06 23:22:40",
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=UnisenderGoTrackingWebhookView,
            event=ANY,
            esp_name="Unisender Go",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "deferred")
        self.assertEqual(event.recipient, "full@example.com")
        self.assertEqual(event.reject_reason, "bounced")
        self.assertEqual(event.description, "err_mailbox_full")
        self.assertEqual(
            event.mta_response, "554 5.2.2 Mailbox full 'full@example.com'."
        )

    def test_spam_event(self):
        raw_event = {
            "event_name": "transactional_email_status",
            "status": "spam",
            "email": "to@example.com",
            "delivery_info": {
                "delivery_status": "err_spam_rejected",
                "destination_response": "550 Spam rejected",
            },
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=UnisenderGoTrackingWebhookView,
            event=ANY,
            esp_name="Unisender Go",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "complained")
        self.assertEqual(event.recipient, "to@example.com")
        self.assertEqual(event.description, "err_spam_rejected")
        self.assertEqual(event.mta_response, "550 Spam rejected")

    def test_unsubscribed_event(self):
        raw_event = {
            "event_name": "transactional_email_status",
            "status": "unsubscribed",
            "email": "to@example.com",
            "comment": "From unsubscribe page 'comment' field",
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=UnisenderGoTrackingWebhookView,
            event=ANY,
            esp_name="Unisender Go",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "unsubscribed")
        self.assertEqual(event.recipient, "to@example.com")
        self.assertEqual(event.description, "From unsubscribe page 'comment' field")

    def test_opened_event(self):
        raw_event = {
            "event_name": "transactional_email_status",
            "status": "opened",
            "email": "to@example.com",
            "delivery_info": {
                "user_agent": "... via ggpht.com GoogleImageProxy",
                "ip": "10.10.1.333",
            },
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=UnisenderGoTrackingWebhookView,
            event=ANY,
            esp_name="Unisender Go",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "opened")
        self.assertEqual(event.recipient, "to@example.com")
        self.assertEqual(event.user_agent, "... via ggpht.com GoogleImageProxy")

    def test_clicked_event(self):
        raw_event = {
            "event_name": "transactional_email_status",
            "status": "clicked",
            "email": "to@example.com",
            "url": "https://example.com",
            "delivery_info": {
                "user_agent": "Mozilla/5.0 AppleWebKit/537.36 ...",
                "ip": "192.168.1.333",
            },
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        kwargs = self.assert_handler_called_once_with(
            self.tracking_handler,
            sender=UnisenderGoTrackingWebhookView,
            event=ANY,
            esp_name="Unisender Go",
        )
        event = kwargs["event"]
        self.assertEqual(event.event_type, "clicked")
        self.assertEqual(event.recipient, "to@example.com")
        self.assertEqual(event.click_url, "https://example.com")
        self.assertEqual(event.user_agent, "Mozilla/5.0 AppleWebKit/537.36 ...")

    def test_multiple_event_option(self):
        # Payload format is different when "Use single event" not checked.
        raw_event = {
            "events_by_user": [
                {
                    "user_id": 111111,
                    "events": [
                        {
                            "event_name": "transactional_email_status",
                            "event_data": {
                                "job_id": "1sn15Z-0007Le-GtVN",
                                "email": "to@example.com",
                                "status": "sent",
                                "event_time": "2024-09-07 19:27:17",
                            },
                        },
                        {
                            "event_name": "transactional_email_status",
                            "event_data": {
                                "job_id": "1sn15Z-0007Le-GtVN",
                                "email": "cc@example.com",
                                "status": "delivered",
                                "event_time": "2024-09-07 19:27:17",
                            },
                        },
                    ],
                }
            ],
        }
        response = self.client_post_signed("/anymail/unisender_go/tracking/", raw_event)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.tracking_handler.call_count, 2)
        events = [
            kwargs["event"] for (args, kwargs) in self.tracking_handler.call_args_list
        ]
        self.assertEqual(events[0].event_type, "sent")
        self.assertEqual(events[0].recipient, "to@example.com")
        self.assertEqual(events[1].event_type, "delivered")
        self.assertEqual(events[1].recipient, "cc@example.com")

        # esp_event is event_data for each event
        self.assertEqual(
            events[0].esp_event,
            raw_event["events_by_user"][0]["events"][0]["event_data"],
        )
        self.assertEqual(
            events[1].esp_event,
            raw_event["events_by_user"][0]["events"][1]["event_data"],
        )

    def test_webhook_setup_verification(self):
        # Unisender Go verifies webhook at setup time by calling GET.
        response = self.client.get("/anymail/unisender_go/tracking/")
        self.assertEqual(response.status_code, 200)
