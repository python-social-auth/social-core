from __future__ import annotations

import copy
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

from openid.consumer.consumer import CancelResponse, FailureResponse, SuccessResponse
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.extensions import ax, sreg
from openid.message import OPENID2_NS, Message

from social_core.backends.livejournal import LiveJournalOpenId
from social_core.backends.open_id import OpenIdAuth
from social_core.exceptions import AuthCanceled, AuthResponseError, AuthSessionError
from social_core.pipeline.social_auth import social_names
from social_core.tests.exception_helpers import assert_auth_error
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME

from .base import BaseBackendTest

if TYPE_CHECKING:
    from social_core.strategy import HttpResponseProtocol
    from social_core.tests.models import User

VERIFIED_RESPONSE_KEY = "_openid_verified_response"
IDENTITY = "http://foobar.livejournal.com/"
DEPARTMENT = "https://example.com/attributes/department"


class OpenIdPartialTest(BaseBackendTest[OpenIdAuth]):
    backend_path = "social_core.backends.open_id.OpenIdAuth"
    expected_username = "user"

    def extra_settings(self):
        return {
            "SOCIAL_AUTH_OPENID_USERNAME_KEY": "nickname",
            "SOCIAL_AUTH_OPENID_SREG_EXTRA_DATA": [("email", "sreg_email")],
            "SOCIAL_AUTH_OPENID_AX_EXTRA_DATA": [(DEPARTMENT, "department")],
        }

    def verified_response(
        self,
        *,
        profile=True,
        signed_ax=True,
        component_names=("Foo", "Bar"),
        fullname: str | None = "Foo Bar",
        ax_fullnames=(),
    ):
        endpoint = OpenIDServiceEndpoint()
        endpoint.claimed_id = IDENTITY
        endpoint.server_url = "https://example.com/openid"
        vars(endpoint)["display_identifier"] = "Display identifier"
        message = Message(OPENID2_NS)
        if profile:
            profile_fields = {"nickname": "user", "email": "user@example.com"}
            if fullname is not None:
                profile_fields["fullname"] = fullname
            sreg.SRegResponse(profile_fields).toMessage(message)
            attributes = ax.FetchResponse()
            for schema, value in ax_fullnames:
                attributes.addValue(schema, value)
            if component_names is not None:
                attributes.addValue(
                    "http://axschema.org/namePerson/first", component_names[0]
                )
                attributes.addValue(
                    "http://axschema.org/namePerson/last", component_names[1]
                )
            attributes.addValue(DEPARTMENT, "Engineering")
            attributes.toMessage(message)
        signed_fields = [
            key
            for key in message.toPostArgs()
            if signed_ax or not key.startswith("openid.ax.")
        ]
        return SuccessResponse(endpoint, message, signed_fields)

    def test_full_name_only_details(self) -> None:
        details = self.backend.get_user_details(
            self.verified_response(component_names=None)
        )
        self.assertEqual(details["fullname"], "Foo Bar")
        self.assertIsNone(details["first_name"])
        self.assertIsNone(details["last_name"])
        normalized = social_names(self.backend, details)["details"]
        self.assertEqual(normalized["first_name"], "Foo")
        self.assertEqual(normalized["last_name"], "Bar")

    def test_explicit_component_names_are_preserved(self) -> None:
        details = self.backend.get_user_details(
            self.verified_response(component_names=("Given", "Surname"))
        )
        normalized = social_names(self.backend, details)["details"]
        self.assertEqual(normalized["fullname"], "Foo Bar")
        self.assertEqual(normalized["first_name"], "Given")
        self.assertEqual(normalized["last_name"], "Surname")

    def test_unavailable_names_from_extensions_are_preserved(self) -> None:
        details = self.backend.get_user_details(
            self.verified_response(fullname=None, component_names=None)
        )
        for key in ("fullname", "first_name", "last_name"):
            self.assertIsNone(details[key])
        self.assertEqual(social_names(self.backend, details)["details"], details)

    def test_explicit_blank_names_from_extensions_are_preserved(self) -> None:
        details = self.backend.get_user_details(
            self.verified_response(fullname="", component_names=("", ""))
        )
        for key in ("fullname", "first_name", "last_name"):
            self.assertEqual(details[key], "")
        self.assertEqual(social_names(self.backend, details)["details"], details)

    def test_blank_ax_alias_preserves_earlier_name(self) -> None:
        current = "http://axschema.org/namePerson"
        legacy = "http://schema.openid.net/namePerson"
        for blank in ("", " "):
            for sreg_name, ax_names in (
                ("Foo Bar", ((legacy, blank),)),
                (None, ((current, "Foo Bar"), (legacy, blank))),
                ("Foo Bar", ((current, blank), (legacy, blank))),
            ):
                with self.subTest(blank=blank, sreg=sreg_name, ax=ax_names):
                    details = self.backend.get_user_details(
                        self.verified_response(
                            fullname=sreg_name,
                            component_names=None,
                            ax_fullnames=ax_names,
                        )
                    )
                    self.assertEqual(details["fullname"], "Foo Bar")
                    normalized = social_names(self.backend, details)["details"]
                    self.assertEqual(normalized["fullname"], "Foo Bar")

    def test_ax_alias_preserves_only_supplied_blank(self) -> None:
        for schema in (
            "http://axschema.org/namePerson",
            "http://schema.openid.net/namePerson",
        ):
            with self.subTest(schema=schema):
                details = self.backend.get_user_details(
                    self.verified_response(
                        fullname=None,
                        component_names=None,
                        ax_fullnames=((schema, ""),),
                    )
                )
                self.assertEqual(details["fullname"], "")
                self.assertEqual(
                    social_names(self.backend, details)["details"], details
                )

    def test_single_name_preserves_username_fallback(self) -> None:
        with patch.object(
            self.backend, "values_from_response", return_value={"fullname": "Prince"}
        ):
            details = self.backend.get_user_details(
                self.verified_response(profile=False)
            )
        self.assertEqual(details["username"], "Prince")
        self.assertIsNone(details["first_name"])
        self.assertIsNone(details["last_name"])
        normalized = social_names(self.backend, details)["details"]
        self.assertEqual(normalized["username"], "Prince")
        self.assertEqual(normalized["first_name"], "Prince")
        self.assertIsNone(normalized["last_name"])

    def start_partial(self, response, *, early=True):
        self.pipeline_settings()
        if early:
            pipeline = list(self.strategy.get_pipeline(self.backend))
            pipeline.remove("social_core.tests.pipeline.ask_for_password")
            pipeline.insert(0, "social_core.tests.pipeline.ask_for_password")
            self.strategy.set_settings({"SOCIAL_AUTH_PIPELINE": pipeline})
        with patch.object(self.backend, "consumer") as consumer:
            consumer.return_value.complete.return_value = response
            result = self.backend.complete()
        consumer.return_value.complete.assert_called_once()
        return result

    def finish_partial(self, result) -> User:
        for step, value in (("password", "foobar"), ("slug", "foo-bar")):
            self.assertEqual(
                cast("HttpResponseProtocol", result).url,
                self.strategy.build_absolute_uri(f"/{step}"),
            )
            token = self.strategy.session_pop(PARTIAL_TOKEN_SESSION_NAME)
            self.strategy.session_set(step, value)
            with patch.object(
                OpenIdAuth,
                "consumer",
                side_effect=AssertionError("Must not reverify callback"),
            ):
                result = self.resume_partial_with_new_request(
                    token, {"openid.identity": "https://wrong.example/user"}
                )
        return cast("User", result)

    def assert_profile_preserved(self, *, early):
        response = self.verified_response()
        expected_details = self.backend.get_user_details(response)
        result = self.start_partial(response, early=early)
        token = cast("str", self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME))
        stored = self.strategy.storage.partial.load(token)
        assert stored is not None
        self.assertNotIn("response", stored.kwargs)
        snapshot = stored.kwargs[VERIFIED_RESPONSE_KEY]
        self.assertEqual(snapshot["endpoint"]["claimed_id"], IDENTITY)
        self.assertEqual(snapshot["signed_fields"], response.signed_fields)

        with patch.object(
            OpenIdAuth, "get_user_details", wraps=self.backend.get_user_details
        ) as details:
            user = self.finish_partial(result)

        if early:
            self.assertEqual(details.call_count, 1)
            restored_response = details.call_args.args[0]
            self.assertEqual(
                self.backend.get_user_details(restored_response), expected_details
            )
            self.assertEqual(
                restored_response.endpoint.getDisplayIdentifier(), "Display identifier"
            )
        self.assertEqual(user.username, "user")
        self.assertEqual(user.email, "user@example.com")
        self.assertEqual(user.first_name, "Foo")
        self.assertEqual(user.social[0].uid, IDENTITY)
        self.assertEqual(user.social[0].extra_data["sreg_email"], "user@example.com")
        self.assertEqual(user.social[0].extra_data["department"], "Engineering")
        self.assertEqual(user.password, "foobar")
        self.assertEqual(user.slug, "foo-bar")

    def test_partial_before_details_and_uid(self) -> None:
        self.assert_profile_preserved(early=True)

    def test_partial_after_details_and_uid(self) -> None:
        self.assert_profile_preserved(early=False)

    def test_verified_response_resume_scopes_request_data(self) -> None:
        self.start_partial(self.verified_response())
        token = self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME)
        assert isinstance(token, str)
        partial = self.strategy.partial_load(token)
        assert partial is not None
        partial.request_data = {"sentinel": "saved"}
        previous_data = self.backend.data

        def authenticate(*args, **kwargs):
            self.assertEqual(self.strategy.request_data(), {"sentinel": "saved"})
            self.assertEqual(self.backend.data, {"sentinel": "saved"})

        with patch.object(self.strategy, "authenticate", side_effect=authenticate):
            self.backend.continue_pipeline(partial)
        self.assertEqual(self.backend.data, previous_data)
        self.assertEqual(self.strategy.request_data(), self.strategy.get_request_data())

    def test_unsigned_extension_data_stays_excluded(self) -> None:
        result = self.start_partial(self.verified_response(signed_ax=False))

        user = self.finish_partial(result)

        self.assertEqual(user.email, "user@example.com")
        self.assertNotIn("department", user.social[0].extra_data)

    def test_livejournal_identity_username_survives_partial(self) -> None:
        self.backend = LiveJournalOpenId(self.strategy, redirect_uri=self.complete_url)
        result = self.start_partial(self.verified_response(profile=False))

        user = self.finish_partial(result)

        self.assertEqual(user.username, "foobar")
        self.assertEqual(user.social[0].uid, IDENTITY)

    def test_missing_or_malformed_snapshot_requires_restart(self) -> None:
        self.start_partial(self.verified_response())
        token = cast("str", self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME))
        stored = self.strategy.storage.partial.load(token)
        assert stored is not None
        valid = copy.deepcopy(stored.kwargs[VERIFIED_RESPONSE_KEY])
        snapshots: list[object] = [
            None,
            {},
            [],
            {**valid, "endpoint": {}},
            {**valid, "endpoint": {"claimed_id": 123}},
            {**valid, "message": []},
            {**valid, "message": {"openid.mode": ["id_res"]}},
            {**valid, "signed_fields": "openid.identity"},
            {**valid, "signed_fields": [123]},
        ]
        for snapshot in snapshots:
            with self.subTest(snapshot=snapshot):
                stored.kwargs[VERIFIED_RESPONSE_KEY] = snapshot
                with assert_auth_error(
                    self, AuthSessionError, "session_context_missing"
                ):
                    self.resume_partial_with_new_request(token)
        stored.kwargs.pop(VERIFIED_RESPONSE_KEY)
        with assert_auth_error(self, AuthSessionError, "session_context_missing"):
            self.resume_partial_with_new_request(token)

    def test_initial_failed_callbacks_are_rejected(self) -> None:
        endpoint = self.verified_response().endpoint
        for response, exception in (
            (FailureResponse(endpoint, "Invalid signature"), AuthResponseError),
            (CancelResponse(endpoint), AuthCanceled),
        ):
            with (
                self.subTest(status=response.status),
                patch.object(self.backend, "consumer") as consumer,
                patch.object(self.strategy, "authenticate") as authenticate,
                self.assertRaises(exception),
            ):
                consumer.return_value.complete.return_value = response
                self.backend.complete()
            authenticate.assert_not_called()
