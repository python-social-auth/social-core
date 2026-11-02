from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast
from unittest.mock import patch
from urllib.parse import urlencode

from openid.consumer.consumer import CancelResponse, FailureResponse, SuccessResponse
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.extensions import ax, sreg
from openid.message import OPENID1_NS, OPENID2_NS, Message

from social_core.backends.belgiumeid import BelgiumEIDOpenId
from social_core.backends.fedora import FedoraOpenId
from social_core.backends.launchpad import LaunchpadOpenId
from social_core.backends.livejournal import LiveJournalOpenId
from social_core.backends.open_id import OpenIdAuth
from social_core.backends.openinfra import OpenInfraOpenId
from social_core.backends.openstack import OpenStackOpenId
from social_core.backends.steam import SteamOpenId
from social_core.backends.suse import OpenSUSEOpenId
from social_core.backends.ubuntu import UbuntuOpenId
from social_core.backends.yandex import YandexOpenId
from social_core.exceptions import (
    AuthCanceled,
    AuthConfigurationError,
    AuthInputError,
    AuthProviderError,
    AuthResponseError,
    AuthSessionError,
)
from social_core.pipeline.social_auth import social_names
from social_core.store import OpenIdSessionWrapper
from social_core.tests.exception_helpers import assert_auth_error
from social_core.tests.models import TestUserSocialAuth, User
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME

from .base import BaseBackendTest
from .open_id import OpenIdTest

if TYPE_CHECKING:
    from social_core.strategy import HttpResponseProtocol

VERIFIED_RESPONSE_KEY = "_openid_verified_response"
BACKEND_SESSION_KEY = "_social_auth_backend"
LEGACY_SESSION_ID_FIELD = "psa_session_id"
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
        server_url="https://example.com/openid",
        claimed_id: str | None = IDENTITY,
        local_id=None,
        return_to=None,
        namespace=OPENID2_NS,
    ):
        endpoint = OpenIDServiceEndpoint()
        endpoint.claimed_id = claimed_id
        endpoint.local_id = local_id
        endpoint.server_url = server_url
        vars(endpoint)["display_identifier"] = "Display identifier"
        message = Message(namespace)
        message.setArg(namespace, "mode", "id_res")
        message.setArg(namespace, "return_to", return_to or self.complete_url)
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

    def set_openid_context(
        self,
        endpoint: OpenIDServiceEndpoint,
        *,
        backend: OpenIdAuth | None = None,
    ) -> None:
        backend = backend or self.backend
        session = self.strategy.openid_session_dict("openid")
        session[OpenIdSessionWrapper.endpoint_key] = endpoint
        session[BACKEND_SESSION_KEY] = backend.name
        self.bind_callback(backend)

    def bind_callback(self, backend: OpenIdAuth | None = None) -> str:
        backend = backend or self.backend
        state = backend.create_state()
        self.strategy.set_request_data({"redirect_state": state}, backend)
        return state

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
        self.set_openid_context(response.endpoint)
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
        endpoint = "https://www.livejournal.com/openid/server.bml"
        response = self.verified_response(profile=False, server_url=endpoint)
        self.backend = LiveJournalOpenId(self.strategy, redirect_uri=self.complete_url)
        # The strategy only authenticates with configured backend classes.
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": (
                    "social_core.backends.livejournal.LiveJournalOpenId",
                )
            }
        )
        self.strategy.set_request_data(
            {"openid.mode": "id_res", "openid.op_endpoint": endpoint}, self.backend
        )
        self.strategy.openid_session_dict("openid")[
            OpenIdSessionWrapper.endpoint_key
        ] = response.endpoint
        self.strategy.openid_session_dict("openid")[BACKEND_SESSION_KEY] = (
            self.backend.name
        )
        result = self.start_partial(response)

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

    def test_generic_callback_requires_initiation_state(self) -> None:
        response = self.verified_response()
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthSessionError, "session_context_missing"),
        ):
            self.backend.complete()
        authenticate.assert_not_called()

    def test_pending_generic_login_rejects_foreign_callback_state(self) -> None:
        response = self.verified_response()
        self.set_openid_context(response.endpoint)
        victim_state = self.strategy.session_get("openid_state")
        self.strategy.set_request_data(
            {"openid.mode": "id_res", "redirect_state": "attacker-state"},
            self.backend,
        )
        victim = User("victim")
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthSessionError, "state_mismatch"),
        ):
            self.backend.complete(user=victim)
        authenticate.assert_not_called()
        self.assertEqual(self.strategy.session_get("openid_state"), victim_state)
        self.assertEqual(victim.social, [])

    def test_pending_login_rejects_missing_or_orphaned_state(self) -> None:
        response = self.verified_response()
        self.set_openid_context(response.endpoint)
        state = self.strategy.session_get("openid_state")
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        self.strategy.remove_from_request_data("redirect_state")
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthInputError, "missing_parameter"),
        ):
            self.backend.complete()
        authenticate.assert_not_called()
        self.assertEqual(self.strategy.session_get("openid_state"), state)

        self.strategy.set_request_data({"redirect_state": state}, self.backend)
        self.strategy.session_pop("openid_state")
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthSessionError, "session_context_missing"),
        ):
            self.backend.complete()
        authenticate.assert_not_called()

    def test_callback_state_is_consumed_once(self) -> None:
        state = self.bind_callback()
        self.backend.validate_state()
        self.assertIsNone(self.strategy.session_get("openid_state"))
        with assert_auth_error(self, AuthSessionError, "session_context_missing"):
            self.backend.validate_state()
        self.assertEqual(self.backend.data["redirect_state"], state)

    def test_generic_callback_requires_matching_backend(self) -> None:
        response = self.verified_response()
        self.set_openid_context(response.endpoint)
        self.strategy.openid_session_dict("openid")[BACKEND_SESSION_KEY] = "ubuntu"
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthSessionError, "session_context_missing"),
        ):
            self.backend.complete()
        authenticate.assert_not_called()

    def test_generic_callback_rejects_malformed_initiation_state(self) -> None:
        response = self.verified_response()
        self.strategy.session_set(
            "openid", {OpenIdSessionWrapper.endpoint_key: b"old pickle"}
        )
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        with (
            patch(
                "social_core.backends.open_id.Consumer.complete",
                return_value=response,
            ),
            assert_auth_error(self, AuthSessionError, "session_context_missing"),
        ):
            self.backend.complete()
        self.assertEqual(self.strategy.session_get("openid"), {})

    def test_generic_completion_clears_newly_malformed_state(self) -> None:
        response = self.verified_response()
        self.set_openid_context(response.endpoint)
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)

        def corrupt_session(*args) -> None:
            self.strategy.session_set(
                "openid", {OpenIdSessionWrapper.endpoint_key: b"old pickle"}
            )

        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(
                self.backend,
                "_validate_completed_generic_provider",
                side_effect=corrupt_session,
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
        ):
            self.backend.complete()
        self.assertEqual(self.strategy.session_get("openid"), {})
        authenticate.assert_called_once()

    def test_generic_callback_rejects_mismatched_discovery_state(self) -> None:
        cases = (
            ("server_url", "https://other.example/openid", "invalid_claim"),
            ("claimed_id", "https://other.example/user", "invalid_claim"),
            ("local_id", "https://other.example/local", "invalid_claim"),
        )
        for field, value, code in cases:
            with self.subTest(field=field):
                response = self.verified_response(local_id=IDENTITY)
                expected = copy.copy(response.endpoint)
                setattr(expected, field, value)
                self.set_openid_context(expected)
                self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
                with (
                    patch.object(
                        self.backend,
                        "_complete_generic_response",
                        return_value=response,
                    ),
                    patch.object(self.strategy, "authenticate") as authenticate,
                    assert_auth_error(self, AuthResponseError, code),
                ):
                    self.backend.complete()
                authenticate.assert_not_called()

    def test_generic_same_session_completion_succeeds(self) -> None:
        response = self.verified_response(
            claimed_id=f"{IDENTITY}#provider-fragment",
            local_id=IDENTITY,
        )
        expected = copy.copy(response.endpoint)
        expected.claimed_id = IDENTITY
        self.set_openid_context(expected)
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
        ):
            self.backend.complete()
        authenticate.assert_called_once()
        self.assertEqual(self.strategy.session_get("openid"), {})

    def test_generic_callback_does_not_use_unsigned_session_id(self) -> None:
        response = self.verified_response()
        self.strategy.set_request_data(
            {
                "openid.mode": "id_res",
                LEGACY_SESSION_ID_FIELD: "attacker-session",
            },
            self.backend,
        )
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.backend.complete()

    def test_generic_callback_requires_signed_return_to(self) -> None:
        response = self.verified_response()
        response.signed_fields.remove("openid.return_to")
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.backend.complete()

    def test_generic_callback_rejects_malformed_return_to(self) -> None:
        response = self.verified_response(return_to="https://[invalid")
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.backend.complete()

    def test_generic_callback_rejects_mismatched_session_id(self) -> None:
        response = self.verified_response(
            return_to=f"{self.complete_url}?psa_session_id=initiating-session"
        )
        self.strategy.set_request_data(
            {
                "openid.mode": "id_res",
                LEGACY_SESSION_ID_FIELD: "other-session",
            },
            self.backend,
        )
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.backend.complete()

    def test_generic_callback_rejects_duplicate_signed_session_id(self) -> None:
        response = self.verified_response(
            return_to=(
                f"{self.complete_url}?psa_session_id=first&psa_session_id=second"
            )
        )
        self.strategy.set_request_data(
            {
                "openid.mode": "id_res",
                LEGACY_SESSION_ID_FIELD: "first",
            },
            self.backend,
        )
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.backend.complete()

    def test_signed_session_id_cannot_select_attacker_session(self) -> None:
        response = self.verified_response(
            return_to=f"{self.complete_url}?psa_session_id=initiating-session"
        )
        self.set_openid_context(response.endpoint)
        self.strategy.set_request_data(
            {
                "openid.mode": "id_res",
                LEGACY_SESSION_ID_FIELD: "initiating-session",
                "redirect_state": self.strategy.session_get("openid_state"),
            },
            self.backend,
        )
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.backend.complete()
        authenticate.assert_not_called()

    def test_generic_attacker_response_cannot_use_victim_session(self) -> None:
        expected = self.verified_response(server_url="https://victim.example/openid")
        self.set_openid_context(expected.endpoint)
        response = self.verified_response(
            server_url="https://attacker.example/openid",
            claimed_id="https://attacker.example/id/mallory",
        )
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        victim = User("victim")
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.backend.complete(user=victim)
        authenticate.assert_not_called()

    def test_generic_op_identifier_completion_succeeds(self) -> None:
        response = self.verified_response(
            server_url="https://provider.example/openid",
            claimed_id="https://provider.example/id/user",
        )
        expected = copy.copy(response.endpoint)
        expected.claimed_id = None
        expected.local_id = None
        expected.type_uris = ["http://specs.openid.net/auth/2.0/server"]
        self.set_openid_context(expected)
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
        ):
            self.backend.complete()
        authenticate.assert_called_once()

    def test_generic_op_identifier_requires_claimed_identity(self) -> None:
        response = self.verified_response(claimed_id=None)
        expected = copy.copy(response.endpoint)
        expected.type_uris = ["http://specs.openid.net/auth/2.0/server"]
        self.set_openid_context(expected)
        self.strategy.set_request_data({"openid.mode": "id_res"}, self.backend)
        with (
            patch.object(
                self.backend, "_complete_generic_response", return_value=response
            ),
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.backend.complete()
        authenticate.assert_not_called()

    def bound_backend(
        self,
        *,
        expected_endpoint="https://login.ubuntu.com/+openid",
        callback_endpoint="https://login.ubuntu.com/+openid",
        openid2=True,
    ) -> UbuntuOpenId:
        backend = UbuntuOpenId(self.strategy, redirect_uri=self.complete_url)
        self.strategy.set_request_data(
            {
                "openid.mode": "id_res",
                "openid.op_endpoint": callback_endpoint,
                **({"openid.ns": OPENID2_NS} if openid2 else {}),
            },
            backend,
        )
        endpoint = OpenIDServiceEndpoint()
        endpoint.server_url = expected_endpoint
        self.strategy.openid_session_dict("openid")[
            OpenIdSessionWrapper.endpoint_key
        ] = endpoint
        self.strategy.openid_session_dict("openid")[BACKEND_SESSION_KEY] = backend.name
        self.bind_callback(backend)
        return backend

    def test_fixed_provider_backends_require_binding(self) -> None:
        for backend_class in (
            UbuntuOpenId,
            OpenSUSEOpenId,
            YandexOpenId,
            LaunchpadOpenId,
            FedoraOpenId,
            BelgiumEIDOpenId,
            OpenStackOpenId,
            OpenInfraOpenId,
            LiveJournalOpenId,
            SteamOpenId,
        ):
            with self.subTest(backend=backend_class.name):
                backend = backend_class(self.strategy, redirect_uri=self.complete_url)
                self.assertTrue(backend.requires_openid_provider_binding())
        self.assertFalse(self.backend.requires_openid_provider_binding())

    def test_fixed_provider_rejects_callback_without_initiation(self) -> None:
        backend = UbuntuOpenId(self.strategy, redirect_uri=self.complete_url)
        self.strategy.set_request_data(
            {
                "openid.mode": "id_res",
                "openid.op_endpoint": "https://login.ubuntu.com/+openid",
            },
            backend,
        )
        with (
            patch.object(backend, "consumer") as consumer,
            assert_auth_error(self, AuthSessionError, "session_context_missing"),
        ):
            backend.complete()
        consumer.assert_not_called()

    def test_fixed_provider_rejects_insecure_saved_endpoint(self) -> None:
        backend = self.bound_backend(
            expected_endpoint="http://login.ubuntu.com/+openid",
            callback_endpoint="http://login.ubuntu.com/+openid",
        )
        with (
            patch.object(backend, "consumer") as consumer,
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            backend.complete()
        consumer.assert_not_called()

    def test_fixed_provider_rejects_untrusted_callback_before_completion(self) -> None:
        for callback_endpoint, code in (
            ("https://attacker.example/openid", "invalid_claim"),
            ("http://login.ubuntu.com/+openid", "invalid_claim"),
            ("", "missing_claim"),
        ):
            with self.subTest(callback_endpoint=callback_endpoint):
                backend = self.bound_backend(callback_endpoint=callback_endpoint)
                with (
                    patch.object(backend, "consumer") as consumer,
                    assert_auth_error(self, AuthResponseError, code),
                ):
                    backend.complete()
                consumer.assert_not_called()

    def test_fixed_provider_rechecks_verified_endpoint(self) -> None:
        backend = self.bound_backend()
        response = self.verified_response(server_url="https://attacker.example/openid")
        with (
            patch.object(backend, "consumer") as consumer,
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            consumer.return_value.complete.return_value = response
            backend.complete()
        consumer.return_value.complete.assert_called_once()
        authenticate.assert_not_called()

    def test_fixed_provider_rejects_generic_initiation_state(self) -> None:
        endpoint = "https://login.ubuntu.com/+openid"
        backend = self.bound_backend(expected_endpoint=endpoint)
        self.strategy.openid_session_dict("openid")[BACKEND_SESSION_KEY] = "openid"
        with (
            patch.object(backend, "consumer") as consumer,
            assert_auth_error(self, AuthSessionError, "session_context_missing"),
        ):
            backend.complete()
        consumer.assert_not_called()

    def test_fixed_provider_accepts_openid1_without_op_endpoint(self) -> None:
        endpoint = "https://login.ubuntu.com/+openid"
        backend = self.bound_backend(
            expected_endpoint=endpoint,
            callback_endpoint="",
            openid2=False,
        )
        response = self.verified_response(
            server_url=endpoint,
            namespace=OPENID1_NS,
        )
        with (
            patch.object(backend, "consumer") as consumer,
            patch.object(self.strategy, "authenticate") as authenticate,
        ):
            consumer.return_value.complete.return_value = response
            backend.complete()
        authenticate.assert_called_once()

    def test_fixed_provider_accepts_matching_verified_endpoint(self) -> None:
        endpoint = "https://login.ubuntu.com/+openid"
        backend = self.bound_backend(expected_endpoint=endpoint)
        response = self.verified_response(server_url=endpoint)
        with (
            patch.object(backend, "consumer") as consumer,
            patch.object(self.strategy, "authenticate") as authenticate,
        ):
            consumer.return_value.complete.return_value = response
            backend.complete()
        authenticate.assert_called_once()

    def test_fixed_provider_rejects_signed_session_selection(self) -> None:
        endpoint = "https://login.ubuntu.com/+openid"
        backend = self.bound_backend(expected_endpoint=endpoint)
        state = self.strategy.session_get("ubuntu_state")
        self.strategy.set_request_data(
            {
                "openid.mode": "id_res",
                "openid.ns": OPENID2_NS,
                "openid.op_endpoint": endpoint,
                "redirect_state": state,
                LEGACY_SESSION_ID_FIELD: "attacker-session",
            },
            backend,
        )
        response = self.verified_response(
            server_url=endpoint,
            return_to=f"{self.complete_url}?psa_session_id=attacker-session",
        )
        with (
            patch.object(backend, "consumer") as consumer,
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            consumer.return_value.complete.return_value = response
            backend.complete()
        authenticate.assert_not_called()
        self.assertEqual(self.strategy.session_get("ubuntu_state"), state)

    def test_fixed_provider_rejects_foreign_state_at_same_endpoint(self) -> None:
        endpoint = "https://login.ubuntu.com/+openid"
        backend = self.bound_backend(expected_endpoint=endpoint)
        victim_state = self.strategy.session_get("ubuntu_state")
        self.strategy.set_request_data({"redirect_state": "attacker-state"}, backend)
        response = self.verified_response(server_url=endpoint)
        with (
            patch.object(backend, "consumer") as consumer,
            patch.object(self.strategy, "authenticate") as authenticate,
            assert_auth_error(self, AuthSessionError, "state_mismatch"),
        ):
            consumer.return_value.complete.return_value = response
            backend.complete(user=User("victim"))
        authenticate.assert_not_called()
        self.assertEqual(self.strategy.session_get("ubuntu_state"), victim_state)

    def test_fixed_provider_cancel_does_not_require_initiation(self) -> None:
        backend = UbuntuOpenId(self.strategy, redirect_uri=self.complete_url)
        self.strategy.set_request_data({"openid.mode": "cancel"}, backend)
        endpoint = OpenIDServiceEndpoint()
        with (
            patch.object(backend, "consumer") as consumer,
            assert_auth_error(self, AuthCanceled, "authorization_declined"),
        ):
            consumer.return_value.complete.return_value = CancelResponse(endpoint)
            backend.complete()
        consumer.return_value.complete.assert_called_once()

    def test_fixed_provider_requires_secure_discovery(self) -> None:
        backend = UbuntuOpenId(self.strategy, redirect_uri=self.complete_url)
        for server_url, code in (
            (None, "malformed_response"),
            ("http://login.ubuntu.com/+openid", "tls_error"),
        ):
            with (
                self.subTest(server_url=server_url),
                patch.object(backend, "consumer") as consumer,
                assert_auth_error(self, AuthProviderError, code),
            ):
                consumer.return_value.begin.return_value = SimpleNamespace(
                    endpoint=SimpleNamespace(server_url=server_url)
                )
                backend.openid_request()
            self.assertEqual(self.strategy.session_get("openid"), {})

    def test_fixed_provider_requires_secure_configured_url(self) -> None:
        class InsecureOpenId(OpenIdAuth):
            URL = "http://provider.example/openid"

        backend = InsecureOpenId(self.strategy, redirect_uri=self.complete_url)
        with (
            patch.object(backend, "consumer") as consumer,
            assert_auth_error(self, AuthConfigurationError, "invalid_setting"),
        ):
            backend.openid_request()
        consumer.assert_not_called()


class UbuntuForeignProviderTest(OpenIdTest):
    backend_path = "social_core.backends.ubuntu.UbuntuOpenId"
    expected_username = "alice"
    discovery_body = """<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
    <XRD>
        <Service priority="0">
            <Type>http://specs.openid.net/auth/2.0/server</Type>
            <URI>https://login.ubuntu.com/+openid</URI>
        </Service>
    </XRD>
</xrds:XRDS>"""
    server_response = urlencode(
        {
            "openid.ns": OPENID2_NS,
            "openid.mode": "id_res",
            "openid.op_endpoint": "https://attacker.example/openid",
            "openid.claimed_id": "https://attacker.example/id/mallory",
            "openid.identity": "https://attacker.example/id/mallory",
            "openid.sreg.nickname": "alice",
        }
    )

    def openid_url(self) -> str:
        return f"{super().openid_url()}/"

    def test_foreign_provider_cannot_migrate_legacy_association(self) -> None:
        alice = User(username="alice")
        social = TestUserSocialAuth(
            alice, "ubuntu", "alice", extra_data={"auth_time": 1}, id_key=""
        )

        with assert_auth_error(self, AuthResponseError, "invalid_claim"):
            self.do_start()

        self.assertEqual(social.uid, "alice")
        self.assertEqual(social.id_key, "")
