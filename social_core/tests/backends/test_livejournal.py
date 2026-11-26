from __future__ import annotations

import datetime as dt
from contextlib import contextmanager
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock, patch
from urllib.parse import parse_qsl, urlencode, urlsplit

from openid.consumer.consumer import GenericConsumer, SuccessResponse
from openid.consumer.discover import DiscoveryFailure, OpenIDServiceEndpoint
from openid.message import OPENID2_NS, Message

from social_core.actions import do_auth, do_complete
from social_core.backends.livejournal import _discover_livejournal_claimed_id
from social_core.exceptions import (
    AuthAssociationError,
    AuthInputError,
    AuthProviderError,
    AuthResponseError,
    AuthSessionError,
)
from social_core.store import OpenIdSessionWrapper
from social_core.tests.exception_helpers import assert_auth_error
from social_core.tests.models import TestUserSocialAuth, User
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME

from .open_id import OpenIdTest

IDENTITY = "https://foobar.livejournal.com/"
SERVER_URL = "https://www.livejournal.com/openid/server.bml"
JANRAIN_NONCE = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
PROVIDER = "https://www.livejournal.com/openid/server.bml"


class LiveJournalOpenIdTest(OpenIdTest):
    backend_path = "social_core.backends.livejournal.LiveJournalOpenId"
    discovery_body = f"""<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
    <XRD>
        <Service priority="0">
            <Type>http://specs.openid.net/auth/2.0/signon</Type>
            <URI>{SERVER_URL}</URI>
            <LocalID>{IDENTITY}</LocalID>
        </Service>
    </XRD>
</xrds:XRDS>"""
    server_response = urlencode(
        {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "id_res",
            "openid.claimed_id": IDENTITY,
            "openid.identity": IDENTITY,
            "openid.op_endpoint": SERVER_URL,
            "openid.response_nonce": f"{JANRAIN_NONCE}wGp2rj",
            "openid.assoc_handle": "1364932966:ZTiur8sem3r2jzZougMZ:4d1cc3b44e",
            "openid.signed": "mode,claimed_id,identity,op_endpoint,return_to,"
            "response_nonce,assoc_handle",
            "openid.sig": "Z8MOozVPTOBhHG5ZS1NeGofxs1Q=",
        }
    )

    def setUp(self) -> None:
        super().setUp()
        self.strategy.set_settings({"SOCIAL_AUTH_LOGIN_REDIRECT_URL": "/done"})

    def start(self, user: User | None = None) -> dict[str, str]:
        """Start the flow as ``user`` and return LiveJournal's callback data."""
        self.strategy.set_request_data({"openid_lj_user": "foobar"}, self.backend)
        self.add_openid_response(
            "GET",
            IDENTITY,
            body=self.discovery_body,
            content_type="application/xrds+xml",
        )
        _form, inputs = self.get_form_data(do_auth(self.backend, user=user))
        return_to = cast("str", inputs["openid.return_to"])
        callback = dict(parse_qsl(self.server_response))
        callback["openid.return_to"] = return_to
        callback.update(parse_qsl(urlsplit(return_to).query))
        return callback

    def complete(self, callback: dict[str, str], user: User | None = None):
        """Deliver ``callback`` to a fresh request made by ``user``."""
        self.strategy = self.strategy.new_request()
        self.backend = type(self.backend)(self.strategy, redirect_uri=self.complete_url)
        self.strategy.set_request_data(callback, self.backend)
        # The signature is verified through the provider since no association
        # was established during discovery.
        self.add_openid_response("POST", SERVER_URL, body="is_valid:true\n")
        login = Mock()
        response = do_complete(self.backend, login, user=user)
        login.assert_not_called()
        return response

    def test_login(self) -> None:
        user = User("existing")
        callback = self.start(user)
        context = self.strategy.session_get("livejournal_state")
        self.assertEqual(
            context, {"state": callback["redirect_state"], "user_id": str(user.id)}
        )

        self.assertEqual(self.complete(callback, user).url, "/done")

        social = TestUserSocialAuth.get_social_auth("livejournal", IDENTITY)
        self.assertIs(social.user, user)
        self.assertEqual(user.username, "existing")
        self.assertEqual(len(User.cache), 1)
        self.assertIsNone(self.strategy.session_get("livejournal_state"))

    def test_partial_pipeline(self) -> None:
        user = User("existing")
        self.pipeline_settings()
        response = self.complete(self.start(user), user)
        self.assertEqual(response.url, self.strategy.build_absolute_uri("/password"))
        self.strategy.session_set("password", "foobar")
        self.strategy.session_set("slug", "foo-bar")
        token = self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME)

        for resuming_user, code in (
            (None, "user_mismatch"),
            (User("other"), "user_mismatch"),
        ):
            with self.subTest(user=resuming_user):
                self.strategy.session_set(PARTIAL_TOKEN_SESSION_NAME, token)
                with assert_auth_error(self, AuthSessionError, code):
                    self.complete({}, resuming_user)
                self.assertEqual(user.social, [])
        self.strategy.session_set(PARTIAL_TOKEN_SESSION_NAME, token)
        self.assertEqual(self.complete({}, user).url, "/done")

        social = TestUserSocialAuth.get_social_auth("livejournal", IDENTITY)
        self.assertIs(social.user, user)
        self.assertEqual(user.username, "existing")

    def test_failed_login(self) -> None:
        with self.assertRaises(AuthInputError):
            do_auth(self.backend, user=User("existing"))

    def test_start_requires_authenticated_user(self) -> None:
        with assert_auth_error(self, AuthSessionError, "session_context_missing"):
            self.start()

    def test_direct_start_requires_prepared_context(self) -> None:
        self.strategy.set_request_data({"openid_lj_user": "foobar"}, self.backend)
        with assert_auth_error(self, AuthSessionError, "session_context_missing"):
            self.backend.start()

    def test_reused_journal_name_does_not_authenticate(self) -> None:
        previous_holder = User("foobar")
        social = TestUserSocialAuth.create_social_auth(
            previous_holder, IDENTITY, "livejournal"
        )
        user = User("existing")

        with assert_auth_error(self, AuthAssociationError, "identity_in_use"):
            self.complete(self.start(user), user)

        self.assertIs(social.user, previous_holder)
        self.assertEqual(user.social, [])

    def test_complete_requires_authenticated_user(self) -> None:
        user = User("existing")
        callback = self.start(user)

        with assert_auth_error(self, AuthSessionError, "session_context_missing"):
            self.complete(callback)

        self.assertEqual(user.social, [])
        self.assertEqual(len(User.cache), 1)

    def test_complete_requires_initiating_user(self) -> None:
        user = User("existing")
        other = User("other")
        callback = self.start(user)

        with assert_auth_error(self, AuthSessionError, "user_mismatch"):
            self.complete(callback, other)

        self.assertEqual(user.social, [])
        self.assertEqual(other.social, [])

    def test_complete_requires_matching_state(self) -> None:
        user = User("existing")
        callback = self.start(user)
        self.strategy.session_set(
            "livejournal_state", {"state": "other", "user_id": str(user.id)}
        )

        with assert_auth_error(self, AuthSessionError, "state_mismatch"):
            self.complete(callback, user)

        self.assertEqual(user.social, [])

    def test_openid_url_uses_https(self) -> None:
        self.strategy.set_request_data({"openid_lj_user": "foobar"}, self.backend)
        self.assertEqual(self.backend.openid_url(), "https://foobar.livejournal.com")

    def test_openid_url_rejects_host_injection(self) -> None:
        for username in (
            "foobar/path",
            "foobar?query",
            "foobar#fragment",
            "foobar:443",
            "foobar:invalid",
        ):
            with self.subTest(username=username):
                self.strategy.set_request_data(
                    {"openid_lj_user": username}, self.backend
                )
                with self.assertRaises(AuthInputError) as caught:
                    self.backend.openid_url()
                self.assertEqual(caught.exception.code, "invalid_parameter")

    def test_discovery_rejects_journal_redirected_to_foreign_provider(self) -> None:
        # The journal is its owner's page and may redirect to the owner's site.
        self.strategy.set_request_data({"openid_lj_user": "mallory"}, self.backend)
        self.backend.prepare_auth(User("existing"))
        self.add_openid_response(
            "GET",
            "https://mallory.livejournal.com/",
            final_url="https://mallory.example/",
            body='<html><head><link rel="openid2.provider" '
            'href="https://mallory.example/openid"></head></html>',
            content_type="text/html",
        )
        with assert_auth_error(self, AuthProviderError, "malformed_response"):
            self.backend.start()
        self.assertEqual(self.strategy.session_get("openid"), {})

    def test_discovery_requires_livejournal_provider(self) -> None:
        self.strategy.set_request_data({"openid_lj_user": "mallory"}, self.backend)
        with patch.object(self.backend, "consumer") as consumer:
            consumer.return_value.begin.return_value = SimpleNamespace(
                endpoint=SimpleNamespace(server_url=PROVIDER)
            )
            self.backend.openid_request()
        for server_url, code in (
            ("https://mallory.example/openid", "malformed_response"),
            ("https://mallory.livejournal.com/openid", "malformed_response"),
            ("https://www.livejournal.com.mallory.example/", "malformed_response"),
            ("https://mallory.example/www.livejournal.com", "malformed_response"),
            ("https://www.livejournal.com@mallory.example/", "malformed_response"),
            ("http://www.livejournal.com/openid/server.bml", "tls_error"),
        ):
            with (
                self.subTest(server_url=server_url),
                patch.object(self.backend, "consumer") as consumer,
                assert_auth_error(self, AuthProviderError, code),
            ):
                consumer.return_value.begin.return_value = SimpleNamespace(
                    endpoint=SimpleNamespace(server_url=server_url)
                )
                self.backend.openid_request()
            self.assertEqual(self.strategy.session_get("openid"), {})

    @contextmanager
    def verified_callback(
        self,
        claimed_id: str,
        *,
        local_id: str | None = None,
        server_url: str = PROVIDER,
    ):
        # A verified assertion for a login initiated in this session.
        user = User("existing")
        self.backend.prepare_auth(user)
        endpoint = OpenIDServiceEndpoint()
        endpoint.server_url = server_url
        endpoint.claimed_id = claimed_id
        endpoint.local_id = local_id
        session = self.strategy.openid_session_dict("openid")
        session[OpenIdSessionWrapper.endpoint_key] = endpoint
        session["_social_auth_backend"] = self.backend.name
        self.strategy.set_request_data(
            {
                "openid.mode": "id_res",
                "openid.ns": OPENID2_NS,
                "openid.op_endpoint": server_url,
                "redirect_state": self.backend.create_state(),
            },
            self.backend,
        )
        message = Message(OPENID2_NS)
        message.setArg(OPENID2_NS, "mode", "id_res")
        message.setArg(OPENID2_NS, "return_to", self.complete_url)
        response = SuccessResponse(endpoint, message, list(message.toPostArgs()))
        with (
            patch.object(self.backend, "consumer") as consumer,
            patch.object(self.strategy, "authenticate") as authenticate,
        ):
            consumer.return_value.complete.return_value = response
            yield authenticate, user

    def test_completion_accepts_journal_identity(self) -> None:
        for claimed_id in (
            "https://foobar.livejournal.com/",
            "http://foobar.livejournal.com/",
            "https://foobar.livejournal.com/#generation",
            "https://users.livejournal.com/_foobar_/",
        ):
            with (
                self.subTest(claimed_id=claimed_id),
                self.verified_callback(claimed_id) as (authenticate, user),
            ):
                self.backend.complete(user=user)
                authenticate.assert_called_once()

    def test_http_claimed_id_uses_https_discovery_and_real_verifier(self) -> None:
        claimed_id = "http://foobar.livejournal.com/"
        self.add_openid_response(
            "GET",
            "https://foobar.livejournal.com/",
            body=self.discovery_body.replace(
                f"<LocalID>{IDENTITY}</LocalID>",
                f"<LocalID>{claimed_id}</LocalID>",
            ),
            content_type="application/xrds+xml",
        )
        asserted = OpenIDServiceEndpoint()
        asserted.claimed_id = claimed_id
        asserted.local_id = claimed_id
        asserted.server_url = PROVIDER
        asserted.type_uris = ["http://specs.openid.net/auth/2.0/signon"]

        # Exercise the library's actual discovery verifier, not a mocked callback.
        verify_discovery = GenericConsumer.__dict__["_discoverAndVerify"]
        verified = verify_discovery(
            self.backend.consumer().consumer, claimed_id, [asserted]
        )

        self.assertEqual(verified.claimed_id, claimed_id)
        self.assertEqual(verified.getLocalID(), claimed_id)
        self.assertEqual(verified.server_url, PROVIDER)

    def test_http_claimed_id_requires_matching_https_delegation(self) -> None:
        claimed_id = "http://foobar.livejournal.com/"
        self.add_openid_response(
            "GET",
            "https://foobar.livejournal.com/",
            body=self.discovery_body.replace(
                IDENTITY, "http://someone-else.livejournal.com/"
            ),
            content_type="application/xrds+xml",
        )
        asserted = OpenIDServiceEndpoint()
        asserted.claimed_id = claimed_id
        asserted.local_id = claimed_id
        asserted.server_url = PROVIDER
        asserted.type_uris = ["http://specs.openid.net/auth/2.0/signon"]

        with self.assertRaises(DiscoveryFailure):
            verify_discovery = GenericConsumer.__dict__["_discoverAndVerify"]
            verify_discovery(self.backend.consumer().consumer, claimed_id, [asserted])

    def test_http_claimed_id_rejects_untrusted_discovery_targets(self) -> None:
        for claimed_id in (
            "http://foobar.livejournal.com.evil.example/",
            "http://foobar.livejournal.com:8080/",
            "http://user@foobar.livejournal.com/",
            "http://foobar.livejournal.com/?next=other",
            "http://[foobar.livejournal.com/",
            "http://foobar.livejournal.com\\@evil.example/",
        ):
            with (
                self.subTest(claimed_id=claimed_id),
                self.assertRaises(DiscoveryFailure),
            ):
                _discover_livejournal_claimed_id(claimed_id)

    def test_completion_rejects_identity_outside_livejournal(self) -> None:
        # A redirected journal's page can name LiveJournal's server and delegate
        # to any journal, while the identity being linked is the page itself.
        journal = "https://foobar.livejournal.com/"
        for claimed_id, local_id in (
            ("https://mallory.example/", journal),
            ("https://livejournal.com.mallory.example/", journal),
            ("https://mallory.example/.livejournal.com", journal),
            ("https://foobar.livejournal.com@mallory.example/", journal),
            ("https://livejournal.com/", None),
            ("https://[foobar.livejournal.com/", None),
        ):
            with (
                self.subTest(claimed_id=claimed_id, local_id=local_id),
                self.verified_callback(claimed_id, local_id=local_id) as (
                    authenticate,
                    user,
                ),
            ):
                with assert_auth_error(self, AuthResponseError, "invalid_claim"):
                    self.backend.complete(user=user)
                authenticate.assert_not_called()

    def test_completion_rejects_saved_foreign_provider(self) -> None:
        with self.verified_callback(
            "https://foobar.livejournal.com/",
            server_url="https://mallory.example/openid",
        ) as (authenticate, user):
            with assert_auth_error(self, AuthResponseError, "invalid_claim"):
                self.backend.complete(user=user)
            authenticate.assert_not_called()
