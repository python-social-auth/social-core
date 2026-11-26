import datetime as dt
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode

import pytest
import responses
from openid.consumer.consumer import GenericConsumer, SuccessResponse
from openid.consumer.discover import DiscoveryFailure, OpenIDServiceEndpoint
from openid.message import OPENID2_NS, Message

from social_core.backends.livejournal import _discover_livejournal_claimed_id
from social_core.exceptions import (
    AuthInputError,
    AuthProviderError,
    AuthResponseError,
)
from social_core.store import OpenIdSessionWrapper
from social_core.tests.exception_helpers import assert_auth_error

from .open_id import OpenIdTest

JANRAIN_NONCE = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
PROVIDER = "https://www.livejournal.com/openid/server.bml"


class LiveJournalOpenIdTest(OpenIdTest):
    backend_path = "social_core.backends.livejournal.LiveJournalOpenId"
    expected_username = "foobar"
    discovery_body = """<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
    <XRD>
        <Service priority="0">
            <Type>http://specs.openid.net/auth/2.0/signon</Type>
            <URI>https://www.livejournal.com/openid/server.bml</URI>
            <LocalID>http://foobar.livejournal.com/</LocalID>
        </Service>
    </XRD>
</xrds:XRDS>"""
    server_response = urlencode(
        {
            "janrain_nonce": JANRAIN_NONCE,
            "openid.mode": "id_res",
            "openid.claimed_id": "http://foobar.livejournal.com/",
            "openid.identity": "http://foobar.livejournal.com/",
            "openid.op_endpoint": "https://www.livejournal.com/openid/server.bml",
            "openid.return_to": f"http://myapp.com/complete/livejournal/?janrain_nonce={JANRAIN_NONCE}",
            "openid.response_nonce": f"{JANRAIN_NONCE}wGp2rj",
            "openid.assoc_handle": "1364932966:ZTiur8sem3r2jzZougMZ:4d1cc3b44e",
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.signed": "mode,claimed_id,identity,op_endpoint,return_to,"
            "response_nonce,assoc_handle",
            "openid.sig": "Z8MOozVPTOBhHG5ZS1NeGofxs1Q=",
        }
    )
    server_bml_body = """assoc_handle:1364935340:ZhruPQ7DJ9eGgUkeUA9A:27f8c32464
assoc_type:HMAC-SHA1
dh_server_public:WzsRyLomvAV3vwvGUrfzXDgfqnTF+m1l3JWb55fyHO7visPT4tmQiTjqFFnSVAtAOvQzoViMiZQisxNwnqSK4lYexoez1z6pP5ry3pqxJAEYj60vFGvRztictEo0brjhmO1SNfjK1ppjOymdykqLpZeaL5fsuLtMCwTnR/JQZVA=
enc_mac_key:LiOEVlLJSVUqfNvb5zPd76nEfvc=
expires_in:1207060
ns:http://specs.openid.net/auth/2.0
session_type:DH-SHA1
"""

    def openid_url(self) -> str:
        return f"{super().openid_url()}/data/yadis"

    def post_start(self) -> None:
        self.strategy.remove_from_request_data("openid_lj_user")

    def _setup_handlers(self) -> None:
        responses.add(
            responses.POST,
            "https://www.livejournal.com/openid/server.bml",
            headers={
                "Accept-Encoding": "identity",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            status=200,
            body=self.server_bml_body,
        )
        responses.add(
            responses.GET,
            "http://foobar.livejournal.com/",
            headers={
                "Accept-Encoding": "identity",
                "Accept": "text/html; q=0.3,"
                "application/xhtml+xml; q=0.5,"
                "application/xrds+xml",
            },
            status=200,
            body=self.discovery_body,
        )

    @pytest.mark.xfail(reason="responses mocking does not work for openid")
    def test_login(self) -> None:
        self.strategy.set_request_data({"openid_lj_user": "foobar"}, self.backend)
        self._setup_handlers()
        self.do_login()

    @pytest.mark.xfail(reason="responses mocking does not work for openid")
    def test_partial_pipeline(self) -> None:
        self.strategy.set_request_data({"openid_lj_user": "foobar"}, self.backend)
        self._setup_handlers()
        self.do_partial_pipeline()

    def test_failed_login(self) -> None:
        self._setup_handlers()
        with self.assertRaises(AuthInputError):
            self.do_login()

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
            yield authenticate

    def test_completion_accepts_journal_identity(self) -> None:
        for claimed_id in (
            "https://foobar.livejournal.com/",
            "http://foobar.livejournal.com/",
            "https://foobar.livejournal.com/#generation",
            "https://users.livejournal.com/_foobar_/",
        ):
            with (
                self.subTest(claimed_id=claimed_id),
                self.verified_callback(claimed_id) as authenticate,
            ):
                self.backend.complete()
                authenticate.assert_called_once()

    def test_http_claimed_id_uses_https_discovery_and_real_verifier(self) -> None:
        claimed_id = "http://foobar.livejournal.com/"
        self.add_openid_response(
            "GET",
            "https://foobar.livejournal.com/",
            body=self.discovery_body,
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
                claimed_id, "http://someone-else.livejournal.com/"
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
                self.verified_callback(claimed_id, local_id=local_id) as authenticate,
            ):
                with assert_auth_error(self, AuthResponseError, "invalid_claim"):
                    self.backend.complete()
                authenticate.assert_not_called()

    def test_completion_rejects_saved_foreign_provider(self) -> None:
        with self.verified_callback(
            "https://foobar.livejournal.com/",
            server_url="https://mallory.example/openid",
        ) as authenticate:
            with assert_auth_error(self, AuthResponseError, "invalid_claim"):
                self.backend.complete()
            authenticate.assert_not_called()
