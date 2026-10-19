import hashlib
import hmac
from base64 import b64decode, b64encode
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

import requests
import responses

from social_core.exceptions import (
    AuthException,
    AuthInputError,
    AuthResponseError,
    AuthSessionError,
)
from social_core.pipeline import DEFAULT_AUTH_PIPELINE

from .base import BaseBackendTest

TEST_KEY = "foo"


class DiscourseTest(BaseBackendTest):
    backend_path = "social_core.backends.discourse.DiscourseAuth"
    expected_username = "beepboop"
    raw_complete_url = "/complete/{0}/"

    def test_missing_sso_parameter(self) -> None:
        with self.assertRaises(AuthInputError):
            self.backend.complete()

    def post_start(self) -> None:
        pass

    def do_start(self, groups: str | None = None):
        self.post_start()
        start = self.backend.start()
        start_url = start.url
        return_url = self.backend.redirect_uri
        start_params = parse_qs(urlparse(start_url).query)
        started_payload = parse_qs(b64decode(start_params["sso"][0]).decode())
        payload = {
            "external_id": "42",
            "email": "user@example.com",
            "username": "beepboop",
            "nonce": started_payload["nonce"][0],
            "return_sso_url": "http://myapp.com/",
        }
        if groups is not None:
            payload["groups"] = groups
        sso = b64encode(urlencode(payload).encode()).decode()
        sig = hmac.new(TEST_KEY.encode(), sso.encode(), hashlib.sha256).hexdigest()
        response_query_params = f"sso={sso}&sig={sig}"

        response_url = f"{return_url}/?{response_query_params}"
        responses.add(
            responses.GET,
            start_url,
            status=301,
            headers={"Location": response_url},
        )
        responses.add(
            responses.GET,
            return_url,
            status=200,
            content_type="text/html",
        )

        response = requests.get(start_url, timeout=1)
        query_values = {
            k: v[0] for k, v in parse_qs(urlparse(response.url).query).items()
        }
        self.strategy.set_request_data(query_values, self.backend)

        return self.backend.complete()

    def prepare_signed_callback(self, nonce: str) -> None:
        payload = urlencode(
            {"nonce": nonce, "external_id": "42", "username": "beepboop"}
        )
        sso = b64encode(payload.encode()).decode()
        sig = hmac.new(TEST_KEY.encode(), sso.encode(), hashlib.sha256).hexdigest()
        self.strategy.set_request_data({"sso": sso, "sig": sig}, self.backend)

    def session_nonce(self) -> str:
        nonce = self.strategy.session_get("discourse_nonce")
        assert isinstance(nonce, str)
        return nonce

    def test_start_binds_nonce_to_session(self) -> None:
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": TEST_KEY}
        )
        start_url = self.backend.start().url
        sso = parse_qs(urlparse(start_url).query)["sso"][0]
        nonce = parse_qs(b64decode(sso).decode())["nonce"][0]
        self.assertEqual(self.strategy.session_get("discourse_nonce"), nonce)

    def test_complete_rejects_foreign_session(self) -> None:
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": TEST_KEY}
        )
        self.backend.start()
        nonce = self.session_nonce()
        self.prepare_signed_callback(nonce)

        self.strategy.session_set("discourse_nonce", "different-login")
        with self.assertRaises(AuthSessionError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "state_mismatch")
        self.assertEqual(
            self.strategy.session_get("discourse_nonce"), "different-login"
        )

        self.strategy.session_set("discourse_nonce", nonce)
        self.assertEqual(self.backend.complete().username, "beepboop")

    def test_complete_rejects_missing_session(self) -> None:
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": TEST_KEY}
        )
        self.backend.start()
        self.prepare_signed_callback(self.session_nonce())
        self.strategy.session_pop("discourse_nonce")
        with self.assertRaises(AuthSessionError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "session_context_missing")

    def test_complete_rejects_missing_callback_nonce(self) -> None:
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": TEST_KEY}
        )
        self.backend.start()
        self.prepare_signed_callback("")
        with self.assertRaises(AuthSessionError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "state_mismatch")

    def test_complete_rejects_missing_stored_nonce(self) -> None:
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": TEST_KEY}
        )
        self.backend.start()
        nonce = self.session_nonce()
        self.prepare_signed_callback(nonce)
        nonce_obj = self.backend.get_nonce(nonce)
        assert nonce_obj is not None
        self.backend.delete_nonce(nonce_obj)

        with self.assertRaises(AuthResponseError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "nonce_mismatch")
        self.assertEqual(self.session_nonce(), nonce)

    def test_new_start_replaces_session_nonce(self) -> None:
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": TEST_KEY}
        )
        self.backend.start()
        old_nonce = self.session_nonce()
        self.backend.start()
        self.assertNotEqual(self.session_nonce(), old_nonce)
        self.prepare_signed_callback(old_nonce)

        with self.assertRaises(AuthSessionError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "state_mismatch")

    def test_complete_rejects_replay(self) -> None:
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": TEST_KEY}
        )
        self.backend.start()
        self.prepare_signed_callback(self.session_nonce())
        self.assertEqual(self.backend.complete().username, "beepboop")
        self.assertIsNone(self.strategy.session_get("discourse_nonce"))
        with self.assertRaises(AuthSessionError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "session_context_missing")

    def test_login(self) -> None:
        """
        Test that we can authenticate with the Discourse IdP
        """
        # pretend we've started with a URL like /login/discourse:
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": TEST_KEY}
        )
        self.do_login()

    def test_failed_login(self) -> None:
        """
        Test that authentication fails when our request is signed with a
        different secret than our payload
        """
        self.strategy.set_settings(
            {"SERVER_URL": "http://example.com", "SECRET": "bar"}
        )
        with self.assertRaises(AuthException):
            self.do_login()

    def test_signed_group_claims_reach_synchronization(self) -> None:
        self.strategy.set_settings(
            {
                "SERVER_URL": "http://example.com",
                "SECRET": TEST_KEY,
                "SOCIAL_AUTH_DISCOURSE_GROUPS_ENABLED": True,
                "SOCIAL_AUTH_PIPELINE": (
                    *DEFAULT_AUTH_PIPELINE,
                    "social_core.pipeline.user.sync_groups",
                ),
            }
        )
        for groups, expected in (("", []), ("first,second", ["first", "second"])):
            with (
                self.subTest(groups=groups),
                patch.object(self.strategy, "sync_user_groups") as synchronize,
            ):
                user = self.do_start(groups=groups)
                self.assertEqual(user.username, self.expected_username)
                synchronize.assert_called_once()
                self.assertEqual(synchronize.call_args.args, (user, expected))

    def test_missing_group_claim_still_fails(self) -> None:
        self.strategy.set_settings(
            {
                "SERVER_URL": "http://example.com",
                "SECRET": TEST_KEY,
                "SOCIAL_AUTH_DISCOURSE_GROUPS_ENABLED": True,
            }
        )
        with self.assertRaises(AuthResponseError) as caught:
            self.do_start()
        self.assertEqual(caught.exception.code, "missing_claim")
