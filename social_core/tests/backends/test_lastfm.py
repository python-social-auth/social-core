import json

import responses

from social_core.exceptions import AuthInputError, AuthSessionError
from social_core.utils import get_querystring, parse_qs

from .base import BaseBackendTest


class LastFmAuthTest(BaseBackendTest):
    backend_path = "social_core.backends.lastfm.LastFmAuth"
    expected_username = "foobar"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_LASTFM_KEY": "a-key",
            "SOCIAL_AUTH_LASTFM_SECRET": "a-secret-key",
        }

    def do_start(self):
        start_url = self.backend.start().url
        query = get_querystring(start_url)
        state = get_querystring(query["cb"])["redirect_state"]
        self.assertEqual(query["api_key"], "a-key")
        self.assertEqual(state, self.strategy.session_get("lastfm_state"))
        self.strategy.set_request_data(
            {"token": "foobar", "redirect_state": state}, self.backend
        )
        responses.add(
            responses.POST,
            "https://ws.audioscrobbler.com/2.0/",
            body=json.dumps({"session": {"name": "foobar", "key": "session-key"}}),
            content_type="application/json",
        )
        return self.backend.complete()

    def test_auth_url_contains_session_bound_callback(self) -> None:
        self.backend.redirect_uri = "https://myapp.com/complete/lastfm?next=/profile"

        start_url = self.backend.start().url
        query = get_querystring(start_url)
        callback_query = get_querystring(query["cb"])

        self.assertEqual(query["api_key"], "a-key")
        self.assertTrue(query["cb"].startswith("https://myapp.com/complete/lastfm?"))
        self.assertEqual(callback_query["next"], "/profile")
        session_state = self.strategy.session_get("lastfm_state")
        self.assertEqual(callback_query["redirect_state"], session_state)

    def test_auth_url_reuses_state_for_concurrent_starts(self) -> None:
        first_callback = get_querystring(self.backend.start().url)["cb"]
        second_callback = get_querystring(self.backend.start().url)["cb"]

        first_state = get_querystring(first_callback)["redirect_state"]
        second_state = get_querystring(second_callback)["redirect_state"]

        self.assertEqual(first_state, second_state)
        session_state = self.strategy.session_get("lastfm_state")
        self.assertEqual(first_state, session_state)

    def test_complete_rejects_missing_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data({"token": "foobar"}, self.backend)

        with self.assertRaises(AuthInputError):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)

    def test_complete_rejects_mismatched_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(
            {"token": "foobar", "redirect_state": "invalid-state"},
            self.backend,
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)

    def test_complete_rejects_orphan_state(self) -> None:
        self.strategy.set_request_data(
            {"token": "foobar", "redirect_state": "orphan-state"},
            self.backend,
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)

    def test_complete_rejects_missing_token(self) -> None:
        state = self.backend.get_or_create_state()
        self.strategy.set_request_data({"redirect_state": state}, self.backend)

        with self.assertRaises(AuthInputError):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)

    def test_session_request_is_signed(self) -> None:
        self.do_start()

        request_data = parse_qs(responses.calls[-1].request.body)
        self.assertEqual(request_data["method"], "auth.getSession")
        self.assertEqual(request_data["api_key"], "a-key")
        self.assertEqual(request_data["token"], "foobar")
        self.assertEqual(request_data["format"], "json")
        self.assertEqual(request_data["api_sig"], "a17701f3803e1ec60da5947b7bb5f793")

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
