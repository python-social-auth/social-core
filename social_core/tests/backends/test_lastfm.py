import json

import responses

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
        self.assertEqual(start_url, "https://www.last.fm/api/auth/?api_key=a-key")
        self.strategy.set_request_data({"token": "foobar"}, self.backend)
        responses.add(
            responses.POST,
            "https://ws.audioscrobbler.com/2.0/",
            body=json.dumps({"session": {"name": "foobar", "key": "session-key"}}),
            content_type="application/json",
        )
        return self.backend.complete()

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
