import hashlib
import hmac
from base64 import b64encode
from urllib.parse import parse_qs, urlencode, urlparse

import requests
import responses

from social_core.exceptions import AuthException

from .base import BaseBackendTest

TEST_KEY = "foo"


class DiscourseTest(BaseBackendTest):
    backend_path = "social_core.backends.discourse.DiscourseAuth"
    expected_username = "beepboop"
    raw_complete_url = "/complete/{0}/"

    def post_start(self) -> None:
        pass

    def do_start(self):
        self.post_start()
        start = self.backend.start()
        start_url = start.url
        return_url = self.backend.redirect_uri
        sso = b64encode(
            urlencode(
                {
                    "email": "user@example.com",
                    "username": "beepboop",
                    "nonce": "6YRje7xlXhpyeJ6qtvBeTUjHkXo1UCTQmCrzN8GXfja3AoAFk2CieDRYgSqMYi4W",
                    "return_sso_url": "http://myapp.com/",
                }
            ).encode()
        ).decode()
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
