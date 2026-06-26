import json
from typing import cast

import responses

from social_core.utils import get_querystring, parse_qs

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class LineOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.line.LineOAuth2"
    user_data_url = "https://api.line.me/v2/profile"
    expected_username = "U4af4980629"
    access_token_body = json.dumps(
        {
            "access_token": "access-token",
            "expires_in": 2592000,
            "refresh_token": "refresh-token",
            "token_type": "Bearer",
        }
    )
    user_data_body = json.dumps(
        {
            "userId": "U4af4980629",
            "displayName": "LINE taro",
            "pictureUrl": "https://profile.line-scdn.net/abcdefghijklmn",
            "statusMessage": "Hello, LINE!",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_access_token_request_uses_authorization_redirect_uri(self) -> None:
        self.do_login()

        auth_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.authorization_url())
        )
        token_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )

        auth_redirect_uri = get_querystring(cast("str", auth_request.url))[
            "redirect_uri"
        ]
        token_redirect_uri = parse_qs(token_request.body)["redirect_uri"]

        self.assertEqual(token_redirect_uri, auth_redirect_uri)

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
