import json

import responses

from social_core.backends.coinbase import API_VERSION
from social_core.utils import get_querystring, parse_qs

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class CoinbaseOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.coinbase.CoinbaseOAuth2"
    user_data_url = "https://api.coinbase.com/v2/user"
    expected_username = "satoshi_nakomoto"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "data": {
                "id": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "name": "Satoshi Nakamoto",
                "username": "satoshi_nakomoto",
                "profile_location": None,
                "profile_bio": None,
                "profile_url": "https://coinbase.com/satoshi_nakomoto",
                "avatar_url": None,
                "resource": "user",
                "resource_path": "/v2/user",
            }
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_current_oauth_configuration(self) -> None:
        self.assertEqual(
            self.backend.authorization_url(),
            "https://login.coinbase.com/oauth2/auth",
        )
        self.assertEqual(
            self.backend.access_token_url(),
            "https://login.coinbase.com/oauth2/token",
        )
        self.assertEqual(
            self.backend.revoke_token_url("token", "uid"),
            "https://login.coinbase.com/oauth2/revoke",
        )
        self.assertEqual(
            get_querystring(self.backend.auth_url())["scope"],
            "wallet:user:read,wallet:user:email",
        )

    def test_configured_scopes_use_commas_and_include_default(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_COINBASE_SCOPE": [
                    "wallet:accounts:read",
                    "wallet:addresses:read",
                ]
            }
        )

        scope = get_querystring(self.backend.auth_url())["scope"]

        self.assertEqual(
            scope,
            "wallet:accounts:read,wallet:addresses:read,"
            "wallet:user:read,wallet:user:email",
        )

    def test_default_scope_can_be_ignored(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_COINBASE_SCOPE": ["wallet:user:email"],
                "SOCIAL_AUTH_COINBASE_IGNORE_DEFAULT_SCOPE": True,
            }
        )

        self.assertEqual(
            get_querystring(self.backend.auth_url())["scope"], "wallet:user:email"
        )

    def test_user_data_sends_api_version(self) -> None:
        responses.add(
            responses.GET,
            self.backend.USER_DATA_URL,
            body=self.user_data_body,
            content_type="application/json",
        )

        self.backend.user_data("foobar")

        request = responses.calls[-1].request
        self.assertEqual(request.headers["Authorization"], "Bearer foobar")
        self.assertEqual(request.headers["CB-VERSION"], API_VERSION)

    def test_user_data_api_version_can_be_overridden(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_COINBASE_API_VERSION": "2026-01-01"})
        responses.add(
            responses.GET,
            self.backend.USER_DATA_URL,
            body=self.user_data_body,
            content_type="application/json",
        )

        self.backend.user_data("foobar")

        self.assertEqual(
            responses.calls[-1].request.headers["CB-VERSION"], "2026-01-01"
        )

    def test_revoke_token_sends_required_parameters_in_body(self) -> None:
        responses.add(responses.POST, self.backend.REVOKE_TOKEN_URL, status=200)

        revoked = self.backend.revoke_token("foobar", "uid")

        request = responses.calls[-1].request
        request_data = parse_qs(request.body)
        self.assertTrue(revoked)
        self.assertEqual(request.url, self.backend.REVOKE_TOKEN_URL)
        self.assertEqual(
            request_data,
            {
                "token": "foobar",
                "client_id": "a-key",
                "client_secret": "a-secret-key",
            },
        )

    def test_revoke_token_can_be_disabled(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_COINBASE_REVOKE_TOKEN_URL": ""})

        self.assertIsNone(self.backend.revoke_token("foobar", "uid"))
        self.assertEqual(len(responses.calls), 0)
