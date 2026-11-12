from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import responses

from social_core.backends.onelogin import OneLoginOpenIdConnect
from social_core.utils import parse_qs

from .open_id_connect import OpenIdConnectTest

if TYPE_CHECKING:
    from requests import PreparedRequest


class OneLoginOpenIdConnectTest(OpenIdConnectTest[OneLoginOpenIdConnect]):
    backend_path = "social_core.backends.onelogin.OneLoginOpenIdConnect"
    issuer = "https://example.onelogin.com/oidc/2"
    user_data_url = f"{issuer}/me"
    expected_username = "alice"
    openid_config_body = json.dumps(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/auth",
            "token_endpoint": f"{issuer}/token",
            "userinfo_endpoint": user_data_url,
            "jwks_uri": f"{issuer}/certs",
            "response_types_supported": ["code", "id_token token", "id_token"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["plain", "S256"],
        }
    )
    user_data_body = json.dumps(
        {
            "sub": "1234",
            "preferred_username": expected_username,
            "name": "Alice Example",
            "given_name": "Alice",
            "family_name": "Example",
            "email": "alice@example.com",
        }
    )

    def extra_settings(self) -> dict[str, Any]:
        return {
            **super().extra_settings(),
            "SOCIAL_AUTH_ONELOGIN_OIDC_ENDPOINT": self.issuer,
        }

    def auth_and_token_requests(self) -> tuple[PreparedRequest, PreparedRequest]:
        return (
            next(
                call.request
                for call in responses.calls
                if urlsplit(call.request.url).path == "/oidc/2/auth"
            ),
            next(
                call.request
                for call in responses.calls
                if urlsplit(call.request.url).path == "/oidc/2/token"
            ),
        )

    def test_login_with_pkce_and_post_authentication(self) -> None:
        user = self.do_login()
        self.assertEqual(user.social[0].uid, "1234")
        self.assertEqual(user.email, "alice@example.com")
        authorization, token_request = self.auth_and_token_requests()
        params = parse_qs(urlsplit(authorization.url).query)
        token_params = parse_qs(token_request.body)
        self.assertEqual(params["code_challenge_method"], "S256")
        self.assertEqual(
            self.backend.generate_code_challenge(token_params["code_verifier"], "S256"),
            params["code_challenge"],
        )
        self.assertCountEqual(params["scope"].split(), ["openid", "profile", "email"])
        self.assertEqual(token_request.method, "POST")
        self.assertNotIn("Authorization", token_request.headers)
        self.assertEqual(token_params["client_id"], self.client_key)
        self.assertEqual(token_params["client_secret"], self.client_secret)

    def test_pkce_can_be_disabled(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_ONELOGIN_USE_PKCE": False})
        self.do_login()
        authorization, token_request = self.auth_and_token_requests()
        self.assertNotIn("code_challenge", parse_qs(urlsplit(authorization.url).query))
        self.assertNotIn("code_verifier", parse_qs(token_request.body))

    def test_basic_authentication_override(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_ONELOGIN_TOKEN_ENDPOINT_AUTH_METHOD": "client_secret_basic"}
        )
        self.do_login()
        _, token_request = self.auth_and_token_requests()
        self.assertTrue(token_request.headers["Authorization"].startswith("Basic "))
        self.assertNotIn("client_secret", parse_qs(token_request.body))

    def test_endpoint_with_trailing_slash(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_ONELOGIN_OIDC_ENDPOINT": f"{self.issuer}/"}
        )
        self.assertEqual(self.backend.authorization_url(), f"{self.issuer}/auth")
        self.assertEqual(self.backend.access_token_url(), f"{self.issuer}/token")
        self.assertEqual(self.backend.userinfo_url(), self.user_data_url)
        self.assertEqual(self.backend.id_token_issuer(), self.issuer)

    def test_stable_identifier(self) -> None:
        assert self.user_data_body is not None
        response = json.loads(self.user_data_body)
        details = self.backend.get_user_details(response)
        self.assertEqual(details["first_name"], "Alice")
        self.assertEqual(details["last_name"], "Example")
        response.update(preferred_username="renamed", email="changed@example.com")
        self.assertEqual(self.backend.get_user_id(details, response), "1234")
