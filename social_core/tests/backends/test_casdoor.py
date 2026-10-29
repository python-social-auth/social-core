from __future__ import annotations

import json
from urllib.parse import urlsplit

import responses

from social_core.backends.casdoor import CasdoorOpenIdConnect
from social_core.utils import parse_qs

from .open_id_connect import OpenIdConnectTest

ROOT_URL = "https://door.example.com"


class CasdoorOpenIdConnectTest(OpenIdConnectTest[CasdoorOpenIdConnect]):
    backend_path = "social_core.backends.casdoor.CasdoorOpenIdConnect"
    issuer = ROOT_URL
    user_data_url = f"{ROOT_URL}/api/userinfo"
    expected_username = "alice"
    openid_config_body = json.dumps(
        {
            "issuer": ROOT_URL,
            "authorization_endpoint": f"{ROOT_URL}/login/oauth/authorize",
            "token_endpoint": f"{ROOT_URL}/api/login/oauth/access_token",
            "userinfo_endpoint": user_data_url,
            "jwks_uri": f"{ROOT_URL}/.well-known/jwks",
            "response_types_supported": ["code", "token", "id_token"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "email", "profile"],
            "code_challenge_methods_supported": ["S256"],
        }
    )
    # Casdoor sends the username as preferred_username and the display
    # name as name
    user_data_body = json.dumps(
        {
            "sub": "1234",
            "iss": ROOT_URL,
            "aud": "a-key",
            "preferred_username": expected_username,
            "name": "Alice Example",
            "email": "alice@example.com",
            "email_verified": True,
        }
    )

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update({f"SOCIAL_AUTH_{self.name}_OIDC_ENDPOINT": ROOT_URL})
        return settings

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual(user.social[0].uid, "1234")
        self.assertEqual(user.email, "alice@example.com")

    def auth_and_token_params(self) -> tuple[dict, dict]:
        authorization = next(
            call.request
            for call in responses.calls
            if urlsplit(call.request.url).path == "/login/oauth/authorize"
        )
        token_request = next(
            call.request
            for call in responses.calls
            if urlsplit(call.request.url).path == "/api/login/oauth/access_token"
        )
        return (
            parse_qs(urlsplit(authorization.url).query),
            parse_qs(token_request.body),
        )

    def test_login_with_pkce(self) -> None:
        self.do_login()
        params, token_params = self.auth_and_token_params()
        self.assertEqual(params["code_challenge_method"], "S256")
        self.assertEqual(
            self.backend.generate_code_challenge(token_params["code_verifier"], "S256"),
            params["code_challenge"],
        )

    def test_pkce_can_be_disabled_by_setting(self) -> None:
        self.strategy.set_settings(
            {**self.extra_settings(), "SOCIAL_AUTH_CASDOOR_USE_PKCE": False}
        )
        self.do_login()
        params, token_params = self.auth_and_token_params()
        self.assertNotIn("code_challenge", params)
        self.assertNotIn("code_verifier", token_params)

    def test_user_details(self) -> None:
        assert self.user_data_body is not None
        details = self.backend.get_user_details(json.loads(self.user_data_body))
        self.assertEqual(details["username"], "alice")
        self.assertEqual(details["fullname"], "Alice Example")
        self.assertEqual(details["email"], "alice@example.com")

    def test_endpoint_with_trailing_slash(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_CASDOOR_OIDC_ENDPOINT": f"{ROOT_URL}/"}
        )
        self.assertEqual(self.backend.oidc_endpoint(), ROOT_URL)
        self.assertEqual(
            self.backend.oidc_config_url(),
            f"{ROOT_URL}/.well-known/openid-configuration",
        )
        self.assertEqual(
            self.backend.authorization_url(), f"{ROOT_URL}/login/oauth/authorize"
        )
        self.assertEqual(self.backend.id_token_issuer(), ROOT_URL)
