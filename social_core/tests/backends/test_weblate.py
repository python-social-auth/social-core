from __future__ import annotations

import json
from urllib.parse import urlsplit

import responses

from social_core.backends.weblate import WeblateOpenIdConnect
from social_core.utils import parse_qs

from .open_id_connect import OpenIdConnectTest


class WeblateOpenIdConnectTest(OpenIdConnectTest[WeblateOpenIdConnect]):
    backend_path = "social_core.backends.weblate.WeblateOpenIdConnect"
    issuer = "https://hosted.weblate.org/oidc"
    user_data_url = f"{issuer}/userinfo/"
    expected_username = "translator"
    openid_config_body = json.dumps(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize/",
            "token_endpoint": f"{issuer}/token/",
            "userinfo_endpoint": user_data_url,
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["S256"],
        }
    )
    user_data_body = json.dumps(
        {
            "sub": "1234",
            "preferred_username": expected_username,
            "name": "Example Translator",
            "family_name": "Example Translator",
            "email": "translator@example.com",
            "email_verified": True,
        }
    )

    def test_login_with_pkce(self) -> None:
        user = self.do_login()
        self.assertEqual(user.social[0].uid, "1234")
        self.assertEqual(user.email, "translator@example.com")
        authorization = next(
            call.request
            for call in responses.calls
            if urlsplit(call.request.url).path == "/oidc/authorize/"
        )
        params = parse_qs(urlsplit(authorization.url).query)
        self.assertEqual(params["code_challenge_method"], "S256")
        self.assertCountEqual(params["scope"].split(), ["openid", "profile", "email"])
        token_request = next(
            call.request
            for call in responses.calls
            if urlsplit(call.request.url).path == "/oidc/token/"
        )
        verifier = parse_qs(token_request.body)["code_verifier"]
        self.assertEqual(
            self.backend.generate_code_challenge(verifier, "S256"),
            params["code_challenge"],
        )

    def test_details_and_stable_identifier(self) -> None:
        assert self.user_data_body is not None
        response = json.loads(self.user_data_body)
        details = self.backend.get_user_details(response)
        self.assertEqual(details["username"], "translator")
        self.assertEqual(details["fullname"], "Example Translator")
        self.assertEqual(details["last_name"], "Example Translator")
        response.update(preferred_username="renamed", email="changed@example.com")
        self.assertEqual(self.backend.get_user_id(details, response), "1234")

    def test_titles_without_discovery(self) -> None:
        self.assertEqual(self.backend.get_title(self.strategy), "Hosted Weblate")
        for endpoint, title in (
            ("https://hosted.weblate.org/oidc/", "Hosted Weblate"),
            ("https://HOSTED.WEBLATE.ORG/oidc", "Hosted Weblate"),
            ("https://weblate.example.com/prefix/oidc/", "Weblate"),
            ("https://hosted.weblate.org.example.com/oidc", "Weblate"),
            ("https://hosted.weblate.org@other.example.com/oidc", "Weblate"),
        ):
            with self.subTest(endpoint=endpoint):
                self.strategy.set_settings(
                    {"SOCIAL_AUTH_WEBLATE_OIDC_ENDPOINT": endpoint}
                )
                self.assertEqual(self.backend.get_title(self.strategy), title)
                self.assertEqual(self.backend.oidc_endpoint(), endpoint.rstrip("/"))
        self.assertEqual(len(responses.calls), 0)

    def test_global_endpoint_setting(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_OIDC_ENDPOINT": "https://global.example.com/oidc"}
        )
        self.assertEqual(self.backend.get_title(self.strategy), "Weblate")
        self.strategy.set_settings({"SOCIAL_AUTH_WEBLATE_OIDC_ENDPOINT": self.issuer})
        self.assertEqual(self.backend.get_title(self.strategy), "Hosted Weblate")

    def test_custom_discovery(self) -> None:
        endpoint = "https://weblate.example.com/prefix/oidc"
        self.strategy.set_settings(
            {"SOCIAL_AUTH_WEBLATE_OIDC_ENDPOINT": f"{endpoint}/"}
        )
        config = {
            key: value.replace(self.issuer, endpoint)
            if isinstance(value, str)
            else value
            for key, value in json.loads(self.openid_config_body).items()
        }
        responses.add(
            responses.GET,
            f"{endpoint}/.well-known/openid-configuration",
            json=config,
        )
        self.assertEqual(self.backend.authorization_url(), f"{endpoint}/authorize/")
        self.assertEqual(self.backend.access_token_url(), f"{endpoint}/token/")
        self.assertEqual(self.backend.userinfo_url(), f"{endpoint}/userinfo/")
        self.assertEqual(self.backend.id_token_issuer(), endpoint)

    def test_legal_version_opt_in(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WEBLATE_SCOPE": ["weblate:legal"]})
        assert self.user_data_body is not None
        response = json.loads(self.user_data_body)
        response["weblate_tos_version"] = "2026-09-01"
        self.user_data_body = json.dumps(response)
        user = self.do_login()
        self.assertEqual(user.social[0].extra_data["weblate_tos_version"], "2026-09-01")
        self.assertIn("weblate:legal", self.backend.get_scope())

    def test_missing_legal_version(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_WEBLATE_SCOPE": ["weblate:legal"]})
        user = self.do_login()
        self.assertNotIn("weblate_tos_version", user.social[0].extra_data)
