from __future__ import annotations

import json

import responses

from social_core.backends.open_id_connect import OpenIdConnectAuth

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest


class BaseOpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.open_id_connect.OpenIdConnectAuth"
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {
                "SOCIAL_AUTH_OIDC_OIDC_ENDPOINT": "https://example.com/oidc",
            }
        )
        return settings

    def pre_complete_callback(self, start_url):
        super().pre_complete_callback(start_url)
        responses.add(
            "GET",
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self):
        self.do_login()


class ExampleOpenIdConnectAuth(OpenIdConnectAuth):
    name = "example123"
    OIDC_ENDPOINT = "https://example.com/oidc"


class ExampleOpenIdConnectTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.ExampleOpenIdConnectAuth"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url):
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self):
        self.do_login()
