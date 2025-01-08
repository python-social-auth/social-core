# pyright: reportAttributeAccessIssue=false

import json

from httpretty import HTTPretty

from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .test_open_id_connect import OpenIdConnectTestMixin

ROOT_URL = "https://vault.example.net:8200/"


class VaultOpenIdConnectTest(OpenIdConnectTestMixin, OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.vault.VaultOpenIdConnect"
    issuer = f"{ROOT_URL}v1/identity/oidc/provider/default"
    openid_config_body = json.dumps(
        {
            "issuer": f"{ROOT_URL}v1/identity/oidc/provider/default",
            "jwks_uri": f"{ROOT_URL}v1/identity/oidc/provider/default/.well-known/keys",
            "authorization_endpoint": f"{ROOT_URL}ui/vault/identity/oidc/provider/default/authorize",
            "token_endpoint": f"{ROOT_URL}v1/identity/oidc/provider/default/token",
            "userinfo_endpoint": f"{ROOT_URL}v1/identity/oidc/provider/default/userinfo",
            "request_uri_parameter_supported": False,
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }
    )

    expected_username = "cartman"

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {
                f"SOCIAL_AUTH_{self.name}_OIDC_ENDPOINT": f"{ROOT_URL}v1/identity/oidc/provider/default",
            }
        )
        return settings

    def pre_complete_callback(self, start_url):
        super().pre_complete_callback(start_url)
        HTTPretty.register_uri(
            "GET",
            uri=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self):
        self.do_login()
