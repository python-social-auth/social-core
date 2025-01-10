# pyright: reportAttributeAccessIssue=false

import json

from httpretty import HTTPretty

from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .test_open_id_connect import OpenIdConnectTestMixin

ROOT_URL = "https://cas.example.net/"


class CASOpenIdConnectTest(OpenIdConnectTestMixin, OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.cas.CASOpenIdConnectAuth"
    issuer = f"{ROOT_URL}oidc"
    openid_config_body = json.dumps(
        {
            "issuer": f"{ROOT_URL}oidc",
            "jwks_uri": f"{ROOT_URL}oidc/jwks",
            "authorization_endpoint": f"{ROOT_URL}oidc/oidcAuthorize",
            "token_endpoint": f"{ROOT_URL}oidc/oidcAccessToken",
            "userinfo_endpoint": f"{ROOT_URL}oidc/oidcProfile",
            "request_uri_parameter_supported": False,
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }
    )

    expected_username = "cartman"

    user_data_body = json.dumps(
        {
            "sub": "Cartman",
            "service": "https://cas.example.net/complete/cas/",
            "auth_time": 1677057708,
            "attributes": {
                "name": "Eric",
                "groups": ["users", "admins"],
                "preferred_username": "cartman",
                "email": "cartman@example.net",
            },
            "id": "Cartman",
            "client_id": "dev",
        }
    )

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {
                f"SOCIAL_AUTH_{self.name}_OIDC_ENDPOINT": f"{ROOT_URL}oidc",
            }
        )
        return settings

    def pre_complete_callback(self, start_url):
        super().pre_complete_callback(start_url)
        HTTPretty.register_uri(
            "GET",
            uri=self.backend.userinfo_url(),
            status=200,
            body=self.user_data_body,
            content_type="text/json",
        )

    def test_everything_works(self):
        self.do_login()
