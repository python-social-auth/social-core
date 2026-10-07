from __future__ import annotations

from urllib.parse import urljoin

from social_core.exceptions import AuthConfigurationError
from social_core.utils import append_slash

from .open_id_connect import OpenIdConnectAuth


class Fence(OpenIdConnectAuth):
    name = "fence"
    title = "Fence"
    OIDC_ENDPOINT = "https://nci-crdc.datacommons.io"
    ID_KEY = "sub"
    LEGACY_ID_KEYS = ("username",)
    MUTABLE_ID_KEYS = ("username", "preferred_username", "email")
    EXTRA_DATA = [*(OpenIdConnectAuth.EXTRA_DATA or []), ("sub", "sub")]
    DEFAULT_SCOPE = ["openid", "user"]
    VALIDATE_AT_HASH: bool = False

    def _url(self, path):
        endpoint = self.OIDC_ENDPOINT
        if endpoint is None:
            raise AuthConfigurationError(
                self, code="missing_setting", parameter="OIDC_ENDPOINT"
            )
        return urljoin(append_slash(endpoint), path)

    def authorization_url(self):
        return self._url("user/oauth2/authorize")

    def access_token_url(self):
        return self._url("user/oauth2/token")

    def oidc_config_url(self) -> str:
        return self._url(".well-known/openid-configuration")

    def get_user_details(self, response):
        return {
            "username": response.get("preferred_username"),
            "email": response.get("username"),
            "fullname": response.get("name"),
            "first_name": response.get("given_name"),
            "last_name": response.get("family_name"),
        }
