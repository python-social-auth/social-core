"""
Okta OAuth2 and OpenIdConnect:
    https://python-social-auth.readthedocs.io/en/latest/backends/okta.html
"""

from typing import Any, cast
from urllib.parse import urljoin, urlparse, urlunparse

from social_core.groups import configured_group_key, read_groups
from social_core.utils import append_slash

from .oauth import BaseOAuth2
from .utils import OIDCDiscoveryMixin


class OktaMixin(OIDCDiscoveryMixin, BaseOAuth2):
    def api_url(self) -> str:
        return append_slash(cast("str", self.setting("API_URL")))

    def authorization_url(self):
        return self._url("v1/authorize")

    def access_token_url(self):
        return self._url("v1/token")

    def _url(self, path):
        return urljoin(self.api_url(), path)

    def oidc_config_url(self) -> str:
        # https://developer.okta.com/docs/reference/api/oidc/#well-known-openid-configuration
        url = urlparse(self.api_url())

        # If the URL path does not contain an authorizedServerId, we need
        # to truncate the path in order to generate a proper openid-configuration
        # URL.
        if url.path == "/oauth2/":
            url = url._replace(path="")

        return urljoin(
            urlunparse(url),
            f"./.well-known/openid-configuration?client_id={self.setting('KEY')}",
        )


class OktaOAuth2(OktaMixin, BaseOAuth2):
    """Okta OAuth authentication backend"""

    name = "okta-oauth2"
    title = "Okta"
    REDIRECT_STATE = False
    SCOPE_SEPARATOR = " "
    ID_KEY = "sub"
    LEGACY_ID_KEYS = ("preferred_username",)
    MUTABLE_ID_KEYS = ("preferred_username",)

    DEFAULT_SCOPE = ["openid", "profile", "email"]
    EXTRA_DATA = [
        ("sub", "sub"),
        ("refresh_token", "refresh_token", True),
        ("expires_in", "expires_in"),
        ("token_type", "token_type", True),
    ]

    def get_user_groups(self, response) -> list[str] | None:
        key = configured_group_key(self)
        if key is None:
            return None
        return read_groups(
            self,
            response,
            key,
            missing_as_empty=self.setting("GROUPS_MISSING_AS_EMPTY", False),
        )

    def get_user_details(self, response):
        """Return user details from Okta account"""
        return {
            "username": response.get("preferred_username"),
            "email": response.get("email") or "",
            "first_name": response.get("given_name"),
            "last_name": response.get("family_name"),
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from Okta"""
        return self.get_json(
            self._url("v1/userinfo"),
            headers={
                "Authorization": f"Bearer {access_token}",
            },
        )
