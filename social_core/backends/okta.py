"""
Okta OAuth2 and OpenIdConnect:
    https://python-social-auth.readthedocs.io/en/latest/backends/okta.html
"""

from urllib.parse import urljoin, urlparse, urlunparse

from social_core.utils import append_slash

from .oauth import BaseOAuth2


class OktaMixin(BaseOAuth2):
    def api_url(self):
        return append_slash(self.setting("API_URL"))

    def authorization_url(self):
        return self._url("v1/authorize")

    def access_token_url(self):
        return self._url("v1/token")

    def _url(self, path):
        return urljoin(append_slash(self.setting("API_URL")), path)

    def oidc_config_url(self):
        # https://developer.okta.com/docs/reference/api/oidc/#well-known-openid-configuration
        url = urlparse(self.api_url())

        # If the URL path does not contain an authorizedServerId, we need
        # to truncate the path in order to generate a proper openid-configuration
        # URL.
        if url.path == "/oauth2/":
            url = url._replace(path="")

        return urljoin(
            urlunparse(url),
            "./.well-known/openid-configuration?client_id={}".format(
                self.setting("KEY")
            ),
        )

    def oidc_config(self):
        return self.get_json(self.oidc_config_url())


class OktaOAuth2(OktaMixin, BaseOAuth2):
    """Okta OAuth authentication backend"""

    name = "okta-oauth2"
    REDIRECT_STATE = False
    SCOPE_SEPARATOR = " "
    ID_KEY = "preferred_username"

    DEFAULT_SCOPE = ["openid", "profile", "email"]
    EXTRA_DATA = [
        ("refresh_token", "refresh_token", True),
        ("expires_in", "expires"),
        ("token_type", "token_type", True),
    ]

    def get_user_details(self, response):
        """Return user details from Okta account"""
        return {
            "username": response.get("preferred_username"),
            "email": response.get("email") or "",
            "first_name": response.get("given_name"),
            "last_name": response.get("family_name"),
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from Okta"""
        return self.get_json(
            self._url("v1/userinfo"),
            headers={
                "Authorization": f"Bearer {access_token}",
            },
        )
