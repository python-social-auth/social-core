from urllib.parse import urlparse

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthMissingParameter


class Auth0OpenIdConnectAuth(OpenIdConnectAuth):
    """
    Auth0 OpenID Connect authentication backend.

    Uses Auth0's OpenID Connect implementation with automatic endpoint discovery
    based on the domain.

    Settings:
        SOCIAL_AUTH_AUTH0_OPENIDCONNECT_DOMAIN = 'your-domain.auth0.com'
        SOCIAL_AUTH_AUTH0_OPENIDCONNECT_KEY = '<client_id>'
        SOCIAL_AUTH_AUTH0_OPENIDCONNECT_SECRET = '<client_secret>'
    """

    name = "auth0_openidconnect"
    USERNAME_KEY = "nickname"
    EXTRA_DATA = ["id_token", "refresh_token", ("sub", "id"), "picture"]

    def normalized_domain(self) -> str:
        """Return Auth0 domain without scheme or surrounding slashes."""
        domain = self.setting("DOMAIN")
        if not domain:
            raise AuthMissingParameter(self, "DOMAIN")

        domain = domain.strip()
        parsed = urlparse(domain)
        if parsed.netloc:
            domain = parsed.netloc

        domain = domain.strip("/")
        if not domain:
            raise AuthMissingParameter(self, "DOMAIN")
        return domain

    def api_path(self, path="") -> str:
        """Build API path for Auth0 domain"""
        base_url = f"https://{self.normalized_domain()}"
        path = path.strip("/")
        if path:
            return f"{base_url}/{path}"
        return base_url

    def oidc_endpoint(self) -> str:
        """Return Auth0 OpenID Connect endpoint without trailing slash."""
        return self.api_path()

    def get_user_id(self, details, response):
        """Return current user id."""
        if self.id_token is not None and self.id_token.get("sub") is not None:
            return self.id_token["sub"]
        return details["user_id"]

    def get_user_details(self, response):
        """Extract user details from Auth0 response"""
        details = super().get_user_details(response)
        user_id = response.get("sub")
        if self.id_token is not None and self.id_token.get("sub") is not None:
            user_id = self.id_token["sub"]

        # Auth0 specific extra data
        details.update(
            {
                "email_verified": response.get("email_verified", False),
                "picture": response.get("picture"),
                "locale": response.get("locale"),
                "user_id": user_id,
            }
        )

        return details
