from social_core.backends.open_id_connect import OpenIdConnectAuth


class Auth0OpenIdConnectAuth(OpenIdConnectAuth):
    """
    Auth0 OpenID Connect authentication backend.

    Uses Auth0's OpenID Connect implementation with automatic endpoint discovery.

    Settings:
        SOCIAL_AUTH_AUTH0_OPENIDCONNECT_DOMAIN = 'your-domain.auth0.com'
        SOCIAL_AUTH_AUTH0_OPENIDCONNECT_KEY = '<client_id>'
        SOCIAL_AUTH_AUTH0_OPENIDCONNECT_SECRET = '<client_secret>'
    """

    name = "auth0_openidconnect"
    USERNAME_KEY = "nickname"
    EXTRA_DATA = ["id_token", "refresh_token", ("sub", "id"), "picture"]

    def api_path(self, path=""):
        """Build API path for Auth0 domain"""
        return "https://{domain}/{path}".format(
            domain=self.setting("DOMAIN"), path=path.lstrip("/")
        )

    def oidc_endpoint(self) -> str:
        """Override to use Auth0 domain instead of OIDC_ENDPOINT setting"""
        return self.api_path("")

    def get_user_id(self, details, response):
        """Return current user id."""
        return details["user_id"]

    def get_user_details(self, response):
        """Extract user details from Auth0 response"""
        details = super().get_user_details(response)
        # Auth0 specific extra data
        details.update(
            {
                "email_verified": response.get("email_verified", False),
                "picture": response.get("picture"),
                "locale": response.get("locale"),
                "user_id": response.get("sub"),
            }
        )

        return details
