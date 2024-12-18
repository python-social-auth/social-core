"""
OpenStreetMap OAuth 2.0 support.

This adds support for OpenStreetMap OAuth service. An application must be
registered first on OpenStreetMap and the settings
SOCIAL_AUTH_OPENSTREETMAP_OAUTH2_KEY and SOCIAL_AUTH_OPENSTREETMAP_OAUTH2_SECRET
must be defined with the corresponding values.

More info: https://wiki.openstreetmap.org/wiki/OAuth
"""

from .oauth import BaseOAuth2PKCE


class OpenStreetMapOAuth2(BaseOAuth2PKCE):
    """OpenStreetMap OAuth2 authentication backend"""

    name = "openstreetmap-oauth2"
    AUTHORIZATION_URL = "https://www.openstreetmap.org/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://www.openstreetmap.org/oauth2/token"
    ACCESS_TOKEN_METHOD = "POST"
    SCOPE_SEPARATOR = " "
    STATE_PARAMETER = True
    DEFAULT_SCOPE = ["read_prefs"]
    EXTRA_DATA = [
        ("id", "id"),
        ("avatar", "avatar"),
        ("account_created", "account_created"),
    ]
    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = "S256"
    DEFAULT_USE_PKCE = True

    def get_user_details(self, response):
        """Return user details from OpenStreetMap account"""
        return {
            "username": response["username"],
            "email": "",
            "fullname": "",
            "first_name": "",
            "last_name": "",
        }

    def user_data(self, access_token, *args, **kwargs):
        """Return user data provided"""

        headers = {"Authorization": f"Bearer {access_token}"}
        response = self.get_json(
            url="https://api.openstreetmap.org/api/0.6/user/details.json",
            headers=headers,
        )

        return {
            "id": response["user"]["id"],
            "username": response["user"]["display_name"],
            "account_created": response["user"]["account_created"],
            "avatar": response["user"].get("img", {}).get("href"),
        }
