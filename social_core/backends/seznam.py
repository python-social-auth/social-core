"""
Seznam OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/seznam.html
"""

from typing import Any

from .oauth import BaseOAuth2


class SeznamOAuth2(BaseOAuth2):
    """Seznam OAuth authentication backend"""

    name = "seznam-oauth2"
    API_URL = "https://login.szn.cz/api/v1/user"
    AUTHORIZATION_URL = "https://login.szn.cz/api/v1/oauth/auth"
    ACCESS_TOKEN_URL = "https://login.szn.cz/api/v1/oauth/token"
    ID_KEY = "oauth_user_id"
    STATE_PARAMETER = True
    DEFAULT_SCOPE = ["identity"]

    def api_url(self):
        return self.setting("API_URL") or self.API_URL

    def get_user_details(self, response):
        """Return user details from Seznam account"""
        fullname, first_name, last_name = self.get_user_names(
            response.get("name"),
            first_name=response.get("firstname"),
            last_name=response.get("lastname"),
        )
        return {
            "username": response.get("username"),
            "email": response.get("email") or "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        return self.get_json(
            self.api_url(), headers={"Authorization": f"bearer {access_token}"}
        )
