"""
Mixcloud OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/mixcloud.html
"""

from typing import Any

from .oauth import BaseOAuth2


class MixcloudOAuth2(BaseOAuth2):
    name = "mixcloud"
    title = "Mixcloud"
    ID_KEY = "username"
    AUTHORIZATION_URL = "https://www.mixcloud.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://www.mixcloud.com/oauth/access_token"

    def get_user_details(self, response):
        fullname = response["name"]
        first_name = ""
        last_name = ""
        return {
            "username": response["username"],
            "email": None,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        return self.get_json(
            "https://api.mixcloud.com/me/",
            params={"access_token": access_token, "alt": "json"},
        )
