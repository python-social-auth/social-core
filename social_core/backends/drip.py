"""
Drip OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/drip.html
"""

from typing import Any

from .oauth import BaseOAuth2


class DripOAuth(BaseOAuth2):
    name = "drip"
    ID_KEY = "email"
    AUTHORIZATION_URL = "https://www.getdrip.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://www.getdrip.com/oauth/token"

    def get_user_id(self, details, response):
        id_key = self.id_key()
        users = response.get("users")
        user = users[0] if users else None
        return self.get_user_id_from_sources(user, details, id_key=id_key)

    def get_user_details(self, response):
        return {
            "email": response["users"][0]["email"],
            "fullname": response["users"][0]["name"],
            "username": response["users"][0]["email"],
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        return self.get_json(
            "https://api.getdrip.com/v2/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
