"""
MapMyFitness OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/mapmyfitness.html
"""

from typing import Any

from .oauth import BaseOAuth2


class MapMyFitnessOAuth2(BaseOAuth2):
    """MapMyFitness OAuth authentication backend"""

    name = "mapmyfitness"
    title = "MapMyFitness"
    REQUIRES_USER_ID = True
    AUTHORIZATION_URL = "https://www.mapmyfitness.com/v7.0/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://oauth2-api.mapmyapi.com/v7.0/oauth2/access_token"
    REQUEST_TOKEN_METHOD = "POST"
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("refresh_token", "refresh_token"),
    ]

    def auth_headers(self):
        key = self.get_key_and_secret()[0]
        return {"Api-Key": key}

    def get_user_details(self, response):
        return {
            "username": response["username"],
            "email": response["email"],
            "fullname": None,
            "first_name": response.get("first_name"),
            "last_name": response.get("last_name"),
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        key = self.get_key_and_secret()[0]
        url = "https://oauth2-api.mapmyapi.com/v7.0/user/self/"
        headers = {"Authorization": f"Bearer {access_token}", "Api-Key": key}
        return self.get_json(url, headers=headers)
