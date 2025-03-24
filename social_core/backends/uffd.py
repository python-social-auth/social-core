from typing import Any
from urllib.parse import urlencode

from .oauth import BaseOAuth2


class UffdOAuth2(BaseOAuth2):
    """Uffd OAuth2 authentication backend

    You need to set the following config:
    SOCIAL_AUTH_UFFD_KEY - client id
    SOCIAL_AUTH_UFFD_SECRET - client secret
    SOCIAL_AUTH_UFFD_BASE_URL - base url to uffd installation
    """

    name = "uffd"
    REFRESH_TOKEN_METHOD = "POST"
    SCOPE_SEPARATOR = " "
    STATE_PARAMETER = True
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("id", "id"),
    ]

    def get_user_details(self, response):
        """Return user details from a Uffd account"""
        fullname, first_name, last_name = self.get_user_names(
            fullname=response.get("name")
        )
        return {
            "username": response.get("nickname"),
            "email": response.get("email") or "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = self.userinfo_url() + "?" + urlencode({"access_token": access_token})
        try:
            user_data: dict[str, Any] = self.get_json(url)
        except ValueError:
            return None
        return user_data

    def authorization_url(self):
        return self.setting("BASE_URL") + "/oauth2/authorize"

    def access_token_url(self):
        return self.setting("BASE_URL") + "/oauth2/token"

    def userinfo_url(self):
        return self.setting("BASE_URL") + "/oauth2/userinfo"
