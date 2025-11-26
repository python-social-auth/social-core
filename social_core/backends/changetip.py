from typing import Any

from .oauth import BaseOAuth2


class ChangeTipOAuth2(BaseOAuth2):
    """ChangeTip OAuth authentication backend
    https://www.changetip.com/api
    """

    name = "changetip"
    AUTHORIZATION_URL = "https://www.changetip.com/o/authorize/"
    ACCESS_TOKEN_URL = "https://www.changetip.com/o/token/"
    SCOPE_SEPARATOR = " "

    def get_user_details(self, response):
        """Return user details from ChangeTip account"""
        return {
            "username": response["username"],
            "email": response.get("email", ""),
            "first_name": "",
            "last_name": "",
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        return self.get_json(
            "https://api.changetip.com/v2/me/", params={"access_token": access_token}
        )
