from typing import Any

from .oauth import BaseOAuth2


class MineIDOAuth2(BaseOAuth2):
    """MineID OAuth2 authentication backend"""

    name = "mineid"
    AUTHORIZATION_URL = "{scheme}://{host}/oauth/authorize"
    ACCESS_TOKEN_URL = "{scheme}://{host}/oauth/access_token"
    SCOPE_SEPARATOR = ","
    EXTRA_DATA = []

    def get_user_details(self, response):
        """Return user details"""
        return {"email": response.get("email"), "username": response.get("email")}

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        return self._user_data(access_token)

    def _user_data(self, access_token, path=None):
        url = "{scheme}://{host}/api/user".format(**self.get_mineid_url_params())
        return self.get_json(url, params={"access_token": access_token})

    def get_authorization_url_format(self) -> dict[str, str]:
        return self.get_mineid_url_params()

    def get_access_token_url_format(self) -> dict[str, str]:
        return self.get_mineid_url_params()

    def get_mineid_url_params(self) -> dict[str, str]:
        return {
            "host": self.setting("HOST", "www.mineid.org"),
            "scheme": self.setting("SCHEME", "https"),
        }
