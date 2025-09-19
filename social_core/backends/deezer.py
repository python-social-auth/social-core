"""
Deezer backend, docs at:
    https://developers.deezer.com/api/oauth
    https://developers.deezer.com/api/permissions
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import parse_qsl

from social_core.utils import wrap_access_token_error

from .oauth import BaseOAuth2

if TYPE_CHECKING:
    from collections.abc import Mapping

    from requests.auth import AuthBase


class DeezerOAuth2(BaseOAuth2):
    """Deezer OAuth2 authentication backend"""

    name = "deezer"
    ID_KEY = "name"
    AUTHORIZATION_URL = "https://connect.deezer.com/oauth/auth.php"
    ACCESS_TOKEN_URL = "https://connect.deezer.com/oauth/access_token.php"
    SCOPE_SEPARATOR = ","
    REDIRECT_STATE = False

    def auth_complete_params(self, state=None):
        client_id, client_secret = self.get_key_and_secret()
        return {
            "app_id": client_id,
            "secret": client_secret,
            "code": self.data.get("code"),
        }

    def request_access_token(
        self,
        url: str,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | bytes | str | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
    ) -> dict[Any, Any]:
        with wrap_access_token_error(self):
            response = self.request(
                url, method=method, headers=headers, data=data, auth=auth, params=params
            )
        return dict(parse_qsl(response.text))

    def get_user_details(self, response):
        """Return user details from Deezer account"""
        fullname, first_name, last_name = self.get_user_names(
            first_name=response.get("firstname"), last_name=response.get("lastname")
        )
        return {
            "username": response.get("name"),
            "email": response.get("email"),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json(
            "http://api.deezer.com/user/me", params={"access_token": access_token}
        )
