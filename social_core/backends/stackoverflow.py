"""
Stackoverflow OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/stackoverflow.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from social_core.utils import parse_qs, wrap_access_token_error

from .oauth import BaseOAuth2

if TYPE_CHECKING:
    from collections.abc import Mapping

    from requests.auth import AuthBase


class StackoverflowOAuth2(BaseOAuth2):
    """Stackoverflow OAuth2 authentication backend"""

    name = "stackoverflow"
    ID_KEY = "user_id"
    AUTHORIZATION_URL = "https://stackexchange.com/oauth"
    ACCESS_TOKEN_URL = "https://stackexchange.com/oauth/access_token"
    SCOPE_SEPARATOR = ","
    EXTRA_DATA = [("id", "id"), ("expires", "expires")]

    def get_user_details(self, response):
        """Return user details from Stackoverflow account"""
        fullname, first_name, last_name = self.get_user_names(
            response.get("display_name")
        )
        return {
            "username": response.get("link").rsplit("/", 1)[-1],
            "full_name": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        return self.get_json(
            "https://api.stackexchange.com/2.1/me",
            params={
                "site": "stackoverflow",
                "access_token": access_token,
                "key": self.setting("API_KEY"),
            },
        )["items"][0]

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
        return parse_qs(response.content)
