"""
LoginRadius BaseOAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/loginradius.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from .oauth import BaseOAuth2

if TYPE_CHECKING:
    from collections.abc import Mapping

    from requests.auth import AuthBase


class LoginRadiusAuth(BaseOAuth2):
    """LoginRadius BaseOAuth2 authentication backend."""

    name = "loginradius"
    ID_KEY = "ID"
    ACCESS_TOKEN_URL = "https://api.loginradius.com/api/v2/access_token"
    PROFILE_URL = "https://api.loginradius.com/api/v2/userprofile"
    REDIRECT_STATE = False
    STATE_PARAMETER = False

    def uses_redirect(self) -> bool:
        """Return False because we return HTML instead."""
        return False

    def auth_html(self):
        key, _secret = self.get_key_and_secret()
        tpl = self.setting("TEMPLATE", "loginradius.html")
        return self.strategy.render_html(
            tpl=tpl,
            context={
                "backend": self,
                "LOGINRADIUS_KEY": key,
                "LOGINRADIUS_REDIRECT_URL": self.get_redirect_uri(),
            },
        )

    def request_access_token(
        self,
        url: str,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | bytes | str | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
    ) -> dict[Any, Any]:
        return super().request_access_token(
            url,
            method,
            headers,
            data,
            auth,
            {
                "token": self.data.get("token"),
                "secret": self.setting("SECRET"),
            },
        )

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service. Implement in subclass."""
        return self.get_json(
            self.PROFILE_URL,
            params={"access_token": access_token},
            data=self.auth_complete_params(self.validate_state()),
            headers=self.auth_headers(),
            method="GET",
        )

    def get_user_details(self, response):
        """Must return user details in a know internal struct:
        {'username': <username if any>,
         'email': <user email if any>,
         'fullname': <user full name if any>,
         'first_name': <user first name if any>,
         'last_name': <user last name if any>}
        """
        return {
            "username": response["NickName"] or "",
            "email": response["Email"][0]["Value"] or "",
            "fullname": response["FullName"] or "",
            "first_name": response["FirstName"] or "",
            "last_name": response["LastName"] or "",
        }

    def get_user_id(self, details, response):
        """Return a unique ID for the current user, by default from server
        response. Since LoginRadius handles multiple providers, we need to
        distinguish them to prevent conflicts."""
        return "{}-{}".format(response.get("Provider"), response.get(self.ID_KEY))
