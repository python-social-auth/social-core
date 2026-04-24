"""Douban OAuth2 backend."""

from typing import Any

from .oauth import BaseOAuth2


class DoubanOAuth2(BaseOAuth2):
    """Douban OAuth authentication backend"""

    name = "douban-oauth2"
    AUTHORIZATION_URL = "https://www.douban.com/service/auth2/auth"
    ACCESS_TOKEN_URL = "https://www.douban.com/service/auth2/token"
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("id", "id"),
        ("uid", "username"),
        ("refresh_token", "refresh_token"),
    ]

    def get_user_details(self, response):
        """Return user details from Douban"""
        fullname, first_name, last_name = self.get_user_names(response.get("name", ""))
        return {
            "username": response.get("uid", ""),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "email": "",
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data provided"""
        return self.get_json(
            "https://api.douban.com/v2/user/~me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
