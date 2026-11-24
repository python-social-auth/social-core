"""
Gitea OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/gitea.html
"""

from __future__ import annotations

from typing import Any

from social_core.backends.base import ResponseT_co
from social_core.exceptions import (
    AuthProviderError,
    AuthResponseError,
    SocialAuthBaseException,
)

from .oauth import BaseOAuth2


class GiteaOAuth2(BaseOAuth2[ResponseT_co]):
    """Gitea OAuth authentication backend"""

    name = "gitea"
    title = "Gitea"
    API_URL = "https://gitea.com"
    AUTHORIZATION_URL = "https://gitea.com/login/oauth/authorize"
    ACCESS_TOKEN_URL = "https://gitea.com/login/oauth/access_token"
    SCOPE_SEPARATOR = ","
    REDIRECT_STATE = False
    STATE_PARAMETER = True
    EXTRA_DATA = [
        ("id", "id"),
        ("expires_in", "expires_in"),
        ("refresh_token", "refresh_token"),
    ]

    def api_url(self, path) -> str:
        api_url = self.setting("API_URL") or self.API_URL
        return f"{api_url.rstrip('/')}{path}"

    def authorization_url(self):
        return self.api_url("/login/oauth/authorize")

    def access_token_url(self):
        return self.api_url("/login/oauth/access_token")

    def get_user_details(self, response):
        """Return user details from Gitea account"""
        fullname = response.get("fullname")
        first_name = None
        last_name = None
        return {
            "username": response.get("login"),
            "email": response.get("email") or "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        data = self._user_data(access_token)

        try:
            emails = self._user_data(access_token, "/emails")
        except (AuthProviderError, AuthResponseError):
            emails = []
        except SocialAuthBaseException:
            raise
        except (ValueError, TypeError):
            emails = []
        else:
            data["emails"] = emails

        if emails:
            email = emails[0]
            primary_emails = [
                e for e in emails if not isinstance(e, dict) or e.get("primary")
            ]
            if primary_emails:
                email = primary_emails[0]
            data["email"] = email["email"]
        return data

    def _user_data(self, access_token, path=None):
        return self.get_json(
            self.api_url(f"/api/v1/user{path or ''}"),
            headers={"Authorization": f"Bearer {access_token}"},
        )
