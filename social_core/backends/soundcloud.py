"""
Soundcloud OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/soundcloud.html
"""

from typing import Any

from social_core.utils import url_add_parameters

from .oauth import BaseOAuth2


class SoundcloudOAuth2(BaseOAuth2):
    """Soundcloud OAuth authentication backend"""

    name = "soundcloud"
    title = "SoundCloud"
    AUTHORIZATION_URL = "https://soundcloud.com/connect"
    ACCESS_TOKEN_URL = "https://api.soundcloud.com/oauth2/token"
    SCOPE_SEPARATOR = ","
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("id", "id"),
        ("refresh_token", "refresh_token"),
        ("expires", "expires"),
    ]

    def get_user_details(self, response):
        """Return user details from Soundcloud account"""
        fullname = response.get("full_name")
        first_name = None
        last_name = None
        return {
            "username": response.get("username"),
            "email": response.get("email") or "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        return self.get_json(
            "https://api.soundcloud.com/me",
            headers={"Authorization": f"OAuth {access_token}"},
            params={"format": "json"},
        )

    def auth_url(self):
        """Return redirect url"""
        state = self.get_or_create_state()

        params = self.auth_params(state)
        params.update(self.get_scope_argument())
        params.update(self.auth_extra_arguments())
        return url_add_parameters(self.authorization_url(), params, True)
