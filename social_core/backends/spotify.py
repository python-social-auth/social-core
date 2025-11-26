"""
Spotify backend, docs at:
    https://developer.spotify.com/spotify-web-api/
    https://developer.spotify.com/spotify-web-api/authorization-guide/
"""

from typing import Any

from .oauth import BaseOAuth2


class SpotifyOAuth2(BaseOAuth2):
    """Spotify OAuth2 authentication backend"""

    name = "spotify"
    ID_KEY = "id"
    AUTHORIZATION_URL = "https://accounts.spotify.com/authorize"
    ACCESS_TOKEN_URL = "https://accounts.spotify.com/api/token"
    SCOPE_SEPARATOR = " "
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("refresh_token", "refresh_token"),
    ]

    def auth_headers(self):
        return {"Authorization": self.get_key_and_secret_basic_auth()}

    def get_user_details(self, response):
        """Return user details from Spotify account"""
        fullname, first_name, last_name = self.get_user_names(
            response.get("display_name")
        )
        return {
            "username": response.get("id"),
            "email": response.get("email"),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        return self.get_json(
            "https://api.spotify.com/v1/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
