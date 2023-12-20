from social_core.backends.oauth import BaseOAuth2


class MusicBrainzOAuth2(BaseOAuth2):
    """MusicBrainz OAuth authentication backend"""

    name = "musicbrainz"
    AUTHORIZATION_URL = "https://musicbrainz.org/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://musicbrainz.org/oauth2/token"
    ACCESS_TOKEN_METHOD = "POST"
    ID_KEY = "metabrainz_user_id"
    DEFAULT_SCOPE = ["profile", "email"]
    SCOPE_SEPARATOR = " "
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("metabrainz_user_id", "id"),
        ("expires_in", "expires"),
    ]

    def get_user_details(self, response):
        """Return user details from MusicBrainz account"""
        return {
            "username": response.get("sub"),
            "email": response.get("email") or "",
            "first_name": response.get("sub"),
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json(
            "https://musicbrainz.org/oauth2/userinfo",
            params={"access_token": access_token},
        )
