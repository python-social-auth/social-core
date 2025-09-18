"""
Discogs OAuth1 backend, docs at:
    https://www.discogs.com/developers/
"""

from social_core.backends.oauth import BaseOAuth1


class DiscogsOAuth1(BaseOAuth1):
    """
    Implements the OAuth1 authentication mechanism for https://www.discogs.com
    """

    name = "discogs"

    OAUTH_TOKEN_PARAMETER_NAME = "oauth_token"

    AUTHORIZATION_URL = "https://www.discogs.com/oauth/authorize"
    REQUEST_TOKEN_URL = "https://api.discogs.com/oauth/request_token"
    ACCESS_TOKEN_URL = "https://api.discogs.com/oauth/access_token"

    def get_user_details(self, user_data):  # type: ignore[reportIncompatibleMethodOverride]
        return {
            "username": user_data["username"],
            "id": user_data["id"],
            "profile": user_data["profile"],
            "name": user_data["name"],
        }

    def user_data(self, access_token, *args, **kwargs):
        identity = self.get_json(
            "https://api.discogs.com/oauth/identity", auth=self.oauth_auth(access_token)
        )

        return self.get_json(
            identity["resource_url"], auth=self.oauth_auth(access_token)
        )
