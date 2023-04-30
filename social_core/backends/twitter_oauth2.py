"""
Twitter OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/twitter-oauth2.html
    https://developer.twitter.com/en/docs/authentication/oauth-2-0/authorization-code
"""

from .oauth import BaseOAuth2


class TwitterOAuth2(BaseOAuth2):
    """Twitter OAuth2 authentication backend"""

    name = "twitter-oauth2"
    AUTHORIZATION_URL = "https://twitter.com/i/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
    ACCESS_TOKEN_METHOD = "POST"
    DEFAULT_SCOPE = ["users.read"]
    SCOPE_SEPARATOR = ","
    REDIRECT_STATE = True
    STATE_PARAMETER = True
    EXTRA_DATA = [
        ("id", "id"),
        ("username", "username"),
        ("fullname", "fullname"),
        ("first_name", "first_name"),
        ("last_name", "last_name"),
        ("created_at", "created_at"),
    ]

    def get_user_details(self, response):
        """Return user details from Twitter account"""
        user = response["data"]
        user_id = user["id"]
        name = user["name"]
        username = user["username"]
        created_at = user["created_at"]

        fullname, first_name, last_name = self.get_user_names(name)

        return {
            "id": user_id,
            "username": username,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "created_at": created_at,
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        response = self.get_json(
            "https://api.twitter.com/2/users/me",
            params={"user.fields": "created_at"},
            headers={"Authorization": "Bearer %s" % access_token},
        )
        return response
