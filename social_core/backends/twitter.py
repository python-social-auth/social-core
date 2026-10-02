"""
Twitter OAuth1 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/twitter.html
"""

from typing import Any

from social_core.exceptions import AuthCanceled, ErrorStage

from .oauth import BaseOAuth1


class TwitterOAuth(BaseOAuth1):
    """Twitter OAuth authentication backend"""

    name = "twitter"
    title = "X"
    icon = "x.svg"
    EXTRA_DATA = [("id", "id")]
    REQUEST_TOKEN_METHOD = "POST"
    AUTHORIZATION_URL = "https://api.twitter.com/oauth/authenticate"
    REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
    ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"
    REDIRECT_STATE = True

    def process_error(self, data, *, stage: ErrorStage = "callback") -> None:
        if "denied" in data:
            raise AuthCanceled(self, code="authorization_declined", stage=stage)
        super().process_error(data, stage=stage)

    def get_user_details(self, response):
        """Return user details from Twitter account"""
        fullname = response["name"]
        first_name = ""
        last_name = ""
        return {
            "username": response["screen_name"],
            "email": response.get("email", ""),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: dict, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data provided"""
        return self.get_json(
            "https://api.twitter.com/1.1/account/verify_credentials.json",
            params={"include_email": "true"},
            auth=self.oauth_auth(access_token, stage="user_info"),
        )
