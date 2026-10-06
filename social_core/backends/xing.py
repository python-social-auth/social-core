"""
XING OAuth1 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/xing.html
"""

from typing import Any

from oauthlib.oauth1 import SIGNATURE_TYPE_AUTH_HEADER
from requests_oauthlib import OAuth1

from social_core.exceptions import AuthResponseError

from .oauth import BaseOAuth1


class XingOAuth(BaseOAuth1):
    """Xing OAuth authentication backend"""

    name = "xing"
    title = "XING"
    AUTHORIZATION_URL = "https://api.xing.com/v1/authorize"
    REQUEST_TOKEN_URL = "https://api.xing.com/v1/request_token"
    ACCESS_TOKEN_URL = "https://api.xing.com/v1/access_token"
    SCOPE_SEPARATOR = "+"
    EXTRA_DATA = [("id", "id"), ("user_id", "user_id")]

    def get_user_details(self, response):
        """Return user details from Xing account"""
        email = response.get("email", "")
        fullname = None
        first_name = response["first_name"]
        last_name = response["last_name"]
        return {
            "username": (first_name or "").strip() + (last_name or "").strip(),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
        }

    def clean_oauth_auth(self, access_token):
        """Override of oauth_auth since Xing doesn't like callback_uri
        and oauth_verifier on authenticated API calls"""
        key, secret = self.get_key_and_secret()
        resource_owner_key = access_token.get("oauth_token")
        resource_owner_secret = access_token.get("oauth_token_secret")
        if not resource_owner_key:
            raise AuthResponseError(
                self, claim="oauth_token", code="missing_claim", stage="user_info"
            )
        if not resource_owner_secret:
            raise AuthResponseError(
                self,
                claim="oauth_token_secret",
                code="missing_claim",
                stage="user_info",
            )
        return OAuth1(
            key,
            secret,
            resource_owner_key=resource_owner_key,
            resource_owner_secret=resource_owner_secret,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
        )

    def user_data(self, access_token: dict, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data provided"""
        profile = self.get_json(
            "https://api.xing.com/v1/users/me.json",
            auth=self.clean_oauth_auth(access_token),
        )["users"][0]
        return {
            "user_id": profile["id"],
            "id": profile["id"],
            "first_name": profile["first_name"],
            "last_name": profile["last_name"],
            "email": profile["active_email"],
        }
