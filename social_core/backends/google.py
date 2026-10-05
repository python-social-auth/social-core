"""
Google OpenId, OAuth2, and OAuth1 backends, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/google.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthResponseError

from .oauth import BaseOAuth1, BaseOAuth2

if TYPE_CHECKING:
    from collections.abc import Mapping


class BaseGoogleAuth(BaseAuth):
    LEGACY_ID_KEYS = ("email",)
    MUTABLE_ID_KEYS = ("email",)

    def validate_email_verified(
        self,
        response: Mapping[str, Any] | None,
        *,
        stage: Literal["user_info", "token_validation"] = "user_info",
    ) -> None:
        """Require Google to explicitly confirm email verification."""
        email_verified = (
            response.get("email_verified") if response is not None else None
        )
        if email_verified is not True:
            raise AuthResponseError(
                self,
                "Google did not provide a verified email.",
                code="missing_claim" if email_verified is None else "invalid_claim",
                claim="email_verified",
                stage=stage,
            )

    def get_user_id(self, details, response):
        """Use the configured stable Google account identifier."""
        if self.setting("ID_KEY"):
            return super().get_user_id(details, response)
        if self.setting("USE_UNIQUE_USER_ID", False):
            if "sub" in response:
                return response["sub"]
            return response["id"]
        return super().get_user_id(details, response)

    def get_user_details(self, response):
        """Return user details from Google API account"""
        email = response.get("email", "")

        name, given_name, family_name = (
            response.get("name", ""),
            response.get("given_name", ""),
            response.get("family_name", ""),
        )

        fullname = name
        first_name = given_name
        last_name = family_name
        return {
            "username": email.split("@", 1)[0],
            "email": email,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }


class BaseGoogleOAuth2API(BaseGoogleAuth):
    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data from Google API"""
        response = self.get_json(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={
                "Authorization": f"Bearer {access_token}",
            },
        )
        self.validate_email_verified(response)
        return response

    def revoke_token_params(self, token, uid):
        return {"token": token}

    def revoke_token_headers(self, token, uid):
        return {"Content-type": "application/json"}


class GoogleOAuth2(BaseGoogleOAuth2API, BaseOAuth2):
    """Google OAuth2 authentication backend"""

    name = "google-oauth2"
    title = "Google"
    icon = "google.svg"
    REDIRECT_STATE = False
    ID_KEY = "sub"
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
    ACCESS_TOKEN_URL = "https://accounts.google.com/o/oauth2/token"
    REVOKE_TOKEN_URL = "https://accounts.google.com/o/oauth2/revoke"
    REVOKE_TOKEN_METHOD: Literal["GET", "POST", "DELETE"] = "GET"
    # The order of the default scope is important
    DEFAULT_SCOPE = ["openid", "email", "profile"]
    EXTRA_DATA = [
        ("sub", "sub"),
        ("refresh_token", "refresh_token", True),
        ("expires_in", "expires_in"),
        ("token_type", "token_type", True),
    ]


class GoogleOAuth(BaseGoogleAuth, BaseOAuth1):
    """Google OAuth authorization mechanism"""

    name = "google-oauth"
    title = "Google"
    icon = "google.svg"
    ID_KEY = "id"
    AUTHORIZATION_URL = "https://www.google.com/accounts/OAuthAuthorizeToken"
    REQUEST_TOKEN_URL = "https://www.google.com/accounts/OAuthGetRequestToken"
    ACCESS_TOKEN_URL = "https://www.google.com/accounts/OAuthGetAccessToken"
    DEFAULT_SCOPE = ["https://www.googleapis.com/auth/userinfo#email"]
    EXTRA_DATA = [("id", "id")]

    def user_data(self, access_token: dict, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data from Google API"""
        return self.get_querystring(
            "https://www.googleapis.com/userinfo/email",
            auth=self.oauth_auth(access_token, stage="user_info"),
        )

    def get_key_and_secret(self):
        """
        Return Google OAuth Consumer Key and Consumer Secret pair

        Uses anonymous by default, beware that this marks the application as
        not registered and a security badge is displayed on authorization page.
        https://developers.google.com/identity/protocols/oauth2
        """
        key_secret = super().get_key_and_secret()
        if key_secret == (None, None):
            key_secret = ("anonymous", "anonymous")
        return key_secret
