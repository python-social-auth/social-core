"""
Bitbucket OAuth2 and OAuth1 backends, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/bitbucket.html
"""

from __future__ import annotations

from typing import Any

from social_core.backends.base import ResponseT_co
from social_core.exceptions import (
    AuthCanceled,
    AuthCredentialError,
    AuthResponseError,
    ErrorStage,
    SocialAuthBaseException,
)

from .oauth import BaseOAuth2


class BitbucketOAuth2(BaseOAuth2[ResponseT_co]):
    name = "bitbucket-oauth2"
    title = "Bitbucket"
    icon = "bitbucket.svg"
    SCOPE_SEPARATOR = " "
    AUTHORIZATION_URL = "https://bitbucket.org/site/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token"
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("scopes", "scopes"),
        ("expires_in", "expires_in"),
        ("token_type", "token_type"),
        ("refresh_token", "refresh_token"),
    ]
    ID_KEY = "uuid"
    MUTABLE_ID_KEYS = ("username",)

    def get_user_id(self, details, response):
        id_key = self.id_key()
        if not self.setting("ID_KEY") and self.setting("USERNAME_AS_ID", False):
            id_key = "username"
        return self.get_user_id_from_sources(response, details, id_key=id_key)

    def get_user_details(self, response):
        """Return user details from Bitbucket account"""
        fullname = response["display_name"]
        first_name = None
        last_name = None

        return {
            "username": response.get("username", ""),
            "email": response.get("email", ""),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data provided"""
        emails = self._get_emails(access_token)
        email = None
        is_confirmed = False

        for address in reversed(emails["values"]):
            email = address["email"]
            is_confirmed = address["is_confirmed"]
            if address["is_primary"]:
                break

        if self.setting("VERIFIED_EMAILS_ONLY", False) and not is_confirmed:
            raise AuthResponseError(
                self,
                "Bitbucket account has no verified email",
                code="profile_email_missing",
                stage="user_info",
            )

        user = self._get_user(access_token)
        if email:
            user["email"] = email
        return user

    def auth_complete_credentials(self):
        return self.get_key_and_secret()

    def get_provider_error(
        self,
        data: object,
        *,
        stage: ErrorStage = "callback",
        status_code: int | None = None,
        retry_after: str | None = None,
    ) -> SocialAuthBaseException | None:
        error = super().get_provider_error(
            data, stage=stage, status_code=status_code, retry_after=retry_after
        )
        if stage != "refresh" or error is None:
            return error
        # Bitbucket rejects a revoked refresh token with a 400 invalid_request
        # "Invalid refresh_token" instead of OAuth's invalid_grant:
        # https://community.atlassian.com/forums/discussion/1545002/how-do-i-refresh-a-token
        # A deactivated Atlassian account gets a 401 "User is inactive":
        # https://jira.atlassian.com/browse/AX-684
        # Its error code is one provider_error reads as a cancellation, which
        # can't happen during a refresh, so the status decides there.
        inactive_user = isinstance(error, AuthCanceled) and status_code == 401
        revoked = (status_code, error.provider_code) == (400, "invalid_request")
        if not (inactive_user or revoked):
            return error
        return AuthCredentialError(
            self,
            error.detail,
            code="reauthentication_required",
            source="provider_response",
            stage=stage,
            provider_code=error.provider_code,
            status_code=status_code,
        )

    def _get_user(self, access_token=None):
        return self.get_json(
            "https://api.bitbucket.org/2.0/user", params={"access_token": access_token}
        )

    def _get_emails(self, access_token=None):
        return self.get_json(
            "https://api.bitbucket.org/2.0/user/emails",
            params={"access_token": access_token},
        )
