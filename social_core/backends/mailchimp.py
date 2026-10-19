from __future__ import annotations

from typing import TYPE_CHECKING, Any

from social_core.exceptions import (
    AuthAssociationError,
    AuthConfigurationError,
    AuthResponseError,
)
from social_core.identifiers import identifier_matches

from .oauth import BaseOAuth2

if TYPE_CHECKING:
    from social_core.storage import UserMixin, UserProtocol


class MailChimpOAuth2(BaseOAuth2):
    """MailChimp OAuth2 authentication backend"""

    name = "mailchimp"
    title = "Mailchimp"
    AUTHORIZATION_URL = "https://login.mailchimp.com/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://login.mailchimp.com/oauth2/token"
    METADATA_URL = "https://login.mailchimp.com/oauth2/metadata"
    STATE_PARAMETER = True
    REDIRECT_STATE = False
    ID_KEY = "mailchimp_identity"
    REQUIRES_USER_ID = True
    EXTRA_DATA = [
        ("accountname", "accountname"),
        ("api_endpoint", "api_endpoint"),
        ("role", "role"),
        ("login", "login"),
        ("user_id", "user_id"),
        ("mailchimp_identity", "mailchimp_identity"),
    ]

    def id_key(self) -> str:
        configured = self.setting("ID_KEY")
        if configured and configured != self.ID_KEY:
            raise AuthConfigurationError(
                self, code="invalid_setting", parameter="ID_KEY", stage="pipeline"
            )
        return self.ID_KEY

    def get_user_details(self, response):
        """Return user details from a Mailchimp metadata response"""
        return {
            "username": response["login"]["login_name"],
            "email": response["login"]["email"],
        }

    def get_legacy_social_auth(
        self,
        uid: str,
        id_key: str,
        response: dict[str, Any],
        user: UserProtocol | None = None,
    ) -> UserMixin | None:
        if id_key != self.ID_KEY or uid != response.get("mailchimp_identity"):
            return None
        storage = self.strategy.storage.user
        # Historical associations used the account ID. The stored login is
        # evidence of the last person to use that association, not its creator.
        legacy = storage.get_social_auth(self.name, str(response["user_id"]))
        if legacy is None or legacy.id_key not in ("", "user_id"):
            return None
        saved_login = legacy.extra_data.get("login")
        saved_login_id = (
            saved_login.get("login_id") if isinstance(saved_login, dict) else None
        )
        if (
            not isinstance(saved_login_id, (str, int))
            or isinstance(saved_login_id, bool)
            or saved_login_id == ""
        ):
            if user is not None and legacy.user == user:
                return legacy
            raise AuthAssociationError(
                self,
                "Stored Mailchimp login identifier is missing; use account recovery",
                code="identifier_migration_conflict",
                stage="pipeline",
            )
        if not identifier_matches(saved_login_id, str(response["login"]["login_id"])):
            return None
        return legacy

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data and datacenter information from service"""
        response = self.get_json(
            self.METADATA_URL, headers={"Authorization": f"OAuth {access_token}"}
        )
        if response is None:
            return None
        login = response.get("login")
        user_id = response.get("user_id")
        login_id = login.get("login_id") if isinstance(login, dict) else None
        for claim, value in (
            ("user_id", user_id),
            ("login.login_id", login_id),
        ):
            if (
                not isinstance(value, (str, int))
                or isinstance(value, bool)
                or value == ""
            ):
                raise AuthResponseError(
                    self, claim=claim, code="missing_claim", stage="user_info"
                )
        response["mailchimp_identity"] = f"{user_id}:{login_id}"
        return response
