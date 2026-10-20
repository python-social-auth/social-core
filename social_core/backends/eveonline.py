"""
EVE Online Single Sign-On (SSO) OAuth2 backend
Documentation at https://eveonline-third-party-documentation.readthedocs.io/en/latest/sso/index.html
"""

from __future__ import annotations

from typing import Any, cast

from social_core.exceptions import AuthAssociationError, AuthResponseError

from .oauth import BaseOAuth2


class EVEOnlineOAuth2(BaseOAuth2):
    """EVE Online OAuth authentication backend"""

    name = "eveonline"
    title = "EVE Online"
    BASE_URL = "https://login.eveonline.com/oauth"
    AUTHORIZATION_URL = f"{BASE_URL}/authorize"
    ACCESS_TOKEN_URL = f"{BASE_URL}/token"
    ID_KEY = "CharacterID"
    EXTRA_DATA = [
        ("CharacterID", "id"),
        ("expires_in", "expires_in"),
        ("CharacterOwnerHash", "owner_hash", True),
        ("refresh_token", "refresh_token", True),
    ]

    def get_user_id(
        self, details: dict[str, Any], response: dict[str, Any]
    ) -> str | int | None:
        """Bind a character only to the player account that last used it."""
        owner_hash = response.get("CharacterOwnerHash")
        if not isinstance(owner_hash, str) or not owner_hash.strip():
            raise AuthResponseError(
                self,
                code="missing_claim",
                claim="CharacterOwnerHash",
                stage="pipeline",
            )

        uid = super().get_user_id(details, response)
        if uid is None or uid == "":
            return uid

        social = self.strategy.storage.user.get_social_auth(self.name, str(uid))
        if social is not None:
            # Historical rows without a hash record the next verified owner.
            stored_owner_hash = social.extra_data.get("owner_hash")
            if stored_owner_hash and stored_owner_hash != owner_hash:
                raise AuthAssociationError(
                    self,
                    code="identity_in_use",
                    stage="pipeline",
                    claim="CharacterOwnerHash",
                )
        return uid

    def get_user_details(self, response):
        """Return user details from EVE Online account"""
        user_data = cast("dict", self.user_data(response["access_token"]))
        fullname = user_data["CharacterName"]
        first_name = None
        last_name = None
        return {
            "email": "",
            "username": (fullname or "").strip(),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Get Character data from EVE server"""
        return self.get_json(
            "https://login.eveonline.com/oauth/verify",
            headers={"Authorization": f"Bearer {access_token}"},
        )
