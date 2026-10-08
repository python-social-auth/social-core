"""
Vend  OAuth2 backend:
"""

import re
from typing import Any

from social_core.exceptions import AuthInputError, AuthResponseError

from .oauth import BaseOAuth2


class VendOAuth2(BaseOAuth2):
    name = "vend"
    title = "Lightspeed Retail (X-Series)"
    ID_KEY = "id"
    AUTHORIZATION_URL = "https://secure.vendhq.com/connect"
    ACCESS_TOKEN_URL = "https://{0}.vendhq.com/api/1.0/token"
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("refresh_token", "refresh_token"),
        ("domain_prefix", "domain_prefix"),
    ]
    DOMAIN_PREFIX_RE = re.compile(
        r"(?=.{1,63}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\Z"
    )

    def domain_prefix(self, response=None) -> str:
        from_response = response is not None and "domain_prefix" in response
        prefix = (
            response["domain_prefix"]
            if response is not None and from_response
            else self.data.get("domain_prefix")
        )
        family = AuthResponseError if from_response else AuthInputError
        fields: dict[str, Any] = {
            "claim": "domain_prefix" if from_response else None,
            "parameter": None if from_response else "domain_prefix",
            "stage": "user_info" if from_response else "callback",
        }
        if not prefix:
            raise family(
                self,
                code="missing_claim" if from_response else "missing_parameter",
                **fields,
            )
        if isinstance(prefix, (list, tuple)):
            prefix = prefix[0] if prefix else ""
        prefix = str(prefix).lower()
        if not self.DOMAIN_PREFIX_RE.match(prefix):
            raise family(
                self,
                code="invalid_claim" if from_response else "invalid_parameter",
                **fields,
            )
        return prefix

    def scoped_uid(self, details, response) -> str:
        id_key = self.id_key()
        user_id = self.get_user_id_from_sources(response, details, id_key=id_key)
        return f"{self.domain_prefix(response)}:{user_id}"

    def access_token_url(self):
        return self.ACCESS_TOKEN_URL.format(self.domain_prefix())

    def get_user_id(self, details, response):
        domain_prefix = self.domain_prefix(response)
        uid = self.scoped_uid(details, response)
        if self.strategy.storage.user.get_social_auth(self.name, uid):
            return uid

        # Previous versions stored only Vend's shop-local numeric user ID.
        # Migrate that legacy association only when its saved shop matches this
        # login; otherwise the old cross-shop collision would remain possible.
        legacy_uid = str(response.get("id"))
        legacy_social = self.strategy.storage.user.get_social_auth(
            self.name, legacy_uid
        )
        if legacy_social:
            legacy_domain_prefix = legacy_social.extra_data.get("domain_prefix")
            if (
                legacy_domain_prefix
                and str(legacy_domain_prefix).lower() == domain_prefix
            ):
                self.strategy.storage.user.migrate_social_auth(
                    legacy_social, uid, self.id_key()
                )
        return uid

    def get_user_details(self, response):
        email = response["email"]
        username = response.get("username") or email.split("@", 1)[0]
        return {
            "username": username,
            "email": email,
            "fullname": None,
            "first_name": None,
            "last_name": None,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        prefix = self.domain_prefix(kwargs.get("response"))
        url = f"https://{prefix}.vendhq.com/api/users"
        data = self.get_json(url, headers={"Authorization": f"Bearer {access_token}"})
        if data.get("users"):
            return dict(data["users"][0], domain_prefix=prefix)
        return {"domain_prefix": prefix}
