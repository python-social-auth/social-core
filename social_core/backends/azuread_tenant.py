"""
Copyright (c) 2015 Microsoft Open Technologies, Inc.

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Azure AD OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/azuread.html

See https://nicksnettravels.builttoroam.com/post/2017/01/24/Verifying-Azure-Active-Directory-JWT-Tokens.aspx
for verifying JWT tokens.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from social_core.backends.base import ResponseT_co
from social_core.exceptions import AuthConfigurationError, AuthResponseError

from .azuread import AzureADOAuth2


class AzureADTenantOAuth2(AzureADOAuth2[ResponseT_co]):
    name = "azuread-tenant-oauth2"
    title = "Microsoft"
    icon = "microsoft.svg"
    ID_KEY = "sub"
    LEGACY_ID_KEYS: tuple[str, ...] = ()
    OPENID_CONFIGURATION_URL = "{base_url}/.well-known/openid-configuration{appid}"
    JWKS_URL = "{base_url}/discovery/keys{appid}"
    # TENANT_ID values that select an authority without naming a tenant.
    MULTI_TENANT_ALIASES = ("common", "organizations", "consumers")

    @property
    def tenant_id(self) -> str:
        value = self.setting("TENANT_ID", "common")
        if not isinstance(value, str) or not value:
            raise AuthConfigurationError(
                self, code="invalid_setting", parameter="TENANT_ID", stage="begin"
            )
        return value

    def get_openid_configuration_url_format(self) -> dict[str, str]:
        return {**super().get_openid_configuration_url_format(), "appid": self._appid()}

    def jwks_url(self):
        return self.JWKS_URL.format(base_url=self.base_url, appid=self._appid())

    def _appid(self) -> str:
        return (
            f"?appid={self.setting('KEY')}" if self.setting("KEY") is not None else ""
        )

    def get_id_token_issuer(self, claims: dict[str, Any]) -> str:
        self.validate_configured_tenant(claims)
        return super().get_id_token_issuer(claims)

    def accepts_any_tenant(self) -> bool:
        # validate_configured_tenant() pins a GUID tenant on every authority.
        try:
            UUID(self.tenant_id)
        except (TypeError, ValueError):
            return super().accepts_any_tenant()
        return False

    def validate_configured_tenant(self, claims: dict[str, Any]) -> None:
        configured_tenant_id = self.tenant_id
        try:
            configured_tenant_uuid = UUID(configured_tenant_id)
        except (TypeError, ValueError) as error:
            if (
                isinstance(configured_tenant_id, str)
                and configured_tenant_id.lower() in self.MULTI_TENANT_ALIASES
            ):
                return
            authority = self.configured_authority_url()
            if (
                authority is not None
                and authority.rsplit("/", 1)[-1].lower() != configured_tenant_id.lower()
            ):
                raise AuthConfigurationError(
                    self,
                    "AUTHORITY_URL must select the configured tenant domain",
                    code="invalid_setting",
                    parameter="TENANT_ID",
                    stage="token_validation",
                ) from error
            # A tenant domain name cannot be compared with ``tid``. It only
            # restricts sign-in while discovery is pinned to that tenant and
            # publishes its concrete issuer; a multi-tenant authority publishes
            # a ``{tenantid}`` template that is filled from the token itself.
            issuer = self.openid_configuration().get("issuer")
            if isinstance(issuer, str) and (
                "{tenantid}" in issuer or "{tenantId}" in issuer
            ):
                raise AuthConfigurationError(
                    self,
                    "TENANT_ID must be a tenant GUID when the authority "
                    "serves more than one tenant",
                    code="invalid_setting",
                    parameter="TENANT_ID",
                    stage="token_validation",
                ) from None
            return

        tenant_id = claims.get("tid")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise AuthResponseError(
                self, claim="tid", code="missing_claim", stage="token_validation"
            )

        try:
            token_tenant_uuid = UUID(tenant_id)
        except ValueError:
            token_tenant_uuid = None

        if configured_tenant_uuid != token_tenant_uuid:
            raise AuthResponseError(
                self,
                "Token tenant does not match configured tenant",
                code="invalid_claim",
                claim="tid",
                stage="token_validation",
            )


class AzureADV2TenantOAuth2(AzureADTenantOAuth2[ResponseT_co]):
    name = "azuread-v2-tenant-oauth2"
    title = "Microsoft"
    icon = "microsoft.svg"
    ID_KEY = "sub"
    LEGACY_ID_KEYS: tuple[str, ...] = ("preferred_username",)
    MUTABLE_ID_KEYS = ("upn", "preferred_username")
    OPENID_CONFIGURATION_URL = "{base_url}/v2.0/.well-known/openid-configuration{appid}"
    AUTHORIZATION_URL = "{base_url}/oauth2/v2.0/authorize"
    ACCESS_TOKEN_URL = "{base_url}/oauth2/v2.0/token"
    JWKS_URL = "{base_url}/discovery/v2.0/keys{appid}"
    DEFAULT_SCOPE = ["openid", "profile", "offline_access"]

    def get_user_details(self, response):
        """Return user details from Azure AD account"""
        fullname, first_name, last_name = (
            response.get("name"),
            response.get("given_name"),
            response.get("family_name"),
        )
        return {
            "username": fullname,
            "email": response.get("preferred_username"),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }
