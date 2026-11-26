"""
CAS OIDC backend
https://apereo.github.io/cas/6.6.x/authentication/OIDC-Authentication.html

Backend for authenticating with Apereo CAS using OIDC. This backend handles
the minor implementation differences between the Apereo CAS OIDC server
implementation and the standard OIDC implementation in Python Social Auth.
"""

from typing import Any

from social_core.backends.base import ResponseT_co
from social_core.groups import read_groups

from .open_id_connect import OpenIdConnectAuth


class CASOpenIdConnectAuth(OpenIdConnectAuth[ResponseT_co]):
    """
    Open ID Connect backends for use with Apereo CAS.
    Currently only the code response type is supported.

    It can also be directly instantiated as a generic OIDC backend.
    To use it you will need to set at minimum:

    SOCIAL_AUTH_CAS_OIDC_ENDPOINT = 'https://.....'  # endpoint without /.well-known/openid-configuration
    SOCIAL_AUTH_CAS_KEY = '<client_id>'
    SOCIAL_AUTH_CAS_SECRET = '<client_secret>'
    SOCIAL_AUTH_CAS_ALLOW_GROUPS = []
    """

    name = "cas"
    title = "CAS"
    ID_KEY = "sub"
    LEGACY_ID_KEYS = ("username",)
    MUTABLE_ID_KEYS = ("username", "preferred_username", "email")
    EXTRA_DATA = [*(OpenIdConnectAuth.EXTRA_DATA or []), ("sub", "sub")]
    STATE_PARAMETER = True

    def oidc_endpoint(self):
        endpoint = super().oidc_endpoint()
        self.log_debug("endpoint: %s", endpoint)
        return endpoint

    def get_user_id(self, details, response):
        self.log_debug("method: get_user_id, details: %s, %s", details, response)
        return super().get_user_id(details, response)

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        data = self.get_json(
            self.userinfo_url(), headers={"Authorization": f"Bearer {access_token}"}
        )
        self.validate_userinfo_sub(data)
        self.log_debug("user_data: %s", data)
        return data.get("attributes", {})

    def get_user_details(self, response):
        username_key = self.setting("USERNAME_KEY", self.USERNAME_KEY)
        self.log_debug("username_key: %s", username_key)
        return super().get_user_details(response)

    def get_user_groups(self, response) -> list[str] | None:
        # Existing CAS allow lists do not require a new extraction setting.
        extract = bool(
            self.setting("GROUPS_ENABLED", False) or self.setting("GROUPS_MAP", {})
        )
        if not (extract or self.setting("ALLOW_GROUPS", [])):
            return None
        # An allow list alone refuses a user without the claim either way. Any
        # other consumer must not take a missing claim for an empty membership
        # list: the user can drop the scope releasing it from the request.
        return read_groups(
            self,
            response,
            "groups",
            missing_as_empty=self.setting("GROUPS_MISSING_AS_EMPTY", not extract),
        )
