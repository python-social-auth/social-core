"""
Okta OAuth2 and OpenIdConnect:
    https://python-social-auth.readthedocs.io/en/latest/backends/okta.html
"""

from typing import Any

from .okta import OktaOAuth2
from .open_id_connect import OpenIdConnectAuth


class OktaOpenIdConnect(OktaOAuth2, OpenIdConnectAuth):
    """Okta OpenID-Connect authentication backend"""

    name = "okta-openidconnect"
    REDIRECT_STATE = False
    RESPONSE_TYPE = "code"

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        return self.validate_userinfo_sub(
            super().user_data(access_token, *args, **kwargs)
        )
