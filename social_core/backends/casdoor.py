"""
Casdoor OpenID Connect backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/casdoor.html
"""

from .open_id_connect import OpenIdConnectAuth


class CasdoorOpenIdConnect(OpenIdConnectAuth):
    """
    Casdoor OIDC authentication backend

    Casdoor is self-hosted, so OIDC_ENDPOINT has to be set to the URL of
    the Casdoor server, for example https://door.example.com
    """

    name = "casdoor"
    title = "Casdoor"
    # Casdoor supports S256 PKCE and advertises it in its discovery document
    DEFAULT_USE_PKCE = True

    def oidc_endpoint(self) -> str:
        return super().oidc_endpoint().rstrip("/")
