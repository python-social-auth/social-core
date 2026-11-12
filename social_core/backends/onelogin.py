"""
OneLogin OpenID Connect backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/onelogin.html
"""

from __future__ import annotations

from social_core.backends.base import ResponseT_co

from .open_id_connect import OpenIdConnectAuth


class OneLoginOpenIdConnect(OpenIdConnectAuth[ResponseT_co]):
    """Authenticate against a configured OneLogin OpenID Connect issuer."""

    name = "onelogin"
    title = "OneLogin"
    DEFAULT_USE_PKCE = True
    TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_post"

    def oidc_endpoint(self) -> str:
        return super().oidc_endpoint().rstrip("/")
