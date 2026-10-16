"""
Weblate OpenID Connect backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/weblate.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .open_id_connect import OpenIdConnectAuth

if TYPE_CHECKING:
    from social_core.strategy import BaseStrategy


class WeblateOpenIdConnect(OpenIdConnectAuth):
    """Authenticate against Hosted Weblate or another Weblate installation."""

    name = "weblate"
    title = "Hosted Weblate"
    icon = "weblate.svg"
    OIDC_ENDPOINT = "https://hosted.weblate.org/oidc"
    DEFAULT_USE_PKCE = True
    EXTRA_DATA = [
        *(OpenIdConnectAuth.EXTRA_DATA or []),
        ("weblate_tos_version", "weblate_tos_version", True),
    ]

    def oidc_endpoint(self) -> str:
        return super().oidc_endpoint().rstrip("/")

    @classmethod
    def get_title(cls, strategy: BaseStrategy) -> str:
        endpoint = cls(strategy=strategy).oidc_endpoint()
        if urlsplit(endpoint).hostname == "hosted.weblate.org":
            return "Hosted Weblate"
        return "Weblate"
