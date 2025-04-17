"""
Fedora OpenId backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/fedora.html
"""

from .open_id import OpenIdAuth
from .open_id_connect import OpenIdConnectAuth


class FedoraOpenIdConnect(OpenIdConnectAuth):
    """
    Fedora OpenID Connect backend.

    To use it, you need to set the SOCIAL_AUTH_FEDORA_OIDC_KEY and
    SOCIAL_AUTH_FEDORA_OIDC_SECRET configuration variables to the client_id and
    client_secret values that the Fedora Infrastructure gave you.
    """

    name = "fedora-oidc"
    USERNAME_KEY = "nickname"
    OIDC_ENDPOINT = "https://id.fedoraproject.org"
    DEFAULT_SCOPE = [
        "openid",
        "profile",
        "email",
        "https://id.fedoraproject.org/scope/agreements",
        "https://id.fedoraproject.org/scope/groups",
    ]


class FedoraOpenId(OpenIdAuth):
    """
    Fedora OpenID backend. DEPRECATED, please use the OpenID Connect backend.
    """

    name = "fedora"
    URL = "https://id.fedoraproject.org"
    USERNAME_KEY = "nickname"
