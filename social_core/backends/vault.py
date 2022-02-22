"""
Backend for Hashicorp Vault OIDC Identity Provider in Vault 1.9+
https://www.vaultproject.io/docs/secrets/identity/oidc-provider
"""
import base64

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.utils import cache



class VaultOpenIdConnect(OpenIdConnectAuth):
    """
    Vault OIDC authentication backend

    This is an alias for the generic OIDC backend
    """
    name = 'vault'
