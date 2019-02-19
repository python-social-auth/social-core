"""
Google OpenIdConnect:
    https://python-social-auth.readthedocs.io/en/latest/backends/google.html
"""
from .open_id_connect import OpenIdConnectAuth
from .google import GoogleOAuth2


class GoogleOpenIdConnect(GoogleOAuth2, OpenIdConnectAuth):
    name = 'google-openidconnect'
    OIDC_ENDPOINT = 'https://accounts.google.com'
    # differs from value in discovery document
    # http://openid.net/specs/openid-connect-core-1_0.html#rfc.section.15.6.2
    ID_TOKEN_ISSUER = 'accounts.google.com'
