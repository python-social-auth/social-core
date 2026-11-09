"""
Belgium EID OpenId backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/belgium_eid.html
"""

from social_core.backends.base import ResponseT_co

from .open_id import OpenIdAuth


class BelgiumEIDOpenId(OpenIdAuth[ResponseT_co]):
    """Belgium e-ID OpenID authentication backend"""

    name = "belgiumeid"
    title = "Belgium eID"
    URL = "https://www.e-contract.be/eid-idp/endpoints/openid/auth"
