"""
Ubuntu One OpenId backend
"""

from social_core.backends.base import ResponseT_co

from .open_id import OpenIdAuth


class UbuntuOpenId(OpenIdAuth[ResponseT_co]):
    name = "ubuntu"
    title = "Ubuntu"
    icon = "ubuntu.svg"
    ID_KEY = "identity_url"
    LEGACY_ID_KEYS = ("nickname",)
    MUTABLE_ID_KEYS = ("nickname",)
    URL = "https://login.ubuntu.com"

    def get_user_id(self, details, response):
        """
        Return the verified OpenID identity URL.
        """
        return self.get_user_id_for_key(details, response, self.id_key())
