"""
Open Suse OpenId backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/suse.html
"""

from .open_id import OpenIdAuth


class OpenSUSEOpenId(OpenIdAuth):
    name = "opensuse"
    title = "openSUSE"
    icon = "opensuse.svg"
    ID_KEY = "identity_url"
    LEGACY_ID_KEYS = ("nickname",)
    MUTABLE_ID_KEYS = ("nickname",)
    URL = "https://www.opensuse.org/openid/user/"

    def get_user_id(self, details, response):
        """
        Return the verified OpenID identity URL.
        """
        return self.get_user_id_for_key(details, response, self.id_key())
