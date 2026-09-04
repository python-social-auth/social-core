"""
Ubuntu One OpenId backend
"""

from .open_id import OpenIdAuth


class UbuntuOpenId(OpenIdAuth):
    name = "ubuntu"
    ID_KEY = "nickname"
    URL = "https://login.ubuntu.com"

    def get_user_id(self, details, response):
        """
        Return user unique id provided by service. For Ubuntu One
        the nickname should be original.
        """
        return self.get_user_id_from_sources(details)
