"""
Launchpad OpenId backend
"""

from .open_id import OpenIdAuth


class LaunchpadOpenId(OpenIdAuth):
    name = "launchpad"
    title = "Launchpad"
    URL = "https://login.launchpad.net"
    USERNAME_KEY = "nickname"
