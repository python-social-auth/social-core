"""
Launchpad OpenId backend
"""

from .base import ResponseT_co
from .open_id import OpenIdAuth


class LaunchpadOpenId(OpenIdAuth[ResponseT_co]):
    name = "launchpad"
    title = "Launchpad"
    URL = "https://login.launchpad.net"
    USERNAME_KEY = "nickname"
