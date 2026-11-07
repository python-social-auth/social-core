"""
Legacy Username backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/username.html
"""

from .base import ResponseT_co
from .legacy import LegacyAuth


class UsernameAuth(LegacyAuth[ResponseT_co]):
    name = "username"
    title = "Username"
    ID_KEY = "username"
    EXTRA_DATA = ["username"]
