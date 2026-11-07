"""
Legacy Email backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/email.html
"""

from social_core.backends.base import ResponseT_co

from .legacy import LegacyAuth


class EmailAuth(LegacyAuth[ResponseT_co]):
    name = "email"
    title = "E-mail"
    ID_KEY = "email"
    REQUIRES_EMAIL_VALIDATION = True
    EXTRA_DATA = ["email"]
