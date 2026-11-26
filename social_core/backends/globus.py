"""
Globus Auth OpenID Connect backend, docs at:
    https://docs.globus.org/api/auth
    http://globus-integration-examples.readthedocs.io
"""

from social_core.backends.base import ResponseT_co
from social_core.backends.open_id_connect import OpenIdConnectAuth


class GlobusOpenIdConnect(OpenIdConnectAuth[ResponseT_co]):
    name = "globus"
    title = "Globus"
    OIDC_ENDPOINT = "https://auth.globus.org"
    JWT_ALGORITHMS = ["RS256", "RS512"]
    EXTRA_DATA = [
        ("expires_in", "expires_in", True),
        ("refresh_token", "refresh_token", True),
        ("id_token", "id_token", True),
        ("other_tokens", "other_tokens", True),
    ]

    def get_user_details(self, response):
        return {
            "username": response.get(self.setting("USERNAME_KEY", self.USERNAME_KEY)),
            "email": response.get(self.setting("EMAIL_KEY", self.EMAIL_KEY)),
            "fullname": response.get("name"),
            "first_name": None,
            "last_name": None,
        }
