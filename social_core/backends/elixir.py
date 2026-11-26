"""
Backend for OpenID Connect ELIXIR AAI
https://www.elixir-europe.org/services/compute/aai
"""

from social_core.backends.base import ResponseT_co
from social_core.backends.open_id_connect import OpenIdConnectAuth


class ElixirOpenIdConnect(OpenIdConnectAuth[ResponseT_co]):
    name = "elixir"
    title = "ELIXIR AAI"
    OIDC_ENDPOINT = "https://login.elixir-czech.org/oidc"
    EXTRA_DATA = [
        ("expires_in", "expires_in", True),
        ("refresh_token", "refresh_token", True),
        ("id_token", "id_token", True),
        ("other_tokens", "other_tokens", True),
    ]
    # In order to get any scopes, you have to register your service with
    # ELIXIR, see documentation at
    # https://www.elixir-europe.org/services/compute/aai
    DEFAULT_SCOPE = ["openid", "email"]
    VALIDATE_AT_HASH: bool = False

    def get_user_details(self, response):
        return {
            "username": response.get(self.setting("USERNAME_KEY", self.USERNAME_KEY)),
            "email": response.get(self.setting("EMAIL_KEY", self.EMAIL_KEY)),
            "fullname": response.get("name"),
            "first_name": None,
            "last_name": None,
        }
