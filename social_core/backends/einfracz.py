"""
Backend for OpenID Connect e-INFRA CZ AAI
https://www.e-infra.cz
"""

from social_core.backends.open_id_connect import OpenIdConnectAuth


class EInfraCZOpenIdConnect(OpenIdConnectAuth):
    name = "e-infra_cz"
    OIDC_ENDPOINT = "https://login.e-infra.cz/oidc"
    EXTRA_DATA = [
        ("expires_in", "expires_in", True),
        ("refresh_token", "refresh_token", True),
        ("id_token", "id_token", True),
        ("other_tokens", "other_tokens", True),
    ]
    # In order to get any scopes, you have to register your service with
    # e-INFRA CZ AAI at https://spadmin.e-infra.cz/
    DEFAULT_SCOPE = ["openid", "email"]
    JWT_DECODE_OPTIONS = {"verify_at_hash": False}

    def get_user_details(self, response):
        username_key = self.setting("USERNAME_KEY", default=self.USERNAME_KEY)
        name = response.get("name") or ""
        fullname, first_name, last_name = self.get_user_names(name)
        return {
            "username": response.get(username_key),
            "email": response.get("email"),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }
