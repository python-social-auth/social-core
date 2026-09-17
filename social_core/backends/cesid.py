"""
Backend for OpenID Connect CESiD AAI - Czech Educational and Scientific Identification
"""

from social_core.backends.open_id_connect import OpenIdConnectAuth


class CesidOpenIdConnect(OpenIdConnectAuth):
    name = "cesid"
    OIDC_ENDPOINT = "https://login.cesid.cesnet.cz/cas/oidc"
    EXTRA_DATA = [
        ("expires_in", "expires_in", True),
        ("refresh_token", "refresh_token", True),
        ("id_token", "id_token", True),
        ("other_tokens", "other_tokens", True),
    ]
    # In order to get any scopes, you have to register your service with
    # CESiD AAI at https://services.cesid.cesnet.cz/
    DEFAULT_SCOPE = ["openid", "email"]
    VALIDATE_AT_HASH: bool = False

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
