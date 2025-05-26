"""
Facebook Limited Login backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/facebook.html
"""

from ..exceptions import AuthTokenError
from .open_id_connect import OpenIdConnectAuth


class FacebookLimitedLogin(OpenIdConnectAuth):
    """Facebook Limited Login (OIDC) backend"""

    name = "facebook-limited-login"
    OIDC_ENDPOINT = "https://www.facebook.com"
    ACCESS_TOKEN_URL = "https://facebook.com/dialog/oauth/"
    ID_TOKEN_MAX_AGE = 3600

    def authenticate(self, *args, **kwargs):
        if (
            "backend" not in kwargs
            or kwargs["backend"].name != self.name
            or "strategy" not in kwargs
            or "response" not in kwargs
        ):
            return None

        # Replace response with the decoded JWT
        raw_jwt = kwargs.get("response", {}).get("access_token")
        kwargs["response"] = self.validate_and_return_id_token(raw_jwt, "")
        return super().authenticate(*args, **kwargs)

    def get_user_details(self, response):
        return {
            "fullname": response.get("name"),
            "email": response.get("email"),
            "picture": response.get("picture"),
        }

    def user_data(self, access_token, *args, **kwargs):
        # We don't have an access token to call any API for the user details.
        return {}

    def validate_claims(self, id_token):
        try:
            super().validate_claims(id_token)
        except AuthTokenError as e:
            if "Incorrect id_token: nonce" in e.args:
                # Ignore errors about nonce. We can't validate it since it's not generated server-side.
                return
            raise
