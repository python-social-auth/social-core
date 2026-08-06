"""
Coinbase OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/coinbase.html
"""

from typing import Any, cast

from .oauth import BaseOAuth2

API_VERSION = "2022-01-06"


class CoinbaseOAuth2(BaseOAuth2):
    name = "coinbase"
    SCOPE_SEPARATOR = ","
    DEFAULT_SCOPE = ["wallet:user:read", "wallet:user:email"]
    AUTHORIZATION_URL = "https://login.coinbase.com/oauth2/auth"
    ACCESS_TOKEN_URL = "https://login.coinbase.com/oauth2/token"
    REVOKE_TOKEN_URL = "https://login.coinbase.com/oauth2/revoke"
    USER_DATA_URL = "https://api.coinbase.com/v2/user"
    REDIRECT_STATE = False

    def get_user_id(self, details, response):
        return response["data"]["id"]

    def get_user_details(self, response):
        """Return user details from Coinbase account"""
        user_data = response["data"]
        email = user_data.get("email", "")
        name = user_data["name"]
        username = user_data.get("username")
        fullname, first_name, last_name = self.get_user_names(name)
        return {
            "username": username,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        return self.get_json(
            self.USER_DATA_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "CB-VERSION": cast("str", self.setting("API_VERSION", API_VERSION)),
            },
        )

    def revoke_token_params(self, token, uid) -> dict[str, str]:
        client_id, client_secret = self.get_key_and_secret()
        return {
            "token": token,
            "client_id": client_id,
            "client_secret": client_secret,
        }

    def revoke_token(self, token, uid):
        if revoke_token_url := self.revoke_token_url(token, uid):
            response = self.request(
                revoke_token_url,
                headers=self.revoke_token_headers(token, uid),
                data=self.revoke_token_params(token, uid),
                method=self.REVOKE_TOKEN_METHOD,
            )
            return self.process_revoke_token_response(response)
        return None
