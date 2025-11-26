"""
Stripe OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/stripe.html
"""

from typing import Any

from .oauth import BaseOAuth2


class StripeOAuth2(BaseOAuth2):
    """Stripe OAuth2 authentication backend"""

    name = "stripe"
    ID_KEY = "stripe_user_id"
    AUTHORIZATION_URL = "https://connect.stripe.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://connect.stripe.com/oauth/token"
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("stripe_publishable_key", "stripe_publishable_key"),
        ("access_token", "access_token"),
        ("livemode", "livemode"),
        ("token_type", "token_type"),
        ("refresh_token", "refresh_token"),
        ("stripe_user_id", "stripe_user_id"),
    ]

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Grab user profile information from Stripe"""
        return self.get_json(
            "https://api.stripe.com/v1/account",
            headers={
                "Authorization": f"Bearer {access_token}",
            },
        )

    def get_user_details(self, response):
        """Return user details from Stripe account"""
        return {
            "email": response.get("email"),
            "username": response.get("stripe_user_id"),
            "first_name": response.get("first_name", ""),
            "last_name": response.get("last_name", ""),
        }

    def auth_complete_params(self, state=None):
        client_id, _client_secret = self.get_key_and_secret()
        return {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "scope": self.SCOPE_SEPARATOR.join(self.get_scope()),
            "code": self.data["code"],
        }

    def auth_headers(self):
        _client_id, client_secret = self.get_key_and_secret()
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {client_secret}",
        }

    def refresh_token_params(self, token: str, *args, **kwargs) -> dict[str, str]:
        return {"refresh_token": token, "grant_type": "refresh_token"}
