from typing import Any

from .oauth import BaseOAuth2


class MonzoOAuth2(BaseOAuth2):
    """
    Monzo OAuth2 authentication backend.
    """

    name = "monzo"
    title = "Monzo"

    AUTHORIZATION_URL = "https://auth.getmondo.co.uk/"
    ACCESS_TOKEN_URL = "https://api.monzo.com/oauth2/token"
    REDIRECT_STATE = False

    def get_user_details(self, response):
        fullname = response["accounts"][0]["description"]
        first_name = ""
        last_name = ""

        return {
            "username": str(response.get("user_id")),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        return self.get_json(
            "https://api.monzo.com/accounts",
            headers={"Authorization": f"Bearer {access_token}"},
        )
