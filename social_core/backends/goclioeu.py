from typing import Any

from .goclio import GoClioOAuth2


class GoClioEuOAuth2(GoClioOAuth2):
    name = "goclioeu"
    AUTHORIZATION_URL = "https://app.goclio.eu/oauth/authorize/"
    ACCESS_TOKEN_URL = "https://app.goclio.eu/oauth/token/"

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        return self.get_json(
            "https://app.goclio.eu/api/v2/users/who_am_i",
            params={"access_token": access_token},
        )
