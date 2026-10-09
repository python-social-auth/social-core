"""
HubSpot OAuth2 backend, docs at:
    https://developers.hubspot.com/docs/methods/oauth2/oauth2-overview
"""

from typing import Any

from .oauth import BaseOAuth2


class HubSpotOAuth2(BaseOAuth2):
    """HubSpot OAuth2 authentication backend"""

    name = "hubspot"
    title = "HubSpot"
    icon = "hubspot.svg"
    ID_KEY = "hubspot_identity"
    REQUIRES_USER_ID = True
    AUTHORIZATION_URL = "https://app.hubspot.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://api.hubapi.com/oauth/v1/token"
    USER_DATA_URL = "https://api.hubapi.com/oauth/v1/access-tokens/"
    DEFAULT_SCOPE = ["oauth"]
    EXTRA_DATA = [
        ("hub_domain", "hub_domain"),
        ("hub_id", "hub_id"),
        ("app_id", "app_id"),
        ("user_id", "user_id"),
        ("hubspot_identity", "hubspot_identity"),
        ("refresh_token", "refresh_token"),
        ("expires_in", "expires_in"),
    ]

    def get_user_details(self, response):
        """Return user details"""
        response["email"] = response["user"]
        return response

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data information from service"""
        response = self.get_json(
            self.USER_DATA_URL + access_token,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response is not None:
            hub_id = response.get("hub_id")
            user_id = response.get("user_id")
            if (
                hub_id is not None
                and hub_id != ""
                and user_id is not None
                and user_id != ""
            ):
                response["hubspot_identity"] = f"{hub_id}:{user_id}"
        return response
