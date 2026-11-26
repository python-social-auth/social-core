from operator import itemgetter
from typing import Any

from social_core.backends.base import ResponseT_co

from .oauth import BaseOAuth2


class EventbriteOAuth2(BaseOAuth2[ResponseT_co]):
    """Eventbrite OAuth2 authentication backend"""

    name = "eventbrite"
    title = "Eventbrite"
    AUTHORIZATION_URL = "https://www.eventbrite.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://www.eventbrite.com/oauth/token"
    METADATA_URL = "https://www.eventbriteapi.com/v3/users/me"
    STATE_PARAMETER = True
    REDIRECT_STATE = False

    def get_primary_email(self, response) -> dict[str, Any]:
        """Return the primary address entry of an Eventbrite metadata response"""
        return next(iter(filter(itemgetter("primary"), response["emails"])))

    def get_user_details(self, response):
        """Return user details from an Eventbrite metadata response"""
        email = self.get_primary_email(response)["email"]

        return {
            "username": email,
            "email": email,
            "first_name": response["first_name"],
            "last_name": response["last_name"],
        }

    def get_email_verified(self, response: Any) -> bool:
        """Return whether the primary Eventbrite address was verified"""
        return self.get_primary_email(response).get("verified") is True

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data and datacenter information from service"""
        return self.get_json(
            self.METADATA_URL, headers={"Authorization": f"Bearer {access_token}"}
        )
