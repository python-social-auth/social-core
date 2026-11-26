"""
Tripit OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/tripit.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from defusedxml import minidom

from social_core.backends.base import ResponseT_co

from .oauth import BaseOAuth1

if TYPE_CHECKING:
    from xml.dom.minidom import Element


class TripItOAuth(BaseOAuth1[ResponseT_co]):
    """TripIt OAuth authentication backend"""

    name = "tripit"
    title = "TripIt"
    AUTHORIZATION_URL = "https://www.tripit.com/oauth/authorize"
    REQUEST_TOKEN_URL = "https://api.tripit.com/oauth/request_token"
    ACCESS_TOKEN_URL = "https://api.tripit.com/oauth/access_token"
    EXTRA_DATA = [("screen_name", "screen_name")]

    def get_user_details(self, response):
        """Return user details from TripIt account"""
        fullname = response["name"]
        first_name = None
        last_name = None
        return {
            "username": response["screen_name"],
            "email": response["email"],
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def get_email_verified(self, response: Any) -> bool:
        """Return whether the TripIt profile address was confirmed"""
        return response.get("email_confirmed") is True

    def user_data(self, access_token: dict, *args, **kwargs) -> dict[str, Any] | None:
        """Return user data provided"""
        content: str = self.oauth_request(
            access_token, "https://api.tripit.com/v1/get/profile"
        ).text
        dom = minidom.parseString(content)
        profiles = dom.getElementsByTagName("Profile")
        public_display_names = dom.getElementsByTagName("public_display_name")
        screen_names = dom.getElementsByTagName("screen_name")
        primary = cast("Element", dom.getElementsByTagName("is_primary")[0].parentNode)
        primary_email = primary.getElementsByTagName("address")
        is_confirmed = primary.getElementsByTagName("is_confirmed")
        return {
            "id": profiles[0].getAttribute("ref"),
            "name": public_display_names[0].childNodes[0].nodeValue,
            "screen_name": screen_names[0].childNodes[0].nodeValue,
            "email": primary_email[0].childNodes[0].nodeValue,
            "email_confirmed": any(
                node.firstChild is not None and node.firstChild.nodeValue == "true"
                for node in is_confirmed
            ),
        }
