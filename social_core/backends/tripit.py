"""
Tripit OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/tripit.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from defusedxml import minidom

from .oauth import BaseOAuth1

if TYPE_CHECKING:
    from xml.dom.minidom import Element


class TripItOAuth(BaseOAuth1):
    """TripIt OAuth authentication backend"""

    name = "tripit"
    AUTHORIZATION_URL = "https://www.tripit.com/oauth/authorize"
    REQUEST_TOKEN_URL = "https://api.tripit.com/oauth/request_token"
    ACCESS_TOKEN_URL = "https://api.tripit.com/oauth/access_token"
    EXTRA_DATA = [("screen_name", "screen_name")]

    def get_user_details(self, response):
        """Return user details from TripIt account"""
        fullname, first_name, last_name = self.get_user_names(response["name"])
        return {
            "username": response["screen_name"],
            "email": response["email"],
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token, *args, **kwargs):
        """Return user data provided"""
        content: str = self.oauth_request(
            access_token, "https://api.tripit.com/v1/get/profile"
        ).text
        dom = minidom.parseString(content)
        profiles = dom.getElementsByTagName("Profile")
        public_display_names = dom.getElementsByTagName("public_display_name")
        screen_names = dom.getElementsByTagName("screen_name")
        primary_email = cast(
            "Element", dom.getElementsByTagName("is_primary")[0].parentNode
        ).getElementsByTagName("address")
        return {
            "id": profiles[0].getAttribute("ref"),
            "name": public_display_names[0].childNodes[0].nodeValue,
            "screen_name": screen_names[0].childNodes[0].nodeValue,
            "email": primary_email[0].childNodes[0].nodeValue,
        }
