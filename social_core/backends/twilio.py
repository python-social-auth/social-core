"""
Twilio Connect association backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/twilio.html
"""

from __future__ import annotations

from urllib.parse import urlencode

from social_core.exceptions import AuthFailed
from social_core.utils import url_add_parameters

from .base import BaseAuth


class TwilioAuth(BaseAuth):
    """Associate Twilio Connect access with an authenticated local user."""

    name = "twilio"
    ID_KEY = "AccountSid"
    REDIRECT_STATE = True
    ASSOCIATION_ONLY = True

    def get_user_details(self, response):
        """Return twilio details, Twilio only provides AccountSID as
        parameters."""
        # /complete/twilio/?AccountSid=ACc65ea16c9ebd4d4684edf814995b27e
        return {
            "username": response["AccountSid"],
        }

    def auth_url(self) -> str:
        """Return authorization redirect url."""
        key, _secret = self.get_key_and_secret()
        callback = self.get_redirect_uri(self.get_association_state())
        query = urlencode({"cb": callback})
        return f"https://www.twilio.com/authorize/{key}?{query}"

    def get_session_state(self):
        return self.strategy.session_get(f"{self.name}_state")

    def get_request_state(self):
        request_state = self.data.get("redirect_state")
        if request_state and isinstance(request_state, list):
            request_state = request_state[0]
        return request_state

    def get_redirect_uri(self, state: str | None = None) -> str:
        uri = self.strategy.absolute_uri(self.redirect_uri)
        if self.REDIRECT_STATE and state:
            uri = url_add_parameters(uri, {"redirect_state": state})
        return uri

    def auth_complete(self, *args, **kwargs):
        """Associate Twilio Connect access with the initiating local user."""
        self.validate_association_state(self.get_request_state(), kwargs.get("user"))
        account_sid = self.data.get("AccountSid")
        if not account_sid:
            raise AuthFailed(self, "Missing AccountSid")
        kwargs.update(
            {
                "response": self.data,
                "backend": self,
            }
        )
        return self.strategy.authenticate(*args, **kwargs)
