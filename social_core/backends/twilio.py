"""
Twilio auth backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/twilio.html
"""

from urllib.parse import urlencode

from social_core.exceptions import (
    AuthFailed,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
)
from social_core.utils import constant_time_compare, url_add_parameters

from .base import BaseAuth


class TwilioAuth(BaseAuth):
    name = "twilio"
    ID_KEY = "AccountSid"
    REDIRECT_STATE = True

    def get_user_details(self, response):
        """Return twilio details, Twilio only provides AccountSID as
        parameters."""
        # /complete/twilio/?AccountSid=ACc65ea16c9ebd4d4684edf814995b27e
        return {
            "username": response["AccountSid"],
            "email": "",
            "fullname": "",
            "first_name": "",
            "last_name": "",
        }

    def auth_url(self) -> str:
        """Return authorization redirect url."""
        key, _secret = self.get_key_and_secret()
        callback = self.get_redirect_uri(self.get_or_create_state())
        query = urlencode({"cb": callback})
        return f"https://www.twilio.com/authorize/{key}?{query}"

    def state_token(self):
        """Generate csrf token to include in the callback URL."""
        return self.strategy.random_string(32)

    def get_or_create_state(self) -> str:
        name = f"{self.name}_state"
        state = self.strategy.session_get(name)
        if state is None:
            state = self.state_token()
            self.strategy.session_set(name, state)
        return state

    def get_session_state(self):
        return self.strategy.session_get(f"{self.name}_state")

    def get_request_state(self):
        request_state = self.data.get("redirect_state")
        if request_state and isinstance(request_state, list):
            request_state = request_state[0]
        return request_state

    def validate_state(self):
        """Validate state value. Raises exception on error."""
        state = self.get_session_state()
        request_state = self.get_request_state()
        if not request_state:
            raise AuthMissingParameter(self, "state")
        if not state:
            raise AuthStateMissing(self, "state")
        if not constant_time_compare(request_state, state):
            raise AuthStateForbidden(self)

    def get_redirect_uri(self, state: str | None = None) -> str:
        uri = self.strategy.absolute_uri(self.redirect_uri)
        if self.REDIRECT_STATE and state:
            uri = url_add_parameters(uri, {"redirect_state": state})
        return uri

    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        account_sid = self.data.get("AccountSid")
        if not account_sid:
            raise AuthFailed(self, "Missing AccountSid")
        self.validate_state()
        kwargs.update({"response": self.data, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)
