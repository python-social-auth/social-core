"""
Twilio Connect association backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/twilio.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from social_core.exceptions import (
    AuthFailed,
    AuthForbidden,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
)
from social_core.utils import (
    constant_time_compare,
    url_add_parameters,
    user_is_authenticated,
)

from .base import BaseAuth

if TYPE_CHECKING:
    from social_core.storage import PartialMixin, UserProtocol


class TwilioAuth(BaseAuth):
    """Associate Twilio Connect access with an authenticated local user."""

    name = "twilio"
    ID_KEY = "AccountSid"
    REDIRECT_STATE = True
    ASSOCIATION_USER_ID_KEY = "twilio_association_user_id"
    DISCONNECT_USER_ID_KEY = "twilio_disconnect_user_id"

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
        context = self.get_session_state()
        if not isinstance(context, dict) or not context.get("state"):
            raise AuthStateMissing(self, "state")
        callback = self.get_redirect_uri(context["state"])
        query = urlencode({"cb": callback})
        return f"https://www.twilio.com/authorize/{key}?{query}"

    def state_token(self) -> str:
        """Generate csrf token to include in the callback URL."""
        return self.strategy.random_string(32)

    def prepare_auth(self, user: UserProtocol | None = None) -> None:
        """Bind a new Twilio Connect association attempt to a local user."""
        if user is None or not user_is_authenticated(user):
            raise AuthForbidden(self, "Twilio Connect requires an authenticated user")
        self.strategy.session_set(
            f"{self.name}_state",
            {"state": self.state_token(), "user_id": str(user.id)},
        )

    def get_session_state(self):
        return self.strategy.session_get(f"{self.name}_state")

    def get_request_state(self):
        request_state = self.data.get("redirect_state")
        if request_state and isinstance(request_state, list):
            request_state = request_state[0]
        return request_state

    def validate_state(self, user: UserProtocol | None = None) -> UserProtocol:
        """Validate and consume state bound to the current local user."""
        context = self.get_session_state()
        request_state = self.get_request_state()
        if not request_state:
            raise AuthMissingParameter(self, "state")
        if not isinstance(context, dict):
            raise AuthStateMissing(self, "state")
        state = context.get("state")
        if (
            not isinstance(request_state, (str, bytes))
            or not isinstance(state, (str, bytes))
            or not constant_time_compare(request_state, state)
        ):
            raise AuthStateForbidden(self)
        if (
            user is None
            or not user_is_authenticated(user)
            or context.get("user_id") != str(user.id)
        ):
            raise AuthForbidden(self, "Twilio Connect association user mismatch")
        self.strategy.session_pop(f"{self.name}_state")
        return user

    def validate_partial_pipeline(
        self, partial: PartialMixin, user: UserProtocol | None = None
    ) -> None:
        """Require a partial flow to remain bound to its authenticated initiator."""
        if user is None or not user_is_authenticated(user):
            raise AuthForbidden(self, "Twilio Connect association user mismatch")
        initiator_id = partial.kwargs.get(
            self.ASSOCIATION_USER_ID_KEY
        ) or partial.kwargs.get(self.DISCONNECT_USER_ID_KEY)
        if initiator_id != str(user.id):
            raise AuthForbidden(self, "Twilio Connect association user mismatch")

    def disconnect(self, *args, **kwargs) -> dict:
        """Bind Twilio disconnection pipelines to their initiating local user."""
        user = kwargs.get("user")
        if user is None or not user_is_authenticated(user):
            raise AuthForbidden(
                self, "Twilio disconnect requires an authenticated user"
            )
        kwargs[self.DISCONNECT_USER_ID_KEY] = str(user.id)
        return super().disconnect(*args, **kwargs)

    def get_redirect_uri(self, state: str | None = None) -> str:
        uri = self.strategy.absolute_uri(self.redirect_uri)
        if self.REDIRECT_STATE and state:
            uri = url_add_parameters(uri, {"redirect_state": state})
        return uri

    def auth_complete(self, *args, **kwargs):
        """Associate Twilio Connect access with the initiating local user."""
        user = self.validate_state(kwargs.get("user"))
        account_sid = self.data.get("AccountSid")
        if not account_sid:
            raise AuthFailed(self, "Missing AccountSid")
        kwargs.update(
            {
                "response": self.data,
                "backend": self,
                self.ASSOCIATION_USER_ID_KEY: str(user.id),
            }
        )
        return self.strategy.authenticate(*args, **kwargs)
