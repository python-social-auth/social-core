import hashlib

from social_core.exceptions import (
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
)
from social_core.utils import (
    constant_time_compare,
    handle_http_errors,
    url_add_parameters,
)

from .base import BaseAuth


class LastFmAuth(BaseAuth):
    """
    Last.Fm authentication backend. Requires two settings:
        SOCIAL_AUTH_LASTFM_KEY
        SOCIAL_AUTH_LASTFM_SECRET

    Don't forget to set the Last.fm callback to something sensible like
        http://your.site/lastfm/complete
    """

    name = "lastfm"
    ID_KEY = "name"
    REQUIRES_USER_ID = True
    AUTH_URL = "https://www.last.fm/api/auth/?api_key={api_key}"
    EXTRA_DATA = [("key", "session_key")]

    def auth_url(self):
        callback = self.get_redirect_uri(self.get_or_create_state())
        return url_add_parameters(
            self.AUTH_URL.format(api_key=self.setting("KEY")), {"cb": callback}
        )

    def state_token(self):
        """Generate a CSRF token to include in the callback URL."""
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
        """Validate that the callback belongs to the initiating session."""
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
        if state:
            uri = url_add_parameters(uri, {"redirect_state": state})
        return uri

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        self.validate_state()
        key, secret = self.get_key_and_secret()
        token = self.data.get("token")
        if not token:
            raise AuthMissingParameter(self, "token")

        # Usage of md5 is mandated by the API: https://www.last.fm/api/webauth
        signature = hashlib.md5(  # noqa: S324
            f"api_key{key}methodauth.getSessiontoken{token}{secret}".encode()
        ).hexdigest()

        response = self.get_json(
            "https://ws.audioscrobbler.com/2.0/",
            data={
                "method": "auth.getSession",
                "api_key": key,
                "token": token,
                "api_sig": signature,
                "format": "json",
            },
            method="POST",
        )

        kwargs.update({"response": response["session"], "backend": self})
        return self.strategy.authenticate(*args, **kwargs)

    def get_user_details(self, response):
        fullname, first_name, last_name = self.get_user_names(response["name"])
        return {
            "username": response["name"],
            "email": "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }
