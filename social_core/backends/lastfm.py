import hashlib

from social_core.exceptions import (
    AuthInputError,
    AuthProviderError,
    AuthResponseError,
    AuthSessionError,
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
    title = "Last.fm"
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
            raise AuthInputError(
                self, parameter="state", code="missing_parameter", stage="callback"
            )
        if not state:
            raise AuthSessionError(
                self, "state", code="session_context_missing", stage="callback"
            )
        if not constant_time_compare(request_state, state):
            raise AuthSessionError(self, code="state_mismatch", stage="callback")

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
            raise AuthInputError(
                self, parameter="token", code="missing_parameter", stage="callback"
            )

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
            stage="token_exchange",
        )

        if not isinstance(response, dict):
            raise AuthResponseError(
                self, code="malformed_response", stage="token_exchange"
            )
        if "error" in response:
            provider_code = response["error"]
            code = "http_error"
            if provider_code == 29:
                code = "rate_limited"
            elif provider_code in (11, 16):
                code = "unavailable"
            raise AuthProviderError(
                self,
                response.get("message"),
                provider_code=provider_code,
                code=code,
                stage="token_exchange",
            )
        session = response.get("session")
        if not isinstance(session, dict):
            raise AuthResponseError(
                self,
                code="missing_claim" if session is None else "malformed_response",
                claim="session",
                stage="token_exchange",
            )
        kwargs.update({"response": session, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)

    def get_user_details(self, response):
        fullname = response["name"]
        first_name = ""
        last_name = ""
        return {
            "username": response["name"],
            "email": "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }
