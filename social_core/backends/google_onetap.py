from google.auth.transport import requests as transport_requests
from google.oauth2 import id_token

from social_core.backends.base import BaseAuth
from social_core.backends.google import BaseGoogleAuth
from social_core.exceptions import AuthException, AuthTokenError


class GoogleOneTap(BaseGoogleAuth, BaseAuth):
    name = "google-onetap"
    CSRF_KEY = "g_csrf_token"
    CREDENTIAL_KEY = "credential"

    def auth_url(self):
        raise AuthException(self, "Cannot start login flow for Google One Tap")

    def verify_csrf(self, request) -> None:
        csrf_token_body = self.data.get(self.CSRF_KEY)
        csrf_token_cookie = request.COOKIES.get(self.CSRF_KEY)

        if not csrf_token_body:
            raise AuthTokenError(self, "Missing csrf token from response")

        # csrf_token_cookie can be missing due to https://issuetracker.google.com/issues/226157137
        if not csrf_token_cookie and self.setting("IGNORE_MISSING_CSRF_COOKIE", False):
            return

        if csrf_token_body != csrf_token_cookie:
            raise AuthTokenError(
                self, "csrf token from cookie and response does not match"
            )

    def get_decoded_info(self):
        try:
            idinfo = id_token.verify_oauth2_token(
                self.data.get(self.CREDENTIAL_KEY),
                transport_requests.Request(),
                self.setting("KEY"),
            )
        except ValueError:
            raise AuthException(self, "Invalid response from Google")

        return idinfo

    def auth_complete(self, *args, **kwargs):
        self.verify_csrf(kwargs["request"])

        response = self.get_decoded_info()
        kwargs.update({"response": response, "backend": self})

        return self.strategy.authenticate(*args, **kwargs)
