from google.auth.transport import requests as transport_requests
from google.oauth2 import id_token

from social_core.backends.base import BaseAuth
from social_core.backends.google import BaseGoogleAuth
from social_core.exceptions import (
    AuthConfigurationError,
    AuthResponseError,
    AuthSessionError,
)
from social_core.utils import constant_time_compare


class GoogleOneTap(BaseGoogleAuth, BaseAuth):
    name = "google-onetap"
    title = "Google"
    icon = "google.svg"
    ID_KEY = "sub"
    EXTRA_DATA = [("sub", "sub")]
    CSRF_KEY = "g_csrf_token"
    CREDENTIAL_KEY = "credential"

    def auth_url(self):
        raise AuthConfigurationError(
            self,
            "Cannot start login flow for Google One Tap",
            code="invalid_setting",
            stage="begin",
        )

    def verify_csrf(self, request) -> None:
        csrf_token_body = self.data.get(self.CSRF_KEY)
        csrf_token_cookie = request.COOKIES.get(self.CSRF_KEY)

        if not csrf_token_body:
            raise AuthResponseError(
                self,
                "Missing csrf token from response",
                code="nonce_mismatch",
                stage="callback",
            )

        # csrf_token_cookie can be missing due to https://issuetracker.google.com/issues/226157137
        if not csrf_token_cookie and self.setting("IGNORE_MISSING_CSRF_COOKIE", False):
            return

        if (
            not isinstance(csrf_token_body, str)
            or not isinstance(csrf_token_cookie, str)
            or not constant_time_compare(csrf_token_body, csrf_token_cookie)
        ):
            raise AuthSessionError(
                self,
                "csrf token from cookie and response does not match",
                code="state_mismatch"
                if csrf_token_cookie
                else "session_context_missing",
                stage="callback",
            )

    def get_decoded_info(self):
        # google-auth skips audience validation when it receives None.
        client_id = self.setting("KEY")
        if not client_id:
            raise AuthConfigurationError(
                self,
                parameter="SOCIAL_AUTH_GOOGLE_ONETAP_KEY",
                code="missing_setting",
                stage="token_validation",
            )

        try:
            idinfo = id_token.verify_oauth2_token(
                self.data.get(self.CREDENTIAL_KEY),
                transport_requests.Request(),
                client_id,
            )
        except ValueError as error:
            raise AuthResponseError(
                self,
                "Invalid response from Google",
                code="invalid_claim",
                stage="token_validation",
            ) from error

        self.validate_email_verified(idinfo, stage="token_validation")
        return idinfo

    def auth_complete(self, *args, **kwargs):
        self.verify_csrf(kwargs["request"])

        response = self.get_decoded_info()
        kwargs.update({"response": response, "backend": self})

        return self.strategy.authenticate(*args, **kwargs)
