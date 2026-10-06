"""
LINE Login OAuth2 backend, docs at:
    https://developers.line.me/en/docs/line-login/
"""

from typing import Any

import requests
from requests import Response

from social_core.exceptions import AuthProviderError, ErrorStage
from social_core.utils import handle_http_errors

from .oauth import BaseOAuth2


class LineOAuth2(BaseOAuth2):
    name = "line"
    title = "LINE"
    AUTHORIZATION_URL = "https://access.line.me/oauth2/v2.1/authorize"
    ACCESS_TOKEN_URL = "https://api.line.me/oauth2/v2.1/token"
    BASE_API_URL = "https://api.line.me"
    USER_INFO_URL = f"{BASE_API_URL}/v2/profile"
    STATE_PARAMETER = True
    DEFAULT_SCOPE = ["profile"]
    REDIRECT_STATE = True
    ID_KEY = "userId"
    EXTRA_DATA = [
        ("userId", "id"),
        ("picture_url", "picture_url"),
        ("status_message", "status_message"),
        ("expires_in", "expire"),
        ("refresh_token", "refresh_token"),
    ]

    def auth_params(self, state=None):
        client_id, _client_secret = self.get_key_and_secret()
        return {
            "response_type": self.RESPONSE_TYPE,
            "client_id": client_id,
            "redirect_uri": self.get_redirect_uri(),
            "state": self.get_or_create_state(),
            "scope": self.get_scope(),
        }

    def process_error(self, data, *, stage: ErrorStage = "callback") -> None:
        super().process_error(data, stage=stage)
        error_code = (
            data.get("errorCode") or data.get("statusCode") or data.get("error")
        )
        error_message = data.get("errorMessage") or data.get("error_description")
        if error_code is not None or error_message is not None:
            raise AuthProviderError(
                self,
                error_message or error_code,
                provider_code=error_code,
                code="http_error",
                stage=stage,
            )

    def request(self, *args, **kwargs) -> Response:
        """Keep native diagnostics while retaining HTTP status recovery guidance."""
        try:
            return super().request(*args, **kwargs)
        except AuthProviderError as error:
            cause = error.__cause__
            if isinstance(cause, requests.HTTPError) and cause.response is not None:
                try:
                    data = cause.response.json()
                except ValueError:
                    data = None
                if isinstance(data, dict):
                    provider_code = data.get("errorCode") or data.get("statusCode")
                    if isinstance(provider_code, (str, int)):
                        error.provider_code = provider_code
                    detail = data.get("errorMessage")
                    if detail is not None:
                        error.detail = str(detail)
            raise

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        self.process_error(self.data)
        self.validate_state()

        response = self.request_access_token(
            self.access_token_url(),
            method=self.ACCESS_TOKEN_METHOD,
            headers=self.auth_headers(),
            data=self.auth_complete_params(),
        )
        access_token = self.get_access_token(response)
        return self.do_auth(access_token, *args, response=response, **kwargs)

    def get_user_details(self, response):
        fullname = response.get("displayName")
        first_name = None
        last_name = None
        username = response.get("userId")
        picture_url = response.get("pictureUrl")
        status_message = response.get("statusMessage")
        return {
            "username": username,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "picture_url": picture_url,
            "status_message": status_message,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        response = self.get_json(
            self.USER_INFO_URL, headers={"Authorization": f"Bearer {access_token}"}
        )
        self._process_error(response, stage="user_info")
        return response
