from typing import Any, Literal

import requests

from social_core.exceptions import AuthProviderError, ErrorStage
from social_core.utils import handle_http_errors

from .oauth import BaseOAuth2


class UntappdOAuth2(BaseOAuth2):
    """Untappd OAuth2 authentication backend"""

    name = "untappd"
    title = "Untappd"
    AUTHORIZATION_URL = "https://untappd.com/oauth/authenticate/"
    ACCESS_TOKEN_URL = "https://untappd.com/oauth/authorize/"
    BASE_API_URL = "https://api.untappd.com"
    USER_INFO_URL = f"{BASE_API_URL}/v4/user/info/"
    ACCESS_TOKEN_METHOD: Literal["GET", "POST"] = "GET"
    STATE_PARAMETER = True
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("id", "id"),
        ("bio", "bio"),
        ("date_joined", "date_joined"),
        ("location", "location"),
        ("url", "url"),
        ("user_avatar", "user_avatar"),
        ("user_avatar_hd", "user_avatar_hd"),
        ("user_cover_photo", "user_cover_photo"),
    ]

    def auth_params(self, state=None):
        client_id, _client_secret = self.get_key_and_secret()
        params = {
            "client_id": client_id,
            "redirect_url": self.get_redirect_uri(),
            "response_type": self.RESPONSE_TYPE,
        }
        if self.STATE_PARAMETER and state:
            params["state"] = state
        return params

    def process_error(self, data, *, stage: ErrorStage = "callback") -> None:
        """
        All errors from Untappd are contained in the 'meta' key of the
        response.
        """
        super().process_error(data, stage=stage)
        response_code = data.get("meta", {}).get("http_code")
        if response_code is not None and response_code != requests.codes.ok:
            code = (
                "rate_limited"
                if response_code == 429
                else "unavailable"
                if response_code >= 500
                else "http_error"
            )
            raise AuthProviderError(
                self,
                data["meta"].get("error_detail"),
                code=code,
                status_code=response_code,
                stage=stage,
            )

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        client_id, client_secret = self.get_key_and_secret()
        code = self.data.get("code")

        self.process_error(self.data)
        state = self.validate_state()

        # Untapped sends the access token request with URL parameters,
        # not a body
        response = self.request_access_token(
            self.access_token_url(),
            method=self.ACCESS_TOKEN_METHOD,
            params={
                "response_type": "code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_url": self.get_redirect_uri(state),
            },
        )

        self.process_error(response, stage="token_exchange")

        # Both the access_token and the rest of the response are
        # buried in the 'response' key
        return self.do_auth(
            response["response"]["access_token"],
            *args,
            response=response["response"],
            **kwargs,
        )

    def get_user_details(self, response):
        """Return user details from an Untappd account"""
        # Start with the user data as it was returned
        user_data = response["user"]

        # Make a few updates to match expected key names
        user_data.update(
            {
                "username": user_data.get("user_name"),
                "email": user_data.get("settings", {}).get("email_address", ""),
                "first_name": user_data.get("first_name"),
                "last_name": user_data.get("last_name"),
                "fullname": user_data.get("fullname", ""),
            }
        )
        return user_data

    def get_user_id(self, details, response):
        """
        Return a unique ID for the current user, by default from
        server response.
        """
        return self.get_user_id_from_sources(response.get("user"), details)

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        response = self.get_json(
            self.USER_INFO_URL, params={"access_token": access_token, "compact": "true"}
        )
        self.process_error(response, stage="user_info")

        # The response data is buried in the 'response' key
        return response["response"]
