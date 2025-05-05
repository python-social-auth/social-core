from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import urlencode

from oauthlib.oauth1 import SIGNATURE_TYPE_AUTH_HEADER
from requests_oauthlib import OAuth1

from ..exceptions import (
    AuthCanceled,
    AuthException,
    AuthFailed,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
    AuthTokenError,
    AuthUnknownError,
)
from ..utils import (
    constant_time_compare,
    handle_http_errors,
    parse_qs,
    url_add_parameters,
)
from .base import BaseAuth

if TYPE_CHECKING:
    from collections.abc import Mapping

    from requests import Response
    from requests.auth import AuthBase


class OAuthAuth(BaseAuth):
    """OAuth authentication backend base class.

    Settings will be inspected to get more values names that should be
    stored on extra_data field. The setting name is created following the
    pattern SOCIAL_AUTH_<uppercase current backend name>_EXTRA_DATA.

    access_token is always stored.

    URLs settings:
        AUTHORIZATION_URL       Authorization service url
        ACCESS_TOKEN_URL        Access token URL
    """

    AUTHORIZATION_URL = ""
    ACCESS_TOKEN_URL = ""
    ACCESS_TOKEN_METHOD: Literal["GET", "POST"] = "POST"
    REVOKE_TOKEN_URL: str = ""
    REVOKE_TOKEN_METHOD: Literal["GET", "POST", "DELETE"] = "POST"
    ID_KEY = "id"
    SCOPE_PARAMETER_NAME = "scope"
    DEFAULT_SCOPE: list[str] | None = None
    SCOPE_SEPARATOR = " "
    REDIRECT_STATE = False
    STATE_PARAMETER = False

    def extra_data(self, user, uid, response, details=None, *args, **kwargs):
        """Return access_token and extra defined names to store in
        extra_data field"""
        data = super().extra_data(user, uid, response, details, *args, **kwargs)
        data["access_token"] = response.get("access_token", "") or kwargs.get(
            "access_token"
        )
        return data

    def state_token(self):
        """Generate csrf token to include as state parameter."""
        return self.strategy.random_string(32)

    def get_or_create_state(self) -> str | None:
        if self.STATE_PARAMETER or self.REDIRECT_STATE:
            # Store state in session for further request validation. The state
            # value is passed as state parameter (as specified in OAuth2 spec),
            # but also added to redirect, that way we can still verify the
            # request if the provider doesn't implement the state parameter.
            # Reuse token if any.
            name = self.name + "_state"
            state = self.strategy.session_get(name)
            if state is None:
                state = self.state_token()
                self.strategy.session_set(name, state)
        else:
            state = None
        return state

    def get_session_state(self):
        return self.strategy.session_get(self.name + "_state")

    def get_request_state(self):
        request_state = self.data.get("state") or self.data.get("redirect_state")
        if request_state and isinstance(request_state, list):
            request_state = request_state[0]
        return request_state

    def validate_state(self):
        """Validate state value. Raises exception on error, returns state
        value if valid."""
        if not self.STATE_PARAMETER and not self.REDIRECT_STATE:
            return None
        state = self.get_session_state()
        request_state = self.get_request_state()
        if not request_state:
            raise AuthMissingParameter(self, "state")
        if not state:
            raise AuthStateMissing(self, "state")
        if not constant_time_compare(request_state, state):
            raise AuthStateForbidden(self)
        return state

    def get_redirect_uri(self, state: str | None = None) -> str:
        """Build redirect with redirect_state parameter."""
        uri = cast("str", self.redirect_uri)
        if self.REDIRECT_STATE and state:
            uri = url_add_parameters(uri, {"redirect_state": state})
        return uri

    def get_scope(self):
        """Return list with needed access scope"""
        scope = self.setting("SCOPE", [])
        if not self.setting("IGNORE_DEFAULT_SCOPE", False):
            scope = scope + (self.DEFAULT_SCOPE or [])
        return scope

    def get_scope_argument(self):
        param = {}
        scope = self.get_scope()
        if scope:
            param[self.SCOPE_PARAMETER_NAME] = self.SCOPE_SEPARATOR.join(scope)
        return param

    def user_data(self, access_token, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service. Implement in subclass"""
        return {}

    def authorization_url(self) -> str:
        return self.AUTHORIZATION_URL

    def access_token_url(self) -> str:
        return self.ACCESS_TOKEN_URL

    def revoke_token_url(self, token, uid) -> str:
        return self.REVOKE_TOKEN_URL

    def revoke_token_params(self, token, uid) -> dict[str, Any]:
        return {}

    def revoke_token_headers(self, token, uid) -> dict[str, Any]:
        return {}

    def process_revoke_token_response(self, response):
        return response.status_code == 200

    def revoke_token(self, token, uid):
        if revoke_token_url := self.revoke_token_url(token, uid):
            params = self.revoke_token_params(token, uid)
            headers = self.revoke_token_headers(token, uid)
            data = urlencode(params) if self.REVOKE_TOKEN_METHOD != "GET" else None
            response = self.request(
                revoke_token_url,
                params=params,
                headers=headers,
                data=data,
                method=self.REVOKE_TOKEN_METHOD,
            )
            return self.process_revoke_token_response(response)
        return None


class BaseOAuth1(OAuthAuth):
    """Consumer based mechanism OAuth authentication, fill the needed
    parameters to communicate properly with authentication service.

    URLs settings:
        REQUEST_TOKEN_URL       Request token URL

    """

    REQUEST_TOKEN_URL = ""
    REQUEST_TOKEN_METHOD: Literal["GET", "POST"] = "GET"
    OAUTH_TOKEN_PARAMETER_NAME = "oauth_token"
    REDIRECT_URI_PARAMETER_NAME = "redirect_uri"
    UNATHORIZED_TOKEN_SUFIX = "unauthorized_token_name"

    def auth_url(self) -> str | bytes | None:
        """Return redirect url"""
        token = self.set_unauthorized_token()
        return self.oauth_authorization_request(token)

    def process_error(self, data):
        if "oauth_problem" in data:
            if data["oauth_problem"] == "user_refused":
                raise AuthCanceled(self, "User refused the access")
            raise AuthUnknownError(self, "Error was " + data["oauth_problem"])

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Return user, might be logged in"""
        # Multiple unauthorized tokens are supported (see #521)
        self.process_error(self.data)
        self.validate_state()
        token = self.get_unauthorized_token()
        access_token = self.access_token(token)
        return self.do_auth(access_token, *args, **kwargs)

    @handle_http_errors
    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        if not isinstance(access_token, dict):
            access_token = parse_qs(access_token)
        data = self.user_data(access_token)
        if data is not None and "access_token" not in data:
            data["access_token"] = access_token
        kwargs.update({"response": data, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)

    def get_unauthorized_token(self):
        name = self.name + self.UNATHORIZED_TOKEN_SUFIX
        unauthed_tokens = self.strategy.session_get(name, [])
        if not unauthed_tokens:
            raise AuthTokenError(self, "Missing unauthorized token")

        data_token = self.data.get(self.OAUTH_TOKEN_PARAMETER_NAME)

        if data_token is None:
            raise AuthTokenError(self, "Missing unauthorized token")

        token = None
        for utoken in unauthed_tokens:
            orig_utoken = utoken
            if not isinstance(utoken, dict):
                utoken = parse_qs(utoken)
            if utoken.get(self.OAUTH_TOKEN_PARAMETER_NAME) == data_token:
                self.strategy.session_set(
                    name, list(set(unauthed_tokens) - {orig_utoken})
                )
                token = utoken
                break
        else:
            raise AuthTokenError(self, "Incorrect tokens")
        return token

    def set_unauthorized_token(self):
        token = self.unauthorized_token()
        name = self.name + self.UNATHORIZED_TOKEN_SUFIX
        tokens = [*self.strategy.session_get(name, []), token]
        self.strategy.session_set(name, tokens)
        return token

    def request_token_extra_arguments(self):
        """Return extra arguments needed on request-token process"""
        return self.setting("REQUEST_TOKEN_EXTRA_ARGUMENTS", {})

    def unauthorized_token(self):
        """Return request for unauthorized token (first stage)"""
        params = self.request_token_extra_arguments()
        params.update(self.get_scope_argument())
        key, secret = self.get_key_and_secret()
        state = self.get_or_create_state()
        response = self.request(
            self.REQUEST_TOKEN_URL,
            params=params,
            auth=OAuth1(key, secret, callback_uri=self.get_redirect_uri(state)),
            method=self.REQUEST_TOKEN_METHOD,
        )
        content = response.content
        if response.encoding or response.apparent_encoding:
            content = content.decode(response.encoding or response.apparent_encoding)
        else:
            content = response.content.decode()
        return content

    def oauth_authorization_request(self, token):
        """Generate OAuth request to authorize token."""
        if not isinstance(token, dict):
            token = parse_qs(token)
        params = self.auth_extra_arguments() or {}
        params.update(self.get_scope_argument())
        params[self.OAUTH_TOKEN_PARAMETER_NAME] = token.get(
            self.OAUTH_TOKEN_PARAMETER_NAME
        )
        state = self.get_or_create_state()
        params[self.REDIRECT_URI_PARAMETER_NAME] = self.get_redirect_uri(state)
        return url_add_parameters(self.authorization_url(), params)

    def oauth_auth(
        self,
        token: dict | None = None,
        oauth_verifier=None,
        signature_type=SIGNATURE_TYPE_AUTH_HEADER,
    ):
        key, secret = self.get_key_and_secret()
        oauth_verifier = oauth_verifier or self.data.get("oauth_verifier")
        if token:
            resource_owner_key = token.get("oauth_token")
            resource_owner_secret = token.get("oauth_token_secret")
            if not resource_owner_key:
                raise AuthTokenError(self, "Missing oauth_token")
            if not resource_owner_secret:
                raise AuthTokenError(self, "Missing oauth_token_secret")
        else:
            resource_owner_key = None
            resource_owner_secret = None
        state = self.get_or_create_state()
        return OAuth1(
            key,
            secret,
            resource_owner_key=resource_owner_key,
            resource_owner_secret=resource_owner_secret,
            callback_uri=self.get_redirect_uri(state),
            verifier=oauth_verifier,
            signature_type=signature_type,
        )

    def oauth_request(
        self, token: dict, url: str, params=None, method: Literal["GET", "POST"] = "GET"
    ) -> Response:
        """Generate OAuth request, setups callback url"""
        return self.request(
            url, method=method, params=params, auth=self.oauth_auth(token)
        )

    def access_token(self, token: dict) -> dict[str, str]:
        """Return request for access token value"""
        return self.get_querystring(
            self.access_token_url(),
            auth=self.oauth_auth(token),
            method=self.ACCESS_TOKEN_METHOD,
        )


class BaseOAuth2(OAuthAuth):
    """Base class for OAuth2 providers.

    OAuth2 details at:
        https://datatracker.ietf.org/doc/html/rfc6749
    """

    REFRESH_TOKEN_URL: str | None = None
    REFRESH_TOKEN_METHOD = "POST"
    RESPONSE_TYPE: str | None = "code"
    REDIRECT_STATE = True
    STATE_PARAMETER = True
    USE_BASIC_AUTH = False

    def use_basic_auth(self) -> bool:
        return self.USE_BASIC_AUTH

    def auth_params(self, state: str | None = None) -> dict[str, str]:
        client_id, client_secret = self.get_key_and_secret()
        params = {"client_id": client_id, "redirect_uri": self.get_redirect_uri(state)}
        if self.STATE_PARAMETER and state:
            params["state"] = state
        if self.RESPONSE_TYPE:
            params["response_type"] = self.RESPONSE_TYPE
        return params

    def auth_url(self) -> str | bytes | None:
        """Return redirect url"""
        state = self.get_or_create_state()
        params = self.auth_params(state)
        params.update(self.get_scope_argument())
        params.update(self.auth_extra_arguments())

        # when self.REDIRECT_STATE is False, redirect_uri matching is strictly enforced,
        # so match the providers value exactly.
        return url_add_parameters(
            self.authorization_url(), params, not self.REDIRECT_STATE
        )

    def auth_complete_params(self, state=None):
        params = {
            "grant_type": "authorization_code",  # request auth code
            "code": self.data.get("code", ""),  # server response code
            "redirect_uri": self.get_redirect_uri(state),
        }
        if not self.use_basic_auth():
            client_id, client_secret = self.get_key_and_secret()
            params.update(
                {
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
            )
        return params

    def auth_complete_credentials(self):
        if self.use_basic_auth():
            return self.get_key_and_secret()
        return None

    def auth_headers(self) -> Mapping[str, str | bytes]:
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

    def extra_data(self, user, uid, response, details, *args, **kwargs):
        """Return access_token, token_type, and extra defined names to store in
        extra_data field"""
        data = super().extra_data(user, uid, response, details=details, *args, **kwargs)
        data["token_type"] = response.get("token_type") or kwargs.get("token_type")
        return data

    def request_access_token(
        self,
        url: str,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | bytes | str | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
    ) -> dict[Any, Any]:
        return self.get_json(
            url, method=method, headers=headers, data=data, auth=auth, params=params
        )

    def process_error(self, data):
        if data.get("error"):
            if "denied" in data["error"] or "cancelled" in data["error"]:
                raise AuthCanceled(self, data.get("error_description", ""))
            raise AuthFailed(self, data.get("error_description") or data["error"])
        if "denied" in data:
            raise AuthCanceled(self, data["denied"])

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        self.process_error(self.data)
        state = self.validate_state()
        data, params = None, None
        if self.ACCESS_TOKEN_METHOD == "GET":
            params = self.auth_complete_params(state)
        else:
            data = self.auth_complete_params(state)

        response = self.request_access_token(
            self.access_token_url(),
            data=data,
            params=params,
            headers=self.auth_headers(),
            auth=self.auth_complete_credentials(),
            method=self.ACCESS_TOKEN_METHOD,
        )
        self.process_error(response)
        return self.do_auth(
            response["access_token"], response=response, *args, **kwargs
        )

    @handle_http_errors
    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        data = self.user_data(access_token, *args, **kwargs)
        response = kwargs.get("response") or {}
        response.update(data or {})
        if "access_token" not in response:
            response["access_token"] = access_token
        kwargs.update({"response": response, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)

    def refresh_token_params(self, token, *args, **kwargs):
        client_id, client_secret = self.get_key_and_secret()
        return {
            "refresh_token": token,
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }

    def process_refresh_token_response(self, response, *args, **kwargs):
        return response.json()

    def refresh_token(self, token, *args, **kwargs):
        params = self.refresh_token_params(token, *args, **kwargs)
        url = self.refresh_token_url()
        method = self.REFRESH_TOKEN_METHOD
        key = "params" if method == "GET" else "data"
        request_args = {"headers": self.auth_headers(), "method": method, key: params}
        request = self.request(url, **request_args)
        return self.process_refresh_token_response(request, *args, **kwargs)

    def refresh_token_url(self):
        return self.REFRESH_TOKEN_URL or self.access_token_url()


class BaseOAuth2PKCE(BaseOAuth2):
    """
    Base class for providers using OAuth2 with Proof Key for Code Exchange (PKCE).

    OAuth2 details at:
        https://datatracker.ietf.org/doc/html/rfc6749
    PKCE details at:
        https://datatracker.ietf.org/doc/html/rfc7636
    """

    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = "s256"
    PKCE_DEFAULT_CODE_VERIFIER_LENGTH = 32
    DEFAULT_USE_PKCE = True

    def create_code_verifier(self):
        name = f"{self.name}_code_verifier"
        code_verifier_len = self.setting(
            "PKCE_CODE_VERIFIER_LENGTH", default=self.PKCE_DEFAULT_CODE_VERIFIER_LENGTH
        )
        code_verifier = self.strategy.random_string(code_verifier_len)
        self.strategy.session_set(name, code_verifier)
        return code_verifier

    def get_code_verifier(self):
        name = f"{self.name}_code_verifier"
        return self.strategy.session_get(name)

    def generate_code_challenge(self, code_verifier, challenge_method):
        method = challenge_method.lower()
        if method == "s256":
            hashed = hashlib.sha256(code_verifier.encode()).digest()
            encoded = base64.urlsafe_b64encode(hashed)
            return encoded.decode().replace("=", "")  # remove padding
        if method == "plain":
            return code_verifier
        raise AuthException(self, "Unsupported code challenge method.")

    def auth_params(self, state=None):
        params = super().auth_params(state=state)

        if self.setting("USE_PKCE", default=self.DEFAULT_USE_PKCE):
            code_challenge_method = self.setting(
                "PKCE_CODE_CHALLENGE_METHOD",
                default=self.PKCE_DEFAULT_CODE_CHALLENGE_METHOD,
            )
            code_verifier = self.create_code_verifier()
            code_challenge = self.generate_code_challenge(
                code_verifier, code_challenge_method
            )
            params["code_challenge_method"] = code_challenge_method
            params["code_challenge"] = code_challenge
        return params

    def auth_complete_params(self, state=None):
        params = super().auth_complete_params(state=state)

        if self.setting("USE_PKCE", default=self.DEFAULT_USE_PKCE):
            code_verifier = self.get_code_verifier()
            params["code_verifier"] = code_verifier

        return params
