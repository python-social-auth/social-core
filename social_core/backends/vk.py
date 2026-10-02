"""
VK.com OpenAPI, OAuth2 and Iframe application OAuth2 backends, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/vk.html
"""

from __future__ import annotations

import json
from hashlib import md5
from time import time
from typing import Any, cast

from social_core.exceptions import (
    AuthException,
    AuthFailed,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthTokenRevoked,
    AuthUnknownError,
)
from social_core.utils import constant_time_compare, handle_http_errors, parse_qs

from .base import BaseAuth
from .oauth import BaseOAuth2, BaseOAuth2PKCE


def vk_sig(payload: str) -> str:
    """
    Calculates signature using md5.

    https://dev.vk.com/en/api/open-api/getting-started#Authorization%20on%20the%20Remote%20Side
    """
    return md5(payload.encode("utf-8")).hexdigest()  # noqa: S324


class VKontakteOpenAPI(BaseAuth):
    """VK.COM OpenAPI authentication backend"""

    name = "vk-openapi"
    ID_KEY = "id"

    def get_user_details(self, response):
        """Return user details from VK.com request"""
        nickname = response.get("nickname") or ""
        fullname = ""
        first_name = response.get("first_name", [""])[0]
        last_name = response.get("last_name", [""])[0]
        return {
            "username": response["id"] if len(nickname) == 0 else nickname,
            "email": "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        response = self.data.copy()
        # The access_token argument is the mid from the signed session. Request
        # data passes through the user's browser and must not define identity.
        response[self.ID_KEY] = access_token
        response[self.id_key()] = access_token
        return response

    def auth_html(self) -> str:
        """Returns local VK authentication page, not necessary for
        VK to authenticate.
        """
        ctx = {
            "VK_APP_ID": self.setting("APP_ID"),
            "VK_COMPLETE_URL": self.redirect_uri,
        }
        local_html = self.setting("LOCAL_HTML", "vkontakte.html")
        return self.strategy.render_html(tpl=local_html, context=ctx)

    def auth_complete(self, *args, **kwargs):
        """Performs check of authentication in VKontakte, returns User if
        succeeded"""
        session_value = self.strategy.session_get(
            f"vk_app_{cast('str', self.setting('APP_ID'))}"
        )
        if "id" not in self.data or not session_value:
            raise ValueError("VK.com authentication is not completed")

        mapping = parse_qs(session_value)
        check_str = "".join(
            f"{item}={mapping[item]}" for item in ["expire", "mid", "secret", "sid"]
        )

        _key, secret = self.get_key_and_secret()
        vk_hash = vk_sig(check_str + secret)
        if vk_hash != mapping["sig"] or int(mapping["expire"]) < time():
            raise ValueError("VK.com authentication failed: Invalid Hash")

        kwargs.update({"backend": self, "response": self.user_data(mapping["mid"])})
        return self.strategy.authenticate(*args, **kwargs)

    def uses_redirect(self) -> bool:
        """VK.com does not require visiting server url in order
        to do authentication, so auth_xxx methods are not needed to be called.
        Their current implementation is just an example"""
        return False


class VKOAuth2(BaseOAuth2):
    """VKOAuth2 authentication backend"""

    name = "vk-oauth2"
    ID_KEY = "id"
    AUTHORIZATION_URL = "https://oauth.vk.ru/authorize"
    ACCESS_TOKEN_URL = "https://oauth.vk.ru/access_token"
    EXTRA_DATA = [("id", "id"), ("expires_in", "expires_in")]

    def get_user_details(self, response):
        """Return user details from VK.com account"""
        fullname = ""
        first_name = response.get("first_name")
        last_name = response.get("last_name")
        return {
            "username": response.get("screen_name"),
            "email": response.get("email", ""),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        request_data = ["screen_name", "nickname", "photo_50"]
        for entry in cast("list[Any]", self.setting("EXTRA_DATA", [])):
            if isinstance(entry, str):
                field = entry
            elif isinstance(entry, (tuple, list)) and 1 <= len(entry) <= 3:
                field = entry[0]
            else:
                raise AuthUnknownError(self, f"Invalid EXTRA_DATA item: {entry!r}")
            if not isinstance(field, str):
                raise AuthUnknownError(self, f"Invalid EXTRA_DATA item: {entry!r}")
            request_data.append(
                "photo_50" if field in {"photo", "user_photo"} else field
            )

        fields = ",".join(dict.fromkeys(request_data))
        response = self.vk_api(
            "users.get",
            {
                "access_token": access_token,
                "fields": fields,
            },
        )

        if response and response.get("error"):
            error = response["error"]
            msg = error.get("error_msg", "Unknown error")
            if error.get("error_code") == 5:
                raise AuthTokenRevoked(self, msg)
            raise AuthException(self, msg)

        if response:
            data = cast("list[dict[str, str | None]]", response.get("response"))[0]
            # Keep legacy response names while requesting the supported API field.
            data["photo"] = data.get("photo_50") or data.get("photo")
            data["user_photo"] = data["photo"]
            return data
        return {}

    def vk_api(self, method: str, data: dict[str, str]) -> dict[Any, Any] | None:
        """
        Calls VK.com OpenAPI method, check:
            https://vk.com/apiclub
            http://goo.gl/yLcaa
        """
        # We need to perform server-side call if no access_token
        data["v"] = cast("str", self.setting("API_VERSION", "5.131"))
        if "access_token" not in data:
            key, secret = self.get_key_and_secret()
            if "api_id" not in data:
                data["api_id"] = key

            data["method"] = method
            data["format"] = "json"
            url = "https://api.vk.ru/api.php"
            param_list = sorted(f"{item}={data[item]}" for item in data)
            data["sig"] = vk_sig("".join(param_list) + secret)
        else:
            url = f"https://api.vk.ru/method/{method}"

        try:
            return self.get_json(url, params=data)
        except (TypeError, KeyError, OSError, ValueError, IndexError):
            return None


class VKIDOAuth2(BaseOAuth2PKCE):
    """VK ID authentication using mandatory PKCE and device-bound tokens."""

    name = "vk-id"
    ID_KEY = "id"
    REQUIRES_USER_ID = True
    AUTHORIZATION_URL = "https://id.vk.ru/authorize"
    ACCESS_TOKEN_URL = "https://id.vk.ru/oauth2/auth"
    USER_INFO_URL = "https://id.vk.ru/oauth2/user_info"
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("id", "id"),
        ("user_id", "user_id"),
        ("expires_in", "expires_in"),
        ("refresh_token", "refresh_token"),
        ("id_token", "id_token"),
        ("scope", "scope"),
        ("device_id", "device_id"),
        ("redirect_uri", "redirect_uri"),
    ]

    def auth_params(self, state=None):
        if (
            not self.setting("USE_PKCE", True)
            or str(self.setting("PKCE_CODE_CHALLENGE_METHOD", "S256")).lower() != "s256"
        ):
            raise AuthException(self, "VK ID requires PKCE with S256")
        length = self.setting("PKCE_CODE_VERIFIER_LENGTH", 43)
        if not isinstance(length, int) or not 43 <= length <= 128:
            raise AuthException(self, "Invalid PKCE code verifier length")
        params = super().auth_params(state)
        params["code_challenge_method"] = "S256"
        return params

    def callback_data(self) -> dict[str, Any]:
        data = dict(self.data.items())
        if "payload" in data:
            try:
                payload = json.loads(data["payload"])
            except (TypeError, ValueError) as exc:
                raise AuthFailed(self, "Invalid VK ID payload") from exc
            if not isinstance(payload, dict):
                raise AuthFailed(self, "Invalid VK ID payload")
            for field in ("code", "device_id", "state", "error", "error_description"):
                if field in payload:
                    if field in data and data[field] != payload[field]:
                        raise AuthFailed(self, f"Conflicting VK ID {field}")
                    data[field] = payload[field]
        for field in ("code", "device_id", "state", "error", "error_description"):
            if field in data and not isinstance(data[field], str):
                raise AuthFailed(self, f"Invalid VK ID {field}")
        return data

    def auth_complete(self, *args, **kwargs):
        original_data = self.data
        self.data = self.callback_data()
        try:
            return super().auth_complete(*args, **kwargs)
        finally:
            self.data = original_data

    def auth_complete_params(self, state=None):
        for field in ("code", "device_id"):
            if not self.data.get(field):
                raise AuthMissingParameter(self, field)
        params = super().auth_complete_params(state)
        params.pop("client_secret", None)
        verifier = self.strategy.session_pop(f"{self.name}_code_verifier")
        if not verifier:
            raise AuthMissingParameter(self, "code_verifier")
        params.update(
            code_verifier=verifier, device_id=self.data["device_id"], state=state
        )
        return params

    def _validate_token_response(self, response, state) -> None:
        if not isinstance(response, dict):
            raise AuthFailed(self, "Invalid VK ID token response")
        self.process_error(response)
        response_state = response.get("state")
        if not isinstance(response_state, str) or not constant_time_compare(
            response_state, state
        ):
            raise AuthStateForbidden(self)
        if (
            not isinstance(response.get("access_token"), str)
            or not response["access_token"]
        ):
            raise AuthMissingParameter(self, "access_token")

    def request_access_token(self, *args, **kwargs):
        response = super().request_access_token(*args, **kwargs)
        self._validate_token_response(response, self.data["state"])
        response.setdefault("device_id", self.data["device_id"])
        response["redirect_uri"] = self.get_redirect_uri()
        return response

    @staticmethod
    def _profile_id(data):
        value = data.get("user_id", data.get("id"))
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return None
        return str(value) if str(value).strip() else None

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any]:
        client_id, _secret = self.get_key_and_secret()
        data = self.get_json(
            self.USER_INFO_URL,
            method="POST",
            headers=self.auth_headers(),
            data={"access_token": access_token, "client_id": client_id},
        )
        if not isinstance(data, dict):
            raise AuthFailed(self, "Invalid VK ID user profile")
        self.process_error(data)
        user = data.get("user")
        if not isinstance(user, dict):
            raise AuthFailed(self, "Invalid VK ID user profile")
        token_id = self._profile_id(kwargs.get("response") or {})
        profile_id = self._profile_id(user)
        if token_id and profile_id and token_id != profile_id:
            raise AuthFailed(self, "VK ID user profile does not match token user ID")
        user_id = profile_id or token_id
        if not user_id:
            raise AuthFailed(self, "Missing VK ID user ID")
        return {
            **user,
            "id": user_id,
            "user_id": user_id,
            "photo": user.get("avatar"),
            "user_photo": user.get("avatar"),
        }

    def get_user_details(self, response):
        return {
            "username": "",
            "email": response.get("email", ""),
            "first_name": response.get("first_name", ""),
            "last_name": response.get("last_name", ""),
        }

    def get_refresh_token_kwargs(self, extra_data: dict[str, Any]) -> dict[str, Any]:
        return {
            "device_id": extra_data.get("device_id"),
            "redirect_uri": extra_data.get("redirect_uri"),
        }

    def refresh_token_params(self, token: str, *args, **kwargs) -> dict[str, str]:
        device_id = kwargs.get("device_id")
        if not isinstance(device_id, str) or not device_id:
            raise AuthMissingParameter(self, "device_id")
        client_id, _secret = self.get_key_and_secret()
        return {
            "grant_type": "refresh_token",
            "refresh_token": token,
            "client_id": client_id,
            "redirect_uri": kwargs.get("redirect_uri") or self.get_redirect_uri(),
            "device_id": device_id,
            "state": self.state_token(),
        }

    @handle_http_errors
    def refresh_token(self, token: str, *args, **kwargs) -> dict:
        params = self.refresh_token_params(token, *args, **kwargs)
        response = super().request_access_token(
            self.refresh_token_url(),
            method=self.REFRESH_TOKEN_METHOD,
            headers=self.auth_headers(),
            data=params,
        )
        self._validate_token_response(response, params["state"])
        response.setdefault("device_id", params["device_id"])
        response["redirect_uri"] = params["redirect_uri"]
        return response


class VKAppOAuth2(VKOAuth2):
    """VK.com Application Authentication support"""

    name = "vk-app"

    def _user_profile(self, access_token: str, viewer_id) -> dict[str, Any]:
        # api_result passes through the user's browser and is not covered by
        # auth_key. Fetch the profile from VK to avoid trusting
        # attacker-controlled identity and profile fields.
        try:
            response = self.user_data(access_token)
        except (TypeError, KeyError, IndexError) as exc:
            raise AuthFailed(self, "Invalid user profile") from exc

        if not response:
            raise AuthFailed(self, "Invalid user profile")

        profile_user_id = response.get(self.ID_KEY)
        if profile_user_id is None or str(profile_user_id) != str(viewer_id):
            raise AuthFailed(self, "User profile ID does not match viewer ID")

        response[self.id_key()] = profile_user_id
        return response

    def auth_complete(self, *args, **kwargs):
        required_params = ("is_app_user", "viewer_id", "access_token", "api_id")
        if not all(param in self.data for param in required_params):
            return None

        auth_key = self.data.get("auth_key")

        # Verify signature before trusting callback data.
        key, secret = self.get_key_and_secret()
        if not auth_key:
            raise AuthFailed(self, "Missing auth key")
        check_key = vk_sig(f"{key}_{self.data.get('viewer_id')}_{secret}")
        if check_key != auth_key:
            raise AuthFailed(self, "Invalid auth key")

        user_check = self.setting("USERMODE")
        user_id = self.data["viewer_id"]
        if user_check is not None:
            user_check = int(user_check)
            is_user = 0
            if user_check == 1:
                is_user = self.data.get("is_app_user", 0)
            elif user_check == 2:
                response = self.vk_api("isAppUser", {"user_id": user_id})
                if response is None:
                    return None
                is_user = response.get("response", 0)
            if not int(is_user):
                return None

        request = self.strategy.request_data()
        response = self._user_profile(cast("str", self.data["access_token"]), user_id)
        return self.strategy.authenticate(
            auth=self,
            backend=self,
            request=request,
            response=response,
        )
