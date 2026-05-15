"""
VK.com OpenAPI, OAuth2 and Iframe application OAuth2 backends, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/vk.html
"""

from __future__ import annotations

import base64
import json
from hashlib import md5, sha256
from time import time
from typing import Any, cast

from social_core.exceptions import (
    AuthException,
    AuthFailed,
    AuthMissingParameter,
    AuthTokenRevoked,
)
from social_core.utils import parse_qs

from .base import BaseAuth
from .oauth import BaseOAuth2


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
        fullname, first_name, last_name = self.get_user_names(
            first_name=response.get("first_name", [""])[0],
            last_name=response.get("last_name", [""])[0],
        )
        return {
            "username": response["id"] if len(nickname) == 0 else nickname,
            "email": "",
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        return self.data

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
        fullname, first_name, last_name = self.get_user_names(
            first_name=response.get("first_name"), last_name=response.get("last_name")
        )
        return {
            "username": response.get("screen_name"),
            "email": response.get("email", ""),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        """Loads user data from service"""
        request_data = [
            "first_name",
            "last_name",
            "screen_name",
            "nickname",
            "photo",
            *cast("list[str]", self.setting("EXTRA_DATA", [])),
        ]

        fields = ",".join(set(request_data))
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
            data["user_photo"] = data.get("photo")  # Backward compatibility
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


class VKIDOAuth2(BaseOAuth2):
    """VK ID OAuth2 authentication backend"""

    name = "vk-id"
    ID_KEY = "id"
    AUTHORIZATION_URL = "https://id.vk.ru/authorize"
    ACCESS_TOKEN_URL = "https://id.vk.ru/oauth2/auth"
    USER_INFO_URL = "https://id.vk.ru/oauth2/user_info"
    REDIRECT_STATE = False
    STATE_PARAMETER = True
    SCOPE_SEPARATOR = " "
    EXTRA_DATA = [
        ("id", "id"),
        ("user_id", "user_id"),
        ("expires_in", "expires_in"),
        ("refresh_token", "refresh_token"),
        ("id_token", "id_token"),
        ("scope", "scope"),
        ("device_id", "device_id"),
    ]

    def code_verifier_session_key(self, state: str | None) -> str:
        return f"{self.name}_code_verifier_{state or 'default'}"

    def generate_code_verifier(self) -> str:
        return self.strategy.random_string(128)

    def generate_code_challenge(self, code_verifier: str) -> str:
        digest = sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def auth_params(self, state: str | None = None) -> dict[str, str]:
        params = super().auth_params(state)
        code_verifier = self.generate_code_verifier()
        self.strategy.session_set(self.code_verifier_session_key(state), code_verifier)
        params.update(
            {
                "code_challenge": self.generate_code_challenge(code_verifier),
                "code_challenge_method": "S256",
            }
        )
        return params

    def callback_data(self) -> dict[str, Any]:
        data = dict(self.data)
        payload = data.get("payload")
        if isinstance(payload, list):
            payload = payload[0] if payload else None
        if isinstance(payload, str) and payload:
            try:
                parsed_payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise AuthFailed(self, "Invalid VK ID payload") from exc
            if isinstance(parsed_payload, dict):
                data.update(parsed_payload)
        return data

    def get_request_state(self):
        request_state = self.callback_data().get("state")
        if request_state and isinstance(request_state, list):
            request_state = request_state[0]
        return request_state

    def auth_complete_params(self, state=None):
        data = self.callback_data()
        code = data.get("code")
        device_id = data.get("device_id")
        if not code:
            raise AuthMissingParameter(self, "code")
        if not device_id:
            raise AuthMissingParameter(self, "device_id")
        self._callback_device_id = device_id

        code_verifier = self.strategy.session_pop(self.code_verifier_session_key(state))
        if not code_verifier:
            raise AuthMissingParameter(self, "code_verifier")

        client_id, _client_secret = self.get_key_and_secret()
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": client_id,
            "device_id": device_id,
            "redirect_uri": self.get_redirect_uri(state),
        }
        if state:
            params["state"] = state
        return params

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        response = kwargs.get("response") or {}
        client_id, _client_secret = self.get_key_and_secret()
        data = self.get_json(
            self.USER_INFO_URL,
            method="POST",
            headers=self.auth_headers(),
            data={
                "access_token": access_token,
                "client_id": client_id,
            },
        )
        self.process_error(data)

        user = data.get("user") if isinstance(data.get("user"), dict) else data
        if not isinstance(user, dict):
            return {}

        user_id = (
            user.get("user_id")
            or user.get("id")
            or response.get("user_id")
            or response.get("id")
        )
        first_name = user.get("first_name") or user.get("firstName") or ""
        last_name = user.get("last_name") or user.get("lastName") or ""
        avatar = (
            user.get("avatar")
            or user.get("photo")
            or user.get("photo_200")
            or user.get("picture")
        )

        return {
            **user,
            "id": str(user_id) if user_id is not None else None,
            "user_id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "email": user.get("email") or response.get("email", ""),
            "user_photo": avatar,
            "photo": avatar,
            "device_id": response.get("device_id")
            or getattr(self, "_callback_device_id", None),
        }

    def get_user_details(self, response):
        fullname, first_name, last_name = self.get_user_names(
            first_name=response.get("first_name"),
            last_name=response.get("last_name"),
        )
        return {
            "username": "",
            "email": response.get("email", ""),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }


class VKAppOAuth2(VKOAuth2):
    """VK.com Application Authentication support"""

    name = "vk-app"

    def auth_complete(self, *args, **kwargs):
        required_params = ("is_app_user", "viewer_id", "access_token", "api_id")
        if not all(param in self.data for param in required_params):
            return None

        auth_key = self.data.get("auth_key")

        # Verify signature, if present
        key, secret = self.get_key_and_secret()
        if auth_key:
            check_key = vk_sig(f"{key}_{self.data.get('viewer_id')}_{secret}")
            if check_key != auth_key:
                raise ValueError("VK.com authentication failed: invalid auth key")

        user_check = self.setting("USERMODE")
        user_id = self.data.get("viewer_id")
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
        response = {self.id_key(): user_id}
        response.update(json.loads(request["api_result"])["response"][0])
        return self.strategy.authenticate(
            auth=self,
            backend=self,
            request=request,
            response=response,
        )
