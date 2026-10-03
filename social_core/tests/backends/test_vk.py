import json
from time import time
from typing import Any, cast
from unittest.mock import patch
from urllib.parse import urlencode

import responses

from social_core.actions import do_auth
from social_core.backends.vk import vk_sig
from social_core.exceptions import (
    AuthCanceled,
    AuthException,
    AuthFailed,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
    AuthUnknownError,
)
from social_core.tests.models import TestUserSocialAuth, User
from social_core.utils import get_querystring, parse_qs

from .base import BaseBackendTest
from .oauth import BaseAuthUrlTestMixin, OAuth2Test

APP_ID = "12345"
APP_SECRET = "a-secret-key"
VIEWER_ID = "424242"


class VKontakteOpenAPITest(BaseBackendTest):
    backend_path = "social_core.backends.vk.VKontakteOpenAPI"
    expected_username = "vkuser"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            f"SOCIAL_AUTH_{self.name}_APP_ID": APP_ID,
            f"SOCIAL_AUTH_{self.name}_SECRET": APP_SECRET,
        }

    def signed_session(
        self,
        user_id: str = VIEWER_ID,
        *,
        expires: int | None = None,
        signature: str | None = None,
    ) -> str:
        session = {
            "expire": str(expires if expires is not None else int(time()) + 3600),
            "mid": user_id,
            "secret": "session-secret",
            "sid": "session-id",
        }
        check_str = "".join(
            f"{item}={session[item]}" for item in ["expire", "mid", "secret", "sid"]
        )
        session["sig"] = signature or vk_sig(check_str + APP_SECRET)
        return urlencode(session)

    def request_data(self, user_id: str = VIEWER_ID) -> dict[str, str | list[str]]:
        return {
            "id": user_id,
            "nickname": self.expected_username,
            "first_name": ["VK"],
            "last_name": ["User"],
        }

    def do_start(self) -> User:
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.strategy.session_set(f"vk_app_{APP_ID}", self.signed_session())
        return self.backend.complete()

    def test_login(self) -> None:
        user = self.do_login()

        self.assertEqual(user.username, self.expected_username)
        self.assertEqual(user.social[0].uid, VIEWER_ID)
        self.assertEqual(user.social[0].provider, self.backend.name)

    def test_uses_signed_session_id_instead_of_request_id(self) -> None:
        forged_id = "999999999"
        request_data = self.request_data(forged_id)
        self.strategy.set_request_data(request_data, self.backend)
        self.strategy.session_set(f"vk_app_{APP_ID}", self.signed_session(VIEWER_ID))

        user = self.backend.complete()

        self.assertEqual(user.social[0].uid, VIEWER_ID)
        self.assertEqual(request_data["id"], forged_id)

    def test_uses_signed_session_id_with_configured_id_key(self) -> None:
        self.strategy.set_settings({f"SOCIAL_AUTH_{self.name}_ID_KEY": "custom_id"})
        request_data = self.request_data()
        request_data["custom_id"] = "999999999"
        self.strategy.set_request_data(request_data, self.backend)
        self.strategy.session_set(f"vk_app_{APP_ID}", self.signed_session(VIEWER_ID))

        user = self.backend.complete()

        self.assertEqual(user.social[0].uid, VIEWER_ID)

    def test_rejects_invalid_session_signature(self) -> None:
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.strategy.session_set(
            f"vk_app_{APP_ID}",
            self.signed_session(signature="0" * 32),
        )

        with self.assertRaisesRegex(ValueError, "Invalid Hash"):
            self.backend.complete()

        self.assertEqual(User.cache, {})
        self.assertEqual(TestUserSocialAuth.cache_by_uid, {})

    def test_rejects_expired_session(self) -> None:
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.strategy.session_set(
            f"vk_app_{APP_ID}",
            self.signed_session(expires=int(time()) - 1),
        )

        with self.assertRaisesRegex(ValueError, "Invalid Hash"):
            self.backend.complete()

        self.assertEqual(User.cache, {})
        self.assertEqual(TestUserSocialAuth.cache_by_uid, {})


class VKOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.vk.VKOAuth2"
    user_data_url = "https://api.vk.ru/method/users.get"
    expected_username = "durov"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "response": [
                {
                    "id": "1",
                    "first_name": "Павел",
                    "last_name": "Дуров",
                    "screen_name": "durov",
                    "nickname": "",
                    "photo_50": "https://example.com/avatar.jpg",
                    "bdate": "10.10.1984",
                }
            ]
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual(user.social[0].uid, "1")
        request = next(
            call.request
            for call in responses.calls
            if cast("str", call.request.url).startswith(self.user_data_url)
        )
        self.assertEqual(
            get_querystring(cast("str", request.url))["fields"],
            "screen_name,nickname,photo_50",
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_extra_data_fields_and_aliases(self) -> None:
        self.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{self.name}_EXTRA_DATA": [
                    "nickname",
                    ("screen_name", "display_name"),
                    ["photo_50", "avatar"],
                    ("nickname", "empty_nickname", True),
                    ("bdate",),
                ]
            }
        )
        user = self.do_login()
        request = next(
            call.request
            for call in responses.calls
            if cast("str", call.request.url).startswith(self.user_data_url)
        )
        self.assertEqual(
            get_querystring(cast("str", request.url))["fields"],
            "screen_name,nickname,photo_50,bdate",
        )
        extra = user.social[0].extra_data
        self.assertEqual(extra["display_name"], "durov")
        assert self.user_data_body is not None
        self.assertEqual(
            extra["avatar"],
            json.loads(self.user_data_body)["response"][0]["photo_50"],
        )
        self.assertEqual(extra["bdate"], "10.10.1984")
        self.assertNotIn("empty_nickname", extra)

    def test_legacy_photo_aliases(self) -> None:
        self.strategy.set_settings(
            {f"SOCIAL_AUTH_{self.name}_EXTRA_DATA": ["photo", "user_photo"]}
        )
        user = self.do_login()
        self.assertEqual(
            user.social[0].extra_data["photo"], "https://example.com/avatar.jpg"
        )
        self.assertEqual(
            user.social[0].extra_data["user_photo"], "https://example.com/avatar.jpg"
        )
        request = next(
            call.request
            for call in responses.calls
            if cast("str", call.request.url).startswith(self.user_data_url)
        )
        self.assertEqual(
            get_querystring(cast("str", request.url))["fields"],
            "screen_name,nickname,photo_50",
        )

    def test_legacy_photo_response(self) -> None:
        responses.add(
            responses.GET,
            self.user_data_url,
            json={"response": [{"id": "1", "photo": "https://example.com/legacy.jpg"}]},
        )
        data = self.backend.user_data("foobar")
        assert data is not None
        self.assertEqual(data["photo"], "https://example.com/legacy.jpg")
        self.assertEqual(data["user_photo"], data["photo"])

    def test_rejects_invalid_extra_data(self) -> None:
        for entry in ((), ("a", "b", True, "c"), 42, [42]):
            with self.subTest(entry=entry):
                self.strategy.set_settings(
                    {f"SOCIAL_AUTH_{self.name}_EXTRA_DATA": [entry]}
                )
                with self.assertRaises(AuthUnknownError):
                    self.backend.user_data("foobar")
                self.assertEqual(len(responses.calls), 0)


class VKAppOAuth2Test(BaseBackendTest):
    backend_path = "social_core.backends.vk.VKAppOAuth2"
    expected_username = "vkuser"
    user_data_url = "https://api.vk.ru/method/users.get"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            f"SOCIAL_AUTH_{self.name}_KEY": APP_ID,
            f"SOCIAL_AUTH_{self.name}_SECRET": APP_SECRET,
        }

    def auth_key(self, viewer_id: str = VIEWER_ID) -> str:
        return vk_sig(f"{APP_ID}_{viewer_id}_{APP_SECRET}")

    def request_data(self, viewer_id: str = VIEWER_ID) -> dict[str, str]:
        return {
            "is_app_user": "1",
            "viewer_id": viewer_id,
            "access_token": "foobar",
            "api_id": APP_ID,
            "api_result": json.dumps(
                {
                    "response": [
                        {
                            "id": viewer_id,
                            "first_name": "VK",
                            "last_name": "User",
                            "screen_name": self.expected_username,
                        }
                    ]
                }
            ),
        }

    def signed_request_data(self, viewer_id: str = VIEWER_ID) -> dict[str, str]:
        data = self.request_data(viewer_id)
        data["auth_key"] = self.auth_key(viewer_id)
        return data

    def add_user_response(
        self, user_id: str = VIEWER_ID, body: object | None = None
    ) -> None:
        if body is None:
            body = {
                "response": [
                    {
                        "id": user_id,
                        "first_name": "VK",
                        "last_name": "User",
                        "screen_name": self.expected_username,
                    }
                ]
            }
        responses.add(
            responses.GET,
            self.user_data_url,
            body=json.dumps(body),
            content_type="application/json",
        )

    def do_start(self) -> User:
        self.strategy.set_request_data(self.signed_request_data(), self.backend)
        self.add_user_response()
        return self.backend.complete()

    def test_login(self) -> None:
        user = self.do_login()

        self.assertEqual(user.username, self.expected_username)
        self.assertEqual(user.social[0].uid, VIEWER_ID)
        self.assertEqual(user.social[0].provider, self.backend.name)

    def test_ignores_api_result(self) -> None:
        data = self.signed_request_data()
        data["api_result"] = json.dumps(
            {
                "response": [
                    {
                        "id": "999999999",
                        "first_name": "Attacker",
                        "last_name": "Controlled",
                        "screen_name": "forged",
                    }
                ]
            }
        )
        self.strategy.set_request_data(data, self.backend)
        self.add_user_response()

        user = self.backend.complete()

        self.assertEqual(user.username, self.expected_username)
        self.assertEqual(user.first_name, "VK")
        self.assertEqual(user.social[0].uid, VIEWER_ID)

    def test_api_result_is_not_required(self) -> None:
        data = self.signed_request_data()
        del data["api_result"]
        self.strategy.set_request_data(data, self.backend)
        self.add_user_response()

        user = self.backend.complete()

        self.assertEqual(user.social[0].uid, VIEWER_ID)

    def test_rejects_mismatched_user_profile_id(self) -> None:
        self.strategy.set_request_data(self.signed_request_data(), self.backend)
        self.add_user_response(user_id="999999999")

        with self.assertRaisesRegex(AuthFailed, "does not match viewer ID"):
            self.backend.complete()

        self.assertEqual(User.cache, {})
        self.assertEqual(TestUserSocialAuth.cache_by_uid, {})

    def test_rejects_missing_user_profile(self) -> None:
        self.strategy.set_request_data(self.signed_request_data(), self.backend)
        self.add_user_response(body={})

        with self.assertRaisesRegex(AuthFailed, "Invalid user profile"):
            self.backend.complete()

    def test_rejects_empty_user_profile(self) -> None:
        self.strategy.set_request_data(self.signed_request_data(), self.backend)
        self.add_user_response(body={"response": []})

        with self.assertRaisesRegex(AuthFailed, "Invalid user profile"):
            self.backend.complete()

    def test_rejects_malformed_user_profile(self) -> None:
        self.strategy.set_request_data(self.signed_request_data(), self.backend)
        self.add_user_response(body={"response": {}})

        with self.assertRaisesRegex(AuthFailed, "Invalid user profile"):
            self.backend.complete()

    def test_rejects_missing_auth_key_before_authentication(self) -> None:
        self.strategy.set_request_data(self.request_data(), self.backend)

        with self.assertRaisesRegex(AuthFailed, "Missing auth key"):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)
        self.assertIsNone(self.strategy.session_get("username"))
        self.assertEqual(User.cache, {})
        self.assertEqual(TestUserSocialAuth.cache_by_uid, {})

    def test_rejects_invalid_auth_key(self) -> None:
        data = self.request_data()
        data["auth_key"] = "0" * 32
        self.strategy.set_request_data(data, self.backend)

        with self.assertRaisesRegex(AuthFailed, "Invalid auth key"):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)

    def test_signed_membership_check(self) -> None:
        self.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{self.name}_USERMODE": 2,
                f"SOCIAL_AUTH_{self.name}_API_VERSION": "5.199",
            }
        )
        responses.add(responses.GET, "https://api.vk.ru/api.php", json={"response": 1})
        user = self.do_login()
        params = get_querystring(cast("str", responses.calls[0].request.url))
        signature = params.pop("sig")
        self.assertEqual(
            params,
            {
                "user_id": VIEWER_ID,
                "v": "5.199",
                "api_id": APP_ID,
                "method": "isAppUser",
                "format": "json",
            },
        )
        self.assertEqual(
            signature,
            vk_sig(
                "".join(sorted(f"{key}={value}" for key, value in params.items()))
                + APP_SECRET
            ),
        )
        self.assertEqual(user.social[0].uid, VIEWER_ID)

    def test_membership_rejected(self) -> None:
        self.strategy.set_settings({f"SOCIAL_AUTH_{self.name}_USERMODE": 2})
        self.strategy.set_request_data(self.signed_request_data(), self.backend)
        responses.add(responses.GET, "https://api.vk.ru/api.php", json={"response": 0})
        self.assertIsNone(self.backend.complete())
        self.assertEqual(len(responses.calls), 1)
        self.assertEqual(User.cache, {})

    def test_membership_unavailable(self) -> None:
        self.strategy.set_settings({f"SOCIAL_AUTH_{self.name}_USERMODE": 2})
        self.strategy.set_request_data(self.signed_request_data(), self.backend)
        responses.add(responses.GET, "https://api.vk.ru/api.php", body="invalid json")
        self.assertIsNone(self.backend.complete())
        self.assertEqual(User.cache, {})


class VKIDOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.vk.VKIDOAuth2"
    raw_complete_url = "/complete/{0}/?code=foobar&device_id=device-id"
    user_data_url = "https://id.vk.ru/oauth2/user_info"
    user_data_url_post = True
    expected_username = "pavel@example.com"
    token_data = {
        "access_token": "foobar",
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": "refresh",
        "id_token": "id-token",
        "user_id": 1,
        "scope": "email",
    }
    user_data_body = json.dumps(
        {
            "user": {
                "user_id": "1",
                "first_name": "Павел",
                "last_name": "Дуров",
                "email": "pavel@example.com",
                "avatar": "https://example.com/avatar.jpg",
            }
        }
    )

    def extra_settings(self):
        return {
            **super().extra_settings(),
            f"SOCIAL_AUTH_{self.name}_USERNAME_IS_FULL_EMAIL": True,
        }

    def pre_complete_callback(self, start_url) -> None:
        state = get_querystring(start_url)["state"]
        responses.add(
            responses.POST,
            self.backend.access_token_url(),
            json={**self.token_data, "state": state},
        )

    def prepare_callback(self):
        start_url = self.backend.start().url
        state = get_querystring(start_url)["state"]
        self.pre_complete_callback(start_url)
        responses.add(responses.POST, self.user_data_url, body=self.user_data_body)
        data = {"code": "foobar", "device_id": "device-id", "state": state}
        self.strategy.set_request_data(data, self.backend)
        return data

    def test_login(self) -> None:
        user = self.do_login()
        token_request = next(
            call.request
            for call in responses.calls
            if call.request.url == self.backend.access_token_url()
        )
        params = parse_qs(token_request.body)
        self.assertEqual(params["client_id"], "a-key")
        self.assertNotIn("client_secret", params)
        self.assertEqual(params["device_id"], "device-id")
        start_query = get_querystring(cast("str", responses.calls[0].request.url))
        self.assertEqual(params["state"], start_query["state"])
        self.assertEqual(
            self.backend.generate_code_challenge(params["code_verifier"], "S256"),
            start_query["code_challenge"],
        )
        self.assertEqual(start_query["code_challenge_method"], "S256")
        self.assertIsNone(self.strategy.session_get("vk-id_code_verifier"))
        user_params = parse_qs(responses.calls[-1].request.body)
        self.assertEqual(user_params, {"client_id": "a-key", "access_token": "foobar"})
        extra = user.social[0].extra_data
        self.assertEqual(user.social[0].uid, "1")
        self.assertEqual(extra["device_id"], "device-id")
        self.assertEqual(extra["refresh_token"], "refresh")
        self.assertEqual(extra["expires_in"], 3600)

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_payload_callback(self) -> None:
        data = self.prepare_callback()
        self.strategy.set_request_data({"payload": json.dumps(data)}, self.backend)
        user = self.backend.complete()
        self.assertEqual(user.social[0].uid, "1")

    def test_mapping_scalars(self) -> None:
        data = self.prepare_callback()

        class MultiValueDict(dict):
            def keys(self):
                return data.keys()

            def __getitem__(self, key):
                return [data[key]]

            def items(self):
                return data.items()

        self.backend.data = MultiValueDict(data)
        self.assertEqual(self.backend.complete().social[0].uid, "1")

    def test_invalid_callbacks(self) -> None:
        start_url = self.backend.start().url
        state = get_querystring(start_url)["state"]
        good = {"code": "foobar", "device_id": "device-id", "state": state}
        cases = [
            ({**good, "payload": "invalid json"}, AuthFailed),
            ({**good, "payload": "[]"}, AuthFailed),
            ({**good, "payload": "null"}, AuthFailed),
            ({**good, "payload": json.dumps({"state": "other"})}, AuthFailed),
            ({**good, "code": ["foobar"]}, AuthFailed),
            ({**good, "device_id": 12}, AuthFailed),
            ({**good, "state": {}}, AuthFailed),
            ({**good, "code": ""}, AuthMissingParameter),
            ({**good, "device_id": ""}, AuthMissingParameter),
            ({"code": "foobar", "device_id": "device-id"}, AuthMissingParameter),
            ({**good, "state": "other"}, AuthStateForbidden),
        ]
        for data, exception in cases:
            with self.subTest(data=data):
                self.strategy.get_request_data().clear()
                self.strategy.set_request_data(data, self.backend)
                with self.assertRaises(exception):
                    self.backend.complete()
                self.assertEqual(len(responses.calls), 0)
                self.assertEqual(User.cache, {})

    def test_payload_cancellation(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(
            {"payload": json.dumps({"error": "access_denied"})}, self.backend
        )
        with self.assertRaises(AuthCanceled):
            self.backend.complete()
        self.assertEqual(len(responses.calls), 0)

    def test_missing_session_state(self) -> None:
        data = self.prepare_callback()
        self.strategy.session_pop("vk-id_state")
        with self.assertRaises(AuthStateMissing):
            self.backend.complete()
        self.assertEqual(len(responses.calls), 0)
        self.assertTrue(data["state"])

    def test_missing_verifier(self) -> None:
        self.prepare_callback()
        self.strategy.session_pop("vk-id_code_verifier")
        with self.assertRaises(AuthMissingParameter):
            self.backend.complete()
        self.assertEqual(len(responses.calls), 0)

    def test_verifier_replay(self) -> None:
        self.prepare_callback()
        self.backend.complete()
        calls = len(responses.calls)
        with self.assertRaises(AuthMissingParameter):
            self.backend.complete()
        self.assertEqual(len(responses.calls), calls)

    def test_requires_s256_pkce(self) -> None:
        for settings in (
            {"USE_PKCE": False},
            {"PKCE_CODE_CHALLENGE_METHOD": "plain"},
            {"PKCE_CODE_VERIFIER_LENGTH": 42},
            {"PKCE_CODE_VERIFIER_LENGTH": 129},
        ):
            with (
                self.subTest(settings=settings),
                patch.object(
                    self.backend,
                    "setting",
                    side_effect=lambda name, default=None, settings=settings: (
                        settings.get(name, default)
                    ),
                ),
                self.assertRaises(AuthException),
            ):
                self.backend.start()

    def test_pkce_method_is_canonical(self) -> None:
        for method in ("S256", "s256"):
            with self.subTest(method=method):
                self.strategy.set_settings(
                    {f"SOCIAL_AUTH_{self.name}_PKCE_CODE_CHALLENGE_METHOD": method}
                )
                params = get_querystring(self.backend.start().url)
                self.assertEqual(params["code_challenge_method"], "S256")
                self.assertEqual(
                    params["code_challenge"],
                    self.backend.generate_code_challenge(
                        self.strategy.session_get("vk-id_code_verifier"), "S256"
                    ),
                )

    def test_invalid_token_responses(self) -> None:
        data = self.prepare_callback()
        for response, exception in (
            ([], AuthFailed),
            ({"error": "invalid_grant"}, AuthFailed),
            ({**self.token_data, "state": "wrong"}, AuthStateForbidden),
            (self.token_data, AuthStateForbidden),
            ({"state": data["state"]}, AuthMissingParameter),
        ):
            with (
                self.subTest(response=response),
                patch.object(self.backend, "get_json", return_value=response),
                self.assertRaises(exception),
            ):
                self.backend.request_access_token(self.backend.access_token_url())

    def test_invalid_profiles(self) -> None:
        profiles: tuple[Any, ...] = (
            [],
            {},
            {"user": []},
            {"user": {}},
            {"user": {"user_id": True}},
            {"error": "invalid_token"},
        )
        for profile in profiles:
            with (
                self.subTest(profile=profile),
                patch.object(self.backend, "get_json", return_value=profile),
                self.assertRaises(AuthFailed),
            ):
                self.backend.user_data("foobar")

    def test_profile_token_id_mismatch(self) -> None:
        self.token_data = {**self.token_data, "user_id": 2}
        self.prepare_callback()
        with self.assertRaisesRegex(AuthFailed, "does not match"):
            self.backend.complete()
        self.assertEqual(User.cache, {})

    def test_token_id_fallback(self) -> None:
        assert self.user_data_body is not None
        profile = json.loads(self.user_data_body)
        del profile["user"]["user_id"]
        self.user_data_body = json.dumps(profile)
        self.assertEqual(self.do_login().social[0].uid, "1")

    def test_token_device_id(self) -> None:
        self.token_data = {**self.token_data, "device_id": "token-device-id"}
        self.assertEqual(
            self.do_login().social[0].extra_data["device_id"], "token-device-id"
        )

    def test_association(self) -> None:
        self.backend.ASSOCIATION_ONLY = True
        user = User("existing", email="local@example.com")
        start_url = do_auth(self.backend, user=user).url
        state = get_querystring(start_url)["state"]
        self.pre_complete_callback(start_url)
        responses.add(responses.POST, self.user_data_url, body=self.user_data_body)
        self.strategy.set_request_data(
            {"code": "foobar", "device_id": "device-id", "state": state}, self.backend
        )
        self.assertIs(self.backend.complete(user=user), user)
        self.assertEqual(user.email, "local@example.com")
        self.assertEqual(user.social[0].uid, "1")
        self.assertIsNone(self.strategy.session_get("vk-id_state"))

    def test_refresh_rotation(self) -> None:
        social = self.do_login().social[0]

        def refresh_response(request):
            params = parse_qs(request.body)
            self.assertEqual(params["grant_type"], "refresh_token")
            self.assertEqual(params["refresh_token"], "refresh")
            self.assertEqual(params["device_id"], "override-device-id")
            self.assertEqual(params["client_id"], "a-key")
            self.assertEqual(
                params["redirect_uri"], "https://example.com/complete/vk-id/"
            )
            self.assertNotIn("client_secret", params)
            self.assertNotIn("code_verifier", params)
            return (
                200,
                {},
                json.dumps(
                    {
                        "access_token": "new-token",
                        "refresh_token": "rotated",
                        "state": params["state"],
                        "expires_in": 7200,
                    }
                ),
            )

        responses.add_callback(
            responses.POST, self.backend.refresh_token_url(), callback=refresh_response
        )
        social.refresh_token(
            self.strategy,
            device_id="override-device-id",
            redirect_uri="https://example.com/complete/vk-id/",
        )
        self.assertEqual(social.extra_data["access_token"], "new-token")
        self.assertEqual(social.extra_data["refresh_token"], "rotated")
        self.assertEqual(social.extra_data["device_id"], "override-device-id")
        self.assertEqual(social.extra_data["id"], "1")
        self.assertEqual(social.extra_data["expires_in"], 7200)

    def test_automatic_refresh(self) -> None:
        redirect_uri = "https://example.com/complete/vk-id/"
        self.backend.redirect_uri = redirect_uri
        social = self.do_login().social[0]
        self.assertEqual(social.extra_data["redirect_uri"], redirect_uri)
        social.extra_data["expires_in"] = 0

        def refresh_response(request):
            params = parse_qs(request.body)
            self.assertEqual(params["refresh_token"], "refresh")
            self.assertEqual(params["device_id"], "device-id")
            self.assertEqual(params["redirect_uri"], redirect_uri)
            self.assertEqual(params["grant_type"], "refresh_token")
            self.assertNotIn("client_secret", params)
            return (
                200,
                {},
                json.dumps(
                    {
                        "access_token": "new-token",
                        "refresh_token": "rotated",
                        "expires_in": 7200,
                        "state": params["state"],
                    }
                ),
            )

        responses.add_callback(
            responses.POST, self.backend.refresh_token_url(), callback=refresh_response
        )
        self.assertEqual(social.get_access_token(self.strategy), "new-token")
        self.assertEqual(social.extra_data["refresh_token"], "rotated")
        self.assertEqual(social.extra_data["device_id"], "device-id")
        self.assertEqual(social.extra_data["redirect_uri"], redirect_uri)
        self.assertEqual(social.extra_data["id"], "1")
        self.assertFalse(social.access_token_expired())
        calls = len(responses.calls)
        self.assertEqual(social.get_access_token(self.strategy), "new-token")
        self.assertEqual(len(responses.calls), calls)

    def test_automatic_refresh_missing_device(self) -> None:
        social = self.do_login().social[0]
        social.extra_data.pop("device_id")
        social.extra_data["expires_in"] = 0
        calls = len(responses.calls)
        with self.assertRaises(AuthMissingParameter):
            social.get_access_token(self.strategy)
        self.assertEqual(len(responses.calls), calls)
        self.assertEqual(social.extra_data["access_token"], "foobar")

    def test_refresh_missing_device(self) -> None:
        with self.assertRaises(AuthMissingParameter):
            self.backend.refresh_token("refresh")
        self.assertEqual(len(responses.calls), 0)

    def test_refresh_errors(self) -> None:
        for response, exception in (
            ({"error": "invalid_grant"}, AuthFailed),
            ({"access_token": "new", "state": "wrong"}, AuthStateForbidden),
        ):
            with (
                self.subTest(response=response),
                patch.object(self.backend, "get_json", return_value=response),
                self.assertRaises(exception),
            ):
                self.backend.refresh_token("refresh", device_id="device-id")
