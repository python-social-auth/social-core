import json
from typing import Any, cast

import responses

from social_core.tests.models import User
from social_core.utils import get_querystring, parse_qs

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class VKOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.vk.VKOAuth2"
    user_data_url = "https://api.vk.ru/method/users.get"
    expected_username = "durov"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "response": [
                {
                    "uid": "1",
                    "first_name": "Павел",
                    "last_name": "Дуров",
                    "screen_name": "durov",
                    "nickname": "",
                    "photo": r"http:\/\/cs7003.vk.me\/v7003815\/22a1\/xgG9fb-IJ3Y.jpg",
                }
            ]
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class VKIDOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.vk.VKIDOAuth2"
    raw_complete_url = "/complete/{0}/?code=foobar&device_id=device-id"
    user_data_url = "https://id.vk.ru/oauth2/user_info"
    user_data_url_post = True
    expected_username = "pavel@example.com"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "refresh",
            "id_token": "id-token",
            "user_id": 1,
            "device_id": "token-device-id",
        }
    )
    user_data_body = json.dumps(
        {
            "user": {
                "user_id": 1,
                "first_name": "Павел",
                "last_name": "Дуров",
                "email": "pavel@example.com",
                "avatar": "https://example.com/avatar.jpg",
            }
        }
    )

    def extra_settings(self) -> dict[str, Any]:
        settings: dict[str, Any] = super().extra_settings()
        settings[f"SOCIAL_AUTH_{self.name}_USERNAME_IS_FULL_EMAIL"] = True
        return settings

    def test_login(self) -> None:
        user = self.do_login()
        social = user.social[0]

        auth_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.authorization_url())
        )
        auth_query = get_querystring(cast("str", auth_request.url))

        token_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )
        token_data = parse_qs(token_request.body)
        self.assertEqual(token_data["client_id"], "a-key")
        self.assertNotIn("client_secret", token_data)
        self.assertEqual(token_data["device_id"], "device-id")
        self.assertEqual(token_data["state"], auth_query["state"])
        self.assertEqual(
            self.backend.generate_code_challenge(token_data["code_verifier"]),
            auth_query["code_challenge"],
        )

        user_info_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.USER_INFO_URL)
        )
        user_info_data = parse_qs(user_info_request.body)
        self.assertEqual(user_info_data["access_token"], "foobar")
        self.assertEqual(user_info_data["client_id"], "a-key")
        self.assertEqual(social.extra_data["device_id"], "token-device-id")

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_login_with_payload_callback(self) -> None:
        start_url = self.backend.start().url
        state = get_querystring(start_url)["state"]
        payload = json.dumps(
            {
                "code": "foobar",
                "device_id": "payload-device-id",
                "state": state,
            }
        )
        self.strategy.set_request_data({"payload": payload}, self.backend)
        responses.add(
            self._method(self.backend.ACCESS_TOKEN_METHOD),
            self.backend.access_token_url(),
            status=200,
            body=self.access_token_body,
            content_type="application/json",
        )
        responses.add(
            responses.POST,
            self.user_data_url,
            body=self.user_data_body,
            content_type=self.user_data_content_type,
        )

        user = cast(User, self.backend.complete())

        token_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )
        token_data = parse_qs(token_request.body)
        self.assertEqual(token_data["device_id"], "payload-device-id")
        self.assertEqual(user.username, self.expected_username)
