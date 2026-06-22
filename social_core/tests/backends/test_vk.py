import json

from social_core.backends.vk import vk_sig
from social_core.exceptions import AuthFailed
from social_core.tests.models import TestUserSocialAuth, User

from .base import BaseBackendTest
from .oauth import BaseAuthUrlTestMixin, OAuth2Test

APP_ID = "12345"
APP_SECRET = "a-secret-key"
VIEWER_ID = "424242"


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


class VKAppOAuth2Test(BaseBackendTest):
    backend_path = "social_core.backends.vk.VKAppOAuth2"
    expected_username = "vkuser"

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

    def do_start(self) -> User:
        self.strategy.set_request_data(self.signed_request_data(), self.backend)
        return self.backend.complete()

    def test_login(self) -> None:
        user = self.do_login()

        self.assertEqual(user.username, self.expected_username)
        self.assertEqual(user.social[0].uid, VIEWER_ID)
        self.assertEqual(user.social[0].provider, self.backend.name)

    def test_rejects_missing_auth_key_before_authentication(self) -> None:
        self.strategy.set_request_data(self.request_data(), self.backend)

        with self.assertRaisesRegex(AuthFailed, "Missing auth key"):
            self.backend.complete()

        self.assertIsNone(self.strategy.session_get("username"))
        self.assertEqual(User.cache, {})
        self.assertEqual(TestUserSocialAuth.cache_by_uid, {})

    def test_rejects_invalid_auth_key(self) -> None:
        data = self.request_data()
        data["auth_key"] = "0" * 32
        self.strategy.set_request_data(data, self.backend)

        with self.assertRaisesRegex(AuthFailed, "Invalid auth key"):
            self.backend.complete()
