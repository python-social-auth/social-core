import json
from types import SimpleNamespace

from social_core.backends.yandex import YandexOpenId
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


def test_yandex_openid_url_uses_https() -> None:
    assert YandexOpenId.URL == "https://openid.yandex.ru"


def test_yandex_openid_configured_key_preserves_identity_url_fallback() -> None:
    strategy = TestStrategy(TestStorage)
    strategy.set_settings({"SOCIAL_AUTH_YANDEX_OPENID_ID_KEY": "custom_id"})
    backend = YandexOpenId(strategy)
    response = SimpleNamespace(identity_url="https://openid.yandex.ru/user")

    assert backend.get_user_id({}, response) == response.identity_url


class YandexOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.yandex.YandexOAuth2"
    user_data_url = "https://login.yandex.ru/info"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "display_name": "foobar",
            "real_name": "Foo Bar",
            "sex": None,
            "id": "101010101",
            "default_email": "foobar@yandex.com",
            "emails": ["foobar@yandex.com"],
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class YandexOAuth2TestEmptyEmail(OAuth2Test, BaseAuthUrlTestMixin):
    """
    When user log in to yandex service with social network account (e.g.
    vk.com), their `default_email` could be empty.
    """

    backend_path = "social_core.backends.yandex.YandexOAuth2"
    user_data_url = "https://login.yandex.ru/info"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "display_name": "foobar",
            "real_name": "Foo Bar",
            "sex": None,
            "id": "101010101",
            "default_email": "",
            "emails": [],
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
