import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


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
    vk.com), they `default_email` could be empty.
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
