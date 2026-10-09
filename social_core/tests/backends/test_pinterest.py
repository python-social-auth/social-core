import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class PinterestOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.pinterest.PinterestOAuth2"
    user_data_url = "https://api.pinterest.com/v1/me/"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "user_id": "4788400174839062",
            "first_name": "Foo",
            "last_name": "Bar",
            "username": "foobar",
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual(
            (user.social[0].uid, user.social[0].id_key),
            ("4788400174839062", "user_id"),
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class PinterestOAuth2BrokenServerResponseTest(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.pinterest.PinterestOAuth2"
    user_data_url = "https://api.pinterest.com/v1/me/"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "data": {
                "id": "4788400174839062",
                "first_name": "Foo",
                "last_name": "Bar",
                "url": "https://www.pinterest.com/foobar/",
            }
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual(
            (user.social[0].uid, user.social[0].id_key),
            ("4788400174839062", "user_id"),
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
