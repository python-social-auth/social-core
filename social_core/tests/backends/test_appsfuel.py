import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class AppsfuelOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.appsfuel.AppsfuelOAuth2"
    user_data_url = "https://api.appsfuel.com/v1/live/user"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "user_id": "123",
            "display_name": "Foo Bar",
            "email": "foobar@example.com",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class AppsfuelOAuth2SandboxTest(AppsfuelOAuth2Test):
    backend_path = "social_core.backends.appsfuel.AppsfuelOAuth2Sandbox"
    user_data_url = "https://api.appsfuel.com/v1/sandbox/user"
