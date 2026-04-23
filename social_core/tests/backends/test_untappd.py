import json

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class UntappdOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.untappd.UntappdOAuth2"
    user_data_url = "https://api.untappd.com/v4/user/info/"
    expected_username = "ada"
    access_token_body = json.dumps(
        {"meta": {"http_code": 200}, "response": {"access_token": "foobar"}}
    )
    user_data_body = json.dumps(
        {
            "meta": {"http_code": 200},
            "response": {
                "user": {
                    "id": "123",
                    "user_name": "ada",
                    "first_name": "Ada",
                    "last_name": "Lovelace",
                    "settings": {"email_address": "ada@example.com"},
                }
            },
        }
    )

    def test_auth_params_include_redirect_url_and_state(self) -> None:
        params = self.backend.auth_params("test-state")

        self.assertEqual(params["redirect_url"], self.backend.get_redirect_uri())
        self.assertEqual(params["state"], "test-state")

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
