import json

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class GoClioOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.goclio.GoClioOAuth2"
    user_data_url = "https://app.goclio.com/api/v2/users/who_am_i"
    expected_username = "123"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "user": {
                "id": "123",
                "email": "ada@example.com",
                "first_name": "Ada",
                "last_name": "Lovelace",
            }
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class GoClioEuOAuth2Test(GoClioOAuth2Test):
    backend_path = "social_core.backends.goclioeu.GoClioEuOAuth2"
    user_data_url = "https://app.goclio.eu/api/v2/users/who_am_i"
