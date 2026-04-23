import json

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class SurveyMonkeyOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.surveymonkey.SurveyMonkeyOAuth2"
    user_data_url = "https://api.surveymonkey.com/v3/users/me"
    expected_username = "ada"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "access_url": "https://api.surveymonkey.com",
            "token_type": "bearer",
        }
    )
    user_data_body = json.dumps(
        {
            "id": "123",
            "username": "ada",
            "email": "ada@example.com",
            "first_name": "Ada",
            "last_name": "Lovelace",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
