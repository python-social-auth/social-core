import json

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class MailChimpOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.mailchimp.MailChimpOAuth2"
    user_data_url = "https://login.mailchimp.com/oauth2/metadata"
    expected_username = "ada"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "accountname": "Example",
            "api_endpoint": "https://us1.api.mailchimp.com",
            "login": {"login_name": "ada", "email": "ada@example.com"},
            "role": "owner",
            "user_id": "123",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
