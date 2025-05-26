import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class SeznamOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.seznam.SeznamOAuth2"
    user_data_url = "https://login.szn.cz/api/v1/user"
    expected_username = "krasty"
    access_token_body = json.dumps(
        {
            "access_token": "foo",
            "account_name": "krasty@seznam.cz",
            "expires_in": 31536000,
            "oauth_user_id": "0123abcd",
            "refresh_token": "bar",
            "scopes": ["identity"],
            "token_type": "bearer",
        }
    )
    user_data_body = json.dumps(
        {
            "email": "krasty@seznam.cz",
            "firstname": "Krasty",
            "lastname": "Dog",
            "oauth_user_id": "0123abcd",
            "username": "krasty",
        }
    )

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
