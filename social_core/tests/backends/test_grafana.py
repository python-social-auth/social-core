import json

from .oauth import OAuth2Test


class GrafanaOAuth2Test(OAuth2Test):
    backend_path = "social_core.backends.grafana.GrafanaOAuth2"
    user_data_url = "https://grafana.com/api/oauth2/user"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
        }
    )
    user_data_body = json.dumps(
        {"login": "fooboy", "email": "foo@bar.com", "name": "Foo Bar"}
    )
    expected_username = "fooboy"

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
