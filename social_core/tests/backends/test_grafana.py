import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class GrafanaOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.grafana.GrafanaOAuth2"
    user_data_url = "https://grafana.com/api/oauth2/user"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
        }
    )
    user_data_body = json.dumps(
        {"id": 123, "login": "fooboy", "email": "foo@bar.com", "name": "Foo Bar"}
    )
    expected_username = "fooboy"

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual((user.social[0].uid, user.social[0].id_key), ("123", "id"))

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
