import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class MineIDOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.mineid.MineIDOAuth2"
    user_data_url = "https://www.mineid.org/api/user"
    expected_username = "foo@bar.com"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "email": "foo@bar.com",
            "primary_profile": None,
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_auth_url_parameters(self) -> None:
        self.check_parameters_in_authorization_url("_AUTHORIZATION_URL")
