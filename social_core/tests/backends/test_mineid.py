import json

from social_core.exceptions import AuthResponseError
from social_core.tests.models import TestUserSocialAuth, User

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

    def test_login_fails_without_immutable_account_identifier(self) -> None:
        with self.assertRaises(AuthResponseError) as caught:
            self.do_start()
        self.assertEqual(caught.exception.code, "missing_claim")
        self.assertFalse(User.cache)
        self.assertFalse(TestUserSocialAuth.cache_by_uid)

    def test_auth_url_parameters(self) -> None:
        self.check_parameters_in_authorization_url("AUTHORIZATION_URL")
