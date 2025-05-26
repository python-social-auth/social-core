# pyright: reportAttributeAccessIssue=false

import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class CognitoAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.cognito.CognitoOAuth2"
    pool_domain = "https://social_core.auth.eu-west-1.amazoncognito.com"
    user_data_url = (
        "https://social_core.auth.eu-west-1.amazoncognito.com/oauth2/userInfo"
    )
    expected_username = "cognito.account.ABCDE1234"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "given_name": "John",
            "family_name": "Doe",
            "username": "cognito.account.ABCDE1234",
            "email": "john@doe.test",
        }
    )

    def extra_settings(self):
        settings = super().extra_settings()
        assert self.name, "subclasses must set the name attribute"
        settings.update(
            {
                "SOCIAL_AUTH_" + self.name + "_POOL_DOMAIN": self.pool_domain,
            }
        )
        return settings

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
