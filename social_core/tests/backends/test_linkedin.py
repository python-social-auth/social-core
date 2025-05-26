import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .open_id_connect import OpenIdConnectTest


class LinkedinOpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.linkedin.LinkedinOpenIdConnect"
    user_data_url = "https://api.linkedin.com/v2/userinfo"
    issuer = "https://www.linkedin.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://www.linkedin.com",
            "authorization_endpoint": "https://www.linkedin.com/oauth/v2/authorization",
            "token_endpoint": "https://www.linkedin.com/oauth/v2/accessToken",
            "userinfo_endpoint": "https://api.linkedin.com/v2/userinfo",
            "jwks_uri": "https://www.linkedin.com/oauth/openid/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "claims_supported": [
                "iss",
                "aud",
                "iat",
                "exp",
                "sub",
                "name",
                "given_name",
                "family_name",
                "picture",
                "email",
                "email_verified",
                "locale",
            ],
        }
    )

    def test_invalid_nonce(self) -> None:
        """Skip the invalid nonce test as LinkedIn does not provide any nonce."""


class BaseLinkedinTest:
    user_data_url = "https://api.linkedin.com/v2/me?projection=(firstName,id,lastName)"
    expected_username = "FooBar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})

    # Reference:
    # https://docs.microsoft.com/en-us/linkedin/consumer/integrations/self
    # -serve/sign-in-with-linkedin?context=linkedin/consumer/context#api-request
    user_data_body = json.dumps(
        {
            "id": "1010101010",
            "firstName": {
                "localized": {"en_US": "Foo"},
                "preferredLocale": {"country": "US", "language": "en"},
            },
            "lastName": {
                "localized": {"en_US": "Bar"},
                "preferredLocale": {"country": "US", "language": "en"},
            },
        }
    )

    def test_login(self) -> None:
        self.do_login()  # type: ignore[attr-defined]

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()  # type: ignore[attr-defined]


class LinkedinOAuth2Test(BaseLinkedinTest, OAuth2Test):
    backend_path = "social_core.backends.linkedin.LinkedinOAuth2"


class LinkedinMobileOAuth2Test(BaseLinkedinTest, OAuth2Test):
    backend_path = "social_core.backends.linkedin.LinkedinMobileOAuth2"
