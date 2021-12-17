import json

from ...backends.facebook import API_VERSION
from ...exceptions import AuthCanceled, AuthUnknownError
from .oauth import OAuth2Test
from .test_open_id_connect import OpenIdConnectTestMixin


class FacebookOAuth2Test(OAuth2Test):
    backend_path = "social_core.backends.facebook.FacebookOAuth2"
    user_data_url = "https://graph.facebook.com/v{version}/me".format(
        version=API_VERSION
    )
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "username": "foobar",
            "first_name": "Foo",
            "last_name": "Bar",
            "verified": True,
            "name": "Foo Bar",
            "gender": "male",
            "updated_time": "2013-02-13T14:59:42+0000",
            "link": "http://www.facebook.com/foobar",
            "id": "110011001100010",
        }
    )

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()


class FacebookOAuth2WrongUserDataTest(FacebookOAuth2Test):
    user_data_body = "null"

    def test_login(self):
        with self.assertRaises(AuthUnknownError):
            self.do_login()

    def test_partial_pipeline(self):
        with self.assertRaises(AuthUnknownError):
            self.do_partial_pipeline()


class FacebookOAuth2AuthCancelTest(FacebookOAuth2Test):
    access_token_status = 400
    access_token_body = json.dumps(
        {
            "error": {
                "message": "redirect_uri isn't an absolute URI. Check RFC 3986.",
                "code": 191,
                "type": "OAuthException",
                "fbtrace_id": "123Abc",
            }
        }
    )

    def test_login(self):
        with self.assertRaises(AuthCanceled) as cm:
            self.do_login()
        self.assertIn("error", cm.exception.response.json())

    def test_partial_pipeline(self):
        with self.assertRaises(AuthCanceled) as cm:
            self.do_partial_pipeline()
        self.assertIn("error", cm.exception.response.json())


class FacebookLimitedLoginTest(OpenIdConnectTestMixin, OAuth2Test):
    backend_path = "social_core.backends.facebook.FacebookLimitedLogin"
    issuer = "https://facebook.com"
    openid_config_body = """
    {
      "issuer": "https://facebook.com",
      "authorization_endpoint": "https://facebook.com/dialog/oauth/",
      "jwks_uri": "https://facebook.com/.well-known/oauth/openid/jwks/",
      "response_types_supported": [
        "id_token",
        "token id_token"
      ],
      "subject_types_supported": "pairwise",
      "id_token_signing_alg_values_supported": [
        "RS256"
      ],
      "claims_supported": [
        "iss",
        "aud",
        "sub",
        "iat",
        "exp",
        "jti",
        "nonce",
        "at_hash",
        "name",
        "email",
        "picture",
        "user_friends",
        "user_birthday",
        "user_age_range"
      ]
    }
    """

    def test_invalid_nonce(self):
        # The nonce isn't generated server-side so the test isn't relevant here.
        pass
