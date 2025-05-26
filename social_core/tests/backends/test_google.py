import json
import time
from unittest import mock
from urllib.parse import urlencode

import jwt
import responses

from ...actions import do_disconnect
from ...exceptions import AuthException, AuthTokenError
from ..models import User
from .base import BaseBackendTest
from .oauth import BaseAuthUrlTestMixin, OAuth1AuthUrlTestMixin, OAuth1Test, OAuth2Test
from .open_id_connect import OpenIdConnectTest


class GoogleOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.google.GoogleOAuth2"
    user_data_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    expected_username = "foo"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "profile": "https://plus.google.com/101010101010101010101",
            "family_name": "Bar",
            "sub": "101010101010101010101",
            "picture": "https://lh5.googleusercontent.com/-ui-GqpNh5Ms/"
            "AAAAAAAAAAI/AAAAAAAAAZw/a7puhHMO_fg/photo.jpg",
            "locale": "en",
            "email_verified": True,
            "given_name": "Foo",
            "email": "foo@bar.com",
            "name": "Foo Bar",
        }
    )

    def test_login(self):
        self.do_login()
        last_request = responses.calls[-1].request
        self.assertEqual(last_request.method, "GET")
        self.assertEqual(self.user_data_url, last_request.url)
        self.assertEqual(
            last_request.headers["Authorization"],
            "Bearer foobar",
        )

    def test_partial_pipeline(self):
        self.do_partial_pipeline()

    def test_with_unique_user_id(self):
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_GOOGLE_OAUTH2_USE_UNIQUE_USER_ID": True,
            }
        )
        self.do_login()


class GoogleOAuth1Test(OAuth1Test, OAuth1AuthUrlTestMixin):
    backend_path = "social_core.backends.google.GoogleOAuth"
    user_data_url = "https://www.googleapis.com/userinfo/email"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    request_token_body = urlencode(
        {
            "oauth_token_secret": "foobar-secret",
            "oauth_token": "foobar",
            "oauth_callback_confirmed": "true",
        }
    )
    user_data_body = urlencode(
        {
            "email": "foobar@gmail.com",
            "isVerified": "true",
            "id": "101010101010101010101",
        }
    )

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()

    def test_with_unique_user_id(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH_USE_UNIQUE_USER_ID": True}
        )
        self.do_login()

    def test_with_anonymous_key_and_secret(self):
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_GOOGLE_OAUTH_KEY": None,
                "SOCIAL_AUTH_GOOGLE_OAUTH_SECRET": None,
            }
        )
        self.do_login()


class GoogleRevokeTokenTest(GoogleOAuth2Test):
    def test_revoke_token(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH2_REVOKE_TOKENS_ON_DISCONNECT": True}
        )
        self.do_login()
        user = User.get(self.expected_username)
        user.password = "password"
        responses.add(
            self._method(self.backend.REVOKE_TOKEN_METHOD),
            self.backend.REVOKE_TOKEN_URL,
            status=200,
        )
        do_disconnect(self.backend, user)


class GoogleOpenIdConnectTest(OpenIdConnectTest):
    backend_path = "social_core.backends.google_openidconnect.GoogleOpenIdConnect"
    user_data_url = "https://www.googleapis.com/plus/v1/people/me/openIdConnect"
    issuer = "accounts.google.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://www.googleapis.com/oauth2/v4/token",
            "userinfo_endpoint": "https://www.googleapis.com/oauth2/v3/userinfo",
            "revocation_endpoint": "https://accounts.google.com/o/oauth2/revoke",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "code token",
                "code id_token",
                "token id_token",
                "code token id_token",
                "none",
            ],
            "subject_types_supported": [
                "public",
            ],
            "id_token_signing_alg_values_supported": [
                "RS256",
            ],
            "scopes_supported": [
                "openid",
                "email",
                "profile",
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "claims_supported": [
                "aud",
                "email",
                "email_verified",
                "exp",
                "family_name",
                "given_name",
                "iat",
                "iss",
                "locale",
                "name",
                "picture",
                "sub",
            ],
        }
    )


class GoogleOneTapTest(BaseBackendTest):
    backend_path = "social_core.backends.google_onetap.GoogleOneTap"
    private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC6lDOJ0zKiNKJM3p0nTOJgaaHhxPoIJARcRzNSkzG0vC4QnXbB
I3E42elTL3Nujyt80frzIji12KIJqAZIFsG6SSzKcYNeXf+dPwehIrWa7z/N5HD4
x9Fufj5GDT7SyHCAHi3BDHkA599fpOw8odBambK2cshMNkjyNDP+MvGORQIDAQAB
AoGBAJUZYaY+VDQzg4+SRlvloPIS9/6HfpeK0ME9VNIkNpCL4PP+IaxuOkiIO2Dy
hnhPiR0SYExziIYpPDQjRgHNzblGXa2jq+jy/SWj+t0+E0vPhg0kBSA4cYclH+c/
xwp0iW0ocVjod4RxFu6qSMU1TY83NNc4khBON3/GZiU99ImBAkEA5+17SuWvbUA/
jQhuAmzMND1QK4cteYFUnkpqpMQsitq/SC/NgcqUKdqteghPPoJOlGH8UfaM+0EK
uf0Dd327XQJBAM3xw6M8TyiPOY6Qvfadk+IqBdsUb9T7Q9xIB0kMEcfwRdKJ3KgR
CvUjxBdXNf7ZuhykIDle80we41yzZK+2WAkCQCM2PQfMA2xU2tEwvHMFzaMIxAk3
xsGxzwURS0uktRaHy47MIylXdlM8biYe6NkWs5N3pPVUt2bWIyjFrycPIckCQQCe
cmGol1/3vqnzy9y7fuUmXlp/AaxA2siNFEW2p7iOcYfmwfaov+QEUu4tXwXF+9G6
83NvcGQTrrgSvFq87bexAkB2f5dFbl2tYWRQ7wGmmX++JDuHwHDI99rnsUxVhSFk
1LiRk3XACJa5y1peU9rkTfWeu5aoFb5WyheQacNQcu80
-----END RSA PRIVATE KEY-----"""
    public_key = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6lDOJ0zKiNKJM3p0nTOJgaaHh
xPoIJARcRzNSkzG0vC4QnXbBI3E42elTL3Nujyt80frzIji12KIJqAZIFsG6SSzK
cYNeXf+dPwehIrWa7z/N5HD4x9Fufj5GDT7SyHCAHi3BDHkA599fpOw8odBambK2
cshMNkjyNDP+MvGORQIDAQAB
-----END PUBLIC KEY-----"""
    client_id = "a-key"

    def setUp(self):
        super().setUp()
        responses.add(
            responses.GET,
            "https://www.googleapis.com/oauth2/v1/certs",
            status=200,
            body=json.dumps({"test_key": self.public_key}),
        )

    def _get_jwt_payload(self):
        claimed_at = int(time.time())
        return {
            "given_name": "test name",
            "email": "test@test.com",
            "aud": self.client_id,
            "iat": claimed_at,
            "exp": claimed_at + 30,
            "iss": "accounts.google.com",
        }

    def test_auth_url(self):
        with self.assertRaises(AuthException):
            self.backend.start()

    def test_verify_csrf_no_csrf_token_body(self):
        with self.assertRaises(AuthTokenError):
            self.backend.verify_csrf(request=mock.Mock())

    def test_verify_csrf_no_csrf_token_cookie_not_ignored(self):
        self.backend.data = {"g_csrf_token": "csrf"}
        with self.assertRaises(AuthTokenError):
            self.backend.verify_csrf(request=mock.Mock(COOKIES={}))

    def test_verify_csrf_no_csrf_token_cookie_ignored(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_ONETAP_IGNORE_MISSING_CSRF_COOKIE": True}
        )
        self.backend.data = {"g_csrf_token": "csrf"}
        self.backend.verify_csrf(request=mock.Mock(COOKIES={}))

    def test_verify_csrf_valid(self):
        self.backend.data = {"g_csrf_token": "csrf"}
        self.backend.verify_csrf(request=mock.Mock(COOKIES={"g_csrf_token": "csrf"}))

    def test_get_decoded_info_error(self):
        payload = self._get_jwt_payload()
        payload["exp"] -= 31
        self.backend.data = {
            "credential": jwt.encode(
                payload,
                self.private_key,
                algorithm="RS256",
                headers={"kid": "test_key"},
            ),
            "g_csrf_token": "csrf",
        }
        request = mock.Mock(COOKIES={"g_csrf_token": "csrf"})

        with self.assertRaises(AuthException):
            self.backend.auth_complete(request=request)

    def test_get_decoded_info_success(self):
        self.backend.data = {
            "credential": jwt.encode(
                self._get_jwt_payload(),
                self.private_key,
                algorithm="RS256",
                headers={"kid": "test_key"},
            ),
            "g_csrf_token": "csrf",
        }
        request = mock.Mock(COOKIES={"g_csrf_token": "csrf"})

        user = self.backend.auth_complete(request=request)

        self.assertEqual(user.email, "test@test.com")
        self.assertEqual(user.first_name, "test name")
