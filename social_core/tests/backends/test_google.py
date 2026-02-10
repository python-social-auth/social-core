from __future__ import annotations

import json
import time
from typing import cast
from unittest import mock
from urllib.parse import urlencode

import jwt
import responses

from social_core.actions import do_disconnect
from social_core.exceptions import AuthException, AuthTokenError
from social_core.tests.models import User

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

    def test_login(self) -> None:
        self.do_login()
        last_request = responses.calls[-1].request
        self.assertEqual(last_request.method, "GET")
        self.assertEqual(self.user_data_url, last_request.url)
        self.assertEqual(
            last_request.headers["Authorization"],
            "Bearer foobar",
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_with_unique_user_id(self) -> None:
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

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_with_unique_user_id(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH_USE_UNIQUE_USER_ID": True}
        )
        self.do_login()

    def test_with_anonymous_key_and_secret(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_GOOGLE_OAUTH_KEY": None,
                "SOCIAL_AUTH_GOOGLE_OAUTH_SECRET": None,
            }
        )
        self.do_login()


class GoogleRevokeTokenTest(GoogleOAuth2Test):
    def test_revoke_token(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH2_REVOKE_TOKENS_ON_DISCONNECT": True}
        )
        self.do_login()
        user = cast("User", User.get(self.expected_username))
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
MIIEowIBAAKCAQEAyF/O/3dZ8p+bYELDbZUwHtrL6FR01TChAffgVr4HXyKWGb25
GpScipmdxCZwzMdIx8sDkQJMY8AeXMAVNT/u6a5HvZshyYqR+IyoEAXIIA9f2v+M
hQrePsXQZ+mwdj+gt2CpIoP7FImyYWmkwNSVcXAEC04ttywEOprsW2jbrVu5L4jM
EeL5EEMCxKHhpqVMF98MOXfALIiPqKmJYJNC1La6/wgSeNbIrgFxj3CulCu0AnOs
Xr+DOwJvdEcCi8VzKWCC2Djbw3HQofE3USGWRC0m18vRp3Y3VNJ6rZu2m0Pi/6nC
Zs7hAQCpQbbZpmFrot7jVoQI4y9R3+x91pTWoQIDAQABAoIBAA49Kgy4aAbC9dEm
Mr9fnymfexGu/Wsa8g4dlcPEQZTZSdkEGkUmc2YGsDyR+L5smPeYWHqzsvGnDjah
cGsLeIhYRKvXfClXdLO4wcaltTN7XuCaprCGSwXN8SyOjDt9nlz5pvtCGBO9DJU5
4yXQKtstTnRD4XbHT3j0rRV6gvCI2DO2ykJtHizcOyeTS7WU7Iwt55kGHog8HpjN
9ujrjkCCsQAgEnaFvwisY21E6VE28LijH+mGpiDtpTkRSFboeBehqz5bfXaFusc2
LPLQOmXtJKBpGrSz31dDKeqzeO65EpCaYOY+SV6mCflE2N6dCecW5yYbpGCMiF6g
c7M1M/kCgYEA/fMOotHXTHqjjSNETdqZqii1iSGFJt/K1jxx6PSqWOPpdAY5qEBP
yV4SRhi/A6Aq15HBRABAjZI1eR2bVpFQXXAZ2O1y/oZZnTgYm67qsMiCkv8qZqqm
g08VZbM73gSzQp6Kn7M5pFJhYUc45ewErJLssihZQ0P2P/g/EpQSLu0CgYEAyf4B
W+RrQCZqn8+3YY/kj49KI6l8DhSSnpfEiYPSwHjVxPPkSaouwn5QZ43yFjWKL7t9
ontAI8rgI11lFA0/vMTlk7LwYivjRs/FO1G/lWmD3gPLyJLkDsTWlj7DESZTuSko
Nuezo0toeGYAwvj8efDaemq1afNZTfo2OA54HAUCgYAbWlnCOd3509/X7OuHgzs3
88iR67Ve2Y4Mg1g1olzS1EGqCJ2fPMYbR3GqcTHp3w+eRonNnEVXul7eG81GhsJk
PhXaosDXH3t5jrg/1Jhc0EwYLznO8ySaUiNY3/Rb1p/EVjVSPEjCJUlt4/EB+ukJ
+Y1bJzNuJlzYyRFqG97VhQKBgQCg7FBA2XXoobKIp3+9plm9VbcHOluvDAzTdK4L
sI4S8TG9u2DAn2ipYuDD335i2zzAUmsBK5gp69Mt2ZZRp0yEI4mTZhfE3povLBBB
9hrf+jQoiHWt0fkHGyKqiE34N8Sz22pCc83V5pnQcdNhgeQDcjNdG+5z/n/Dc/gG
KODf0QKBgGd83wO3vOrxxXaYc0HocqQBXUoD8tveMmlHfE7B5/a3GrW7lbrZZGK9
2HoqEwQAXnz6n1j4pXFh+9PvnU3059Qj/89oAcJhPpro9067R6Og6kETn03YE67S
Ef9c7COsUJeZOpsWXofUG1Lm8iHgRiE9aXyyrltEmcOGdJLy8kIX
-----END RSA PRIVATE KEY-----"""
    public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyF/O/3dZ8p+bYELDbZUw
HtrL6FR01TChAffgVr4HXyKWGb25GpScipmdxCZwzMdIx8sDkQJMY8AeXMAVNT/u
6a5HvZshyYqR+IyoEAXIIA9f2v+MhQrePsXQZ+mwdj+gt2CpIoP7FImyYWmkwNSV
cXAEC04ttywEOprsW2jbrVu5L4jMEeL5EEMCxKHhpqVMF98MOXfALIiPqKmJYJNC
1La6/wgSeNbIrgFxj3CulCu0AnOsXr+DOwJvdEcCi8VzKWCC2Djbw3HQofE3USGW
RC0m18vRp3Y3VNJ6rZu2m0Pi/6nCZs7hAQCpQbbZpmFrot7jVoQI4y9R3+x91pTW
oQIDAQAB
-----END PUBLIC KEY-----"""
    client_id = "a-key"

    def setUp(self) -> None:
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

    def test_auth_url(self) -> None:
        with self.assertRaises(AuthException):
            self.backend.start()

    def test_verify_csrf_no_csrf_token_body(self) -> None:
        with self.assertRaises(AuthTokenError):
            self.backend.verify_csrf(request=mock.Mock())

    def test_verify_csrf_no_csrf_token_cookie_not_ignored(self) -> None:
        self.backend.data = {"g_csrf_token": "csrf"}
        with self.assertRaises(AuthTokenError):
            self.backend.verify_csrf(request=mock.Mock(COOKIES={}))

    def test_verify_csrf_no_csrf_token_cookie_ignored(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_ONETAP_IGNORE_MISSING_CSRF_COOKIE": True}
        )
        self.backend.data = {"g_csrf_token": "csrf"}
        self.backend.verify_csrf(request=mock.Mock(COOKIES={}))

    def test_verify_csrf_valid(self) -> None:
        self.backend.data = {"g_csrf_token": "csrf"}
        self.backend.verify_csrf(request=mock.Mock(COOKIES={"g_csrf_token": "csrf"}))

    def test_get_decoded_info_error(self) -> None:
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

    def test_get_decoded_info_success(self) -> None:
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
