"""
Copyright (c) 2017 Noderabbit Inc., d.b.a. Appsembler

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import base64
import json
from time import time
from typing import TYPE_CHECKING, cast

import jwt
import responses
from jwt.algorithms import RSAAlgorithm

from social_core.exceptions import AuthMissingParameter, AuthTokenError
from social_core.utils import get_querystring

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# Dummy public and private keys:
RSA_PUBLIC_JWT_KEY = {
    # https://github.com/jpadilla/pyjwt/blob/06f461a/tests/keys/jwk_rsa_pub.json
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB",
}

RSA_PRIVATE_JWT_KEY = {
    # https://github.com/jpadilla/pyjwt/blob/06f461a/tests/keys/jwk_rsa_key.json
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB",
    "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
    "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
    "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
    "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",
    "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
    "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4",
}


class AzureADB2COAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    AUTH_KEY = "abcdef12-1234-9876-0000-abcdef098765"
    EXPIRES_IN = 3600
    AUTH_TIME = int(time())
    EXPIRES_ON = AUTH_TIME + EXPIRES_IN
    ISSUER = "https://footenant.b2clogin.com/9a9a9a9a-1111-5555-0000-bc24adfdae00/v2.0/"
    JWKS_URL = "https://footenant.b2clogin.com/footenant.onmicrosoft.com/discovery/v2.0/keys?p=b2c_1_signin"
    POLICY = "b2c_1_signin"
    TOKEN_POLICY = "B2C_1_SignIn"

    backend_path = "social_core.backends.azuread_b2c.AzureADB2COAuth2"
    expected_username = "FooBar"
    access_token_body = ""
    refresh_token_body = json.dumps(
        {
            "access_token": "foobar-new-token",
            "token_type": "bearer",
            "expires_in": EXPIRES_IN,
            "refresh_token": "foobar-new-refresh-token",
            "scope": "identity",
        }
    )

    def build_id_token(self, **overrides) -> str:
        payload = {
            "aud": self.AUTH_KEY,
            "auth_time": self.AUTH_TIME,
            "country": "Axphain",
            "emails": ["foobar@example.com"],
            "exp": self.EXPIRES_ON,
            "family_name": "Bar",
            "given_name": "Foo",
            "iat": self.AUTH_TIME,
            "iss": self.ISSUER,
            "name": "FooBar",
            "nbf": self.AUTH_TIME,
            "oid": "11223344-5566-7788-9999-aabbccddeeff",
            "postalCode": "00000",
            "sub": "11223344-5566-7788-9999-aabbccddeeff",
            "tfp": self.TOKEN_POLICY,
            "ver": "1.0",
        }
        for key, value in overrides.items():
            if value is None:
                payload.pop(key, None)
            else:
                payload[key] = value

        return jwt.encode(
            key=cast(
                "RSAPrivateKey",
                RSAAlgorithm.from_jwk(json.dumps(RSA_PRIVATE_JWT_KEY)),
            ),
            headers={
                "kid": RSA_PRIVATE_JWT_KEY["kid"],
            },
            algorithm="RS256",
            payload=payload,
        )

    def build_access_token_body(
        self,
        id_token: str | None = None,
        access_token: str | None = "foobar",  # noqa: S107
        **overrides,
    ) -> str:
        body = {
            "token_type": "bearer",
            "id_token": id_token or self.build_id_token(**overrides),
            "expires_in": self.EXPIRES_IN,
            "expires_on": self.EXPIRES_ON,
            "not_before": self.AUTH_TIME,
        }
        if access_token is not None:
            body["access_token"] = access_token
        return json.dumps(body)

    def tamper_id_token(self, id_token: str, **overrides) -> str:
        header, _payload, signature = id_token.split(".")
        payload = jwt.decode(
            id_token,
            options={"verify_signature": False, "verify_aud": False},
        )
        payload.update(overrides)
        data = json.dumps(payload, separators=(",", ":")).encode()
        tampered_payload = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        return f"{header}.{tampered_payload}.{signature}"

    def extra_settings(self):
        settings = super().extra_settings()
        assert self.name, "Name must be set in subclasses"
        settings.update(
            {
                f"SOCIAL_AUTH_{self.name}_POLICY": self.POLICY,
                f"SOCIAL_AUTH_{self.name}_KEY": self.AUTH_KEY,
                f"SOCIAL_AUTH_{self.name}_TENANT_NAME": "footenant",
            }
        )
        return settings

    def setUp(self) -> None:
        super().setUp()
        self.access_token_body = self.build_access_token_body()

        responses.add(
            responses.GET,
            self.backend.openid_configuration_url(),
            status=200,
            body=json.dumps(
                {
                    "issuer": self.ISSUER,
                    "jwks_uri": self.JWKS_URL,
                    "id_token_signing_alg_values_supported": ["RS256"],
                }
            ),
            content_type="application/json",
        )
        responses.add(
            responses.GET,
            self.JWKS_URL,
            status=200,
            body=json.dumps({"keys": [RSA_PUBLIC_JWT_KEY]}),
            content_type="application/json",
        )

    def test_login(self) -> None:
        self.do_login()

    def test_login_accepts_id_token_only_response(self) -> None:
        self.access_token_body = self.build_access_token_body(access_token=None)
        id_token = json.loads(self.access_token_body)["id_token"]

        user = self.do_login()

        self.assertEqual(user.social[0].extra_data["access_token"], id_token)

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        _user, social = self.do_refresh_token()
        self.assertEqual(social.extra_data["access_token"], "foobar-new-token")

    def test_auth_url_uses_configured_policy_when_request_includes_policy(self) -> None:
        self.strategy.set_request_data({"p": "b2c_1_passwordreset"}, self.backend)

        auth_query = get_querystring(self.backend.start().url)

        self.assertEqual(auth_query["p"], self.POLICY)

    def test_login_rejects_invalid_id_token_signature(self) -> None:
        self.access_token_body = self.build_access_token_body(
            self.tamper_id_token(self.build_id_token(), name="Attacker")
        )

        with self.assertRaises(AuthTokenError):
            self.do_start()

    def test_login_rejects_wrong_id_token_audience(self) -> None:
        self.access_token_body = self.build_access_token_body(aud="other-app")

        with self.assertRaises(AuthTokenError):
            self.do_start()

    def test_login_rejects_wrong_id_token_issuer(self) -> None:
        self.access_token_body = self.build_access_token_body(
            iss="https://footenant.b2clogin.com/00000000-0000-0000-0000-000000000000/v2.0/"
        )

        with self.assertRaises(AuthTokenError):
            self.do_start()

    def test_login_rejects_wrong_id_token_policy(self) -> None:
        self.access_token_body = self.build_access_token_body(tfp="B2C_1_PasswordReset")

        with self.assertRaises(AuthTokenError):
            self.do_start()

    def test_login_rejects_missing_id_token_policy(self) -> None:
        self.access_token_body = self.build_access_token_body(tfp=None)

        with self.assertRaises(AuthMissingParameter):
            self.do_start()

    def test_login_accepts_legacy_acr_policy_claim(self) -> None:
        self.access_token_body = self.build_access_token_body(
            tfp=None, acr=self.TOKEN_POLICY
        )

        self.do_login()
