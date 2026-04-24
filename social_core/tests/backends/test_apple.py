import json
from time import time
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import jwt
import responses
from jwt.algorithms import RSAAlgorithm

from social_core.exceptions import AuthFailed

from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .test_azuread_b2c import RSA_PRIVATE_JWT_KEY, RSA_PUBLIC_JWT_KEY

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

TEST_KEY = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKQya8aIoeoOLeThk7Ad/lLyAo2fTp9IuhIpy2CivH/qoAoGCCqGSM49
AwEHoUQDQgAEyEY7IMlNJtyaF/pdcM/PpQ8OCe19Sf1Yxq4HQsrB2b7QogB95Vjt
6mTZDAhlXIBtuM/JLrdkMfPmwjVKLgxHAQ==
-----END EC PRIVATE KEY-----
"""


token_data = {
    "sub": "11011110101011011011111011101111",
    "first_name": "Foo",
    "last_name": "Bar",
    "email": "foobar@apple.com",
}


class AppleIdTest(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.apple.AppleIdAuth"
    user_data_url = "https://appleid.apple.com/auth/authorize/"
    id_token = "a-id-token"
    access_token_body = json.dumps(
        {"id_token": id_token, "access_token": "a-test-token"}
    )
    expected_username = token_data["sub"]

    def extra_settings(self):
        assert self.name, "Name must be set in subclasses"
        return {
            f"SOCIAL_AUTH_{self.name}_TEAM": "a-team-id",
            f"SOCIAL_AUTH_{self.name}_KEY": "a-key-id",
            f"SOCIAL_AUTH_{self.name}_CLIENT": "a-client-id",
            f"SOCIAL_AUTH_{self.name}_SECRET": TEST_KEY,
            f"SOCIAL_AUTH_{self.name}_SCOPE": ["name", "email"],
        }

    def build_id_token(self, **overrides) -> str:
        auth_time = int(time())
        payload = {
            "aud": "a-client-id",
            "email": "foobar@apple.com",
            "exp": auth_time + 3600,
            "iat": auth_time,
            "iss": self.backend.ID_TOKEN_ISSUER,
            "sub": "11011110101011011011111011101111",
        }
        payload.update(overrides)
        return jwt.encode(
            payload,
            key=cast(
                "RSAPrivateKey",
                RSAAlgorithm.from_jwk(json.dumps(RSA_PRIVATE_JWT_KEY)),
            ),
            algorithm="RS256",
            headers={"kid": RSA_PRIVATE_JWT_KEY["kid"]},
        )

    def add_apple_jwk_response(self) -> None:
        responses.add(
            responses.GET,
            self.backend.JWK_URL,
            body=json.dumps({"keys": [RSA_PUBLIC_JWT_KEY]}),
            content_type="application/json",
        )

    def test_login(self) -> None:
        with patch(
            f"{self.backend_path}.decode_id_token",
            return_value=token_data,
        ) as decode_mock:
            self.do_login()
        assert decode_mock.called
        assert decode_mock.call_args[0] == (self.id_token,)

    def test_partial_pipeline(self) -> None:
        with patch(
            f"{self.backend_path}.decode_id_token",
            return_value=token_data,
        ) as decode_mock:
            self.do_partial_pipeline()
        assert decode_mock.called
        assert decode_mock.call_args[0] == (self.id_token,)

    def test_decode_id_token_accepts_valid_issuer(self) -> None:
        self.add_apple_jwk_response()

        decoded = self.backend.decode_id_token(self.build_id_token())

        self.assertEqual(decoded["iss"], "https://appleid.apple.com")
        self.assertEqual(decoded["aud"], "a-client-id")

    def test_decode_id_token_rejects_wrong_issuer(self) -> None:
        self.add_apple_jwk_response()

        with self.assertRaises(AuthFailed):
            self.backend.decode_id_token(self.build_id_token(iss="https://example.com"))
