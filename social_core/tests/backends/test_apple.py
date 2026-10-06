import json
from time import time
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import jwt
import responses
from jwt.algorithms import RSAAlgorithm

from social_core.exceptions import AuthResponseError
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME

from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .test_azuread_b2c import RSA_PRIVATE_JWT_KEY, RSA_PUBLIC_JWT_KEY

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    from social_core.strategy import HttpResponseProtocol
    from social_core.tests.models import User

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

    def build_id_token(
        self, *, kid: str | None = RSA_PRIVATE_JWT_KEY["kid"], **overrides
    ) -> str:
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
            headers={"kid": kid} if kid is not None else {},
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

    def assert_partial_name_preserved(self, name) -> None:
        self.pipeline_settings()
        pipeline = list(self.strategy.get_pipeline(self.backend))
        pipeline.remove("social_core.tests.pipeline.ask_for_password")
        pipeline.insert(0, "social_core.tests.pipeline.ask_for_password")
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": pipeline,
                "SOCIAL_AUTH_APPLE_ID_USER_FIELDS": [
                    "username",
                    "email",
                    "first_name",
                    "last_name",
                ],
            }
        )
        if name:
            self.strategy.set_request_data(
                {"user": json.dumps({"name": name})}, self.backend
            )
        self.add_apple_jwk_response()
        result = self.backend.do_auth(self.build_id_token())

        for step, value, request_data in (
            ("password", "foobar", {}),
            (
                "slug",
                "foo-bar",
                {
                    "user": json.dumps(
                        {"name": {"firstName": "Wrong", "lastName": "Name"}}
                    )
                },
            ),
        ):
            self.assertEqual(
                cast("HttpResponseProtocol", result).url,
                self.strategy.build_absolute_uri(f"/{step}"),
            )
            token = self.strategy.session_pop(PARTIAL_TOKEN_SESSION_NAME)
            self.strategy.session_set(step, value)
            result = self.resume_partial_with_new_request(token, request_data)

        user = cast("User", result)
        self.assertEqual(user.first_name, name.get("firstName") or None)
        if name.get("lastName"):
            self.assertEqual(user.extra_user_fields["last_name"], name["lastName"])
        else:
            self.assertNotIn("last_name", user.extra_user_fields)
        self.assertEqual(user.email, "foobar@apple.com")
        self.assertEqual(user.social[0].uid, token_data["sub"])
        self.assertEqual(user.password, "foobar")
        self.assertEqual(user.slug, "foo-bar")

    def test_partial_pipeline_preserves_callback_name(self) -> None:
        self.assert_partial_name_preserved({"firstName": "Foo", "lastName": "Bar"})

    def test_partial_pipeline_does_not_read_name_from_resume(self) -> None:
        self.assert_partial_name_preserved({})

    def test_user_details_keeps_request_name_fallback(self) -> None:
        self.strategy.set_request_data(
            {"user": json.dumps({"name": {"firstName": "Foo", "lastName": "Bar"}})},
            self.backend,
        )

        details = self.backend.get_user_details(token_data)

        self.assertEqual(details["first_name"], "Foo")
        self.assertEqual(details["last_name"], "Bar")

    def test_decode_id_token_accepts_valid_issuer(self) -> None:
        self.add_apple_jwk_response()

        decoded = self.backend.decode_id_token(self.build_id_token())

        self.assertEqual(decoded["iss"], "https://appleid.apple.com")
        self.assertEqual(decoded["aud"], "a-client-id")

    def test_decode_id_token_accepts_key_without_identifier(self) -> None:
        key = {
            name: value for name, value in RSA_PUBLIC_JWT_KEY.items() if name != "kid"
        }
        with patch.object(self.backend, "get_json", return_value={"keys": [key]}):
            decoded = self.backend.decode_id_token(self.build_id_token(kid=None))
        self.assertEqual(decoded["sub"], token_data["sub"])

    def test_decode_id_token_ignores_unkeyed_entry_when_identifier_matches(
        self,
    ) -> None:
        unkeyed = {
            name: value for name, value in RSA_PUBLIC_JWT_KEY.items() if name != "kid"
        }
        with patch.object(
            self.backend,
            "get_json",
            return_value={"keys": [unkeyed, RSA_PUBLIC_JWT_KEY]},
        ):
            decoded = self.backend.decode_id_token(self.build_id_token())
        self.assertEqual(decoded["sub"], token_data["sub"])

    def test_decode_id_token_rejects_wrong_issuer(self) -> None:
        self.add_apple_jwk_response()

        with self.assertRaises(AuthResponseError):
            self.backend.decode_id_token(self.build_id_token(iss="https://example.com"))
