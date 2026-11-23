from __future__ import annotations

import json
from typing import Any

import jwt
import responses
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.algorithms import OKPAlgorithm
from jwt.utils import base64url_encode

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthResponseError
from social_core.tests.exception_helpers import assert_auth_error

from .open_id_connect import OpenIdConnectTest


class OpenIdConnectDiagnosticsTest(OpenIdConnectTest[OpenIdConnectAuth]):
    backend_path = "social_core.backends.open_id_connect.OpenIdConnectAuth"
    issuer = "https://oidc-diagnostics.example"
    openid_config_body = json.dumps(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/auth",
            "token_endpoint": f"{issuer}/token",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "jwks_uri": f"{issuer}/keys",
        }
    )
    expected_username = "cartman"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            **super().extra_settings(),
            "SOCIAL_AUTH_OIDC_OIDC_ENDPOINT": self.issuer,
        }

    def pre_complete_callback(self, start_url: str) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            self.backend.userinfo_url(),
            json={"preferred_username": self.expected_username},
        )

    def replace_signing_keys(
        self, url: str, keys: list[dict[str, Any]]
    ) -> responses.Response:
        response = responses.Response(responses.GET, url, json={"keys": keys})
        responses.replace(response)
        return response

    def signing_key_url(self) -> str:
        url = self.backend.jwks_uri()
        invalidate = self.backend.get_jwks_keys_for_uri.invalidate
        invalidate(self.backend, url)
        self.addCleanup(invalidate, self.backend, url)
        return url

    def test_missing_signing_key_logged_after_cache_refresh(self) -> None:
        url = self.signing_key_url()
        body = json.loads(self.prepare_access_token_body(kid="missing-provider-key"))
        id_token = body["id_token"]
        _, payload, signature = id_token.split(".")
        header = base64url_encode(
            json.dumps(
                {"kid": "missing-provider-key", "alg": ["provider-value"]}
            ).encode()
        ).decode()

        for token, algorithm in (
            (id_token, "RS256"),
            (f"{header}.{payload}.{signature}", "unknown"),
        ):
            with self.subTest(algorithm=algorithm):
                self.backend.get_jwks_keys()
                refreshed = self.replace_signing_keys(url, [self.public_key])
                with (
                    self.assertLogs("social", level="DEBUG") as logs,
                    assert_auth_error(
                        self, AuthResponseError, "invalid_signature"
                    ) as error,
                ):
                    self.backend.decode_and_validate_id_token(
                        token, body["access_token"]
                    )

                self.assertEqual(refreshed.call_count, 1)
                self.assertEqual(error.exception.stage, "token_validation")
                self.assertEqual(
                    str(error.exception),
                    "The authentication response signature could not be verified.",
                )
                self.assertEqual(
                    logs.output,
                    [
                        f"DEBUG:social:oidc: No matching ID token signing JWK after cache refresh (algorithm={algorithm})"
                    ],
                )

    def test_failed_candidate_signature_logged_without_cache_refresh(self) -> None:
        url = self.signing_key_url()
        keys = self.replace_signing_keys(url, [self.public_key])
        with self.assertLogs("social", level="DEBUG") as logs:
            self.authtoken_raised(
                "invalid_signature", kid=self.key["kid"], tamper_message=True
            )

        self.assertEqual(keys.call_count, 1)
        self.assertEqual(
            logs.output,
            [
                "DEBUG:social:oidc: ID token signature did not verify with candidate JWK (algorithm=RS256)"
            ],
        )

    def test_empty_jwks_without_token_key_id_logged(self) -> None:
        url = self.signing_key_url()
        keys = self.replace_signing_keys(url, [])

        with self.assertLogs("social", level="DEBUG") as logs:
            self.authtoken_raised("invalid_signature")

        self.assertEqual(keys.call_count, 1)
        self.assertEqual(
            logs.output,
            ["DEBUG:social:oidc: No ID token signing JWK available (algorithm=RS256)"],
        )

    def test_unloadable_signing_key_logged(self) -> None:
        url = self.signing_key_url()
        body = json.loads(self.prepare_access_token_body(kid=self.key["kid"]))

        for raw_algorithm, label in (
            ("RS256", "RS256"),
            ("unknown-provider-algorithm", "unknown"),
        ):
            with self.subTest(label=label):
                self.backend.get_jwks_keys_for_uri.invalidate(self.backend, url)
                malformed_key = {
                    "kid": self.key["kid"],
                    "kty": "RSA",
                    "alg": raw_algorithm,
                    "n": "invalid-key-material!",
                }
                self.replace_signing_keys(url, [malformed_key])

                with (
                    self.assertLogs("social", level="DEBUG") as logs,
                    assert_auth_error(
                        self, AuthResponseError, "invalid_claim"
                    ) as error,
                ):
                    self.backend.decode_and_validate_id_token(
                        body["id_token"], body["access_token"]
                    )

                self.assertIsInstance(error.exception.__cause__, jwt.PyJWTError)
                self.assertEqual(error.exception.stage, "token_validation")
                self.assertEqual(
                    str(error.exception),
                    "An authentication response field could not be verified.",
                )
                self.assertEqual(
                    logs.output,
                    [
                        f"DEBUG:social:oidc: Unable to load ID token signing JWK (algorithm={label})"
                    ],
                )

    def test_signing_algorithm_rejected_by_allowlist_logged(self) -> None:
        url = self.signing_key_url()
        private_key = Ed25519PrivateKey.generate()
        kid = "provider-ed25519-key"
        jwk = OKPAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
        self.replace_signing_keys(url, [dict(jwk, alg="EdDSA", kid=kid)])
        claims = {"iss": self.issuer, "aud": self.client_key, "sub": "provider-subject"}
        token = jwt.encode(claims, private_key, algorithm="EdDSA", headers={"kid": kid})

        with (
            self.assertLogs("social", level="DEBUG") as logs,
            assert_auth_error(self, AuthResponseError, "invalid_signature") as error,
        ):
            self.backend.decode_and_validate_id_token(token, None)

        self.assertIsInstance(error.exception.__cause__, jwt.InvalidAlgorithmError)
        self.assertEqual(error.exception.stage, "token_validation")
        self.assertEqual(
            str(error.exception),
            "The authentication response signature could not be verified.",
        )
        self.assertEqual(
            logs.output,
            [
                "DEBUG:social:oidc: ID token signing algorithm rejected by allowlist (algorithm=EdDSA)"
            ],
        )

        self.strategy.set_settings({"SOCIAL_AUTH_OIDC_JWT_ALGORITHMS": ["EdDSA"]})
        with self.assertNoLogs("social", level="DEBUG"):
            self.assertEqual(
                self.backend.decode_and_validate_id_token(token, None), claims
            )

    def test_successful_login_after_signing_key_refresh_has_no_diagnostic(self) -> None:
        url = self.signing_key_url()
        self.backend.get_jwks_keys()
        kid = "rotated-provider-key"
        refreshed = self.replace_signing_keys(url, [dict(self.public_key, kid=kid)])
        self.access_token_kwargs = {"kid": kid}

        with self.assertNoLogs("social", level="DEBUG"):
            user = self.do_login()

        self.assertEqual(user.social[0].uid, "1234")
        self.assertEqual(refreshed.call_count, 1)
