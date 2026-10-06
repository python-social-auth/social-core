import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import jwt

from social_core.exceptions import AuthException, AuthResponseError
from social_core.tests.exception_helpers import assert_auth_error

from .base import BaseBackendTest


class MediaWikiTest(BaseBackendTest):
    backend_path = "social_core.backends.mediawiki.MediaWiki"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_MEDIAWIKI_KEY": "key",
            "SOCIAL_AUTH_MEDIAWIKI_SECRET": "secret",
            "SOCIAL_AUTH_MEDIAWIKI_URL": "https://example.com/wiki",
        }

    def test_jwt_error_is_wrapped(self) -> None:
        error = jwt.PyJWKError("invalid key")
        response = {
            "access_token": {
                "oauth_token": b"token",
                "oauth_token_secret": b"secret",
            }
        }

        with (
            patch.object(
                self.backend,
                "request",
                return_value=SimpleNamespace(content=b"token"),
            ),
            patch("social_core.backends.mediawiki.jwt.decode", side_effect=error),
            self.assertRaises(AuthException) as context,
        ):
            self.backend.get_user_details(
                self.backend.user_data(response["access_token"])
            )

        self.assertIs(context.exception.__cause__, error)
        self.assertIsInstance(context.exception, AuthResponseError)
        self.assertEqual(context.exception.code, "invalid_claim")
        self.assertEqual(context.exception.stage, "user_info")

    def test_group_extraction_is_opt_in(self) -> None:
        response = {"groups": ["sysop", "user", "sysop"]}
        self.assertIsNone(self.backend.get_user_groups(response))
        self.strategy.set_settings({"SOCIAL_AUTH_MEDIAWIKI_GROUPS_ENABLED": True})
        self.assertEqual(self.backend.get_user_groups(response), ["sysop", "user"])
        self.assertEqual(self.backend.get_user_groups({"groups": []}), [])

    def test_missing_groups_policy_does_not_accept_malformed_claims(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_MEDIAWIKI_GROUPS_ENABLED": True})
        with self.assertRaises(AuthResponseError) as caught:
            self.backend.get_user_groups({})
        self.assertEqual(caught.exception.code, "missing_claim")
        self.strategy.set_settings(
            {"SOCIAL_AUTH_MEDIAWIKI_GROUPS_MISSING_AS_EMPTY": True}
        )
        self.assertEqual(self.backend.get_user_groups({}), [])
        with self.assertRaises(AuthResponseError) as caught:
            self.backend.get_user_groups({"groups": "sysop"})
        self.assertEqual(caught.exception.code, "invalid_claim")

    def test_signed_identity_requires_claims_with_valid_types(self) -> None:
        identity = {
            "iss": "https://example.com/wiki",
            "iat": time.time(),
            "nonce": "nonce",
            "username": "user",
            "sub": "subject",
            "aud": "key",
        }
        response = {
            "access_token": {"oauth_token": "token", "oauth_token_secret": "secret"}
        }
        claims_to_validate = ("iss", "iat", "nonce", "username", "sub")
        invalid_values: tuple[object, ...] = (None, [], {}, "", False)
        for claim in claims_to_validate:
            for value in invalid_values:
                claims = {**identity, claim: value}
                if value is None:
                    del claims[claim]
                # Sign the JSON directly: jwt.encode rejects malformed issuers.
                token = jwt.api_jws.encode(
                    json.dumps(claims).encode(), "secret", algorithm="HS256"
                )
                request_response = SimpleNamespace(
                    content=token,
                    request=SimpleNamespace(
                        headers={"Authorization": 'oauth_nonce="nonce"'}
                    ),
                )
                with (
                    self.subTest(claim=claim, value=value),
                    patch.object(
                        self.backend, "request", return_value=request_response
                    ),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    self.backend.get_user_details(
                        self.backend.user_data(response["access_token"])
                    )
                self.assertEqual(
                    caught.exception.code,
                    "missing_claim" if value is None else "invalid_claim",
                )
                self.assertEqual(caught.exception.claim, claim)
                self.assertEqual(caught.exception.stage, "user_info")

    def test_signed_identity_rejects_nonnumeric_and_nonfinite_iat(self) -> None:
        for value in ("not-a-number", "NaN", "Infinity", -float("inf")):
            token = jwt.encode(
                {
                    "iss": "https://example.com/wiki",
                    "iat": value,
                    "nonce": "nonce",
                    "username": "user",
                    "sub": "subject",
                    "aud": "key",
                },
                "secret",
                algorithm="HS256",
            )
            with (
                self.subTest(iat=value),
                patch.object(
                    self.backend, "request", return_value=SimpleNamespace(content=token)
                ),
                self.assertRaises(AuthResponseError) as caught,
            ):
                self.backend.user_data(
                    {"oauth_token": "token", "oauth_token_secret": "secret"}
                )
            self.assertEqual(caught.exception.code, "invalid_claim")
            self.assertEqual(caught.exception.claim, "iat")
            self.assertEqual(caught.exception.stage, "user_info")

    def test_configured_id_key_preserves_identity_claim(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_MEDIAWIKI_ID_KEY": "sub"})
        response = {
            "access_token": {
                "oauth_token": b"token",
                "oauth_token_secret": b"secret",
            }
        }
        request = SimpleNamespace(headers={"Authorization": 'oauth_nonce="nonce"'})
        request_response = SimpleNamespace(content=b"token", request=request)
        identity = {
            "iss": "https://example.com/wiki",
            "iat": 0,
            "nonce": "nonce",
            "username": "user",
            "sub": "stable-subject",
            "email": "user@example.com",
        }

        with (
            patch.object(self.backend, "request", return_value=request_response),
            patch("social_core.backends.mediawiki.jwt.decode", return_value=identity),
        ):
            details = self.backend.get_user_details(
                self.backend.user_data(response["access_token"])
            )
            self.assertEqual(
                self.backend.get_user_id(details, response),
                "stable-subject",
            )
            self.strategy.set_settings({"SOCIAL_AUTH_MEDIAWIKI_ID_KEY": "email"})
            email_details = self.backend.get_user_details(
                self.backend.user_data(response["access_token"])
            )
            self.strategy.set_settings(
                {"SOCIAL_AUTH_MEDIAWIKI_ID_KEY": "missing_claim"}
            )
            with assert_auth_error(self, AuthResponseError, "missing_claim"):
                self.backend.get_user_details(
                    self.backend.user_data(response["access_token"])
                )

        self.assertEqual(details["sub"], "stable-subject")
        self.assertEqual(email_details["email"], "user@example.com")
