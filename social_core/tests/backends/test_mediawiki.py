from types import SimpleNamespace
from unittest.mock import patch

import jwt

from social_core.exceptions import AuthException, AuthMissingParameter

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
            self.backend.get_user_details(response)

        self.assertIs(context.exception.__cause__, error)

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
            details = self.backend.get_user_details(response)
            self.assertEqual(
                self.backend.get_user_id(details, response),
                "stable-subject",
            )
            self.strategy.set_settings({"SOCIAL_AUTH_MEDIAWIKI_ID_KEY": "email"})
            email_details = self.backend.get_user_details(response)
            self.strategy.set_settings(
                {"SOCIAL_AUTH_MEDIAWIKI_ID_KEY": "missing_claim"}
            )
            with self.assertRaisesRegex(AuthMissingParameter, "missing_claim"):
                self.backend.get_user_details(response)

        self.assertEqual(details["sub"], "stable-subject")
        self.assertEqual(email_details["email"], "user@example.com")
