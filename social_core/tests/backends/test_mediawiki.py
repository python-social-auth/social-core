from types import SimpleNamespace
from unittest.mock import patch

import jwt

from social_core.exceptions import AuthException

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
