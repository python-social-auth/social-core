from unittest.mock import patch

import jwt

from social_core.exceptions import AuthTokenError

from .base import BaseBackendTest


class PingOpenIdConnectTest(BaseBackendTest):
    backend_path = "social_core.backends.ping.PingOpenIdConnect"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_PING_KEY": "key",
            "SOCIAL_AUTH_PING_SECRET": "secret",
        }

    def test_invalid_jwk_raises_auth_token_error(self) -> None:
        with (
            patch.object(self.backend, "get_jwks_keys", return_value=[{}]),
            self.assertRaises(AuthTokenError) as context,
        ):
            self.backend.validate_and_return_id_token("token", "access-token")

        self.assertIsInstance(context.exception.__cause__, jwt.PyJWTError)
