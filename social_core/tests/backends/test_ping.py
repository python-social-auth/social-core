import time
from unittest.mock import patch

import jwt
from jwt import InvalidAudienceError

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

    def test_refresh_uses_ping_id_token_decoder(self) -> None:
        with (
            patch.object(
                self.backend,
                "find_valid_key",
                return_value={"alg": "RS256"},
            ),
            patch.object(
                self.backend,
                "id_token_issuer",
                return_value="https://issuer.example",
            ),
            patch("social_core.backends.ping.jwt.PyJWK"),
            patch(
                "social_core.backends.ping.jwt.decode",
                side_effect=InvalidAudienceError,
            ),
            self.assertRaises(AuthTokenError) as context,
        ):
            self.backend.validate_and_return_refresh_id_token(
                "token",
                "access-token",
            )

        self.assertEqual(context.exception.args, ("Invalid audience",))

    def test_refresh_retains_common_id_token_validation(self) -> None:
        claims = {
            "aud": "key",
            "azp": "key",
            "at_hash": "invalid",
            "iat": int(time.time()),
        }
        with (
            patch.object(
                self.backend,
                "find_valid_key",
                return_value={"alg": "RS256"},
            ),
            patch.object(
                self.backend,
                "id_token_issuer",
                return_value="https://issuer.example",
            ),
            patch("social_core.backends.ping.jwt.PyJWK"),
            patch("social_core.backends.ping.jwt.decode", return_value=claims),
            self.assertRaises(AuthTokenError) as context,
        ):
            self.backend.validate_and_return_refresh_id_token(
                "token",
                "access-token",
            )

        self.assertEqual(context.exception.args, ("Invalid access token",))
