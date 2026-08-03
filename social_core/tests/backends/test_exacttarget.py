from unittest.mock import patch

import jwt

from social_core.exceptions import AuthCanceled

from .base import BaseBackendTest


class ExactTargetOAuth2Test(BaseBackendTest):
    backend_path = "social_core.backends.exacttarget.ExactTargetOAuth2"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_EXACTTARGET_KEY": "key",
            "SOCIAL_AUTH_EXACTTARGET_SECRET": "secret",
        }

    def test_jwt_error_is_wrapped(self) -> None:
        error = jwt.ExpiredSignatureError("expired")

        with (
            patch("social_core.backends.exacttarget.jwt.decode", side_effect=error),
            self.assertRaises(AuthCanceled) as context,
        ):
            self.backend.do_auth("token")

        self.assertIs(context.exception.__cause__, error)
