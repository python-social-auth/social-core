import json
from typing import cast
from unittest.mock import patch

import responses

from social_core.exceptions import (
    AuthCanceled,
    AuthConfigurationError,
    AuthProviderError,
    AuthResponseError,
)
from social_core.utils import get_querystring, parse_qs

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class LineOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.line.LineOAuth2"
    user_data_url = "https://api.line.me/v2/profile"
    expected_username = "U4af4980629"
    access_token_body = json.dumps(
        {
            "access_token": "access-token",
            "expires_in": 2592000,
            "refresh_token": "refresh-token",
            "token_type": "Bearer",
        }
    )
    user_data_body = json.dumps(
        {
            "userId": "U4af4980629",
            "displayName": "LINE taro",
            "pictureUrl": "https://profile.line-scdn.net/abcdefghijklmn",
            "statusMessage": "Hello, LINE!",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_standard_callback_errors(self) -> None:
        for provider_code, family, code, recovery in (
            ("access_denied", AuthCanceled, "authorization_declined", "none"),
            (
                "invalid_client",
                AuthConfigurationError,
                "invalid_setting",
                "contact_administrator",
            ),
        ):
            with (
                self.subTest(provider_code=provider_code),
                self.assertRaises(family) as caught,
            ):
                self.backend.process_error(
                    {"error": provider_code, "error_description": "Provider detail"}
                )
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "callback")
            self.assertEqual(caught.exception.recovery, recovery)

    def test_line_specific_callback_error(self) -> None:
        with self.assertRaises(AuthProviderError) as caught:
            self.backend.process_error(
                {"errorCode": "400", "errorMessage": "LINE detail"}
            )
        self.assertEqual(caught.exception.provider_code, "400")
        self.assertEqual(caught.exception.stage, "callback")

    def test_line_token_endpoint_error_stage(self) -> None:
        self.backend.data = {}
        with (
            patch.object(self.backend, "validate_state"),
            patch.object(self.backend, "auth_complete_params", return_value={}),
            patch.object(self.backend, "get_json", return_value={"errorCode": "400"}),
            self.assertRaises(AuthProviderError) as caught,
        ):
            self.backend.auth_complete()
        self.assertEqual(caught.exception.stage, "token_exchange")

    def test_unusable_access_tokens_never_reach_profile_lookup(self) -> None:
        tokens: tuple[object, ...] = (None, "", False, 0, [], {})
        for payload in ({}, *({"access_token": token} for token in tokens)):
            with (
                self.subTest(payload=payload),
                patch.object(self.backend, "validate_state"),
                patch.object(self.backend, "auth_complete_params", return_value={}),
                patch.object(self.backend, "get_json", return_value=payload),
                patch.object(self.backend, "user_data") as user_data,
                patch.object(self.strategy, "authenticate") as authenticate,
                self.assertRaises(AuthResponseError) as caught,
            ):
                self.backend.auth_complete()
            self.assertEqual(caught.exception.code, "missing_claim")
            self.assertEqual(caught.exception.claim, "access_token")
            self.assertEqual(caught.exception.stage, "token_exchange")
            user_data.assert_not_called()
            authenticate.assert_not_called()

    def test_line_profile_endpoint_error_stage(self) -> None:
        for payload, family in (
            ({"errorCode": "400"}, AuthProviderError),
            ({"errorMessage": "LINE detail"}, AuthProviderError),
            ({"error": "invalid_client"}, AuthConfigurationError),
        ):
            with (
                self.subTest(payload=payload),
                patch.object(self.backend, "get_json", return_value=payload),
                self.assertRaises(family) as caught,
            ):
                self.backend.user_data("token")
            self.assertEqual(caught.exception.stage, "user_info")

    def test_access_token_request_uses_authorization_redirect_uri(self) -> None:
        self.do_login()

        auth_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.authorization_url())
        )
        token_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )

        auth_redirect_uri = get_querystring(cast("str", auth_request.url))[
            "redirect_uri"
        ]
        token_redirect_uri = parse_qs(token_request.body)["redirect_uri"]

        self.assertEqual(token_redirect_uri, auth_redirect_uri)

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
