"""Facebook quota classification at the HTTP boundary."""

from __future__ import annotations

import unittest
from functools import partial
from unittest.mock import Mock, patch

import requests

from social_core.backends.base import BaseAuth
from social_core.backends.facebook import FacebookAppOAuth2, FacebookOAuth2
from social_core.exceptions import AuthProviderError
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy
from social_core.utils import http_error


class FacebookProviderErrorTest(unittest.TestCase):
    def response(self, status, data=None):
        response = Mock(spec=requests.Response, status_code=status, headers={})
        if data is None:
            response.json.side_effect = ValueError("not JSON")
        else:
            response.json.return_value = data
        return response

    def test_facebook_quota_errors_keep_diagnostics_and_retry_recovery(self):
        for backend_class in (FacebookOAuth2, FacebookAppOAuth2):
            backend = backend_class(
                TestStrategy(TestStorage), redirect_uri="https://example.com/complete"
            )
            backend.data = {"code": "authorization-code"}
            for operation, stage in (
                (backend.auth_complete, "token_exchange"),
                (partial(backend.do_auth, "token"), "user_info"),
            ):
                # The app backend receives its token directly, without an exchange.
                if backend_class is FacebookAppOAuth2 and stage == "token_exchange":
                    operation = partial(
                        backend.request_access_token, backend.access_token_url()
                    )
                for provider_code in (4, 17, 32, 613):
                    for status in (400, 403):
                        payload = {
                            "error": {
                                "code": provider_code,
                                "type": "OAuthException",
                                "message": "private-quota-detail",
                            }
                        }
                        response = self.response(status, payload)
                        response.headers = {"Retry-After": "120"}
                        cause = requests.HTTPError(response=response)
                        response.raise_for_status.side_effect = cause
                        with (
                            self.subTest(
                                backend=backend.name,
                                stage=stage,
                                provider_code=provider_code,
                                status=status,
                            ),
                            patch.object(
                                backend, "validate_state", return_value="state"
                            ),
                            patch.object(
                                backend,
                                "get_key_and_secret",
                                return_value=("key", "secret"),
                            ),
                            patch.object(
                                backend.strategy, "authenticate"
                            ) as authenticate,
                            patch("requests.request", return_value=response),
                            self.assertRaises(AuthProviderError) as caught,
                        ):
                            operation()
                        error = caught.exception
                        self.assertEqual(error.code, "rate_limited")
                        self.assertEqual(error.recovery, "retry_later")
                        self.assertEqual(error.source, "provider_response")
                        self.assertEqual(error.provider_code, provider_code)
                        self.assertEqual(error.status_code, status)
                        self.assertEqual(error.stage, stage)
                        self.assertEqual(error.retry_after, "120")
                        self.assertEqual(error.detail, "private-quota-detail")
                        self.assertIs(error.__cause__, cause)
                        self.assertNotIn("private-quota-detail", str(error))
                        self.assertNotIn(
                            "private-quota-detail", str(error.public_metadata())
                        )
                        authenticate.assert_not_called()

    def test_facebook_other_http_errors_keep_generic_classification(self):
        backend = FacebookOAuth2(TestStrategy(TestStorage))
        for status, payload, provider_code, code in (
            (403, {"error": {"code": 200}}, 200, "http_error"),
            (403, {"error": {"code": 341}}, 341, "http_error"),
            (403, {"error": {"code": "4"}}, "4", "http_error"),
            (403, None, None, "http_error"),
            (403, {}, None, "http_error"),
            (429, None, None, "rate_limited"),
        ):
            response = self.response(status, payload)
            cause = requests.HTTPError(response=response)
            response.raise_for_status.side_effect = cause
            with (
                self.subTest(status=status, payload=payload),
                patch("requests.request", return_value=response),
                self.assertRaises(AuthProviderError) as caught,
            ):
                backend.request(backend.USER_DATA_URL)
            error = caught.exception
            self.assertEqual(error.code, code)
            self.assertEqual(error.provider_code, provider_code)
            self.assertEqual(error.status_code, status)
            self.assertIs(error.__cause__, cause)

    def test_facebook_quota_codes_are_not_global(self):
        for provider_code in (4, 17, 32, 613):
            cause = requests.HTTPError(
                response=self.response(403, {"error": {"code": provider_code}})
            )
            error = http_error(BaseAuth(TestStrategy(TestStorage)), cause)
            self.assertEqual(error.code, "http_error")
            self.assertEqual(error.provider_code, provider_code)
