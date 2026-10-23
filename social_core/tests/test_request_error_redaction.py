"""Request URL credentials must not appear in ordinary chained tracebacks."""

from __future__ import annotations

import io
import logging
import traceback
import unittest
from typing import Any
from unittest.mock import patch

import requests
import responses
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import MaxRetryError, NewConnectionError

from social_core.backends.base import BaseAuth
from social_core.backends.facebook import FacebookOAuth2
from social_core.backends.hubspot import HubSpotOAuth2
from social_core.exceptions import AuthConfigurationError, AuthProviderError
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy
from social_core.utils import (
    handle_http_errors,
    redact_request_error,
    wrap_access_token_error,
)


class RequestErrorRedactionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.backend: BaseAuth[Any] = BaseAuth(self.strategy)

    def test_request_exception_branches(self) -> None:
        url = "https://provider.example/token?client_secret=SECRET_MARKER"
        for exception, family, code in (
            (requests.exceptions.SSLError, AuthProviderError, "tls_error"),
            (requests.ReadTimeout, AuthProviderError, "timeout"),
            (requests.ConnectTimeout, AuthProviderError, "timeout"),
            (requests.exceptions.InvalidURL, AuthConfigurationError, "invalid_setting"),
            (
                requests.exceptions.InvalidSchema,
                AuthConfigurationError,
                "invalid_setting",
            ),
            (
                requests.exceptions.MissingSchema,
                AuthConfigurationError,
                "invalid_setting",
            ),
            (requests.ConnectionError, AuthProviderError, "connection_failed"),
            (requests.HTTPError, AuthProviderError, "http_error"),
            (requests.exceptions.ChunkedEncodingError, AuthProviderError, "http_error"),
        ):
            cause = exception(f"Request failed for url: {url}")
            with (
                self.subTest(exception=exception),
                patch("requests.request", side_effect=cause),
                self.assertRaises(family) as caught,
            ):
                self.backend.request(url, stage="token_exchange")
            error = caught.exception
            self.assertIs(error.__cause__, cause)
            self.assertEqual(error.code, code)
            self.assertEqual(error.stage, "token_exchange")
            self.assertNotIn(
                "SECRET_MARKER", "".join(traceback.format_exception(error))
            )
            self.assertEqual(str(cause), "Request failed for url: <redacted-url>")

    @responses.activate
    def test_facebook_token_exchange_logging(self) -> None:
        backend = FacebookOAuth2(self.strategy)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_FACEBOOK_KEY": "app-id",
                "SOCIAL_AUTH_FACEBOOK_SECRET": "FACEBOOK_SECRET_MARKER",
            }
        )
        self.strategy.set_request_data({"code": "invalid-code"}, backend)
        responses.get(backend.access_token_url(), status=400)
        output = io.StringIO()
        logger = logging.getLogger("redaction-regression")
        handler = logging.StreamHandler(output)
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        with patch.object(backend, "validate_state", return_value="state"):
            try:
                backend.auth_complete()
            except AuthProviderError as error:
                logger.exception("Callback failed")
                self.assertEqual(error.stage, "token_exchange")
                self.assertIsInstance(error.__cause__, requests.HTTPError)
            else:
                self.fail("Expected a failed token exchange")
        self.assertEqual(len(responses.calls), 1)
        request_url = responses.calls[0].request.url
        assert request_url is not None
        self.assertIn("FACEBOOK_SECRET_MARKER", request_url)
        self.assertNotIn("FACEBOOK_SECRET_MARKER", output.getvalue())
        self.assertIn("400 Client Error", output.getvalue())
        self.assertIn("<redacted-url>", output.getvalue())

    @responses.activate
    def test_hubspot_path_token_and_response_access(self) -> None:
        backend = HubSpotOAuth2(self.strategy)
        url = backend.USER_DATA_URL + "HUBSPOT_TOKEN_MARKER"
        responses.get(
            url,
            status=503,
            json={"message": "Unavailable"},
            headers={"Retry-After": "30"},
        )
        with self.assertRaises(AuthProviderError) as caught:
            backend.user_data("HUBSPOT_TOKEN_MARKER")
        error = caught.exception
        self.assertEqual(error.code, "unavailable")
        self.assertEqual(error.stage, "user_info")
        self.assertEqual(error.status_code, 503)
        self.assertEqual(error.retry_after, "30")
        cause = error.__cause__
        assert isinstance(cause, requests.HTTPError)
        assert cause.response is not None
        assert cause.request is not None
        self.assertEqual(cause.response.url, url)
        self.assertEqual(cause.request.url, url)
        self.assertEqual(cause.response.json(), {"message": "Unavailable"})
        self.assertNotIn(
            "HUBSPOT_TOKEN_MARKER", "".join(traceback.format_exception(error))
        )

    def test_http_error_wrappers(self) -> None:
        @handle_http_errors
        def fail(backend: BaseAuth, cause: requests.HTTPError) -> None:
            raise cause

        for wrapper in ("decorator", "context_manager"):
            cause = requests.HTTPError(
                "400 Client Error for url: https://provider.example/PATH_SECRET_MARKER"
            )
            with (
                self.subTest(wrapper=wrapper),
                self.assertRaises(AuthProviderError) as caught,
            ):
                if wrapper == "decorator":
                    fail(self.backend, cause)
                else:
                    with wrap_access_token_error(self.backend):
                        raise cause
            self.assertIs(caught.exception.__cause__, cause)
            self.assertNotIn(
                "PATH_SECRET_MARKER",
                "".join(traceback.format_exception(caught.exception)),
            )

    def test_nested_transport_errors_and_cycles(self) -> None:
        transport = NewConnectionError(
            HTTPConnection("provider.example"), "Connection refused"
        )
        retry = MaxRetryError(
            HTTPConnectionPool("provider.example"),
            "/token/TRANSPORT_SECRET_MARKER",
            reason=transport,
        )
        retry.__cause__ = transport
        cause = requests.ConnectionError(retry)
        cause.__context__ = retry
        transport.__context__ = cause
        with (
            patch("requests.request", side_effect=cause),
            self.assertRaises(AuthProviderError) as caught,
        ):
            self.backend.request(
                "https://provider.example/token/TRANSPORT_SECRET_MARKER"
            )
        self.assertIs(caught.exception.__cause__, cause)
        self.assertIs(cause.args[0], retry)
        self.assertEqual(retry.url, "/token/TRANSPORT_SECRET_MARKER")
        self.assertNotIn(
            "TRANSPORT_SECRET_MARKER",
            "".join(traceback.format_exception(caught.exception)),
        )
        self.assertIn("Max retries exceeded", str(retry))
        self.assertIn("Connection refused", str(transport))

    def test_url_formats_and_idempotence(self) -> None:
        for message, request_url in (
            ("Failed for url: /token?secret=FORMAT_SECRET_MARKER", None),
            ("Failed with url: /token/FORMAT_SECRET_MARKER (Caused by timeout)", None),
            ("Invalid URL 'missing/FORMAT_SECRET_MARKER': No scheme supplied", None),
            (
                'No connection adapters were found for "wrong:FORMAT_SECRET_MARKER"',
                None,
            ),
            ("Failed to parse: https://[broken/FORMAT_SECRET_MARKER", None),
            ("TLS failed (https://user:FORMAT_SECRET_MARKER@[::1]/token).", None),
            (
                "https://one.example/FORMAT_SECRET_MARKER and https://two.example/FORMAT_SECRET_MARKER",
                None,
            ),
            (
                "Bad target 'malformed FORMAT_SECRET_MARKER'",
                "malformed FORMAT_SECRET_MARKER",
            ),
            (
                repr("https://provider.example/token/FORMAT_SECRET_MARKER\n'quoted'"),
                "https://provider.example/token/FORMAT_SECRET_MARKER\n'quoted'",
            ),
            (
                "Failed https://provider.example/token?secret=FORMAT_SECRET_MARKER",
                "https://provider.example/token",
            ),
        ):
            with self.subTest(message=message):
                cause = requests.ConnectionError(message)
                redact_request_error(cause, request_url=request_url)
                self.assertNotIn("FORMAT_SECRET_MARKER", str(cause))
                self.assertIn("<redacted-url>", str(cause))
                first = str(cause)
                redact_request_error(cause, request_url=request_url)
                self.assertEqual(str(cause), first)

    def test_messages_without_urls_are_preserved(self) -> None:
        cause = requests.ReadTimeout("Read timed out (read timeout=5)")
        redact_request_error(cause)
        self.assertEqual(str(cause), "Read timed out (read timeout=5)")
