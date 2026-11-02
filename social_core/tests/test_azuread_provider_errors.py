"""Azure provider diagnostics across callback and HTTP error boundaries."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import requests

from social_core.backends.azuread import AzureADOAuth2
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthConfigurationError
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy
from social_core.utils import http_error, module_member


class AzureProviderErrorTest(unittest.TestCase):
    @staticmethod
    def response(status: int, data: object) -> Mock:
        response = Mock(spec=requests.Response, status_code=status, headers={})
        response.json.return_value = data
        return response

    def test_azure_pkce_classification(self):
        for path in (
            "social_core.backends.azuread.AzureADOAuth2",
            "social_core.backends.azuread.AzureADOAuth2V2",
            "social_core.backends.azuread_tenant.AzureADTenantOAuth2",
            "social_core.backends.azuread_tenant.AzureADV2TenantOAuth2",
            "social_core.backends.azuread_b2c.AzureADB2COAuth2",
        ):
            backend = module_member(path)(TestStrategy(TestStorage))
            for fields in (
                {"error_codes": [9002325]},
                {
                    "error_description": "  AADSTS9002325: private trace-id correlation-id"
                },
            ):
                payload = {"error": "invalid_request", **fields}
                with self.subTest(path=path, fields=fields):
                    backend.data = payload
                    with (
                        patch.object(backend, "request_access_token") as exchange,
                        patch.object(backend, "do_auth") as authenticate,
                        self.assertRaises(AuthConfigurationError) as caught,
                    ):
                        backend.auth_complete()
                    exchange.assert_not_called()
                    authenticate.assert_not_called()
                    self.assertEqual(caught.exception.code, "invalid_setting")
                    self.assertEqual(caught.exception.stage, "callback")
                    response = self.response(400, payload)
                    response.headers = {"Retry-After": "30"}
                    error = http_error(
                        backend,
                        requests.HTTPError(response=response),
                        stage="token_exchange",
                    )
                    self.assertIsInstance(error, AuthConfigurationError)
                    self.assertEqual(error.code, "invalid_setting")
                    self.assertEqual(error.stage, "token_exchange")
                    self.assertEqual(error.provider_code, "invalid_request")
                    self.assertEqual(error.status_code, 400)
                    self.assertEqual(error.retry_after, "30")
                    self.assertEqual(error.source, "configuration")
                    self.assertEqual(error.recovery, "contact_administrator")
                    self.assertNotIn("private", str(error))
                    self.assertNotIn("trace-id", str(error.public_metadata()))
                    self.assertEqual(error.detail, fields.get("error_description", ""))
                    generic = BaseOAuth2(TestStrategy(TestStorage)).get_provider_error(
                        payload
                    )
                    assert generic is not None
                    self.assertEqual(generic.code, "invalid_setting")

    def test_azure_pkce_requires_exact_error(self):
        backend = AzureADOAuth2(TestStrategy(TestStorage))
        payload: object
        for payload in (
            {"error": "invalid_request", "error_codes": [9002326]},
            {"error": "invalid_request", "error_codes": "9002325"},
            {"error": "invalid_request", "error_codes": [9002325.0]},
            {
                "error": "invalid_request",
                "error_description": "embedded AADSTS9002325: text",
            },
            {"error": "invalid_request", "error_description": "AADSTS90023250: text"},
            {"error": "invalid_request", "error_description": ["AADSTS9002325:"]},
            {"error": "invalid_grant", "error_codes": [9002325]},
            {"error_description": "AADSTS9002325: text"},
            [],
        ):
            with (
                self.subTest(payload=payload),
                self.assertNoLogs("social", level="WARNING"),
            ):
                backend.get_provider_error(payload)

    def test_azure_pkce_logs_actionable_guidance(self):
        backend = AzureADOAuth2(TestStrategy(TestStorage))
        with self.assertLogs("social", level="WARNING") as captured:
            error = backend.get_provider_error(
                {
                    "error": "invalid_request",
                    "error_description": "AADSTS9002325: private trace-id",
                }
            )
        self.assertIn("move it to Web", captured.output[0])
        self.assertIn("Single-page application (SPA)", captured.output[0])
        self.assertNotIn("private trace-id", captured.output[0])
        assert error is not None
        self.assertEqual(error.code, "invalid_setting")
