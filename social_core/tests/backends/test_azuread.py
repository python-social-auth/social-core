"""
Copyright (c) 2015 Microsoft Open Technologies, Inc.

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import json
import os
import tempfile
from typing import cast
from unittest import TestCase
from unittest.mock import patch
from urllib.parse import parse_qs

import responses

from social_core.exceptions import AuthMissingParameter

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class AzureADOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.azuread.AzureADOAuth2"
    user_data_url = "https://graph.windows.net/me"
    expected_username = "foobar"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
            "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL"
            "3N0cy53aW5kb3dzLm5ldC83Mjc0MDZhYy03MDY4LTQ4ZmEtOTJiOS1jMmQ"
            "2NzIxMWJjNTAvIiwiaWF0IjpudWxsLCJleHAiOm51bGwsImF1ZCI6IjAyO"
            "WNjMDEwLWJiNzQtNGQyYi1hMDQwLWY5Y2VkM2ZkMmM3NiIsInN1YiI6In"
            "FVOHhrczltSHFuVjZRMzR6aDdTQVpvY2loOUV6cnJJOW1wVlhPSWJWQTg"
            "iLCJ2ZXIiOiIxLjAiLCJ0aWQiOiI3Mjc0MDZhYy03MDY4LTQ4ZmEtOTJi"
            "OS1jMmQ2NzIxMWJjNTAiLCJvaWQiOiI3ZjhlMTk2OS04YjgxLTQzOGMtO"
            "GQ0ZS1hZDZmNTYyYjI4YmIiLCJ1cG4iOiJmb29iYXJAdGVzdC5vbm1pY3"
            "Jvc29mdC5jb20iLCJnaXZlbl9uYW1lIjoiZm9vIiwiZmFtaWx5X25hbWU"
            "iOiJiYXIiLCJuYW1lIjoiZm9vIGJhciIsInVuaXF1ZV9uYW1lIjoiZm9v"
            "YmFyQHRlc3Qub25taWNyb3NvZnQuY29tIiwicHdkX2V4cCI6IjQ3MzMwO"
            "TY4IiwicHdkX3VybCI6Imh0dHBzOi8vcG9ydGFsLm1pY3Jvc29mdG9ubG"
            "luZS5jb20vQ2hhbmdlUGFzc3dvcmQuYXNweCJ9.3V50dHXTZOHj9UWtkn"
            "2g7BjX5JxNe8skYlK4PdhiLz4",
            "expires_in": 3600,
            "expires_on": 1423650396,
            "not_before": 1423646496,
        }
    )
    refresh_token_body = json.dumps(
        {
            "access_token": "foobar-new-token",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "foobar-new-refresh-token",
            "scope": "identity",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        _user, social = self.do_refresh_token()
        self.assertEqual(social.extra_data["access_token"], "foobar-new-token")


class AzureADOAuth2TokenRequestBodyMixin(TestCase):
    def _token_request_body(self, url_prefix: str) -> dict[str, list[str]]:
        matches = [
            call.request
            for call in responses.calls
            if cast("str", call.request.url).startswith(url_prefix)
        ]
        self.assertGreaterEqual(
            len(matches),
            1,
            f"expected at least one token request for {url_prefix}, found {len(matches)}",
        )
        request = matches[-1]
        body = request.body or ""
        if isinstance(body, bytes):
            body = body.decode()
        return parse_qs(body)


class AzureADOAuth2FederatedIdentityCredentialTest(
    AzureADOAuth2TokenRequestBodyMixin, AzureADOAuth2Test
):
    def extra_settings(self):
        settings = super().extra_settings()
        settings.pop("SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET", None)
        settings["SOCIAL_AUTH_AZUREAD_OAUTH2_CLIENT_ASSERTION"] = "fic-assertion"
        return settings

    def test_login_uses_client_assertion(self) -> None:
        self.do_login()
        body = self._token_request_body(self.backend.access_token_url())
        self.assertIn("client_assertion", body)
        self.assertEqual(body["client_assertion"], ["fic-assertion"])
        self.assertEqual(
            body.get("client_assertion_type"),
            ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
        )
        self.assertNotIn("client_secret", body)

    def test_refresh_token_uses_client_assertion(self) -> None:
        self.do_refresh_token()
        body = self._token_request_body(self.backend.refresh_token_url())
        self.assertIn("client_assertion", body)
        self.assertNotIn("client_secret", body)


class AzureADOAuth2FederatedIdentityCredentialFromFileTest(
    AzureADOAuth2TokenRequestBodyMixin, AzureADOAuth2Test
):
    def setUp(self) -> None:
        super().setUp()
        # Default token file for class-level flows; individual tests can override.
        self.token_path = self._write_temp_token("default-assertion")
        patcher = patch.dict(
            os.environ,
            {
                "OAUTH2_FEDERATED_TOKEN_FILE": self.token_path,
                "AZURE_FEDERATED_TOKEN_FILE": self.token_path,
            },
            clear=False,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def extra_settings(self):
        settings = super().extra_settings()
        settings.pop("SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET", None)
        settings.pop("SOCIAL_AUTH_AZUREAD_OAUTH2_CLIENT_ASSERTION", None)
        settings.pop("SOCIAL_AUTH_AZUREAD_OAUTH2_FEDERATED_TOKEN_FILE", None)
        return settings

    def _write_temp_token(self, value: str) -> str:
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(value)
            self.addCleanup(os.remove, handle.name)
            return handle.name

    def test_login_uses_oauth2_env_token_path(self) -> None:
        token_path = self._write_temp_token("env-assertion")
        with patch.dict(
            os.environ, {"OAUTH2_FEDERATED_TOKEN_FILE": token_path}, clear=False
        ):
            self.do_login()

        body = self._token_request_body(self.backend.access_token_url())
        self.assertEqual(body.get("client_assertion"), ["env-assertion"])
        self.assertEqual(
            body.get("client_assertion_type"),
            ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
        )
        self.assertNotIn("client_secret", body)

    def test_login_uses_azure_env_token_path(self) -> None:
        token_path = self._write_temp_token("azure-env-assertion")
        with patch.dict(
            os.environ,
            {
                "OAUTH2_FEDERATED_TOKEN_FILE": "",
                "AZURE_FEDERATED_TOKEN_FILE": token_path,
            },
            clear=False,
        ):
            self.do_login()

        body = self._token_request_body(self.backend.access_token_url())
        self.assertEqual(body.get("client_assertion"), ["azure-env-assertion"])
        self.assertNotIn("client_secret", body)

    def test_missing_env_token_path_raises(self) -> None:
        with (
            patch.dict(
                os.environ,
                {"OAUTH2_FEDERATED_TOKEN_FILE": "/no/such/file"},
                clear=False,
            ),
            self.assertRaises(AuthMissingParameter),
        ):
            self.do_login()

    def test_empty_token_file_raises(self) -> None:
        token_path = self._write_temp_token(" \n\t")
        with (
            patch.dict(
                os.environ,
                {
                    "OAUTH2_FEDERATED_TOKEN_FILE": token_path,
                    "AZURE_FEDERATED_TOKEN_FILE": token_path,
                },
                clear=False,
            ),
            self.assertRaises(AuthMissingParameter),
        ):
            self.do_login()

    def test_empty_token_file_optional_returns_none(self) -> None:
        token_path = self._write_temp_token(" \n\t")
        with patch.dict(
            os.environ,
            {
                "OAUTH2_FEDERATED_TOKEN_FILE": token_path,
                "AZURE_FEDERATED_TOKEN_FILE": token_path,
            },
            clear=False,
        ):
            assertion = self.backend.client_assertion(required=False)

        self.assertIsNone(assertion)


class AzureADOAuth2MissingCredentialsTest(AzureADOAuth2Test):
    def extra_settings(self):
        settings = super().extra_settings()
        settings.pop("SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET", None)
        settings.pop("SOCIAL_AUTH_AZUREAD_OAUTH2_CLIENT_ASSERTION", None)
        return settings

    def test_missing_secret_and_assertion_fails(self) -> None:
        with (
            patch.dict(
                os.environ,
                {
                    "AZURE_FEDERATED_TOKEN_FILE": "",
                    "OAUTH2_FEDERATED_TOKEN_FILE": "",
                },
                clear=False,
            ),
            self.assertRaises(AuthMissingParameter),
        ):
            self.do_login()

    def test_login(self) -> None:
        with self.assertRaises(AuthMissingParameter):
            super().test_login()

    def test_partial_pipeline(self) -> None:
        with self.assertRaises(AuthMissingParameter):
            super().test_partial_pipeline()

    def test_refresh_token(self) -> None:
        with self.assertRaises(AuthMissingParameter):
            super().test_refresh_token()
