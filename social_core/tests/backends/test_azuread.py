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

import base64
import json
import os
import tempfile
from time import time
from typing import TYPE_CHECKING, cast
from unittest import TestCase
from unittest.mock import patch
from urllib.parse import parse_qs

import jwt
import responses
from jwt.algorithms import RSAAlgorithm

from social_core.exceptions import AuthMissingParameter, AuthTokenError

from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .test_azuread_b2c import RSA_PRIVATE_JWT_KEY, RSA_PUBLIC_JWT_KEY

if TYPE_CHECKING:
    from typing import Any

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class AzureADOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    AUTH_KEY = "a-key"
    AUTH_TIME = int(time())
    EXPIRES_IN = 3600
    EXPIRES_ON = AUTH_TIME + EXPIRES_IN
    JWKS_URL = "https://login.microsoftonline.com/common/discovery/keys"
    ISSUER = "https://sts.windows.net/727406ac-7068-48fa-92b9-c2d67211bc50/"
    ISSUER_TEMPLATE = "https://sts.windows.net/{tenantid}/"
    KEY_ISSUER = ISSUER_TEMPLATE
    TENANT_ID = "727406ac-7068-48fa-92b9-c2d67211bc50"
    TOKEN_VERSION = "1.0"

    backend_path = "social_core.backends.azuread.AzureADOAuth2"
    user_data_url = "https://graph.windows.net/me"
    expected_username = "foobar"
    access_token_body = ""
    refresh_token_body = json.dumps(
        {
            "access_token": "foobar-new-token",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "foobar-new-refresh-token",
            "scope": "identity",
        }
    )

    def setUp(self) -> None:
        super().setUp()
        self.access_token_body = self.build_access_token_body()
        responses.add(
            responses.GET,
            self.backend.openid_configuration_url(),
            body=json.dumps(
                {
                    "issuer": self.ISSUER_TEMPLATE,
                    "jwks_uri": self.JWKS_URL,
                    "id_token_signing_alg_values_supported": ["RS256"],
                }
            ),
            content_type="application/json",
        )
        responses.add(
            responses.GET,
            self.JWKS_URL,
            body=json.dumps(
                {"keys": [{**RSA_PUBLIC_JWT_KEY, "issuer": self.KEY_ISSUER}]}
            ),
            content_type="application/json",
        )

    def build_id_token(self, **overrides) -> str:
        payload = {
            "aud": self.AUTH_KEY,
            "exp": self.EXPIRES_ON,
            "family_name": "bar",
            "given_name": "foo",
            "iat": self.AUTH_TIME,
            "iss": self.ISSUER,
            "name": "foo bar",
            "nbf": self.AUTH_TIME,
            "oid": "7f8e1969-8b81-438c-8d4e-ad6f562b28bb",
            "preferred_username": "foobar@test.onmicrosoft.com",
            "sub": "qU8xks9mHqnV6Q34zh7SAZocih9EzrrI9mpVXOiBVA8",
            "tid": self.TENANT_ID,
            "upn": "foobar@test.onmicrosoft.com",
            "ver": self.TOKEN_VERSION,
        }
        payload.update(overrides)
        return jwt.encode(
            payload,
            key=cast(
                "RSAPrivateKey",
                RSAAlgorithm.from_jwk(json.dumps(RSA_PRIVATE_JWT_KEY)),
            ),
            algorithm="RS256",
            headers={"kid": RSA_PRIVATE_JWT_KEY["kid"]},
        )

    def build_access_token_body(self, **id_token_overrides) -> str:
        return json.dumps(
            {
                "access_token": "foobar",
                "token_type": "bearer",
                "id_token": self.build_id_token(**id_token_overrides),
                "expires_in": self.EXPIRES_IN,
                "expires_on": self.EXPIRES_ON,
                "not_before": self.AUTH_TIME,
            }
        )

    def tamper_id_token(self, id_token: str, **overrides) -> str:
        header, _payload, signature = id_token.split(".")
        payload = jwt.decode(
            id_token,
            options={"verify_signature": False, "verify_aud": False},
        )
        payload.update(overrides)
        data = json.dumps(payload, separators=(",", ":")).encode()
        tampered_payload = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        return f"{header}.{tampered_payload}.{signature}"

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        _user, social = self.do_refresh_token()
        self.assertEqual(social.extra_data["access_token"], "foobar-new-token")

    def test_login_rejects_invalid_id_token_signature(self) -> None:
        id_token = self.build_id_token()
        self.access_token_body = json.dumps(
            {
                "access_token": "foobar",
                "token_type": "bearer",
                "id_token": self.tamper_id_token(id_token, upn="attacker@example.com"),
            }
        )

        with self.assertRaises(AuthTokenError):
            self.do_start()

    def test_login_rejects_wrong_id_token_audience(self) -> None:
        self.access_token_body = self.build_access_token_body(aud="other-app")

        with self.assertRaises(AuthTokenError):
            self.do_start()

    def test_login_rejects_wrong_id_token_issuer(self) -> None:
        self.access_token_body = self.build_access_token_body(
            iss="https://sts.windows.net/00000000-0000-0000-0000-000000000000/"
        )

        with self.assertRaises(AuthTokenError):
            self.do_start()

    def test_login_rejects_invalid_id_token_tenant_id(self) -> None:
        self.access_token_body = self.build_access_token_body(tid=None)

        with self.assertRaises(AuthMissingParameter):
            self.do_start()

    def test_openid_configuration_and_jwks_cache_shared_by_url(self) -> None:
        cast("Any", self.backend.get_openid_configuration).invalidate()
        cast("Any", self.backend.get_jwks_keys_for_uri).invalidate()

        other_backend = self.backend.__class__(
            self.strategy, redirect_uri=self.complete_url
        )

        self.backend.openid_configuration()
        other_backend.openid_configuration()
        self.backend.get_jwks_keys()
        other_backend.get_jwks_keys()

        self.assertEqual(
            self.response_call_count(self.backend.openid_configuration_url()), 1
        )
        self.assertEqual(self.response_call_count(self.JWKS_URL), 1)

    def response_call_count(self, url: str) -> int:
        return sum(1 for call in responses.calls if call.request.url == url)


class AzureADOAuth2V2Test(AzureADOAuth2Test):
    backend_path = "social_core.backends.azuread.AzureADOAuth2V2"
    ISSUER = (
        "https://login.microsoftonline.com/727406ac-7068-48fa-92b9-c2d67211bc50/v2.0"
    )
    ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0"
    KEY_ISSUER = ISSUER_TEMPLATE
    JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    TOKEN_VERSION = "2.0"


class AzureADTenantOAuth2Test(AzureADOAuth2Test):
    backend_path = "social_core.backends.azuread_tenant.AzureADTenantOAuth2"
    JWKS_URL = (
        "https://login.microsoftonline.com/"
        f"{AzureADOAuth2Test.TENANT_ID}/discovery/keys?appid=a-key"
    )

    def extra_settings(self):
        settings = super().extra_settings()
        assert self.name, "Name must be set in subclasses"
        settings[f"SOCIAL_AUTH_{self.name}_TENANT_ID"] = self.TENANT_ID
        return settings

    def issuer_for_tenant(self, tenant_id: str) -> str:
        return self.ISSUER.replace(self.TENANT_ID, tenant_id)

    def test_login_rejects_wrong_configured_tenant_id(self) -> None:
        other_tenant_id = "00000000-0000-0000-0000-000000000000"
        self.access_token_body = self.build_access_token_body(
            iss=self.issuer_for_tenant(other_tenant_id),
            tid=other_tenant_id,
        )

        with self.assertRaises(AuthTokenError):
            self.do_start()


class AzureADV2TenantOAuth2Test(AzureADTenantOAuth2Test):
    backend_path = "social_core.backends.azuread_tenant.AzureADV2TenantOAuth2"
    ISSUER = (
        "https://login.microsoftonline.com/727406ac-7068-48fa-92b9-c2d67211bc50/v2.0"
    )
    ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0"
    KEY_ISSUER = ISSUER_TEMPLATE
    JWKS_URL = (
        "https://login.microsoftonline.com/"
        f"{AzureADOAuth2Test.TENANT_ID}/discovery/v2.0/keys?appid=a-key"
    )
    TOKEN_VERSION = "2.0"


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

    def test_login_rejects_invalid_id_token_signature(self) -> None:
        with self.assertRaises(AuthMissingParameter):
            super().test_login_rejects_invalid_id_token_signature()

    def test_login_rejects_wrong_id_token_audience(self) -> None:
        with self.assertRaises(AuthMissingParameter):
            super().test_login_rejects_wrong_id_token_audience()

    def test_login_rejects_wrong_id_token_issuer(self) -> None:
        with self.assertRaises(AuthMissingParameter):
            super().test_login_rejects_wrong_id_token_issuer()
