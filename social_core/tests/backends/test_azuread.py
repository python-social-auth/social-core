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

from social_core.exceptions import (
    AuthConfigurationError,
    AuthPolicyError,
    AuthResponseError,
)

from .azuread import AzureOAuth2TestMixin
from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .test_azuread_b2c import RSA_PRIVATE_JWT_KEY, RSA_PUBLIC_JWT_KEY

if TYPE_CHECKING:
    from typing import Any

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class AzureADOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin, AzureOAuth2TestMixin):
    AUTH_KEY = "a-key"
    AUTH_TIME = int(time())
    EXPIRES_IN = 3600
    EXPIRES_ON = AUTH_TIME + EXPIRES_IN
    JWKS_URL = "https://login.microsoftonline.com/common/discovery/keys"
    ISSUER = "https://sts.windows.net/727406ac-7068-48fa-92b9-c2d67211bc50/"
    ISSUER_TEMPLATE = "https://sts.windows.net/{tenantid}/"
    KEY_ISSUER = ISSUER_TEMPLATE
    TENANT_ID = "727406ac-7068-48fa-92b9-c2d67211bc50"
    OTHER_TENANT_ID = "00000000-0000-0000-0000-000000000000"
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
                "refresh_token": "foobar-refresh-token",
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
        self.assert_pkce_requests()

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

        with self.assertRaises(AuthResponseError):
            self.do_start()

    def test_login_rejects_wrong_id_token_audience(self) -> None:
        self.access_token_body = self.build_access_token_body(aud="other-app")

        with self.assertRaises(AuthResponseError):
            self.do_start()

    def test_login_rejects_wrong_id_token_issuer(self) -> None:
        self.access_token_body = self.build_access_token_body(
            iss="https://sts.windows.net/00000000-0000-0000-0000-000000000000/"
        )

        with self.assertRaises(AuthResponseError):
            self.do_start()

    def test_login_rejects_invalid_id_token_tenant_id(self) -> None:
        self.access_token_body = self.build_access_token_body(tid=None)

        with self.assertRaises(AuthResponseError):
            self.do_start()

    def configure(self, **settings: object) -> None:
        self.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{self.name}_{name}": value
                for name, value in settings.items()
            }
        )

    def test_groups_require_named_tenants_on_multi_tenant_authority(self) -> None:
        value: object
        self.configure(GROUPS_KEY="roles")
        response = {"tid": self.OTHER_TENANT_ID, "roles": ["staff"]}
        for value in (False, "true", 1):
            self.configure(GROUPS_ALLOW_ANY_TENANT=value)
            with (
                self.subTest(value=value),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                self.backend.get_user_groups(response)
            self.assertEqual(caught.exception.code, "missing_setting")
            self.assertEqual(caught.exception.parameter, "GROUPS_TENANT_IDS")
            self.assertEqual(caught.exception.stage, "pipeline")
        self.configure(GROUPS_ALLOW_ANY_TENANT=True)
        self.assertEqual(self.backend.get_user_groups(response), ["staff"])

    def test_email_allowlist_requires_trusted_tenant_on_common_authority(self) -> None:
        if not self.backend.accepts_any_tenant():
            self.skipTest("This backend pins the token to one tenant")
        self.configure(WHITELISTED_DOMAINS=["example.org"])
        details = {"email": "member@example.org"}
        with self.assertRaises(AuthConfigurationError) as caught:
            self.backend.auth_allowed({"tid": self.TENANT_ID}, details)
        self.assertEqual(caught.exception.parameter, "EMAIL_TENANT_IDS")
        self.assertEqual(caught.exception.stage, "pipeline")

        self.configure(EMAIL_TENANT_IDS=[self.TENANT_ID])
        self.assertTrue(self.backend.auth_allowed({"tid": self.TENANT_ID}, details))
        with self.assertRaises(AuthPolicyError):
            self.backend.auth_allowed({"tid": self.OTHER_TENANT_ID}, details)

    def test_email_allowlist_rejects_untrusted_signed_tenant(self) -> None:
        if (
            not self.backend.accepts_any_tenant()
            or "MissingCredentials" in type(self).__name__
        ):
            self.skipTest("This backend pins the tenant or cannot exchange a token")
        self.configure(
            WHITELISTED_EMAILS=["member@example.org"],
            EMAIL_TENANT_IDS=[self.TENANT_ID],
        )
        self.access_token_body = self.build_access_token_body(
            iss=self.ISSUER.replace(self.TENANT_ID, self.OTHER_TENANT_ID),
            tid=self.OTHER_TENANT_ID,
            email="member@example.org",
        )
        with self.assertRaises(AuthPolicyError):
            self.do_start()

    def test_email_allowlist_needs_no_tenant_list_for_pinned_authority(self) -> None:
        self.configure(
            AUTHORITY_URL=f"https://login.microsoftonline.com/{self.TENANT_ID}",
            WHITELISTED_DOMAINS=["example.org"],
        )
        responses.add(
            responses.GET,
            self.backend.openid_configuration_url(),
            json={"issuer": self.ISSUER, "jwks_uri": self.JWKS_URL},
        )
        self.assertTrue(
            self.backend.auth_allowed(
                {"tid": self.TENANT_ID}, {"email": "member@example.org"}
            )
        )

    def test_groups_need_no_named_tenants_on_tenant_authority(self) -> None:
        self.configure(
            AUTHORITY_URL=f"https://login.microsoftonline.com/{self.TENANT_ID}",
            GROUPS_KEY="roles",
        )
        responses.add(
            responses.GET,
            self.backend.openid_configuration_url(),
            json={"issuer": self.ISSUER, "jwks_uri": self.JWKS_URL},
        )
        self.assertEqual(self.backend.get_user_groups({"roles": ["staff"]}), ["staff"])

    def test_groups_honor_named_tenants_only(self) -> None:
        tenant_id: object
        self.configure(
            GROUPS_KEY="roles",
            GROUPS_TENANT_IDS=[self.TENANT_ID.upper()],
            GROUPS_ALLOW_ANY_TENANT=True,
            ALLOW_GROUPS=["staff"],
        )
        response: dict[str, object] = {"tid": self.TENANT_ID, "roles": ["staff"]}
        self.assertEqual(self.backend.get_user_groups(response), ["staff"])
        self.assertTrue(self.backend.auth_allowed(response, {}))
        for tenant_id in (self.OTHER_TENANT_ID, "contoso.example", "", None, 1):
            response = {"tid": tenant_id, "roles": ["staff"]}
            with self.subTest(tenant_id=tenant_id):
                with self.assertRaises(AuthPolicyError):
                    self.backend.get_user_groups(response)
                with self.assertRaises(AuthPolicyError):
                    self.backend.auth_allowed(response, {})
        with self.assertRaises(AuthPolicyError):
            self.backend.get_user_groups({"roles": ["staff"]})

    def test_invalid_group_tenants_are_a_configuration_error(self) -> None:
        value: object
        self.configure(GROUPS_KEY="roles", GROUPS_ALLOW_ANY_TENANT=True)
        response = {"tid": self.TENANT_ID, "roles": ["staff"]}
        for value in ("*", self.TENANT_ID, {}, [1], [None], ["contoso.example"]):
            self.configure(GROUPS_TENANT_IDS=value)
            with (
                self.subTest(value=value),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                self.backend.get_user_groups(response)
            self.assertEqual(caught.exception.code, "invalid_setting")
            self.assertEqual(caught.exception.parameter, "GROUPS_TENANT_IDS")
            self.assertEqual(caught.exception.stage, "pipeline")

    def test_login_refuses_groups_assigned_by_other_tenant(self) -> None:
        self.configure(
            GROUPS_KEY="roles",
            GROUPS_TENANT_IDS=[self.TENANT_ID],
            ALLOW_GROUPS=["staff"],
        )
        self.access_token_body = self.build_access_token_body(
            iss=self.ISSUER.replace(self.TENANT_ID, self.OTHER_TENANT_ID),
            tid=self.OTHER_TENANT_ID,
            roles=["staff"],
        )

        with self.assertRaises(AuthPolicyError):
            self.do_start()

    def test_untrusted_tenant_cannot_clear_synchronized_groups(self) -> None:
        self.configure(
            GROUPS_KEY="roles",
            GROUPS_TENANT_IDS=[self.TENANT_ID],
            GROUPS_MAP={"staff": ["Staff"]},
        )
        with self.assertRaises(AuthPolicyError):
            self.backend.get_user_groups({"tid": self.OTHER_TENANT_ID, "roles": []})

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

        with self.assertRaises(AuthResponseError):
            self.do_start()

    def test_groups_require_named_tenants_on_multi_tenant_authority(self) -> None:
        # The configured GUID tenant is the only one whose tokens are accepted.
        self.configure(GROUPS_KEY="roles")
        self.assertEqual(self.backend.get_user_groups({"roles": ["staff"]}), ["staff"])

        self.configure(TENANT_ID="common")
        responses.add(
            responses.GET,
            self.backend.openid_configuration_url(),
            json={"issuer": self.ISSUER_TEMPLATE, "jwks_uri": self.JWKS_URL},
        )
        super().test_groups_require_named_tenants_on_multi_tenant_authority()

    def test_login_refuses_groups_assigned_by_other_tenant(self) -> None:
        self.configure(TENANT_ID="common")
        responses.add(
            responses.GET,
            self.backend.openid_configuration_url(),
            json={"issuer": self.ISSUER_TEMPLATE, "jwks_uri": self.JWKS_URL},
        )
        super().test_login_refuses_groups_assigned_by_other_tenant()

    def test_authority_override_preserves_configured_tenant_restriction(self) -> None:
        configuration = self.backend.openid_configuration()
        self.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{self.name}_AUTHORITY_URL": "https://login.microsoftonline.com/organizations"
            }
        )
        responses.add(
            responses.GET, self.backend.openid_configuration_url(), json=configuration
        )
        self.test_login_rejects_wrong_configured_tenant_id()

    def test_authority_override_rejects_unverifiable_tenant_domain(self) -> None:
        configuration = self.backend.openid_configuration()
        self.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{self.name}_AUTHORITY_URL": "https://login.microsoftonline.com/organizations",
                f"SOCIAL_AUTH_{self.name}_TENANT_ID": "contoso.onmicrosoft.com",
            }
        )
        responses.add(
            responses.GET, self.backend.openid_configuration_url(), json=configuration
        )

        with self.assertRaises(AuthConfigurationError) as caught:
            self.do_start()
        self.assertEqual(caught.exception.code, "invalid_setting")
        self.assertEqual(caught.exception.parameter, "TENANT_ID")

    def test_login_with_tenant_domain_and_tenant_issuer(self) -> None:
        self.strategy.set_settings(
            {f"SOCIAL_AUTH_{self.name}_TENANT_ID": "contoso.onmicrosoft.com"}
        )
        responses.add(
            responses.GET,
            self.backend.openid_configuration_url(),
            json={"issuer": self.ISSUER, "jwks_uri": self.JWKS_URL},
        )
        self.do_login()

    def test_login_with_tenant_domain_rejects_other_tenant_issuer(self) -> None:
        other_tenant_id = "00000000-0000-0000-0000-000000000000"
        self.strategy.set_settings(
            {f"SOCIAL_AUTH_{self.name}_TENANT_ID": "contoso.onmicrosoft.com"}
        )
        responses.add(
            responses.GET,
            self.backend.openid_configuration_url(),
            json={"issuer": self.ISSUER, "jwks_uri": self.JWKS_URL},
        )
        self.access_token_body = self.build_access_token_body(
            iss=self.issuer_for_tenant(other_tenant_id),
            tid=other_tenant_id,
        )

        with self.assertRaises(AuthResponseError):
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

    def test_configurable_id_key(self) -> None:
        response = {
            "preferred_username": "mutable@example.com",
            "sub": "stable-subject",
        }
        self.assertEqual(
            self.backend.get_user_id({}, response),
            "stable-subject",
        )

        self.strategy.set_settings(
            {"SOCIAL_AUTH_AZUREAD_V2_TENANT_OAUTH2_ID_KEY": "preferred_username"}
        )
        self.assertEqual(self.backend.get_user_id({}, response), "mutable@example.com")


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
            self.assertRaises(AuthConfigurationError),
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
            self.assertRaises(AuthConfigurationError),
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
    def test_login_without_pkce(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login_without_pkce()

    def test_two_tabs_keep_their_own_pkce_verifiers(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_two_tabs_keep_their_own_pkce_verifiers()

    def test_login_with_pkce(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login_with_pkce()

    def test_partial_pipeline_with_pkce(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_partial_pipeline_with_pkce()

    def test_login_with_authority_override(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login_with_authority_override()

    def test_get_auth_token_uses_real_refresh_token(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_get_auth_token_uses_real_refresh_token()

    def test_get_auth_token_without_refresh_token(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_get_auth_token_without_refresh_token()

    def test_get_auth_token_keeps_valid_token(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_get_auth_token_keeps_valid_token()

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
            self.assertRaises(AuthConfigurationError),
        ):
            self.do_login()

    def test_login(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login()

    def test_partial_pipeline(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_partial_pipeline()

    def test_refresh_token(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_refresh_token()

    def test_login_rejects_invalid_id_token_signature(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login_rejects_invalid_id_token_signature()

    def test_login_rejects_wrong_id_token_audience(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login_rejects_wrong_id_token_audience()

    def test_login_rejects_wrong_id_token_issuer(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login_rejects_wrong_id_token_issuer()

    def test_login_rejects_invalid_id_token_tenant_id(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login_rejects_invalid_id_token_tenant_id()

    def test_login_refuses_groups_assigned_by_other_tenant(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            super().test_login_refuses_groups_assigned_by_other_tenant()
