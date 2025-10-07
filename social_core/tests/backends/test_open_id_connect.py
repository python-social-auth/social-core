from __future__ import annotations

import json

import responses

from social_core.backends.open_id_connect import OpenIdConnectAuth

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest


class BaseOpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.open_id_connect.OpenIdConnectAuth"
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {
                "SOCIAL_AUTH_OIDC_OIDC_ENDPOINT": "https://example.com/oidc",
            }
        )
        return settings

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            "GET",
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()


class ExampleOpenIdConnectAuth(OpenIdConnectAuth):
    name = "example123"
    OIDC_ENDPOINT = "https://example.com/oidc"


class ExampleOpenIdConnectTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.ExampleOpenIdConnectAuth"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()


class OpenIdConnectAuthNoValidateAtHash(ExampleOpenIdConnectAuth):
    VALIDATE_AT_HASH = False


class ExampleOpenIdConnectNoValidateAtHashTest(OpenIdConnectTest):
    backend_path = "social_core.tests.backends.test_open_id_connect.OpenIdConnectAuthNoValidateAtHash"
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"
    allow_invalid_at_hash = True

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()


class OpenIdConnectCustomAtHash(ExampleOpenIdConnectAuth):
    CUSTOM_AT_HASH_ALGO = "SHA512"


class ExampleOpenIdConnectCustomAtHashTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectCustomAtHash"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def prepare_access_token_body(  # NOQA: PLR0913
        self,
        client_key=None,
        tamper_message=False,
        expiration_datetime=None,
        kid=None,
        issue_datetime=None,
        nonce=None,
        issuer=None,
        at_hash=None,
    ):
        if at_hash is None:
            at_hash = OpenIdConnectAuth.calc_at_hash("foobar", "RS256", "sha512")
        return super().prepare_access_token_body(
            client_key=client_key,
            tamper_message=tamper_message,
            expiration_datetime=expiration_datetime,
            kid=kid,
            issue_datetime=issue_datetime,
            nonce=nonce,
            issuer=issuer,
            at_hash=at_hash,
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_mismatch_custom_at_hash_algo(self) -> None:
        if self.skip_invalid_at_hash:
            self.skipTest("the call doesn't match any registered mock.")

        at_hash = OpenIdConnectAuth.calc_at_hash("foobar", "RS256", "sha256")

        if self.allow_invalid_at_hash:
            self.access_token_kwargs = {"at_hash": at_hash}
            self.do_login()
        else:
            self.authtoken_raised("Token error: Invalid access token", at_hash=at_hash)

    def test_invalid_custom_at_hash_algo(self) -> None:
        with self.assertRaisesRegex(
            NotImplementedError, "Unsupported custom at hash algorithm"
        ):
            OpenIdConnectAuth.calc_at_hash("foobar", "RS256", "INVALID_ALGO")
