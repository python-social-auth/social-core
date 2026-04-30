from __future__ import annotations

import json
from typing import Protocol, cast

import responses

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthInvalidParameter, AuthTokenError
from social_core.utils import get_querystring, parse_qs

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest


class OpenIdConnectPkceAssertionsCapable(Protocol):
    backend: OpenIdConnectAuth

    def assertEqual(self, first, second, msg=None) -> None: ...

    def assertIsNone(self, obj, msg=None) -> None: ...

    def assertIsNotNone(self, obj, msg=None) -> None: ...


class OpenIdConnectPkceAssertionsMixin:
    backend: OpenIdConnectAuth

    def assert_pkce_enabled(self: OpenIdConnectPkceAssertionsCapable) -> None:
        auth_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.authorization_url())
        )
        code_challenge = get_querystring(cast("str", auth_request.url)).get(
            "code_challenge"
        )
        code_challenge_method = get_querystring(cast("str", auth_request.url)).get(
            "code_challenge_method"
        )

        self.assertIsNotNone(code_challenge)
        self.assertEqual(code_challenge_method, "S256")

        auth_complete = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )
        code_verifier = parse_qs(auth_complete.body).get("code_verifier")

        self.assertEqual(
            self.backend.generate_code_challenge(code_verifier, code_challenge_method),
            code_challenge,
        )

    def assert_pkce_disabled(self: OpenIdConnectPkceAssertionsCapable) -> None:
        auth_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.authorization_url())
        )
        auth_query = get_querystring(cast("str", auth_request.url))

        self.assertIsNone(auth_query.get("code_challenge"))
        self.assertIsNone(auth_query.get("code_challenge_method"))

        auth_complete = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )

        self.assertIsNone(parse_qs(auth_complete.body).get("code_verifier"))


class BaseOpenIdConnectTest(
    OpenIdConnectTest, BaseAuthUrlTestMixin, OpenIdConnectPkceAssertionsMixin
):
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

    def test_pkce_disabled_by_default(self) -> None:
        self.do_login()
        self.assert_pkce_disabled()

    def test_pkce_can_be_enabled_by_setting(self) -> None:
        self.strategy.set_settings(
            {
                **self.extra_settings(),
                f"SOCIAL_AUTH_{self.name}_USE_PKCE": True,
            }
        )

        self.do_login()

        self.assert_pkce_enabled()


class ExampleOpenIdConnectAuth(OpenIdConnectAuth):
    name = "example123"
    OIDC_ENDPOINT = "https://example.com/oidc"


class OpenIdConnectPkceEnabledByDefault(ExampleOpenIdConnectAuth):
    name = "example123-pkce-default"
    DEFAULT_USE_PKCE = True


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

    def setUp(self) -> None:
        super().setUp()
        self.userinfo_response = {"preferred_username": self.expected_username}

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps(self.userinfo_response),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_user_id_comes_from_id_token_when_userinfo_omits_sub(self) -> None:
        user = self.do_login()

        self.assertEqual(user.social[0].uid, "1234")

    def test_matching_userinfo_sub_succeeds(self) -> None:
        self.userinfo_response["sub"] = "1234"

        user = self.do_login()

        self.assertEqual(user.social[0].uid, "1234")

    def test_mismatched_userinfo_sub_raises_error(self) -> None:
        self.userinfo_response["sub"] = "not-validated-subject"

        with self.assertRaisesRegex(
            AuthTokenError, "Token error: Invalid UserInfo sub"
        ):
            self.do_login()

    def test_missing_access_token_response_raises_token_error(self) -> None:
        self.authtoken_raised(
            "Token error: Missing access_token in OpenID Connect token response",
            access_token=None,
        )


class ExampleOpenIdConnectPkceEnabledByDefaultTest(
    OpenIdConnectTest, OpenIdConnectPkceAssertionsMixin
):
    backend_path = "social_core.tests.backends.test_open_id_connect.OpenIdConnectPkceEnabledByDefault"
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

    def test_pkce_enabled_by_backend_default(self) -> None:
        self.do_login()
        self.assert_pkce_enabled()

    def test_pkce_can_be_disabled_by_setting(self) -> None:
        self.strategy.set_settings(
            {
                **self.extra_settings(),
                f"SOCIAL_AUTH_{self.name}_USE_PKCE": False,
            }
        )

        self.do_login()

        self.assert_pkce_disabled()


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
        subject=None,
        access_token: str | None = "foobar",  # noqa: S107
    ):
        if at_hash is None and access_token is not None:
            at_hash = OpenIdConnectAuth.calc_at_hash(access_token, "RS256", "sha512")
        return super().prepare_access_token_body(
            client_key=client_key,
            tamper_message=tamper_message,
            expiration_datetime=expiration_datetime,
            kid=kid,
            issue_datetime=issue_datetime,
            nonce=nonce,
            issuer=issuer,
            at_hash=at_hash,
            subject=subject,
            access_token=access_token,
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


class OpenIdConnectWithAcrValues(ExampleOpenIdConnectAuth):
    ACR_VALUES = "urn:mace:incommon:iap:silver"


class ExampleOpenIdConnectAcrValuesTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithAcrValues"
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

    def test_acr_values_in_auth_params(self) -> None:
        params = self.backend.auth_params(state="test-state")
        self.assertEqual(params["acr_values"], "urn:mace:incommon:iap:silver")


class OpenIdConnectWithLoginHint(ExampleOpenIdConnectAuth):
    LOGIN_HINT = "user@example.com"


class ExampleOpenIdConnectLoginHintTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithLoginHint"
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

    def test_login_hint_in_auth_params(self) -> None:
        params = self.backend.auth_params(state="test-state")
        self.assertEqual(params["login_hint"], "user@example.com")


class OpenIdConnectWithIdTokenHint(ExampleOpenIdConnectAuth):
    ID_TOKEN_HINT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.fake"


class ExampleOpenIdConnectIdTokenHintTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithIdTokenHint"
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

    def test_id_token_hint_in_auth_params(self) -> None:
        params = self.backend.auth_params(state="test-state")
        self.assertEqual(
            params["id_token_hint"],
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.fake",
        )


class OpenIdConnectWithUiLocales(ExampleOpenIdConnectAuth):
    UI_LOCALES = "en-US fr-CA"


class ExampleOpenIdConnectUiLocalesTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithUiLocales"
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

    def test_ui_locales_in_auth_params(self) -> None:
        params = self.backend.auth_params(state="test-state")
        self.assertEqual(params["ui_locales"], "en-US fr-CA")


class OpenIdConnectWithInvalidParams(ExampleOpenIdConnectAuth):
    """Test invalid empty parameter values"""


class ExampleOpenIdConnectInvalidParamsTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithInvalidParams"
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

    def test_empty_acr_values_raises_error(self) -> None:
        with self.assertRaises(AuthInvalidParameter):
            self.strategy.set_settings(
                {
                    **self.extra_settings(),
                    f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_ACR_VALUES": "",
                }
            )
            self.backend.auth_params(state="test-state")

    def test_empty_login_hint_raises_error(self) -> None:
        with self.assertRaises(AuthInvalidParameter):
            self.strategy.set_settings(
                {
                    **self.extra_settings(),
                    f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_LOGIN_HINT": "",
                }
            )
            self.backend.auth_params(state="test-state")

    def test_empty_id_token_hint_raises_error(self) -> None:
        with self.assertRaises(AuthInvalidParameter):
            self.strategy.set_settings(
                {
                    **self.extra_settings(),
                    f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_ID_TOKEN_HINT": "",
                }
            )
            self.backend.auth_params(state="test-state")

    def test_empty_ui_locales_raises_error(self) -> None:
        with self.assertRaises(AuthInvalidParameter):
            self.strategy.set_settings(
                {
                    **self.extra_settings(),
                    f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_UI_LOCALES": "",
                }
            )
            self.backend.auth_params(state="test-state")
