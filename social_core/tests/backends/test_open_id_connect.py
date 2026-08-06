from __future__ import annotations

import copy
import datetime
import json
from typing import Protocol, cast
from unittest.mock import patch

import jwt
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

    def login_for_refresh(self, **id_token_kwargs):
        self.access_token_kwargs = {
            "refresh_token": "refresh-token",
            **id_token_kwargs,
        }
        user = self.do_login()
        return user.social[0]

    def refresh_response(self, **id_token_kwargs) -> str:
        return self.prepare_access_token_body(
            access_token="refreshed-access-token",  # noqa: S106
            include_nonce=False,
            **id_token_kwargs,
        )

    def refresh_social(self, social, body: str) -> None:
        responses.add(
            self._method(self.backend.REFRESH_TOKEN_METHOD),
            self.backend.refresh_token_url(),
            status=200,
            body=body,
            content_type="application/json",
        )
        social.refresh_token(strategy=self.strategy)

    def assert_refresh_rejected(self, body: str, message: str) -> None:
        social = self.login_for_refresh()
        original_extra_data = copy.deepcopy(social.extra_data)

        with self.assertRaisesRegex(AuthTokenError, message):
            self.refresh_social(social, body)

        self.assertEqual(social.extra_data, original_extra_data)

    def test_refresh_without_id_token_preserves_context(self) -> None:
        social = self.login_for_refresh()
        original_id_token = social.extra_data["id_token"]
        original_context = copy.deepcopy(
            social.extra_data[self.backend.ID_TOKEN_CONTEXT_KEY]
        )

        self.refresh_social(
            social,
            json.dumps(
                {
                    "access_token": "refreshed-access-token",
                    "token_type": "bearer",
                }
            ),
        )

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")
        self.assertEqual(social.extra_data["id_token"], original_id_token)
        self.assertEqual(
            social.extra_data[self.backend.ID_TOKEN_CONTEXT_KEY],
            original_context,
        )

    def test_refresh_validates_id_token_without_nonce(self) -> None:
        social = self.login_for_refresh()
        original_context = copy.deepcopy(
            social.extra_data[self.backend.ID_TOKEN_CONTEXT_KEY]
        )
        body = self.refresh_response()

        self.refresh_social(social, body)

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")
        self.assertEqual(social.extra_data["id_token"], json.loads(body)["id_token"])
        self.assertEqual(
            social.extra_data[self.backend.ID_TOKEN_CONTEXT_KEY],
            original_context,
        )

    def test_refresh_rejects_missing_access_token(self) -> None:
        body = self.prepare_access_token_body(
            access_token=None,
            include_nonce=False,
        )
        self.assert_refresh_rejected(
            body,
            "Missing access_token in OpenID Connect refresh response",
        )

    def test_refresh_rejects_invalid_signature(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(tamper_message=True),
            "Signature verification failed",
        )

    def test_refresh_rejects_expired_id_token(self) -> None:
        expiration = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            seconds=30
        )
        self.assert_refresh_rejected(
            self.refresh_response(expiration_datetime=expiration),
            "Signature has expired",
        )

    def test_refresh_rejects_invalid_issuer(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(issuer="https://invalid.example.com"),
            "Invalid issuer",
        )

    def test_refresh_rejects_invalid_audience(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(client_key="invalid-client"),
            "Invalid audience",
        )

    def test_refresh_rejects_changed_audience_set(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(client_key=[self.client_key, "another-audience"]),
            "Incorrect refreshed id_token: aud",
        )

    def test_refresh_rejects_missing_azp_for_multiple_audiences(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(
                client_key=[self.client_key, "another-audience"],
                include_azp=False,
            ),
            "Incorrect id_token: azp",
        )

    def test_refresh_rejects_invalid_azp(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(authorized_party="another-audience"),
            "Incorrect id_token: azp",
        )

    def test_refresh_rejects_changed_azp(self) -> None:
        social = self.login_for_refresh(include_azp=False)
        original_extra_data = copy.deepcopy(social.extra_data)

        with self.assertRaisesRegex(
            AuthTokenError,
            "Incorrect refreshed id_token: azp",
        ):
            self.refresh_social(social, self.refresh_response())

        self.assertEqual(social.extra_data, original_extra_data)

    def test_refresh_rejects_omitted_azp(self) -> None:
        social = self.login_for_refresh()
        original_extra_data = copy.deepcopy(social.extra_data)

        with self.assertRaisesRegex(
            AuthTokenError,
            "Incorrect refreshed id_token: azp",
        ):
            self.refresh_social(
                social,
                self.refresh_response(include_azp=False),
            )

        self.assertEqual(social.extra_data, original_extra_data)

    def test_refresh_rejects_invalid_at_hash(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(at_hash="invalid-hash"),
            "Invalid access token",
        )

    def test_refresh_rejects_changed_subject(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(subject="different-subject"),
            "Incorrect refreshed id_token: sub",
        )

    def test_refresh_rejects_changed_auth_time(self) -> None:
        social = self.login_for_refresh(auth_time=1_700_000_000)
        original_extra_data = copy.deepcopy(social.extra_data)

        with self.assertRaisesRegex(
            AuthTokenError,
            "Incorrect refreshed id_token: auth_time",
        ):
            self.refresh_social(
                social,
                self.refresh_response(auth_time=1_700_000_001),
            )

        self.assertEqual(social.extra_data, original_extra_data)

    def test_refresh_accepts_matching_nonce(self) -> None:
        social = self.login_for_refresh()
        context = social.extra_data[self.backend.ID_TOKEN_CONTEXT_KEY]

        self.refresh_social(
            social,
            self.prepare_access_token_body(
                access_token="refreshed-access-token",  # noqa: S106
                nonce=context["nonce"],
            ),
        )

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")

    def test_refresh_rejects_changed_nonce(self) -> None:
        self.assert_refresh_rejected(
            self.prepare_access_token_body(
                access_token="refreshed-access-token",  # noqa: S106
                nonce="different-nonce",
            ),
            "Incorrect refreshed id_token: nonce",
        )

    def test_refresh_seeds_missing_legacy_context(self) -> None:
        social = self.login_for_refresh()
        social.extra_data.pop(self.backend.ID_TOKEN_CONTEXT_KEY)

        self.refresh_social(social, self.refresh_response())

        self.assertEqual(
            social.extra_data[self.backend.ID_TOKEN_CONTEXT_KEY]["sub"],
            "1234",
        )
        original_extra_data = copy.deepcopy(social.extra_data)
        with self.assertRaisesRegex(
            AuthTokenError,
            "Incorrect refreshed id_token: sub",
        ):
            self.refresh_social(
                social,
                self.refresh_response(subject="different-subject"),
            )
        self.assertEqual(social.extra_data, original_extra_data)

    def test_legacy_refresh_rejects_changed_subject(self) -> None:
        social = self.login_for_refresh()
        social.extra_data.pop(self.backend.ID_TOKEN_CONTEXT_KEY)
        original_extra_data = copy.deepcopy(social.extra_data)

        with self.assertRaisesRegex(
            AuthTokenError,
            "Incorrect refreshed id_token: sub",
        ):
            self.refresh_social(
                social,
                self.refresh_response(subject="different-subject"),
            )

        self.assertEqual(social.extra_data, original_extra_data)

    def test_legacy_refresh_requires_subject_identity_key(self) -> None:
        social = self.login_for_refresh()
        social.extra_data.pop(self.backend.ID_TOKEN_CONTEXT_KEY)
        original_extra_data = copy.deepcopy(social.extra_data)

        with (
            patch.object(OpenIdConnectAuth, "id_key", return_value="username"),
            self.assertRaisesRegex(
                AuthTokenError,
                "reauthentication required",
            ),
        ):
            self.refresh_social(social, self.refresh_response())

        self.assertEqual(social.extra_data, original_extra_data)


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

    def test_malformed_id_token_raises_auth_token_error(self) -> None:
        with self.assertRaises(AuthTokenError) as context:
            self.backend.validate_and_return_id_token("malformed", "access-token")

        self.assertIsInstance(context.exception.__cause__, jwt.PyJWTError)

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

    def prepare_access_token_body(  # NOQA: PLR0913, PLR0917
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
        refresh_token: str | None = None,
        include_nonce: bool = True,
        auth_time: int | None = None,
        include_azp: bool = True,
        authorized_party: str | None = None,
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
            refresh_token=refresh_token,
            include_nonce=include_nonce,
            auth_time=auth_time,
            include_azp=include_azp,
            authorized_party=authorized_party,
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
