"""Check recovery decisions for failed provider and pipeline operations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import unittest
from functools import partial
from unittest.mock import Mock, patch

import jwt
import requests
from openid.consumer.discover import DiscoveryFailure

from social_core.backends.apple import AppleIdAuth
from social_core.backends.auth0_openidconnect import Auth0OpenIdConnectAuth
from social_core.backends.azuread import AzureADOAuth2
from social_core.backends.azuread_tenant import (
    AzureADTenantOAuth2,
    AzureADV2TenantOAuth2,
)
from social_core.backends.base import BaseAuth
from social_core.backends.bungie import BungieOAuth2
from social_core.backends.discourse import DiscourseAuth
from social_core.backends.facebook import FacebookAppOAuth2, FacebookOAuth2
from social_core.backends.github import GithubOAuth2
from social_core.backends.github_enterprise import (
    GithubEnterpriseOAuth2,
    GithubEnterpriseOrganizationOAuth2,
    GithubEnterpriseTeamOAuth2,
)
from social_core.backends.justgiving import JustGivingOAuth2
from social_core.backends.mediawiki import MediaWiki
from social_core.backends.microsoft import MicrosoftOAuth2
from social_core.backends.oauth import BaseOAuth1, BaseOAuth2, BaseOAuth2PKCE
from social_core.backends.open_id import OPENID_ID_FIELD, OpenIdAuth
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.backends.ping import PingOpenIdConnect
from social_core.backends.telegram import TelegramAuth
from social_core.backends.twilio import TwilioAuth
from social_core.backends.twitter import TwitterOAuth
from social_core.backends.vk import VKOAuth2
from social_core.backends.weixin import WeixinOAuth2, WeixinOAuth2APP
from social_core.backends.xing import XingOAuth
from social_core.backends.yahoo import YahooOAuth2
from social_core.exceptions import (
    AuthCanceled,
    AuthConfigurationError,
    AuthCredentialError,
    AuthInputError,
    AuthProviderError,
    AuthResponseError,
    AuthSessionError,
    AuthUnknownError,
)
from social_core.pipeline import user, utils
from social_core.pipeline.social_auth import load_extra_data
from social_core.tests.models import TestStorage, User
from social_core.tests.strategy import TestStrategy


class AuthenticationFailureBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )

    def test_oidc_invalid_login_settings_require_administrator(self):
        for setting, value in (
            ("DISPLAY", ""),
            ("DISPLAY", "invalid"),
            ("PROMPT", ""),
            ("PROMPT", "invalid"),
            ("MAX_AGE", -1),
        ):
            with self.subTest(setting=setting, value=value):
                strategy = TestStrategy(TestStorage)
                strategy.set_settings(
                    {
                        "SOCIAL_AUTH_KEY": "key",
                        "SOCIAL_AUTH_SECRET": "secret",
                        f"SOCIAL_AUTH_{setting}": value,
                    }
                )
                backend = OpenIdConnectAuth(strategy)
                with (
                    patch.object(
                        backend,
                        "authorization_url",
                        return_value="https://example.com/auth",
                    ),
                    self.assertRaises(AuthConfigurationError) as caught,
                ):
                    backend.auth_params("state")
                self.assertEqual(caught.exception.stage, "begin")
                self.assertEqual(caught.exception.recovery, "contact_administrator")

    def test_invalid_extra_data_setting_fails_during_pipeline_storage(self):
        backend = BaseAuth(self.strategy)
        social = Mock()
        for entry in ((), ("a", "b", "c", "d")):
            self.strategy.set_settings({"SOCIAL_AUTH_EXTRA_DATA": [entry]})
            with (
                self.subTest(entry=entry),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                load_extra_data(backend, {}, {}, "user", social=social)
            self.assertEqual(caught.exception.code, "invalid_setting")
            self.assertEqual(caught.exception.parameter, "EXTRA_DATA")
            self.assertEqual(caught.exception.stage, "pipeline")
            social.set_extra_data.assert_not_called()

    def test_oidc_discovery_transport_failures_preserve_operation_stage(self):
        backend = OpenIdConnectAuth(self.strategy)
        # The cache decorator attaches invalidate dynamically.
        getattr(backend.oidc_config, "invalidate")(backend)  # noqa: B009
        for operation, stage in (
            (backend.authorization_url, "begin"),
            (backend.access_token_url, "token_exchange"),
            (backend.refresh_token_url, "refresh"),
            (backend.jwks_uri, "token_validation"),
            (backend.userinfo_url, "user_info"),
            (partial(backend.revoke_token_url, "token", "user"), "disconnect"),
        ):
            cause = requests.ReadTimeout("private diagnostic")
            with (
                self.subTest(stage=stage),
                patch("requests.request", side_effect=cause),
                self.assertRaises(AuthProviderError) as caught,
            ):
                operation()
            self.assertEqual(caught.exception.stage, stage)
            self.assertEqual(caught.exception.code, "timeout")
            self.assertEqual(caught.exception.recovery, "retry_later")
            self.assertIs(caught.exception.__cause__, cause)

    def test_oidc_refresh_url_preserves_custom_endpoint_overrides(self):
        backend = OpenIdConnectAuth(self.strategy)
        with patch.object(
            backend, "access_token_url", return_value="https://example.com/custom"
        ):
            self.assertEqual(backend.refresh_token_url(), "https://example.com/custom")
        with patch.object(backend, "REFRESH_TOKEN_URL", "https://example.com/refresh"):
            self.assertEqual(backend.refresh_token_url(), "https://example.com/refresh")

    def test_github_enterprise_missing_settings_match_operation(self):
        for backend_class in (
            GithubEnterpriseOAuth2,
            GithubEnterpriseOrganizationOAuth2,
            GithubEnterpriseTeamOAuth2,
        ):
            backend = backend_class(self.strategy)
            for operation, stage, parameter in (
                (backend.auth_url, "begin", "URL"),
                (backend.auth_complete, "token_exchange", "URL"),
                (partial(backend.refresh_token, "token"), "refresh", "URL"),
                (partial(backend.user_data, "token"), "user_info", "API_URL"),
            ):
                with (
                    self.subTest(backend=backend.name, stage=stage),
                    patch.object(backend, "validate_state", return_value="state"),
                    self.assertRaises(AuthConfigurationError) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.code, "missing_setting")
                self.assertEqual(caught.exception.parameter, parameter)

    def test_auth0_domain_failures_match_discovery_operation(self):
        backend = Auth0OpenIdConnectAuth(self.strategy)
        for domain in (None, "", " ", "/"):
            self.strategy.set_settings(
                {"SOCIAL_AUTH_AUTH0_OPENIDCONNECT_DOMAIN": domain}
            )
            # The cache decorator attaches invalidate dynamically.
            getattr(backend.oidc_config, "invalidate")(backend)  # noqa: B009
            for operation, stage in (
                (backend.authorization_url, "begin"),
                (backend.access_token_url, "token_exchange"),
                (backend.auth_complete_credentials, "token_exchange"),
                (backend.refresh_token_url, "refresh"),
                (backend.jwks_uri, "token_validation"),
                (backend.id_token_issuer, "token_validation"),
                (backend.userinfo_url, "user_info"),
                (partial(backend.revoke_token_url, "token", "user"), "disconnect"),
            ):
                with (
                    self.subTest(domain=domain, stage=stage, operation=operation),
                    self.assertRaises(AuthConfigurationError) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.code, "missing_setting")
                self.assertEqual(caught.exception.parameter, "DOMAIN")

    def test_custom_token_exchanges_stop_before_profile_lookup(self):
        for backend_class in (
            BungieOAuth2,
            MicrosoftOAuth2,
            JustGivingOAuth2,
            YahooOAuth2,
        ):
            backend = backend_class(self.strategy)
            for token_response in ({}, {"access_token": None}, {"access_token": ""}):
                with (
                    self.subTest(backend=backend.name, response=token_response),
                    patch.object(backend, "validate_state", return_value="state"),
                    patch.object(backend, "get_json", return_value=token_response),
                    patch.object(backend, "user_data") as user_data,
                    patch.object(self.strategy, "authenticate") as authenticate,
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    backend.auth_complete()
                self.assertEqual(caught.exception.code, "missing_claim")
                self.assertEqual(caught.exception.claim, "access_token")
                self.assertEqual(caught.exception.stage, "token_exchange")
                user_data.assert_not_called()
                authenticate.assert_not_called()

    def test_association_user_failure_stage_matches_operation(self):
        backend = TwilioAuth(self.strategy)
        initiator = User("initiator")
        backend.prepare_auth(initiator)
        state = backend.get_association_state()
        saved_partial = Mock(pipeline_type="authentication", kwargs={})
        for operation, stage in (
            (backend.prepare_auth, "begin"),
            (partial(backend.validate_association_state, state), "callback"),
            (partial(backend.validate_partial_pipeline, saved_partial), "callback"),
            (backend.disconnect, "disconnect"),
        ):
            with (
                self.subTest(stage=stage),
                self.assertRaises(AuthSessionError) as caught,
            ):
                operation()
            self.assertEqual(caught.exception.code, "session_context_missing")
            self.assertEqual(caught.exception.stage, stage)
        with self.assertRaises(AuthSessionError) as caught:
            backend.disconnect(
                user=initiator,
                **{backend.association_user_id_key("disconnect"): "other"},
            )
        self.assertEqual(caught.exception.code, "user_mismatch")
        self.assertEqual(caught.exception.stage, "disconnect")

    def test_oidc_unusable_signing_key_response_is_not_a_transport_failure(self):
        backend = OpenIdConnectAuth(self.strategy)
        for text in ("not JSON", "{}", "[]"):
            with (
                self.subTest(text=text),
                patch.object(
                    backend, "jwks_uri", return_value="https://example.com/keys"
                ),
                patch.object(backend, "request", return_value=Mock(text=text)),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.get_remote_jwks_keys()
            self.assertEqual(caught.exception.code, "malformed_response")
            self.assertEqual(caught.exception.stage, "token_validation")
            self.assertIsNotNone(caught.exception.__cause__)

    def test_oidc_keys_must_be_a_collection_of_objects(self):
        backend = OpenIdConnectAuth(self.strategy)
        payloads: tuple[object, ...] = (
            None,
            "key",
            {},
            [None],
            [1],
            [{"kid": "key"}, "bad"],
        )
        for keys in payloads:
            response = Mock(text=json.dumps({"keys": keys}))
            with (
                self.subTest(keys=keys),
                patch.object(
                    backend, "jwks_uri", return_value="https://example.com/keys"
                ),
                patch.object(backend, "request", return_value=response),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.get_remote_jwks_keys()
            self.assertEqual(caught.exception.code, "malformed_response")
            self.assertEqual(caught.exception.stage, "token_validation")
        for keys in ([], [{"kid": "key"}]):
            with (
                patch.object(
                    backend, "jwks_uri", return_value="https://example.com/keys"
                ),
                patch.object(
                    backend,
                    "request",
                    return_value=Mock(text=json.dumps({"keys": keys})),
                ),
            ):
                self.assertEqual(backend.get_remote_jwks_keys(), keys)

    def test_oidc_future_token_and_absent_nonce_require_fresh_login(self):
        backend = OpenIdConnectAuth(self.strategy)
        for claims, code in (
            ({"nbf": time.time() + 3600}, "response_not_yet_valid"),
            ({"iat": time.time()}, "nonce_mismatch"),
        ):
            with (
                self.subTest(claims=claims),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.validate_claims(claims)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "token_validation")
            self.assertEqual(
                caught.exception.recovery,
                "contact_administrator"
                if code == "response_not_yet_valid"
                else "restart_login",
            )

    def test_invalid_refresh_audiences_distinguish_stored_and_new_credentials(self):
        backend = OpenIdConnectAuth(self.strategy)
        context = {"iss": "https://example.com", "sub": "user", "aud": ["key"]}
        for previous, current, family, code in (
            (
                {**context, "aud": 1},
                context,
                AuthCredentialError,
                "reauthentication_required",
            ),
            (context, {**context, "aud": 1}, AuthResponseError, "invalid_claim"),
        ):
            with self.subTest(family=family), self.assertRaises(family) as caught:
                backend.validate_refresh_id_token_claims(previous, current)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "refresh")

    def test_unvalidated_id_token_cannot_be_saved(self):
        backend = OpenIdConnectAuth(self.strategy)
        with self.assertRaises(AuthResponseError) as caught:
            backend.extra_data(None, "user", {"id_token": "unvalidated"}, {}, {})
        self.assertEqual(caught.exception.code, "invalid_claim")

    def test_oauth1_callback_refusal_and_provider_problem_have_different_recovery(self):
        backend = BaseOAuth1(self.strategy)
        for problem, family, recovery in (
            ("user_refused", AuthCanceled, "none"),
            ("unknown", AuthProviderError, "contact_administrator"),
        ):
            with self.subTest(problem=problem), self.assertRaises(family) as caught:
                backend.process_error({"oauth_problem": problem})
            self.assertEqual(caught.exception.stage, "callback")
            self.assertEqual(caught.exception.recovery, recovery)

    def test_oauth1_missing_and_mismatched_session_tokens_require_restart(self):
        backend = BaseOAuth1(self.strategy)
        for tokens, data, code in (
            ([], {}, "session_context_missing"),
            (["oauth_token=stored"], {}, "session_context_missing"),
            (["oauth_token=stored"], {"oauth_token": "other"}, "state_mismatch"),
        ):
            self.strategy.session_set(
                backend.name + backend.UNATHORIZED_TOKEN_SUFIX, tokens
            )
            backend.data = data
            with (
                self.subTest(tokens=tokens, data=data),
                self.assertRaises(AuthSessionError) as caught,
            ):
                backend.get_unauthorized_token()
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.recovery, "restart_login")
            self.assertEqual(caught.exception.stage, "callback")

    def test_azure_assertion_configuration_failures_preserve_operation_stage(self):
        self.strategy.set_settings({"SOCIAL_AUTH_SECRET": None})
        backend = AzureADOAuth2(self.strategy)
        for path, file_error, content in (
            (None, None, "unused"),
            ("/assertion", FileNotFoundError("private diagnostic"), "unused"),
            ("/assertion", PermissionError("private diagnostic"), "unused"),
            ("/assertion", None, " \n\t"),
        ):
            self.strategy.set_settings({"SOCIAL_AUTH_FEDERATED_TOKEN_FILE": path})
            for operation, stage in (
                (partial(backend.auth_complete_params, "state"), "token_exchange"),
                (partial(backend.refresh_token_params, "refresh"), "refresh"),
            ):
                with (
                    self.subTest(path=path, file_error=file_error, stage=stage),
                    patch.dict(
                        os.environ,
                        {
                            "OAUTH2_FEDERATED_TOKEN_FILE": "",
                            "AZURE_FEDERATED_TOKEN_FILE": "",
                        },
                    ),
                    patch(
                        "social_core.backends.azuread.Path.read_text",
                        side_effect=file_error,
                        return_value=content,
                    ) as read_text,
                    self.assertRaises(AuthConfigurationError) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.code, "missing_setting")
                self.assertEqual(caught.exception.parameter, "client_assertion")
                self.assertEqual(caught.exception.recovery, "contact_administrator")
                self.assertIs(caught.exception.__cause__, file_error)
                self.assertNotIn("private diagnostic", str(caught.exception))
                if path is None:
                    read_text.assert_not_called()
                else:
                    read_text.assert_called_once_with(encoding="utf-8")

    def test_oauth1_incomplete_token_credentials_are_response_failures(self):
        oauth = BaseOAuth1(self.strategy)
        xing = XingOAuth(self.strategy)
        for operation in (oauth.oauth_auth, xing.clean_oauth_auth):
            for token in ({"oauth_token_secret": "secret"}, {"oauth_token": "token"}):
                with (
                    self.subTest(operation=operation, token=token),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    operation(token)
                self.assertEqual(caught.exception.code, "missing_claim")

    def test_oauth2_missing_token_never_enters_pipeline(self):
        backend = BaseOAuth2(self.strategy)
        tokens: tuple[object, ...] = (None, "", False, 0, [], {})
        for payload in ({}, *({"access_token": token} for token in tokens)):
            with (
                self.subTest(payload=payload),
                patch.object(backend, "validate_state", return_value="state"),
                patch.object(backend, "request_access_token", return_value=payload),
                patch.object(backend, "do_auth") as do_auth,
                patch.object(self.strategy, "authenticate") as authenticate,
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.auth_complete()
            self.assertEqual(caught.exception.code, "missing_claim")
            self.assertEqual(caught.exception.claim, "access_token")
            self.assertEqual(caught.exception.stage, "token_exchange")
            do_auth.assert_not_called()
            authenticate.assert_not_called()

    def test_pkce_invalid_method_is_a_login_initiation_configuration_failure(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_PKCE_CODE_CHALLENGE_METHOD": "unsupported"}
        )
        backend = BaseOAuth2PKCE(self.strategy)
        with self.assertRaises(AuthConfigurationError) as caught:
            backend.auth_url()
        self.assertEqual(caught.exception.code, "invalid_setting")
        self.assertEqual(caught.exception.parameter, "PKCE_CODE_CHALLENGE_METHOD")
        self.assertEqual(caught.exception.stage, "begin")
        self.assertEqual(caught.exception.recovery, "contact_administrator")

    def test_openid_discovery_and_missing_identifier_are_initiation_failures(self):
        backend = OpenIdAuth(self.strategy)
        for operation in (backend.setup_request, backend.uses_redirect):
            with (
                self.subTest(operation=operation),
                self.assertRaises(AuthInputError) as caught,
            ):
                operation()
            self.assertEqual(caught.exception.code, "missing_parameter")
            self.assertEqual(caught.exception.parameter, OPENID_ID_FIELD)
            self.assertEqual(caught.exception.stage, "begin")
        backend.data = {OPENID_ID_FIELD: "https://example.com/openid"}
        for operation in (backend.setup_request, backend.uses_redirect):
            cause = DiscoveryFailure("private discovery diagnostic", None)
            with (
                self.subTest(operation=operation),
                patch.object(
                    backend,
                    "consumer",
                    return_value=Mock(begin=Mock(side_effect=cause)),
                ),
                self.assertRaises(AuthProviderError) as discovery_failure,
            ):
                operation()
            self.assertEqual(discovery_failure.exception.stage, "begin")
            self.assertEqual(discovery_failure.exception.code, "http_error")
            self.assertIs(discovery_failure.exception.__cause__, cause)
            self.assertNotIn(
                "private discovery diagnostic", str(discovery_failure.exception)
            )

    def test_azure_tenant_claims_fail_during_token_validation(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_TENANT_ID": "12345678-1234-1234-1234-123456789abc"}
        )
        for backend_class in (AzureADTenantOAuth2, AzureADV2TenantOAuth2):
            backend = backend_class(self.strategy)
            for claims, code in (
                ({}, "missing_claim"),
                ({"tid": None}, "missing_claim"),
                ({"tid": "malformed"}, "invalid_claim"),
                ({"tid": "00000000-0000-0000-0000-000000000000"}, "invalid_claim"),
            ):
                with (
                    self.subTest(backend=backend.name, claims=claims),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    backend.get_id_token_issuer(claims)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.claim, "tid")
                self.assertEqual(caught.exception.stage, "token_validation")

    def test_refresh_json_failure_preserves_cause_and_stage(self):
        backend = BaseOAuth2(self.strategy)
        cause = ValueError("invalid JSON")
        response = Mock()
        response.json.side_effect = cause
        with (
            patch.object(backend, "request", return_value=response),
            self.assertRaises(AuthResponseError) as caught,
        ):
            backend.refresh_token("token")
        self.assertEqual(caught.exception.code, "malformed_response")
        self.assertEqual(caught.exception.stage, "refresh")
        self.assertIs(caught.exception.__cause__, cause)

    def test_telegram_configuration_input_expiry_and_signature_are_distinct(self):
        for settings, data, family, code in (
            ({}, {}, AuthConfigurationError, "missing_setting"),
            ({"BOT_TOKEN": "secret"}, {}, AuthInputError, "missing_parameter"),
            (
                {"BOT_TOKEN": "secret"},
                {"auth_date": 0, "hash": "invalid"},
                AuthResponseError,
                "response_expired",
            ),
            (
                {"BOT_TOKEN": "secret"},
                {"auth_date": int(time.time()), "hash": "invalid"},
                AuthResponseError,
                "invalid_signature",
            ),
        ):
            strategy = TestStrategy(TestStorage)
            strategy.set_settings(
                {f"SOCIAL_AUTH_{name}": value for name, value in settings.items()}
            )
            with self.subTest(code=code), self.assertRaises(family) as caught:
                TelegramAuth(strategy).verify_data(data)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "callback")

    def test_telegram_invalid_dates_are_callback_input_failures(self):
        self.strategy.set_settings({"SOCIAL_AUTH_TELEGRAM_BOT_TOKEN": "secret"})
        backend = TelegramAuth(self.strategy)
        invalid_values: tuple[object, ...] = ("not-a-date", "", [], {}, True, 1.5)
        for value in invalid_values:
            backend.data = {"auth_date": value, "hash": "hash"}
            with (
                self.subTest(auth_date=value),
                patch.object(self.strategy, "authenticate") as authenticate,
                self.assertRaises(AuthInputError) as caught,
            ):
                backend.auth_complete()
            self.assertEqual(caught.exception.code, "invalid_parameter")
            self.assertEqual(caught.exception.parameter, "auth_date")
            self.assertEqual(caught.exception.stage, "callback")
            self.assertEqual(caught.exception.source, "request")
            authenticate.assert_not_called()

    def test_facebook_token_exchange_rejects_invalid_success_responses(self):
        backend = FacebookOAuth2(self.strategy)
        backend.data = {"code": "code"}
        for payload, code in (
            (None, "malformed_response"),
            ([], "malformed_response"),
            (False, "malformed_response"),
            ({}, "missing_claim"),
            ({"access_token": None}, "missing_claim"),
            ({"access_token": ""}, "missing_claim"),
        ):
            with (
                self.subTest(payload=payload),
                patch.object(backend, "validate_state", return_value="state"),
                patch.object(
                    backend,
                    "request",
                    return_value=Mock(json=Mock(return_value=payload)),
                ),
                patch.object(backend, "user_data") as user_data,
                patch.object(self.strategy, "authenticate") as authenticate,
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.auth_complete()
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "token_exchange")
            user_data.assert_not_called()
            authenticate.assert_not_called()

    def test_facebook_querystring_token_response_remains_supported(self):
        backend = FacebookOAuth2(self.strategy)
        backend.data = {"code": "code"}
        response = Mock(
            json=Mock(side_effect=ValueError), text="access_token=token&expires=1"
        )
        with (
            patch.object(backend, "validate_state", return_value="state"),
            patch.object(backend, "request", return_value=response),
            patch.object(backend, "do_auth", return_value="user") as do_auth,
        ):
            self.assertEqual(backend.auth_complete(), "user")
        do_auth.assert_called_once_with(
            "token", {"access_token": "token", "expires": "1"}
        )

    def test_apple_missing_token_and_unusable_keys_are_response_failures(self):
        backend = AppleIdAuth(self.strategy)
        for operation in (
            partial(backend.decode_id_token, ""),
            partial(backend.do_auth, ""),
        ):
            with self.assertRaises(AuthResponseError) as caught:
                operation()
            self.assertEqual(caught.exception.code, "missing_claim")
        payloads: tuple[object, ...] = (
            [],
            None,
            {},
            {"keys": None},
            {"keys": []},
            {"keys": [None]},
            {"keys": [{}]},
            {"keys": [{"kid": ""}]},
            {"keys": [{"kid": 1}]},
            {"keys": [{"kid": "expected"}, None]},
            {"keys": [{"kid": "other"}]},
        )
        for payload in payloads:
            with (
                self.subTest(payload=payload),
                patch.object(backend, "get_json", return_value=payload),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.get_apple_jwk("expected")
            self.assertEqual(caught.exception.code, "malformed_response")
            self.assertEqual(caught.exception.stage, "token_validation")

    def test_apple_selects_valid_keys_with_or_without_identifier(self):
        backend = AppleIdAuth(self.strategy)
        keys = [{"kid": "first"}, {"kid": "second"}]
        with patch.object(backend, "get_json", return_value={"keys": keys}):
            self.assertEqual(json.loads(backend.get_apple_jwk()), keys[0])
            self.assertEqual(json.loads(backend.get_apple_jwk("second")), keys[1])

    def test_azure_malformed_jwks_are_rejected_before_caching(self):
        backend = AzureADOAuth2(self.strategy)
        payloads: tuple[object, ...] = (
            None,
            [],
            {"keys": {}},
            {"keys": "key"},
            {"keys": [None]},
            {"keys": [1]},
            {"keys": [{"kid": "key"}, "invalid"]},
        )
        valid_keys = [{"kid": "key"}]
        for index, payload in enumerate(payloads):
            uri = f"https://example.com/jwks-shape-regression/{index}"
            # The cache decorator attaches invalidate dynamically.
            getattr(backend.get_jwks_keys_for_uri, "invalidate")(backend, uri)  # noqa: B009
            with patch.object(
                backend, "get_json", side_effect=[payload, {"keys": valid_keys}]
            ) as get_json:
                with (
                    self.subTest(payload=payload),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    backend.get_jwks_keys_for_uri(uri)
                self.assertEqual(caught.exception.code, "malformed_response")
                self.assertEqual(caught.exception.stage, "token_validation")
                self.assertEqual(caught.exception.source, "provider_response")
                self.assertEqual(backend.get_jwks_keys_for_uri(uri), valid_keys)
                self.assertEqual(get_json.call_count, 2)

    def test_azure_missing_claims_and_unverifiable_key_are_response_failures(self):
        backend = AzureADOAuth2(self.strategy)
        with patch.object(backend, "openid_configuration", return_value={}):
            for operation, claim in (
                (backend.jwks_uri, "jwks_uri"),
                (partial(backend.get_id_token_issuer, {}), "issuer"),
            ):
                with (
                    self.subTest(claim=claim),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.claim, claim)
                self.assertEqual(caught.exception.code, "missing_claim")
        # The cache decorator attaches invalidate dynamically.
        getattr(backend.get_jwks_keys_for_uri, "invalidate")(  # noqa: B009
            backend, "https://example.com/empty-keys"
        )
        with (
            patch.object(backend, "get_json", return_value={}),
            self.assertRaises(AuthResponseError) as caught,
        ):
            backend.get_jwks_keys_for_uri("https://example.com/empty-keys")
        self.assertEqual(caught.exception.claim, "keys")
        for header, code in (
            ({}, "missing_claim"),
            ({"kid": "unavailable"}, "invalid_signature"),
        ):
            with (
                self.subTest(header=header),
                patch("jwt.get_unverified_header", return_value=header),
                patch.object(backend, "get_jwks_keys", return_value=[]),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.get_id_token_key("token")
            self.assertEqual(caught.exception.code, code)
        for jwt_operation in (backend.get_unverified_claims, backend.get_id_token_key):
            with self.assertRaises(AuthResponseError) as caught:
                jwt_operation("malformed-token")
            self.assertEqual(caught.exception.code, "invalid_claim")

    def test_ping_jwt_failures_keep_protocol_reason_and_cause(self):
        backend = PingOpenIdConnect(self.strategy)
        with (
            patch.object(backend, "find_valid_key", return_value=None),
            self.assertRaises(AuthResponseError) as caught,
        ):
            backend.decode_and_validate_id_token("token", "access")
        self.assertEqual(caught.exception.code, "invalid_signature")
        for cause, code in (
            (jwt.ExpiredSignatureError(), "response_expired"),
            (jwt.InvalidTokenError(), "invalid_claim"),
            (jwt.PyJWTError(), "invalid_claim"),
        ):
            with (
                self.subTest(cause=cause),
                patch.object(
                    backend,
                    "find_valid_key",
                    return_value={"alg": "HS256", "kty": "oct", "k": "a2V5"},
                ),
                patch.object(backend, "id_token_issuer", return_value="issuer"),
                patch("jwt.decode", side_effect=cause),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.decode_and_validate_id_token("token", "access")
            self.assertEqual(caught.exception.code, code)
            self.assertIs(caught.exception.__cause__, cause)

    def test_mediawiki_error_body_and_missing_token_claims_never_authenticate(self):
        backend = MediaWiki(self.strategy)
        token = {"oauth_token": "token", "oauth_token_secret": "secret"}
        for operation, content, code in (
            (
                backend.unauthorized_token,
                b"Error private details",
                "malformed_response",
            ),
            (
                partial(backend.access_token, token),
                b"Error private details",
                "malformed_response",
            ),
            (
                partial(backend.access_token, token),
                b"oauth_token_secret=secret",
                "missing_claim",
            ),
            (
                partial(backend.access_token, token),
                b"oauth_token=token",
                "missing_claim",
            ),
        ):
            with (
                self.subTest(content=content, operation=operation),
                patch.object(backend, "request", return_value=Mock(content=content)),
                self.assertRaises(AuthResponseError) as caught,
            ):
                operation()
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn("private details", str(caught.exception))
        with self.assertRaises(AuthResponseError) as token_error:
            backend.oauth_authorization_request({})
        self.assertEqual(token_error.exception.code, "missing_claim")
        self.assertEqual(token_error.exception.stage, "begin")
        self.assertEqual(token_error.exception.claim, "oauth_token")

    def test_mediawiki_identity_issuer_timestamp_and_nonce_are_validated(self):
        backend = MediaWiki(self.strategy)
        self.strategy.set_settings({"SOCIAL_AUTH_MEDIAWIKI_URL": backend.MEDIAWIKI_URL})
        identity = {
            "iss": backend.MEDIAWIKI_URL,
            "iat": time.time(),
            "nonce": "expected",
            "username": "user",
            "sub": "subject",
        }
        for claims, header, code in (
            ({**identity, "iss": "https://other.example.com"}, "", "invalid_claim"),
            ({**identity, "iat": time.time() + 3600}, "", "invalid_claim"),
            (identity, "", "missing_claim"),
            (identity, 'oauth_nonce="other"', "nonce_mismatch"),
        ):
            response = Mock(content=b"token")
            response.request.headers = {"Authorization": header}
            with (
                self.subTest(claims=claims, header=header),
                patch.object(backend, "request", return_value=response),
                patch("jwt.decode", return_value=claims),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.user_data(
                    {"oauth_token": "token", "oauth_token_secret": "secret"}
                )
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "user_info")

    def test_facebook_and_twitter_cancellation_remains_catchable(self):
        backend = FacebookOAuth2(self.strategy)
        with self.assertRaises(AuthProviderError) as caught:
            backend.process_error({"error_code": 100, "error_message": "private"})
        self.assertNotIn("private", str(caught.exception))
        with self.assertRaises(AuthInputError):
            backend.auth_complete()
        with self.assertRaises(AuthCanceled) as cancellation:
            TwitterOAuth(self.strategy).process_error({"denied": "token"})
        self.assertEqual(cancellation.exception.recovery, "none")
        with self.assertRaises(AuthCanceled):
            BaseOAuth2(self.strategy).process_error({"denied": "token"})

    def test_facebook_signed_request_rejects_malformed_signature_and_missing_identity(
        self,
    ):
        backend = FacebookAppOAuth2(self.strategy)
        for signed_request in (
            "no-separator",
            "aW52YWxpZA.eyJhbGdvcml0aG0iOiAiSE1BQy1TSEEyNTYifQ",
        ):
            with (
                self.subTest(signed_request=signed_request),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.load_signed_request(signed_request)
            self.assertEqual(caught.exception.code, "invalid_signature")
        payload = base64.urlsafe_b64encode(
            json.dumps({"issued_at": time.time()}).encode()
        ).rstrip(b"=")
        signature = hmac.new(b"secret", payload, hashlib.sha256).digest()
        encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
        backend.data = {
            "signed_request": f"{encoded_signature.decode()}.{payload.decode()}"
        }
        with (
            patch.object(backend, "do_auth") as do_auth,
            self.assertRaises(AuthResponseError) as caught,
        ):
            backend.auth_complete()
        self.assertEqual(caught.exception.code, "missing_claim")
        self.assertEqual(caught.exception.claim, "user_id")
        self.assertEqual(caught.exception.source, "provider_response")
        self.assertEqual(caught.exception.stage, "callback")
        do_auth.assert_not_called()

    def test_weixin_token_failures_stop_before_profile_fetch(self):
        for backend_class in (WeixinOAuth2, WeixinOAuth2APP):
            backend = backend_class(self.strategy)
            backend.data = {"code": "authorization-code"}
            for cause, payload, family in (
                (KeyError("missing"), None, AuthUnknownError),
                (None, {"errcode": 40029, "errmsg": "private"}, AuthProviderError),
            ):
                with (
                    self.subTest(backend=backend.name, family=family),
                    patch.object(backend, "validate_state", return_value="state"),
                    patch.object(
                        backend,
                        "get_json",
                        side_effect=cause,
                        return_value=payload,
                    ),
                    patch.object(backend, "do_auth") as do_auth,
                    self.assertRaises(family) as caught,
                ):
                    backend.auth_complete()
                if cause is None:
                    self.assertEqual(caught.exception.stage, "token_exchange")
                else:
                    self.assertIs(caught.exception.__cause__, cause)
                do_auth.assert_not_called()

    def test_optional_github_emails_and_vk_api_preserve_configuration_errors(
        self,
    ):
        github = GithubOAuth2(self.strategy)
        vk = VKOAuth2(self.strategy)
        error = AuthConfigurationError(code="invalid_setting")
        with (
            patch.object(github, "_user_data", side_effect=[{"login": "user"}, error]),
            self.assertRaises(AuthConfigurationError) as caught,
        ):
            github.user_data("token")
        self.assertIs(caught.exception, error)
        with patch.object(
            github, "_user_data", side_effect=[{"login": "user"}, ValueError("JSON")]
        ):
            self.assertEqual(github.user_data("token"), {"login": "user"})
        with (
            patch.object(vk, "get_json", side_effect=error),
            self.assertRaises(AuthConfigurationError) as caught,
        ):
            vk.vk_api("users.get", {"access_token": "token"})
        self.assertIs(caught.exception, error)

    def test_vk_revoked_token_and_provider_errors_are_distinct(self):
        backend = VKOAuth2(self.strategy)
        for payload, family, code in (
            ({"error": {"error_code": 5}}, AuthCredentialError, "token_revoked"),
            ({"error": {"error_code": 100}}, AuthProviderError, "http_error"),
            ({"error": "malformed"}, AuthResponseError, "malformed_response"),
        ):
            with (
                self.subTest(code=code),
                patch.object(backend, "vk_api", return_value=payload),
                self.assertRaises(family) as caught,
            ):
                backend.user_data("token")
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "user_info")

    def test_missing_storage_is_reported_at_each_pipeline_entry(self):
        strategy = TestStrategy(None)
        backend = BaseAuth(strategy)
        operations = (
            partial(user.get_username, strategy, {}, backend),
            partial(user.user_details, strategy, {}, None),
            partial(utils.partial_prepare, strategy, backend, 1),
            partial(utils.partial_store, strategy, backend, 1),
            partial(utils.partial_load, strategy, "token"),
        )
        for operation in operations:
            with (
                self.subTest(operation=operation),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                operation()
            self.assertEqual(caught.exception.parameter, "storage")
            self.assertEqual(caught.exception.stage, "pipeline")

    def test_invalid_provider_url_is_configuration_failure(self):
        backend = BaseAuth(self.strategy)
        for cause in (
            requests.exceptions.InvalidURL(),
            requests.exceptions.InvalidSchema(),
            requests.exceptions.MissingSchema(),
        ):
            with (
                self.subTest(cause=cause),
                patch("requests.request", side_effect=cause),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                backend.request("invalid", stage="begin")
            self.assertEqual(caught.exception.parameter, "url")
            self.assertIs(caught.exception.__cause__, cause)

    def test_discourse_hmac_mismatch_is_a_signature_failure(self):
        backend = DiscourseAuth(self.strategy)
        self.strategy.request_data().update({"sso": "payload", "sig": "wrong"})
        with self.assertRaises(AuthResponseError) as caught:
            backend.auth_complete()
        self.assertEqual(caught.exception.code, "invalid_signature")
        self.assertEqual(caught.exception.stage, "callback")
