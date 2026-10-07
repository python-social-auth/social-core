"""Exercise classification at provider, transport, and protocol boundaries."""

from __future__ import annotations

import unittest
from functools import partial
from unittest.mock import Mock, patch

import jwt
import requests

from social_core.backends.azuread import AzureADOAuth2
from social_core.backends.base import BaseAuth
from social_core.backends.fedora import FedoraOpenIdConnect
from social_core.backends.lastfm import LastFmAuth
from social_core.backends.line import LineOAuth2
from social_core.backends.linkedin import LinkedinOAuth2
from social_core.backends.oauth import BaseOAuth1, BaseOAuth2
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.backends.ping import PingOpenIdConnect
from social_core.backends.untappd import UntappdOAuth2
from social_core.backends.utils import jwt_error
from social_core.backends.vk import VKIDOAuth2, VKOAuth2
from social_core.backends.weixin import WeixinOAuth2, WeixinOAuth2APP
from social_core.exceptions import (
    AuthCanceled,
    AuthConfigurationError,
    AuthCredentialError,
    AuthProviderError,
    AuthResponseError,
    AuthSessionError,
    ErrorStage,
)
from social_core.tests.models import TestStorage, User
from social_core.tests.strategy import TestStrategy
from social_core.utils import http_error, module_member, provider_error


class ProviderErrorTest(unittest.TestCase):
    def setUp(self):
        self.backend = BaseAuth(TestStrategy(TestStorage))

    def response(self, status, data=None):
        response = Mock(spec=requests.Response, status_code=status, headers={})
        if data is None:
            response.json.side_effect = ValueError("not JSON")
        else:
            response.json.return_value = data
        return response

    def test_http_status_does_not_establish_cancellation_or_expiry(self):
        for status, code in (
            (400, "http_error"),
            (401, "http_error"),
            (403, "http_error"),
            (429, "rate_limited"),
            (500, "unavailable"),
            (503, "unavailable"),
        ):
            payloads: tuple[object, ...] = (
                None,
                [],
                {"error_description": "access_denied expired token"},
            )
            for data in payloads:
                with self.subTest(status=status, data=data):
                    cause = requests.HTTPError(response=self.response(status, data))
                    error = http_error(self.backend, cause, stage="token_exchange")
                    self.assertIsInstance(error, AuthProviderError)
                    self.assertEqual(error.code, code)
                    self.assertEqual(error.status_code, status)
                    self.assertEqual(error.stage, "token_exchange")

    def test_structured_provider_code_overrides_generic_status(self):
        for provider_code, family, code in (
            ("access_denied", AuthCanceled, "authorization_declined"),
            ("invalid_client", AuthConfigurationError, "invalid_setting"),
            ("invalid_grant", AuthCredentialError, "authorization_code_rejected"),
            (
                "bad_verification_code",
                AuthCredentialError,
                "authorization_code_rejected",
            ),
            ("invalid_token", AuthCredentialError, "credential_rejected"),
            ("unrecognized", AuthProviderError, "http_error"),
        ):
            with self.subTest(provider_code=provider_code):
                cause = requests.HTTPError(
                    response=self.response(
                        400,
                        {"error": provider_code, "error_description": "private-token"},
                    )
                )
                error = http_error(self.backend, cause, stage="token_exchange")
                self.assertIsInstance(error, family)
                self.assertEqual(error.code, code)
                self.assertEqual(error.provider_code, provider_code)
                self.assertNotIn("private-token", str(error))
                self.assertNotIn("private-token", str(error.public_metadata()))

    def test_refresh_rejection_requires_new_authentication(self):
        error = provider_error(
            self.backend, {"error": "invalid_grant"}, stage="refresh"
        )
        assert error is not None
        self.assertEqual(error.code, "reauthentication_required")
        self.assertEqual(error.source, "provider_response")

    def test_legacy_error_hook_allows_login_and_refresh(self):
        backend = BaseOAuth2(TestStrategy(TestStorage))
        hook = Mock()

        def process_error(data):
            hook(data)

        payload = {"access_token": "token"}
        with (
            patch.object(backend, "process_error", new=process_error),
            patch.object(backend, "validate_state", return_value="state"),
            patch.object(backend, "get_json", return_value=payload),
            patch.object(backend, "request", return_value=self.response(200, payload)),
            patch.object(backend, "do_auth", return_value="user") as do_auth,
        ):
            self.assertEqual(backend.auth_complete(), "user")
            self.assertEqual(backend.refresh_token("refresh-token"), payload)

        do_auth.assert_called_once_with("token", response=payload)
        self.assertEqual(hook.call_count, 3)

    def test_legacy_error_hook_failures_keep_the_operation_stage(self):
        backend = BaseOAuth2(TestStrategy(TestStorage))
        error = AuthProviderError(backend, code="unavailable")
        hook = Mock()

        def process_error(data):
            hook(data)
            raise error

        for stage in ("token_exchange", "refresh"):
            with (
                self.subTest(stage=stage),
                patch.object(backend, "process_error", new=process_error),
                patch.object(backend, "get_json", return_value={}),
                patch.object(backend, "request", return_value=self.response(200, {})),
                self.assertRaises(AuthProviderError) as caught,
            ):
                if stage == "refresh":
                    backend.refresh_token("refresh-token")
                else:
                    backend.request_access_token("https://example.com/token")
            self.assertIs(caught.exception, error)
            self.assertEqual(error.stage, stage)
            self.assertEqual(error.recovery, "retry_later")
        self.assertEqual(hook.call_count, 2)

    def test_error_hook_type_errors_are_not_retried(self):
        backend = BaseOAuth2(TestStrategy(TestStorage))
        hook = Mock()

        def process_error(data, *, stage="callback"):
            hook(data, stage=stage)
            raise TypeError("hook implementation failed")

        with (
            patch.object(backend, "process_error", new=process_error),
            patch.object(backend, "get_json", return_value={}),
            self.assertRaisesRegex(TypeError, "hook implementation failed"),
        ):
            backend.request_access_token("https://example.com/token")
        hook.assert_called_once_with({}, stage="token_exchange")

    def test_missing_response_and_retry_after(self):
        error = http_error(self.backend, requests.HTTPError())
        self.assertIsNone(error.status_code)
        self.assertEqual(error.code, "http_error")
        response = self.response(429)
        response.headers["Retry-After"] = "120"
        error = http_error(self.backend, requests.HTTPError(response=response))
        self.assertEqual(error.retry_after, "120")

    def test_transport_failures_keep_distinct_recovery_and_cause(self):
        for cause, code, recovery in (
            (
                requests.exceptions.SSLError("private URL"),
                "tls_error",
                "contact_administrator",
            ),
            (requests.ConnectTimeout(), "timeout", "retry_later"),
            (requests.ReadTimeout(), "timeout", "retry_later"),
            (requests.ConnectionError(), "connection_failed", "retry_later"),
        ):
            with self.subTest(code=code), patch("requests.request", side_effect=cause):
                with self.assertRaises(AuthProviderError) as caught:
                    self.backend.request("https://example.com", stage="refresh")
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.recovery, recovery)
                self.assertEqual(caught.exception.stage, "refresh")
                self.assertIs(caught.exception.__cause__, cause)
                self.assertNotIn("private URL", str(caught.exception))

    def test_remaining_requests_failures_are_structured(self):
        stages: tuple[ErrorStage, ...] = (
            "begin",
            "token_exchange",
            "token_validation",
            "user_info",
            "refresh",
            "disconnect",
        )
        for exception in (
            requests.TooManyRedirects,
            requests.exceptions.ContentDecodingError,
            requests.exceptions.RetryError,
            requests.RequestException,
        ):
            for stage in stages:
                cause = exception("private provider URL")
                with (
                    self.subTest(exception=exception, stage=stage),
                    patch("requests.request", side_effect=cause),
                    self.assertRaises(AuthProviderError) as caught,
                ):
                    self.backend.request("https://example.com", stage=stage)
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.code, "http_error")
                self.assertEqual(caught.exception.recovery, "contact_administrator")
                self.assertIs(caught.exception.__cause__, cause)
                self.assertNotIn("private provider URL", str(caught.exception))
                self.assertNotIn(
                    "private provider URL", str(caught.exception.public_metadata())
                )

    def test_http_errors_from_request_keep_status_classification(self):
        cause = requests.HTTPError(response=self.response(503))
        with (
            patch("requests.request", side_effect=cause),
            self.assertRaises(AuthProviderError) as caught,
        ):
            self.backend.request("https://example.com", stage="begin")
        self.assertEqual(caught.exception.code, "unavailable")
        self.assertEqual(caught.exception.stage, "begin")
        self.assertEqual(caught.exception.status_code, 503)
        self.assertIs(caught.exception.__cause__, cause)

    def test_vk_profile_failures_stop_authentication_and_keep_retry_guidance(self):
        backend = VKOAuth2(TestStrategy(TestStorage))
        for status, code in ((429, "rate_limited"), (503, "unavailable")):
            response = self.response(status)
            response.raise_for_status.side_effect = requests.HTTPError(
                response=response
            )
            with (
                self.subTest(status=status),
                patch("requests.request", return_value=response),
                patch.object(backend.strategy, "authenticate") as authenticate,
                self.assertRaises(AuthProviderError) as caught,
            ):
                backend.do_auth("token")
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "user_info")
            self.assertEqual(caught.exception.recovery, "retry_later")
            authenticate.assert_not_called()
        with (
            patch("requests.request", side_effect=requests.ReadTimeout()),
            self.assertRaises(AuthProviderError) as caught,
        ):
            backend.user_data("token")
        self.assertEqual(caught.exception.code, "timeout")
        response = self.response(200)
        with (
            patch("requests.request", return_value=response),
            self.assertRaises(AuthResponseError) as malformed,
        ):
            backend.user_data("token")
        self.assertEqual(malformed.exception.code, "malformed_response")

    def test_facebook_token_transport_failures_report_token_exchange(self):
        backend = module_member("social_core.backends.facebook.FacebookOAuth2")(
            TestStrategy(TestStorage)
        )
        backend.data = {"code": "code"}
        response = self.response(503)
        cause = requests.HTTPError(response=response)
        response.raise_for_status.side_effect = cause
        for transport_cause in (requests.ReadTimeout(), None):
            with (
                self.subTest(cause=transport_cause),
                patch.object(backend, "validate_state", return_value="state"),
                patch.object(
                    backend, "get_key_and_secret", return_value=("key", "secret")
                ),
                patch(
                    "requests.request",
                    side_effect=transport_cause,
                    return_value=response,
                ),
                patch.object(backend, "do_auth") as do_auth,
                self.assertRaises(AuthProviderError) as caught,
            ):
                backend.auth_complete()
            self.assertEqual(caught.exception.stage, "token_exchange")
            self.assertEqual(caught.exception.recovery, "retry_later")
            self.assertIs(caught.exception.__cause__, transport_cause or cause)
            do_auth.assert_not_called()

    def test_azure_validation_and_lastfm_exchange_requests_preserve_failure_stage(self):
        strategy = TestStrategy(TestStorage)
        strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )
        azure = AzureADOAuth2(strategy)
        lastfm = LastFmAuth(strategy)
        lastfm_user = User("lastfm-user")
        lastfm.data = {"token": "token", "redirect_state": "state"}
        configuration_url = "https://example.com/stage-regression/discovery"
        keys_url = "https://example.com/stage-regression/keys"
        # The cache decorator attaches invalidate dynamically.
        getattr(azure.get_openid_configuration, "invalidate")(azure, configuration_url)
        getattr(azure.get_jwks_keys_for_uri, "invalidate")(azure, keys_url)
        for operation, stage in (
            (
                partial(azure.get_openid_configuration, configuration_url),
                "token_validation",
            ),
            (partial(azure.get_jwks_keys_for_uri, keys_url), "token_validation"),
            (partial(lastfm.auth_complete, user=lastfm_user), "token_exchange"),
        ):
            for transport_failure in (False, True):
                if stage == "token_exchange":
                    strategy.session_set(
                        "lastfm_state",
                        {"state": "state", "user_id": str(lastfm_user.id)},
                    )
                response = self.response(503)
                cause = (
                    requests.ReadTimeout("private diagnostic")
                    if transport_failure
                    else requests.HTTPError(response=response)
                )
                if not transport_failure:
                    response.raise_for_status.side_effect = cause
                with (
                    self.subTest(
                        operation=operation, transport_failure=transport_failure
                    ),
                    patch(
                        "requests.request",
                        return_value=response,
                        side_effect=cause if transport_failure else None,
                    ),
                    patch.object(strategy, "authenticate") as authenticate,
                    self.assertRaises(AuthProviderError) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(
                    caught.exception.code,
                    "timeout" if transport_failure else "unavailable",
                )
                self.assertEqual(caught.exception.recovery, "retry_later")
                self.assertIs(caught.exception.__cause__, cause)
                authenticate.assert_not_called()

    def test_lastfm_native_errors_stop_exchange_with_provider_diagnostics(self):
        strategy = TestStrategy(TestStorage)
        strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )
        backend = LastFmAuth(strategy)
        user = User("lastfm-user")
        backend.data = {"token": "token", "redirect_state": "state"}
        for provider_code, code, recovery in (
            (4, "http_error", "contact_administrator"),
            (11, "unavailable", "retry_later"),
            (16, "unavailable", "retry_later"),
            (29, "rate_limited", "retry_later"),
            (999, "http_error", "contact_administrator"),
        ):
            strategy.session_set(
                "lastfm_state", {"state": "state", "user_id": str(user.id)}
            )
            payload = {"error": provider_code, "message": "private diagnostic"}
            response = self.response(200, payload)
            with (
                self.subTest(provider_code=provider_code),
                patch("requests.request", return_value=response),
                patch.object(strategy, "authenticate") as authenticate,
                self.assertRaises(AuthProviderError) as caught,
            ):
                backend.auth_complete(user=user)
            error = caught.exception
            self.assertEqual(error.code, code)
            self.assertEqual(error.provider_code, provider_code)
            self.assertEqual(error.stage, "token_exchange")
            self.assertEqual(error.recovery, recovery)
            self.assertEqual(error.detail, "private diagnostic")
            self.assertNotIn("private diagnostic", str(error))
            authenticate.assert_not_called()

    def test_lastfm_unusable_success_payloads_are_structured_response_errors(self):
        strategy = TestStrategy(TestStorage)
        strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )
        backend = LastFmAuth(strategy)
        user = User("lastfm-user")
        backend.data = {"token": "token", "redirect_state": "state"}
        for payload, code in (
            ([], "malformed_response"),
            ({}, "missing_claim"),
            ({"session": []}, "malformed_response"),
        ):
            strategy.session_set(
                "lastfm_state", {"state": "state", "user_id": str(user.id)}
            )
            with (
                self.subTest(payload=payload),
                patch("requests.request", return_value=self.response(200, payload)),
                patch.object(strategy, "authenticate") as authenticate,
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.auth_complete(user=user)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "token_exchange")
            authenticate.assert_not_called()

    def test_oidc_invalid_discovery_is_not_cached_and_preserves_operation_stage(self):
        backend = OpenIdConnectAuth(TestStrategy(TestStorage))
        valid = {
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "userinfo_endpoint": "https://example.com/userinfo",
            "revocation_endpoint": "https://example.com/revoke",
            "issuer": "https://example.com",
            "jwks_uri": "https://example.com/jwks",
        }
        invalid_payloads: tuple[object, ...] = (
            None,
            [],
            ["endpoint"],
            "endpoint",
            42,
            False,
        )
        for operation, stage in (
            (backend.authorization_url, "begin"),
            (backend.access_token_url, "token_exchange"),
            (backend.refresh_token_url, "refresh"),
            (backend.use_basic_auth, "token_exchange"),
            (backend.userinfo_url, "user_info"),
            (backend.id_token_issuer, "token_validation"),
            (backend.jwks_uri, "token_validation"),
            (partial(backend.revoke_token_url, "token", "user"), "disconnect"),
        ):
            for payload in invalid_payloads:
                getattr(backend.oidc_config, "invalidate")(backend)
                with (
                    self.subTest(stage=stage, payload=payload),
                    patch.object(
                        backend, "get_json", side_effect=[payload, valid]
                    ) as get_json,
                ):
                    with self.assertRaises(AuthResponseError) as caught:
                        operation()
                    self.assertEqual(caught.exception.code, "malformed_response")
                    self.assertEqual(caught.exception.stage, stage)
                    self.assertEqual(caught.exception.source, "provider_response")
                    operation()
                    self.assertEqual(backend.oidc_config(), valid)
                    self.assertEqual(get_json.call_count, 2)
        getattr(backend.oidc_config, "invalidate")(backend)

    def test_oidc_discovery_missing_endpoint_is_a_provider_response_failure(self):
        strategy = TestStrategy(TestStorage)
        backend = OpenIdConnectAuth(strategy)
        for operation, claim, stage in (
            (backend.authorization_url, "authorization_endpoint", "begin"),
            (backend.access_token_url, "token_endpoint", "token_exchange"),
            (backend.refresh_token_url, "token_endpoint", "refresh"),
            (backend.id_token_issuer, "issuer", "token_validation"),
            (backend.jwks_uri, "jwks_uri", "token_validation"),
            (backend.userinfo_url, "userinfo_endpoint", "user_info"),
            (
                partial(backend.revoke_token_url, "token", "user"),
                "revocation_endpoint",
                "disconnect",
            ),
        ):
            with (
                self.subTest(claim=claim, stage=stage),
                patch.object(backend, "oidc_config", return_value={}),
                self.assertRaises(AuthResponseError) as caught,
            ):
                operation()
            self.assertEqual(caught.exception.code, "missing_claim")
            self.assertEqual(caught.exception.claim, claim)
            self.assertEqual(caught.exception.stage, stage)

    def test_invalid_oidc_endpoint_settings_are_configuration_failures(self):
        strategy = TestStrategy(TestStorage)
        backend = OpenIdConnectAuth(strategy)
        invalid_values: tuple[object, ...] = (True, False, 42, 0, [], {}, ["url"])
        for operation, parameter, stage in (
            (backend.authorization_url, "AUTHORIZATION_URL", "begin"),
            (backend.access_token_url, "ACCESS_TOKEN_URL", "token_exchange"),
            (backend.refresh_token_url, "ACCESS_TOKEN_URL", "refresh"),
            (backend.id_token_issuer, "ID_TOKEN_ISSUER", "token_validation"),
            (backend.jwks_uri, "JWKS_URI", "token_validation"),
            (backend.userinfo_url, "USERINFO_URL", "user_info"),
            (
                partial(backend.revoke_token_url, "token", "user"),
                "REVOKE_TOKEN_URL",
                "disconnect",
            ),
        ):
            for value in invalid_values:
                strategy.set_settings({f"SOCIAL_AUTH_{parameter}": value})
                with (
                    self.subTest(parameter=parameter, stage=stage, value=value),
                    patch.object(backend, "oidc_config") as discovery,
                    self.assertRaises(AuthConfigurationError) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.code, "invalid_setting")
                self.assertEqual(caught.exception.parameter, parameter)
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.source, "configuration")
                discovery.assert_not_called()
                strategy.set_settings({f"SOCIAL_AUTH_{parameter}": None})

    def test_refresh_non_object_json_is_a_structured_response_failure(self):
        payloads: tuple[object, ...] = (None, [], ["denied"], "token", 1, False)
        for backend_class in (BaseOAuth2, OpenIdConnectAuth, PingOpenIdConnect):
            backend = backend_class(TestStrategy(TestStorage))
            for payload in payloads:
                response = self.response(200, payload)
                response.json.side_effect = None
                response.json.return_value = payload
                with (
                    self.subTest(backend=backend.name, payload=payload),
                    patch.object(backend, "request", return_value=response),
                    patch.object(backend, "refresh_token_params", return_value={}),
                    patch.object(
                        backend,
                        "refresh_token_url",
                        return_value="https://example.com/token",
                    ),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    backend.refresh_token("token")
                self.assertEqual(caught.exception.code, "malformed_response")
                self.assertEqual(caught.exception.stage, "refresh")

    def test_fedora_discovery_timeout_stops_login_with_retry_guidance(self):
        strategy = TestStrategy(TestStorage)
        strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )
        backend = FedoraOpenIdConnect(strategy, redirect_uri="/complete/fedora-oidc/")
        # The cache decorator attaches invalidate dynamically.
        getattr(backend.oidc_config, "invalidate")(backend)
        cause = requests.ReadTimeout("Read timed out. (read timeout=5.0)")
        with (
            patch("requests.request", side_effect=cause) as request,
            patch.object(strategy, "redirect") as redirect,
            patch.object(strategy, "authenticate") as authenticate,
            self.assertRaises(AuthProviderError) as caught,
        ):
            backend.start()
        self.assertEqual(caught.exception.code, "timeout")
        self.assertEqual(caught.exception.source, "provider_response")
        self.assertEqual(caught.exception.stage, "begin")
        self.assertEqual(caught.exception.recovery, "retry_later")
        self.assertIs(caught.exception.__cause__, cause)
        self.assertEqual(
            request.call_args.args[1],
            "https://id.fedoraproject.org/.well-known/openid-configuration",
        )
        redirect.assert_not_called()
        authenticate.assert_not_called()

    def test_line_native_http_errors_keep_diagnostics_and_http_recovery(self):
        backend = LineOAuth2(TestStrategy(TestStorage))
        for operation, stage in (
            (
                partial(backend.request_access_token, "https://example.com/token"),
                "token_exchange",
            ),
            (partial(backend.user_data, "token"), "user_info"),
        ):
            for status, code in (
                (400, "http_error"),
                (429, "rate_limited"),
                (503, "unavailable"),
            ):
                payload = {"errorCode": "native-code", "errorMessage": "private-detail"}
                response = self.response(status, payload)
                response.headers = {"Retry-After": "120"}
                cause = requests.HTTPError(response=response)
                response.raise_for_status.side_effect = cause
                with (
                    self.subTest(stage=stage, status=status),
                    patch("requests.request", return_value=response),
                    self.assertRaises(AuthProviderError) as caught,
                ):
                    operation()
                error = caught.exception
                self.assertEqual(error.code, code)
                self.assertEqual(error.stage, stage)
                self.assertEqual(error.status_code, status)
                self.assertEqual(error.retry_after, "120")
                self.assertEqual(error.provider_code, "native-code")
                self.assertEqual(error.detail, "private-detail")
                self.assertIs(error.__cause__, cause)
                self.assertNotIn("private-detail", str(error))
                self.assertNotIn("native-code", str(error.public_metadata()))

    def test_line_http_errors_without_native_payload_preserve_generic_failure(self):
        backend = LineOAuth2(TestStrategy(TestStorage))
        payloads: tuple[object, ...] = (
            None,
            [],
            {"statusCode": 400},
            {"error": "server_error"},
        )
        for payload in payloads:
            response = self.response(503, payload)
            response.raise_for_status.side_effect = requests.HTTPError(
                response=response
            )
            with (
                self.subTest(payload=payload),
                patch("requests.request", return_value=response),
                self.assertRaises(AuthProviderError) as caught,
            ):
                backend.user_data("token")
            self.assertEqual(caught.exception.code, "unavailable")
            self.assertEqual(caught.exception.recovery, "retry_later")

    def test_native_token_errors_stop_login_before_pipeline(self):
        for backend_class, payload, code in (
            (LinkedinOAuth2, {"serviceErrorCode": 100, "status": 403}, "http_error"),
            (UntappdOAuth2, {"meta": {"http_code": 429}}, "rate_limited"),
            (UntappdOAuth2, {"meta": {"http_code": 503}}, "unavailable"),
        ):
            backend = backend_class(TestStrategy(TestStorage))
            with (
                self.subTest(backend=backend.name, code=code),
                patch.object(backend, "get_json", return_value=payload),
                self.assertRaises(AuthProviderError) as caught,
            ):
                backend.request_access_token("https://example.com/token")
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "token_exchange")

    def test_native_refresh_errors_preserve_refresh_stage(self):
        backend = LinkedinOAuth2(TestStrategy(TestStorage))
        response = self.response(200, {"serviceErrorCode": 100, "status": 403})
        with (
            patch.object(backend, "request", return_value=response),
            patch.object(backend, "refresh_token_params", return_value={}),
            self.assertRaises(AuthProviderError) as caught,
        ):
            backend.refresh_token("token")
        self.assertEqual(caught.exception.stage, "refresh")

    def test_weixin_native_errors_preserve_provider_code_and_operation(self):
        for backend_class in (WeixinOAuth2, WeixinOAuth2APP):
            backend = backend_class(TestStrategy(TestStorage))
            payload = {"errcode": 40030, "errmsg": "private token diagnostic"}
            for operation, stage in (
                (partial(backend.refresh_token, "token"), "refresh"),
                (backend.auth_complete, "token_exchange"),
                (
                    partial(backend.user_data, "token", response={"openid": "id"}),
                    "user_info",
                ),
            ):
                with (
                    self.subTest(backend=backend.name, stage=stage),
                    patch.object(backend, "validate_state", return_value="state"),
                    patch.object(backend, "get_json", return_value=payload),
                    patch.object(
                        backend, "request", return_value=self.response(200, payload)
                    ),
                    patch.object(backend.strategy, "authenticate") as authenticate,
                    self.assertRaises(AuthProviderError) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.provider_code, 40030)
                self.assertEqual(caught.exception.detail, "private token diagnostic")
                self.assertNotIn("private token diagnostic", str(caught.exception))
                authenticate.assert_not_called()

    def test_linkedin_native_status_controls_recovery_at_each_stage(self):
        backend = LinkedinOAuth2(TestStrategy(TestStorage))
        stages: tuple[ErrorStage, ...] = (
            "callback",
            "token_exchange",
            "user_info",
            "refresh",
        )
        for stage in stages:
            for status, code, recovery in (
                (403, "http_error", "contact_administrator"),
                (429, "rate_limited", "retry_later"),
                (503, "unavailable", "retry_later"),
                (None, "http_error", "contact_administrator"),
            ):
                with (
                    self.subTest(stage=stage, status=status),
                    self.assertRaises(AuthProviderError) as caught,
                ):
                    backend.process_error(
                        {
                            "serviceErrorCode": 100,
                            "status": status,
                            "message": "private diagnostic",
                        },
                        stage=stage,
                    )
                error = caught.exception
                self.assertEqual(error.code, code)
                self.assertEqual(error.recovery, recovery)
                self.assertEqual(error.stage, stage)
                self.assertEqual(error.status_code, status)
                self.assertEqual(error.provider_code, 100)
                self.assertEqual(error.detail, "private diagnostic")
                self.assertNotIn("private diagnostic", str(error))

    def test_untappd_profile_reports_retryable_native_status(self):
        backend = UntappdOAuth2(TestStrategy(TestStorage))
        for status, code in ((429, "rate_limited"), (503, "unavailable")):
            with (
                self.subTest(status=status),
                patch.object(
                    backend, "get_json", return_value={"meta": {"http_code": status}}
                ),
                self.assertRaises(AuthProviderError) as caught,
            ):
                backend.user_data("token")
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "user_info")
            self.assertEqual(caught.exception.recovery, "retry_later")

    def test_json_failure_and_http_failure_are_not_confused(self):
        response = self.response(200)
        response.raise_for_status.return_value = None
        with (
            patch("requests.request", return_value=response),
            self.assertRaises(AuthResponseError) as caught,
        ):
            self.backend.get_json("https://example.com", stage="token_validation")
        self.assertEqual(caught.exception.code, "malformed_response")

    def test_non_profile_requests_report_operation_stage(self):
        strategy = TestStrategy(TestStorage)
        strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )
        oauth1 = BaseOAuth1(strategy, redirect_uri="https://example.com/callback")
        oauth1.REQUEST_TOKEN_URL = "https://example.com/request-token"
        oauth1.ACCESS_TOKEN_URL = "https://example.com/access-token"
        oauth2 = BaseOAuth2(strategy)
        oauth2.REVOKE_TOKEN_URL = "https://example.com/revoke-token"
        token = {"oauth_token": "token", "oauth_token_secret": "token-secret"}
        for operation, stage in (
            (oauth1.unauthorized_token, "begin"),
            (partial(oauth1.access_token, token), "token_exchange"),
            (partial(oauth2.revoke_token, "token", "uid"), "disconnect"),
        ):
            response = self.response(503)
            response.raise_for_status.side_effect = requests.HTTPError(
                response=response
            )
            for cause in (requests.ConnectTimeout(), None):
                with (
                    self.subTest(stage=stage, cause=cause),
                    patch("requests.request", side_effect=cause, return_value=response),
                    self.assertRaises(AuthProviderError) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.recovery, "retry_later")

    def test_token_errors_precede_oidc_field_validation(self):
        backend = BaseOAuth2(TestStrategy(TestStorage))
        with (
            patch.object(backend, "get_json", return_value={"error": "invalid_client"}),
            self.assertRaises(AuthConfigurationError) as caught,
        ):
            backend.request_access_token("https://example.com/token")
        self.assertEqual(caught.exception.stage, "token_exchange")

    def test_jwt_types_supply_meaning_without_message_matching(self):
        for cause, code, claim in (
            (
                jwt.ExpiredSignatureError("different description"),
                "response_expired",
                "exp",
            ),
            (
                jwt.InvalidSignatureError("different description"),
                "invalid_signature",
                None,
            ),
            (jwt.InvalidAudienceError("different description"), "invalid_claim", "aud"),
            (jwt.MissingRequiredClaimError("sub"), "missing_claim", "sub"),
        ):
            with self.subTest(code=code):
                error = jwt_error(self.backend, cause)
                self.assertEqual(error.code, code)
                self.assertEqual(error.claim, claim)

    def test_profile_json_fallbacks_preserve_classified_failures(self):
        paths = (
            "social_core.backends.digitalocean.DigitalOceanOAuth",
            "social_core.backends.clever.CleverOAuth2",
            "social_core.backends.trello.TrelloOAuth",
            "social_core.backends.classlink.ClasslinkOAuth",
            "social_core.backends.uffd.UffdOAuth2",
            "social_core.backends.cilogon.CILogonOAuth2",
            "social_core.backends.taobao.TAOBAOAuth",
            "social_core.backends.salesforce.SalesforceOAuth2",
        )
        for path in paths:
            backend = module_member(path)(TestStrategy(TestStorage))
            for family, code in (
                (AuthProviderError, "unavailable"),
                (AuthResponseError, "invalid_claim"),
                (AuthConfigurationError, "invalid_setting"),
            ):
                cause = family(backend, code=code, stage="user_info")
                with (
                    self.subTest(path=path, code=code),
                    patch.object(backend, "get_json", side_effect=cause),
                    patch.object(backend, "oauth_auth", return_value=None, create=True),
                    self.assertRaises(family) as caught,
                ):
                    backend.user_data(
                        "foobar", response={"id": "https://example.com/userinfo"}
                    )
                self.assertIs(caught.exception, cause)

    def test_salesforce_unavailable_profile_never_enters_pipeline(self):
        backend = module_member("social_core.backends.salesforce.SalesforceOAuth2")(
            TestStrategy(TestStorage)
        )
        response = self.response(503)
        response.raise_for_status.side_effect = requests.HTTPError(response=response)
        with (
            patch("requests.request", return_value=response),
            patch.object(backend.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthProviderError) as caught,
        ):
            backend.do_auth("foobar", response={"id": "https://example.com/userinfo"})
        self.assertEqual(caught.exception.code, "unavailable")
        self.assertEqual(caught.exception.recovery, "retry_later")
        authenticate.assert_not_called()

    def test_vk_refresh_invalid_grant_is_not_a_login_code_rejection(self):
        for status in (200, 400):
            backend = module_member("social_core.backends.vk.VKIDOAuth2")(
                TestStrategy(TestStorage)
            )
            response = self.response(status, {"error": "invalid_grant"})
            if status != 200:
                response.raise_for_status.side_effect = requests.HTTPError(
                    response=response
                )
            with (
                self.subTest(status=status),
                patch("requests.request", return_value=response),
                self.assertRaises(AuthCredentialError) as caught,
            ):
                backend.refresh_token("refresh", device_id="device")
            self.assertEqual(caught.exception.stage, "refresh")
            self.assertEqual(caught.exception.code, "reauthentication_required")
            self.assertEqual(caught.exception.recovery, "reauthenticate")

    def test_vk_refresh_invalid_state_and_missing_tokens_preserve_operation_stage(self):
        backend = VKIDOAuth2(TestStrategy(TestStorage))
        backend.data = {"state": "expected", "device_id": "device"}
        for operation, stage in (
            (
                partial(backend.request_access_token, "https://example.com/token"),
                "token_exchange",
            ),
            (partial(backend.refresh_token, "refresh", device_id="device"), "refresh"),
        ):
            for payload, family, code in (
                ({"state": "expected"}, AuthResponseError, "missing_claim"),
                (
                    {"state": "expected", "access_token": None},
                    AuthResponseError,
                    "missing_claim",
                ),
                (
                    {"state": "expected", "access_token": ""},
                    AuthResponseError,
                    "missing_claim",
                ),
                (
                    {"state": "other", "access_token": "token"},
                    AuthSessionError,
                    "state_mismatch",
                ),
                ({"access_token": "token"}, AuthSessionError, "state_mismatch"),
            ):
                with (
                    self.subTest(stage=stage, payload=payload),
                    patch.object(backend, "state_token", return_value="expected"),
                    patch.object(backend, "get_json", return_value=payload),
                    self.assertRaises(family) as caught,
                ):
                    operation()
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.stage, stage)
                if code == "missing_claim":
                    self.assertEqual(caught.exception.claim, "access_token")

    def test_vk_native_profile_failures_preserve_codes_and_recovery(self):
        backend = VKOAuth2(TestStrategy(TestStorage))
        for provider_code, family, code, recovery in (
            (5, AuthCredentialError, "token_revoked", "reauthenticate"),
            (6, AuthProviderError, "rate_limited", "retry_later"),
            (9, AuthProviderError, "rate_limited", "retry_later"),
            (29, AuthProviderError, "rate_limited", "retry_later"),
            (10, AuthProviderError, "unavailable", "retry_later"),
            (43, AuthProviderError, "unavailable", "retry_later"),
            (36, AuthProviderError, "timeout", "retry_later"),
            (100, AuthProviderError, "http_error", "contact_administrator"),
            (999, AuthProviderError, "http_error", "contact_administrator"),
        ):
            payload = {
                "error": {
                    "error_code": provider_code,
                    "error_msg": "private diagnostic",
                }
            }
            response = self.response(200, payload)
            with (
                self.subTest(provider_code=provider_code),
                patch("requests.request", return_value=response),
                patch.object(backend.strategy, "authenticate") as authenticate,
                self.assertRaises(family) as caught,
            ):
                backend.do_auth("token")
            error = caught.exception
            self.assertEqual(error.code, code)
            self.assertEqual(error.provider_code, provider_code)
            self.assertEqual(error.stage, "user_info")
            self.assertEqual(error.recovery, recovery)
            self.assertEqual(error.detail, "private diagnostic")
            self.assertNotIn("private diagnostic", str(error))
            authenticate.assert_not_called()
