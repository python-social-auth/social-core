"""Reject protocol errors and unusable tokens before consuming credentials."""

from __future__ import annotations

import unittest
from functools import partial
from unittest.mock import Mock, patch

import jwt
import requests

from social_core.backends.azuread import AzureADOAuth2
from social_core.backends.azuread_b2c import AzureADB2COAuth2
from social_core.backends.bungie import BungieOAuth2
from social_core.backends.deezer import DeezerOAuth2
from social_core.backends.evernote import EvernoteOAuth
from social_core.backends.justgiving import JustGivingOAuth2
from social_core.backends.line import LineOAuth2
from social_core.backends.mediawiki import MediaWiki
from social_core.backends.microsoft import MicrosoftOAuth2
from social_core.backends.oauth import BaseOAuth1, BaseOAuth2
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.backends.qiita import QiitaOAuth2
from social_core.backends.qq import QQOAuth2
from social_core.backends.stackoverflow import StackoverflowOAuth2
from social_core.backends.untappd import UntappdOAuth2
from social_core.backends.vk import VKIDOAuth2
from social_core.backends.weixin import WeixinOAuth2
from social_core.backends.yahoo import YahooOAuth2
from social_core.exceptions import (
    AuthCanceled,
    AuthCredentialError,
    AuthProviderError,
    AuthResponseError,
    ErrorStage,
)
from social_core.tests.backends.test_azuread_b2c import RSA_PRIVATE_JWT_KEY
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy
from social_core.utils import module_member


class TokenResponseErrorTest(unittest.TestCase):
    def setUp(self):
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_KEY": "key", "SOCIAL_AUTH_SECRET": "secret"}
        )

    def test_azure_discovery_rejects_non_objects_before_caching(self):
        for backend_class in (AzureADOAuth2, AzureADB2COAuth2):
            backend = backend_class(self.strategy)
            for index, payload in enumerate((None, [], ["issuer"], "issuer", 1, False)):
                url = f"https://example.com/discovery-shape/{backend.name}/{index}"
                valid = {
                    "issuer": "https://example.com",
                    "jwks_uri": "https://example.com/keys",
                }
                # The cache decorator attaches invalidate dynamically.
                invalidate = getattr(backend.get_openid_configuration, "invalidate")
                invalidate(backend, url)
                with (
                    self.subTest(backend=backend.name, payload=payload),
                    patch.object(backend, "openid_configuration_url", return_value=url),
                    patch.object(
                        backend, "get_json", side_effect=[payload, valid]
                    ) as get_json,
                ):
                    with self.assertRaises(AuthResponseError) as caught:
                        backend.jwks_uri()
                    self.assertEqual(caught.exception.code, "malformed_response")
                    self.assertEqual(caught.exception.stage, "token_validation")
                    self.assertEqual(caught.exception.source, "provider_response")
                    self.assertEqual(backend.jwks_uri(), valid["jwks_uri"])
                    self.assertEqual(backend.get_id_token_issuer({}), valid["issuer"])
                    self.assertEqual(get_json.call_count, 2)
                    get_json.assert_called_with(url, stage="token_validation")
                invalidate(backend, url)

    def test_oauth1_access_token_credentials_rejected_before_profile(self):
        backend = BaseOAuth1(self.strategy)
        token = {"oauth_token": "request-token", "oauth_token_secret": "request-secret"}
        values: tuple[object, ...] = (None, "", 0, [], {})
        for claim in ("oauth_token", "oauth_token_secret"):
            for value in values:
                response: dict = {
                    "oauth_token": "token",
                    "oauth_token_secret": "secret",
                }
                if value is None:
                    response.pop(claim)
                else:
                    response[claim] = value
                with (
                    self.subTest(claim=claim, value=value),
                    patch.object(backend, "get_querystring", return_value=response),
                    patch.object(backend, "user_data") as profile,
                    patch.object(self.strategy, "authenticate") as authenticate,
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    backend.do_auth(backend.access_token(token))
                self.assertEqual(caught.exception.code, "missing_claim")
                self.assertEqual(caught.exception.claim, claim)
                self.assertEqual(caught.exception.stage, "token_exchange")
                self.assertEqual(caught.exception.source, "provider_response")
                profile.assert_not_called()
                authenticate.assert_not_called()

    def test_oauth1_missing_credentials_report_exchange_and_profile_stages(self):
        methods = [
            (backend.access_token, "token_exchange")
            for backend in (
                BaseOAuth1(self.strategy),
                EvernoteOAuth(self.strategy),
                MediaWiki(self.strategy),
            )
        ]
        for path in (
            "google.GoogleOAuth",
            "fitbit.FitbitOAuth1",
            "upwork.UpworkOAuth",
            "twitter.TwitterOAuth",
            "tumblr.TumblrOAuth",
            "trello.TrelloOAuth",
            "discogs.DiscogsOAuth1",
            "vimeo.VimeoOAuth1",
            "tripit.TripItOAuth",
            "xing.XingOAuth",
        ):
            backend = module_member(f"social_core.backends.{path}")(self.strategy)
            methods.append((backend.user_data, "user_info"))
        for operation, stage in methods:
            for token, claim in (
                ({"oauth_token_secret": "secret"}, "oauth_token"),
                ({"oauth_token": "token"}, "oauth_token_secret"),
            ):
                with (
                    self.subTest(operation=operation, token=token),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    operation(token)
                self.assertEqual(caught.exception.code, "missing_claim")
                self.assertEqual(caught.exception.stage, stage)
                self.assertEqual(caught.exception.claim, claim)

    def test_oauth2_completion_calls_hook_once_per_response(self):
        hook = Mock()

        def process_error(data, *, stage="callback"):
            hook(data, stage=stage)

        for backend_class in (
            BaseOAuth2,
            BungieOAuth2,
            JustGivingOAuth2,
            LineOAuth2,
            MicrosoftOAuth2,
            UntappdOAuth2,
            WeixinOAuth2,
            YahooOAuth2,
        ):
            backend = backend_class(self.strategy)
            backend.data = {"code": "authorization-code"}
            payload: dict[str, object] = {"access_token": "access-token"}
            if isinstance(backend, UntappdOAuth2):
                payload = {"response": payload}
            hook.reset_mock()
            with (
                self.subTest(backend=backend.name),
                patch.object(backend, "process_error", new=process_error),
                patch.object(backend, "validate_state", return_value="state"),
                patch.object(backend, "auth_complete_params", return_value={}),
                patch.object(backend, "get_json", return_value=payload),
                patch.object(backend, "do_auth", return_value="user"),
            ):
                self.assertEqual(backend.auth_complete(), "user")
            self.assertEqual(hook.call_count, 2)
            self.assertEqual(hook.call_args_list[0].args, (backend.data,))
            hook.assert_called_with(payload, stage="token_exchange")

    def test_vk_id_token_checks_do_not_repeat_hook(self):
        backend = VKIDOAuth2(self.strategy, redirect_uri="https://example.com/callback")
        backend.data = {"state": "state", "device_id": "device"}
        payload = {"state": "state", "access_token": "access-token"}
        hook = Mock()

        def process_error(data, *, stage="callback"):
            hook(data, stage=stage)

        with (
            patch.object(backend, "process_error", new=process_error),
            patch.object(backend, "get_json", return_value=payload),
            patch.object(backend, "state_token", return_value="state"),
        ):
            backend.request_access_token("https://example.com/token")
            hook.assert_called_once_with(payload, stage="token_exchange")
            hook.reset_mock()
            backend.refresh_token("refresh-token", device_id="device")
            hook.assert_called_once_with(payload, stage="refresh")

    def test_custom_token_parsers_classify_errors_at_active_stage(self):
        stages: tuple[ErrorStage, ...] = ("token_exchange", "refresh")
        for backend_class in (DeezerOAuth2, QQOAuth2, StackoverflowOAuth2):
            backend = backend_class(self.strategy)
            for stage in stages:
                for provider_code, family, code in (
                    ("access_denied", AuthCanceled, "authorization_declined"),
                    (
                        "invalid_grant",
                        AuthCredentialError,
                        "reauthentication_required"
                        if stage == "refresh"
                        else "authorization_code_rejected",
                    ),
                    ("unknown_failure", AuthProviderError, "http_error"),
                ):
                    response = Mock(
                        spec=requests.Response,
                        status_code=200,
                        text=f"error={provider_code}",
                        content=f"error={provider_code}".encode(),
                    )
                    with (
                        self.subTest(
                            backend=backend.name,
                            stage=stage,
                            provider_code=provider_code,
                        ),
                        patch.object(backend, "request", return_value=response),
                        self.assertRaises(family) as caught,
                    ):
                        backend.request_access_token(
                            "https://example.com/token", stage=stage
                        )
                    self.assertEqual(caught.exception.code, code)
                    self.assertEqual(caught.exception.stage, stage)
                    self.assertEqual(caught.exception.provider_code, provider_code)

    def test_custom_token_parsers_call_hook_once_before_login(self):
        for backend_class in (DeezerOAuth2, QQOAuth2, StackoverflowOAuth2):
            backend = backend_class(self.strategy)
            backend.data = {"code": "authorization-code"}
            for content, family in (
                (b"access_token=token&expires=3600", None),
                (b"error=access_denied", AuthCanceled),
            ):
                response = Mock(
                    spec=requests.Response,
                    status_code=200,
                    content=content,
                    text=content.decode(),
                )
                with (
                    self.subTest(backend=backend.name, content=content),
                    patch.object(
                        backend, "process_error", wraps=backend.process_error
                    ) as hook,
                    patch.object(backend, "validate_state", return_value="state"),
                    patch.object(backend, "request", return_value=response),
                    patch.object(backend, "do_auth", return_value="user") as do_auth,
                ):
                    if family is None:
                        self.assertEqual(backend.auth_complete(), "user")
                        self.assertEqual(
                            hook.call_args.args,
                            ({"access_token": "token", "expires": "3600"},),
                        )
                        do_auth.assert_called_once_with(
                            "token",
                            response={"access_token": "token", "expires": "3600"},
                        )
                    else:
                        with self.assertRaises(family) as caught:
                            backend.auth_complete()
                        self.assertEqual(caught.exception.stage, "token_exchange")
                        self.assertEqual(caught.exception.recovery, "none")
                        do_auth.assert_not_called()
                    self.assertEqual(hook.call_count, 2)
                    self.assertEqual(hook.call_args.kwargs, {"stage": "token_exchange"})

    def test_provider_token_remapping_requires_usable_native_token(self):
        stages: tuple[ErrorStage, ...] = ("token_exchange", "refresh")
        invalid_values: tuple[object, ...] = (None, "", 42, [], {})
        for backend_class, claim in (
            (AzureADB2COAuth2, "id_token"),
            (QiitaOAuth2, "token"),
        ):
            backend = backend_class(self.strategy)
            for stage in stages:
                for payload in (
                    {},
                    *({claim: value} for value in invalid_values),
                ):
                    with (
                        self.subTest(
                            backend=backend.name, stage=stage, payload=payload
                        ),
                        patch.object(backend, "get_json", return_value=payload),
                        self.assertRaises(AuthResponseError) as caught,
                    ):
                        backend.request_access_token(
                            "https://example.com/token", stage=stage
                        )
                    self.assertEqual(caught.exception.code, "missing_claim")
                    self.assertEqual(caught.exception.claim, claim)
                    self.assertEqual(caught.exception.stage, stage)
                    self.assertEqual(caught.exception.source, "provider_response")
                    self.assertNotIn("access_token", payload)

    def test_provider_token_remapping_preserves_valid_response(self):
        for backend_class, payload, expected in (
            (AzureADB2COAuth2, {"id_token": "id-token"}, "id-token"),
            (AzureADB2COAuth2, {"access_token": "access-token"}, "access-token"),
            (QiitaOAuth2, {"token": "access-token"}, "access-token"),
        ):
            backend = backend_class(self.strategy)
            with (
                self.subTest(backend=backend.name, payload=payload),
                patch.object(backend, "get_json", return_value=payload),
            ):
                response = backend.request_access_token("https://example.com/token")
            self.assertIs(response, payload)
            self.assertEqual(response["access_token"], expected)

    def test_oidc_rejects_unusable_tokens_before_validation(self):
        backend = OpenIdConnectAuth(self.strategy)
        invalid_values: tuple[object, ...] = (None, "", 42, [], {})
        signed_token = jwt.encode(
            {
                "sub": "subject",
                "at_hash": backend.calc_at_hash("access-token", "RS256"),
            },
            key=jwt.PyJWK.from_dict(RSA_PRIVATE_JWT_KEY).key,
            algorithm="RS256",
        )
        for stage in ("token_validation", "refresh"):
            for claim in ("id_token", "access_token"):
                for value in invalid_values:
                    if stage == "refresh" and claim == "id_token" and value is None:
                        # Refresh responses may omit an ID token.
                        continue
                    payload = {
                        "id_token": signed_token,
                        "access_token": "access-token",
                        claim: value,
                    }
                    response = Mock(spec=requests.Response)
                    response.json.return_value = payload
                    backend.id_token = {"sub": "original-subject"}
                    with (
                        self.subTest(stage=stage, claim=claim, value=value),
                        patch.object(backend, "get_json", return_value=payload),
                        patch.object(backend, "decode_and_validate_id_token") as decode,
                        self.assertRaises(AuthResponseError) as caught,
                    ):
                        if stage == "refresh":
                            backend.process_refresh_token_response(response)
                        else:
                            backend.request_access_token("https://example.com/token")
                    self.assertEqual(caught.exception.code, "missing_claim")
                    self.assertEqual(caught.exception.claim, claim)
                    self.assertEqual(caught.exception.stage, stage)
                    self.assertEqual(caught.exception.source, "provider_response")
                    self.assertEqual(backend.id_token, {"sub": "original-subject"})
                    decode.assert_not_called()

    def test_custom_discovery_loaders_reject_non_objects(self):
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_API_URL": "https://example.com/oauth2",
                "SOCIAL_AUTH_KEY": "key",
            }
        )
        for path in (
            "fence.Fence",
            "okta.OktaOAuth2",
            "okta_openidconnect.OktaOpenIdConnect",
        ):
            backend = module_member(f"social_core.backends.{path}")(self.strategy)
            invalidate = getattr(backend.oidc_config, "invalidate", None)
            if invalidate is not None:
                invalidate(backend)
            with patch.object(
                backend, "get_json", side_effect=[[], {"issuer": "https://example.com"}]
            ) as get_json:
                with (
                    self.subTest(backend=backend.name),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    backend.oidc_config()
                self.assertEqual(caught.exception.code, "malformed_response")
                self.assertEqual(caught.exception.stage, "begin")
                self.assertEqual(
                    backend.oidc_config(), {"issuer": "https://example.com"}
                )
                self.assertEqual(get_json.call_count, 2)
            if invalidate is not None:
                invalidate(backend)

    def test_oauth1_token_errors_stop_before_session_or_profile_changes(self):
        for backend_class in (BaseOAuth1, EvernoteOAuth, MediaWiki):
            backend = backend_class(self.strategy)
            for stage in ("begin", "token_exchange"):
                for problem, family, code in (
                    ("user_refused", AuthCanceled, "authorization_declined"),
                    ("token_rejected", AuthProviderError, "http_error"),
                ):
                    response = Mock(
                        spec=requests.Response,
                        content=f"oauth_problem={problem}".encode(),
                        text=f"oauth_problem={problem}",
                        encoding="utf-8",
                    )
                    with (
                        self.subTest(
                            backend=backend.name, stage=stage, problem=problem
                        ),
                        patch.object(backend, "request", return_value=response),
                        patch.object(backend, "oauth_auth", return_value=None),
                        patch.object(backend, "user_data") as profile,
                        patch.object(self.strategy, "authenticate") as authenticate,
                        self.assertRaises(family) as caught,
                    ):
                        if stage == "begin":
                            backend.set_unauthorized_token()
                        else:
                            backend.do_auth(backend.access_token({}))
                    self.assertEqual(caught.exception.code, code)
                    self.assertEqual(caught.exception.provider_code, problem)
                    self.assertEqual(caught.exception.stage, stage)
                    self.assertEqual(
                        self.strategy.session_get(
                            backend.name + backend.UNATHORIZED_TOKEN_SUFIX, []
                        ),
                        [],
                    )
                    profile.assert_not_called()
                    authenticate.assert_not_called()

    def test_oauth1_malformed_request_tokens_stop_before_storage_and_redirect(self):
        for backend_class in (BaseOAuth1, EvernoteOAuth, MediaWiki):
            backend = backend_class(self.strategy)
            session_key = backend.name + backend.UNATHORIZED_TOKEN_SUFIX
            existing = ["oauth_token=previous&oauth_token_secret=secret"]
            self.strategy.session_set(session_key, existing)
            for content, claim in (
                ("", "oauth_token"),
                ("unexpected=value", "oauth_token"),
                ("oauth_token=token", "oauth_token_secret"),
                ("oauth_token_secret=secret", "oauth_token"),
                ("oauth_token=&oauth_token_secret=secret", "oauth_token"),
                ("oauth_token=token&oauth_token_secret=", "oauth_token_secret"),
            ):
                response = Mock(
                    spec=requests.Response,
                    content=content.encode(),
                    text=content,
                    encoding="utf-8",
                )
                with (
                    self.subTest(backend=backend.name, content=content),
                    patch.object(backend, "request", return_value=response),
                    patch.object(self.strategy, "redirect") as redirect,
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    backend.start()
                self.assertEqual(caught.exception.code, "missing_claim")
                self.assertEqual(caught.exception.claim, claim)
                self.assertEqual(caught.exception.stage, "begin")
                self.assertEqual(self.strategy.session_get(session_key), existing)
                redirect.assert_not_called()

    def test_oauth1_token_responses_call_legacy_error_hook(self):
        backend = BaseOAuth1(self.strategy)
        response = Mock(
            spec=requests.Response,
            content=b"oauth_token=token&oauth_token_secret=secret",
            text="oauth_token=token&oauth_token_secret=secret",
            encoding="utf-8",
        )
        token = {"oauth_token": "token", "oauth_token_secret": "secret"}
        payloads = []

        def legacy_hook(data):
            payloads.append(data)

        for stage, operation, expected in (
            ("begin", backend.set_unauthorized_token, response.text),
            ("token_exchange", partial(backend.access_token, token), token),
        ):
            payloads.clear()
            with (
                self.subTest(stage=stage),
                patch.object(backend, "request", return_value=response),
                patch.object(backend, "process_error", new=legacy_hook),
            ):
                self.assertEqual(operation(), expected)
            self.assertEqual(payloads, [token])
        self.assertEqual(
            self.strategy.session_get(backend.name + backend.UNATHORIZED_TOKEN_SUFIX),
            [response.text],
        )
