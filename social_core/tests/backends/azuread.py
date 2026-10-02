"""Shared Azure OAuth regression assertions."""

from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING, cast
from urllib.parse import parse_qs, urlsplit

import responses

from social_core.exceptions import AuthConfigurationError

if TYPE_CHECKING:
    from social_core.backends.azuread import AzureADOAuth2

    from .oauth import OAuth2Test


class AzureOAuth2TestMixin:
    def test_invalid_authority_url(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        for authority in (
            "",
            42,
            "http://login.example.com/common",
            "/common",
            "https://login.example.com",
            "https://user:secret@login.example.com/common",
            "https://@login.example.com/common",
            "https://login.example.com/common?query",
            "https://login.example.com/common#fragment",
            "https://login.example.com:invalid/common",
            "https://[invalid/common",
            "https://login.example.com/co mmon",
        ):
            with case.subTest(authority=authority):
                case.strategy.set_settings(
                    {f"SOCIAL_AUTH_{case.name}_AUTHORITY_URL": authority}
                )
                for operation, stage in (
                    (case.backend.authorization_url, "begin"),
                    (case.backend.access_token_url, "token_exchange"),
                    (case.backend.refresh_token_url, "refresh"),
                    (case.backend.openid_configuration_url, "token_validation"),
                ):
                    with (
                        case.subTest(stage=stage),
                        case.assertRaises(AuthConfigurationError) as caught,
                    ):
                        operation()
                    case.assertEqual(caught.exception.stage, stage)
                    case.assertEqual(caught.exception.parameter, "AUTHORITY_URL")
                    case.assertEqual(caught.exception.source, "configuration")

    def test_authority_host_fallback(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        original_base = case.backend.base_url
        original_host = case.backend.authority_host
        case.strategy.set_settings(
            {f"SOCIAL_AUTH_{case.name}_AUTHORITY_HOST": "login.example.com"}
        )
        case.assertEqual(
            case.backend.base_url,
            original_base.replace(original_host, "login.example.com"),
        )

    def test_login_with_pkce(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        case.strategy.set_settings({f"SOCIAL_AUTH_{case.name}_USE_PKCE": True})
        case.do_login()
        auth_request = next(
            call.request
            for call in responses.calls
            if cast("str", call.request.url).startswith(
                case.backend.authorization_url()
            )
        )
        token_request = next(
            call.request
            for call in responses.calls
            if call.request.url == case.backend.access_token_url()
        )
        query = parse_qs(urlsplit(cast("str", auth_request.url)).query)
        body = parse_qs(cast("str", token_request.body))
        verifier = body["code_verifier"][0]
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        case.assertEqual(query["code_challenge_method"], ["S256"])
        case.assertEqual(query["code_challenge"], [challenge])

    def test_partial_pipeline_with_pkce(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        case.strategy.set_settings({f"SOCIAL_AUTH_{case.name}_USE_PKCE": True})
        case.do_partial_pipeline()

    def test_authority_url_controls_all_endpoints(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        original_base = case.backend.base_url
        endpoints = (
            case.backend.authorization_url(),
            case.backend.access_token_url(),
            case.backend.refresh_token_url(),
            case.backend.openid_configuration_url(),
        )
        for path in (
            "organizations",
            "consumers",
            "00000000-0000-0000-0000-000000000000",
            "tenant.onmicrosoft.com",
        ):
            with case.subTest(path=path):
                authority = f"https://login.example.com/{path}"
                case.strategy.set_settings(
                    {f"SOCIAL_AUTH_{case.name}_AUTHORITY_URL": authority + "/"}
                )
                case.assertEqual(case.backend.base_url, authority)
                case.assertEqual(
                    (
                        case.backend.authorization_url(),
                        case.backend.access_token_url(),
                        case.backend.refresh_token_url(),
                        case.backend.openid_configuration_url(),
                    ),
                    tuple(url.replace(original_base, authority) for url in endpoints),
                )

    def test_explicit_endpoint_overrides_with_authority(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        case.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{case.name}_AUTHORITY_URL": "https://login.example.com/organizations",
                f"SOCIAL_AUTH_{case.name}_AUTHORIZATION_URL": "https://override.example.com/authorize",
                f"SOCIAL_AUTH_{case.name}_ACCESS_TOKEN_URL": "https://override.example.com/token",
                f"SOCIAL_AUTH_{case.name}_OPENID_CONFIGURATION_URL": "https://override.example.com/discovery",
            }
        )
        case.assertEqual(
            case.backend.authorization_url(), "https://override.example.com/authorize"
        )
        case.assertEqual(
            case.backend.access_token_url(), "https://override.example.com/token"
        )
        case.assertEqual(
            case.backend.refresh_token_url(), "https://override.example.com/token"
        )
        case.assertEqual(
            case.backend.openid_configuration_url(),
            "https://override.example.com/discovery",
        )

    def test_login_with_authority_override(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        configuration = case.backend.openid_configuration()
        case.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{case.name}_AUTHORITY_URL": "https://login.example.com/organizations"
            }
        )
        responses.add(
            responses.GET, case.backend.openid_configuration_url(), json=configuration
        )
        case.do_login()

    def test_get_auth_token_uses_real_refresh_token(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        user = case.do_login()
        social = user.social_user
        social.extra_data["refresh_token"] = "real-refresh-token"
        social.extra_data["expires_on"] = 1
        # B2C stores the expiry under exp/expires_on; force all expiry paths.
        social.extra_data["auth_time"] = 1
        method = {"GET": responses.GET, "POST": responses.POST}[
            case.backend.REFRESH_TOKEN_METHOD
        ]
        responses.add(
            method, case.backend.refresh_token_url(), body=case.refresh_token_body
        )
        case.assertEqual(case.backend.get_auth_token(user.id), "foobar-new-token")
        body = parse_qs(cast("str", responses.calls[-1].request.body))
        case.assertEqual(body["refresh_token"], ["real-refresh-token"])
        case.assertEqual(social.extra_data["refresh_token"], "foobar-new-refresh-token")
        case.assertEqual(social.extra_data["access_token"], "foobar-new-token")
        case.assertFalse(social.access_token_expired())
        calls = len(responses.calls)
        case.assertEqual(case.backend.get_auth_token(user.id), "foobar-new-token")
        case.assertEqual(len(responses.calls), calls)

    def test_get_auth_token_without_refresh_token(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        user = case.do_login()
        social = user.social_user
        social.extra_data.pop("refresh_token", None)
        social.extra_data["expires_on"] = 1
        social.extra_data["auth_time"] = 1
        calls = len(responses.calls)
        case.assertEqual(case.backend.get_auth_token(user.id), social.access_token)
        case.assertEqual(len(responses.calls), calls)

    def test_get_auth_token_keeps_valid_token(self) -> None:
        case = cast("OAuth2Test[AzureADOAuth2]", self)
        user = case.do_login()
        user.social_user.extra_data["refresh_token"] = "real-refresh-token"
        calls = len(responses.calls)
        case.assertEqual(
            case.backend.get_auth_token(user.id), user.social_user.access_token
        )
        case.assertEqual(len(responses.calls), calls)
