from __future__ import annotations

import time
from typing import Generic, TypeVar, cast
from unittest.mock import patch
from urllib.parse import urlparse

import requests
import responses

from social_core.backends.oauth import BaseOAuth1, BaseOAuth2, OAuthAuth
from social_core.exceptions import (
    AuthConfigurationError,
    AuthInputError,
    AuthSessionError,
)
from social_core.tests.models import User
from social_core.utils import get_querystring, parse_qs, url_add_parameters

from .base import BaseBackendTest

OAuthBackendT = TypeVar("OAuthBackendT", bound=OAuthAuth)


class BaseOAuthTest(BaseBackendTest[OAuthBackendT], Generic[OAuthBackendT]):
    user_data_body: str | None = None
    user_data_url: str = ""
    user_data_url_post: bool = False
    user_data_content_type: str = "application/json"
    access_token_body: str | None = None
    access_token_status: int = 200

    def extra_settings(self) -> dict[str, str | list[str]]:
        assert self.name, "Subclasses must set the name attribute"
        return {
            f"SOCIAL_AUTH_{self.name}_KEY": "a-key",
            f"SOCIAL_AUTH_{self.name}_SECRET": "a-secret-key",
        }

    def _method(self, method):
        return {"GET": responses.GET, "POST": responses.POST}[method]

    def handle_state(self, start_url: str, target_url: str) -> str:
        start_query = parse_qs(urlparse(start_url).query)
        redirect_uri = start_query.get("redirect_uri")

        if getattr(self.backend, "STATE_PARAMETER", False) and start_query.get("state"):
            target_url = url_add_parameters(target_url, {"state": start_query["state"]})

        if redirect_uri and getattr(self.backend, "REDIRECT_STATE", False):
            redirect_query = parse_qs(urlparse(redirect_uri).query)
            if redirect_query.get("redirect_state"):
                target_url = url_add_parameters(
                    target_url, {"redirect_state": redirect_query["redirect_state"]}
                )
        return target_url

    def auth_handlers(self, start_url: str) -> str:
        target_url = self.handle_state(
            start_url, self.strategy.build_absolute_uri(self.complete_url)
        )
        responses.add(
            responses.GET,
            start_url,
            status=301,
            headers={"Location": target_url},
        )
        responses.add(responses.GET, target_url, status=200, body="foobar")
        if self.user_data_url:
            responses.add(
                responses.POST if self.user_data_url_post else responses.GET,
                self.user_data_url,
                body=self.user_data_body or "",
                content_type=self.user_data_content_type,
            )
        return target_url

    def pre_complete_callback(self, start_url) -> None:
        responses.add(
            self._method(self.backend.ACCESS_TOKEN_METHOD),
            url=self.backend.access_token_url(),
            status=self.access_token_status,
            body=self.access_token_body or "",
            content_type="application/json",
        )

    def do_start(self):
        start_url = self.backend.start().url
        target_url = self.auth_handlers(start_url)
        response = requests.get(start_url, timeout=1)
        self.assertEqual(response.url, target_url)
        self.assertEqual(response.text, "foobar")
        self.strategy.set_request_data(
            parse_qs(urlparse(start_url).query), self.backend
        )
        self.strategy.set_request_data(
            parse_qs(urlparse(target_url).query), self.backend
        )
        self.pre_complete_callback(start_url)
        return self.backend.complete()


BaseOAuth1BackendT = TypeVar("BaseOAuth1BackendT", bound=BaseOAuth1)


class OAuth1Test(BaseOAuthTest[BaseOAuth1BackendT], Generic[BaseOAuth1BackendT]):
    request_token_body: str
    raw_complete_url = "/complete/{0}/?oauth_verifier=bazqux&oauth_token=foobar"

    def request_token_handler(self) -> None:
        assert self.request_token_body, "Subclasses must set request_token_body"
        responses.add(
            self._method(self.backend.REQUEST_TOKEN_METHOD),
            self.backend.REQUEST_TOKEN_URL,
            body=self.request_token_body,
            status=200,
        )

    def do_start(self):
        self.request_token_handler()
        return super().do_start()


BaseOAuth2BackendT = TypeVar("BaseOAuth2BackendT", bound=BaseOAuth2)


class OAuth2Test(BaseOAuthTest[BaseOAuth2BackendT], Generic[BaseOAuth2BackendT]):
    raw_complete_url = "/complete/{0}/?code=foobar"
    refresh_token_body = ""

    def refresh_token_arguments(self):
        return {}

    def do_refresh_token(self):
        self.do_login()
        responses.add(
            self._method(self.backend.REFRESH_TOKEN_METHOD),
            self.backend.refresh_token_url(),
            status=200,
            body=self.refresh_token_body,
        )
        user = next(iter(User.cache.values()))
        social = user.social[0]
        social.refresh_token(strategy=self.strategy, **self.refresh_token_arguments())
        return user, social


class OAuth2StateTestMixin(Generic[BaseOAuth2BackendT]):
    backend: BaseOAuth2BackendT

    def test_abandoned_transaction_is_pruned_on_next_start(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        now = int(time.time())
        with patch("social_core.backends.oauth.time.time", return_value=now):
            old_state = get_querystring(case.backend.start().url)["state"]
        with patch("social_core.backends.oauth.time.time", return_value=now + 1801):
            new_state = get_querystring(case.backend.start().url)["state"]

        case.assertIsNone(
            case.strategy.session_get(case.backend.transaction_key(old_state))
        )
        case.assertIsNotNone(
            case.strategy.session_get(case.backend.transaction_key(new_state))
        )
        case.assertEqual(
            case.strategy.session_get(f"{case.backend.name}_oauth2_transaction_index"),
            {new_state: now + 1801},
        )

    def test_state_collision_retries_without_replacing_first_transaction(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        now = int(time.time())
        with patch.object(
            case.backend,
            "state_token",
            side_effect=["first-state", "first-state", "second-state"],
        ):
            with patch("social_core.backends.oauth.time.time", return_value=now - 1):
                first = get_querystring(case.backend.start().url)["state"]
            with patch("social_core.backends.oauth.time.time", return_value=now):
                second = get_querystring(case.backend.start().url)["state"]

        case.assertEqual((first, second), ("first-state", "second-state"))
        for state in (first, second):
            transaction = case.strategy.session_get(case.backend.transaction_key(state))
            assert isinstance(transaction, dict)
            case.assertEqual(transaction["state"], state)
            case.strategy.set_request_data(
                {"code": "foobar", "state": state}, case.backend
            )
            case.assertEqual(case.backend.validate_state(), state)
        case.assertEqual(len(responses.calls), 0)

    def test_state_collision_exhaustion_preserves_first_transaction(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        with patch.object(case.backend, "state_token", return_value="same-state"):
            state = get_querystring(case.backend.start().url)["state"]
            with case.assertRaises(AuthSessionError):
                case.backend.start()
        case.strategy.set_request_data({"code": "foobar", "state": state}, case.backend)
        case.assertEqual(case.backend.validate_state(), state)
        case.assertEqual(len(responses.calls), 0)

    def test_concurrent_states_complete_in_either_order(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        states = [
            get_querystring(case.backend.start().url).get("state") for _ in range(2)
        ]
        case.assertIsNotNone(states[0])
        case.assertIsNotNone(states[1])
        case.assertNotEqual(*states)
        for state in reversed(states):
            case.strategy.set_request_data(
                {"code": "foobar", "state": state}, case.backend
            )
            case.assertEqual(case.backend.validate_state(), state)
        case.assertIsNone(
            case.strategy.session_get(f"{case.backend.name}_oauth2_transaction_index")
        )
        case.assertEqual(len(responses.calls), 0)

    def test_state_replay_and_foreign_session_rejected(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        state = get_querystring(case.backend.start().url)["state"]
        foreign = case.strategy.new_request()
        foreign.session_pop(case.backend.transaction_key(state))
        foreign_backend = type(case.backend)(foreign, redirect_uri=case.complete_url)
        foreign.set_request_data({"code": "foobar", "state": state}, foreign_backend)
        with case.assertRaises(AuthSessionError):
            foreign_backend.validate_state()
        case.assertIsNotNone(
            case.strategy.session_get(case.backend.transaction_key(state))
        )

        case.strategy.set_request_data({"code": "foobar", "state": state}, case.backend)
        case.assertEqual(case.backend.validate_state(), state)
        with case.assertRaises(AuthSessionError):
            case.backend.validate_state()
        case.assertEqual(len(responses.calls), 0)

    def test_two_requests_with_same_session_snapshot_cannot_both_claim(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        state = get_querystring(case.backend.start().url)["state"]
        first_strategy = case.strategy.new_request()
        second_strategy = case.strategy.new_request()
        first = type(case.backend)(first_strategy, redirect_uri=case.complete_url)
        second = type(case.backend)(second_strategy, redirect_uri=case.complete_url)
        for strategy, backend in ((first_strategy, first), (second_strategy, second)):
            strategy.set_request_data({"code": "foobar", "state": state}, backend)
        case.assertEqual(first.validate_state(), state)
        with case.assertRaises(AuthSessionError):
            second.validate_state()
        case.assertEqual(len(responses.calls), 0)

    def test_expired_state_rejected(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        state = get_querystring(case.backend.start().url)["state"]
        transaction = case.strategy.session_get(case.backend.transaction_key(state))
        assert isinstance(transaction, dict)
        timestamp = transaction["timestamp"]
        case.strategy.set_request_data({"code": "foobar", "state": state}, case.backend)
        with (
            patch(
                "social_core.backends.oauth.time.time", return_value=timestamp + 1801
            ),
            case.assertRaises(AuthSessionError),
        ):
            case.backend.validate_state()
        case.assertIsNotNone(
            case.strategy.session_get(case.backend.transaction_key(state))
        )
        case.assertEqual(case.backend.validate_state(), state)
        case.assertEqual(len(responses.calls), 0)

    def test_legacy_state_requires_restart(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        case.strategy.session_set(f"{case.backend.name}_state", "old-state")
        case.strategy.set_request_data(
            {"code": "foobar", "state": "old-state"}, case.backend
        )
        with case.assertRaises(AuthSessionError):
            case.backend.validate_state()

    def test_missing_atomic_storage_contract_fails_closed(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        state = get_querystring(case.backend.start().url)["state"]
        case.strategy.set_request_data({"code": "foobar", "state": state}, case.backend)
        with (
            patch.object(
                case.strategy.storage.nonce, "consume", side_effect=NotImplementedError
            ),
            case.assertRaises(AuthConfigurationError),
        ):
            case.backend.validate_state()
        case.assertEqual(len(responses.calls), 0)

    def test_auth_url_contains_state_parameter(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        start_url = case.backend.start().url
        state = get_querystring(start_url)["state"]
        transaction = case.strategy.session_get(case.backend.transaction_key(state))
        assert isinstance(transaction, dict)
        case.assertEqual(
            state,
            transaction["state"],
        )

    def test_complete_rejects_missing_state_parameter(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        case.backend.start()
        case.strategy.set_request_data({"code": "foobar"}, case.backend)

        with case.assertRaises(AuthInputError):
            case.backend.complete()

    def test_complete_rejects_mismatched_state_parameter(self) -> None:
        case = cast("BaseBackendTest[BaseOAuth2BackendT]", self)
        case.backend.start()
        case.strategy.set_request_data(
            {"code": "foobar", "state": "invalid-state"}, case.backend
        )

        with case.assertRaises(AuthSessionError):
            case.backend.complete()


class OAuth2PkcePlainTest(OAuth2Test):
    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {f"SOCIAL_AUTH_{self.name}_PKCE_CODE_CHALLENGE_METHOD": "plain"}
        )
        return settings

    def do_login(self):
        user = super().do_login()

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
        self.assertEqual(code_challenge_method, "plain")

        auth_complete = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )
        code_verifier = parse_qs(auth_complete.body).get("code_verifier")
        self.assertEqual(code_challenge, code_verifier)

        return user


class OAuth2PkceS256Test(OAuth2Test):
    def do_login(self):
        # use default value of PKCE_CODE_CHALLENGE_METHOD (s256)
        user = super().do_login()

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
        self.assertIn(code_challenge_method, ["s256", "S256"])

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

        return user


class BaseAuthUrlTestMixin(Generic[OAuthBackendT]):
    backend: OAuthBackendT

    def check_parameters_in_authorization_url(
        self, auth_url_key="AUTHORIZATION_URL"
    ) -> None:
        """
        Check the parameters in authorization url

        When inserting parameters directly into AUTHORIZATION_URL, we expect the
        other parameters to be added to the end of the url
        """
        original_url = (
            self.backend.AUTHORIZATION_URL or self.backend.authorization_url()
        )
        with (
            patch.object(
                self.backend,
                "authorization_url",
                return_value=f"{original_url}?param1=value1&param2=value2",
            ),
            patch.object(
                self.backend,
                auth_url_key,
                f"{original_url}?param1=value1&param2=value2",
            ),
        ):
            # we expect an & symbol to join the different parameters
            assert "?param1=value1&param2=value2&" in self.backend.auth_url()

    def test_auth_url_parameters(self) -> None:
        self.check_parameters_in_authorization_url()


class OAuth1AuthUrlTestMixin(BaseAuthUrlTestMixin):
    def request_token_handler(self) -> None:
        raise NotImplementedError

    def test_auth_url_parameters(self) -> None:
        self.request_token_handler()
        self.check_parameters_in_authorization_url()
