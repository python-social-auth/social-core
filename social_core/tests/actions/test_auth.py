from __future__ import annotations

import unittest
from typing import TYPE_CHECKING
from unittest.mock import patch

from social_core.actions import do_auth
from social_core.backends.base import BaseAuth
from social_core.tests.models import TestStorage, User
from social_core.tests.strategy import Redirect, TestStrategy

if TYPE_CHECKING:
    from typing import Never, assert_type

    from social_core.registry import REGISTRY
    from social_core.strategy import BaseStrategy


class InitiationBackend(BaseAuth[Redirect]):
    name = "initiation"

    def auth_url(self) -> str:
        return "/auth"


def accept_any_backend(backend: BaseAuth[object]) -> None:
    """Accept a backend of any response type."""


class AuthActionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.backend = InitiationBackend(self.strategy)

    def test_supplied_user_is_passed_to_hook(self) -> None:
        user = User("existing")

        with patch.object(self.backend, "prepare_auth") as prepare_auth:
            response = do_auth(self.backend, user=user)

        prepare_auth.assert_called_once_with(user=user)
        self.assertIs(prepare_auth.call_args.kwargs["user"], user)
        self.assertEqual(response.url, "/auth")

    def test_omitted_user_calls_no_op_hook_and_starts(self) -> None:
        with patch.object(
            self.backend, "prepare_auth", wraps=self.backend.prepare_auth
        ) as prepare_auth:
            response = do_auth(self.backend)

        prepare_auth.assert_called_once_with(user=None)
        self.assertEqual(response.url, "/auth")

    def test_response_type_follows_strategy(self) -> None:
        response = do_auth(self.backend)

        if TYPE_CHECKING:
            # The strategy's response type flows through the backend.
            assert_type(self.backend.strategy.redirect("/auth"), Redirect)
            assert_type(self.backend.start(), Redirect)
            assert_type(response, Redirect)
            assert_type(self.strategy.get_backend("initiation"), BaseAuth[Redirect])
            # Backends are covariant, so BaseAuth[object] accepts any backend.
            accept_any_backend(self.backend)
            # The default strategy produces no responses, so it works for a
            # backend of any response type, even one pinned to a single type.
            assert_type(REGISTRY.default_strategy, BaseStrategy[Never])
            assert_type(InitiationBackend().start(), Redirect)
        self.assertIsInstance(response, Redirect)

    def test_hook_runs_after_session_handling_and_before_start(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_FIELDS_STORED_IN_SESSION": ["extra"]})
        self.strategy.set_request_data(
            {"extra": "value", "next": "/after-login"}, self.backend
        )
        calls = []

        def prepare_auth(*, user) -> None:
            self.assertIsNone(user)
            self.assertEqual(self.strategy.session_get("extra"), "value")
            self.assertEqual(self.strategy.session_get("next"), "/after-login")
            calls.append("prepare")

        def start():
            calls.append("start")
            return self.strategy.redirect("/auth")

        with (
            patch.object(self.backend, "prepare_auth", side_effect=prepare_auth),
            patch.object(self.backend, "start", side_effect=start),
        ):
            do_auth(self.backend)

        self.assertEqual(calls, ["prepare", "start"])

    def test_hook_exception_prevents_start(self) -> None:
        with (
            patch.object(
                self.backend, "prepare_auth", side_effect=ValueError("rejected")
            ),
            patch.object(self.backend, "start") as start,
            self.assertRaisesRegex(ValueError, "rejected"),
        ):
            do_auth(self.backend)

        start.assert_not_called()

    def test_redirect_name_remains_positional(self) -> None:
        self.strategy.set_request_data({"return_to": "/after-login"}, self.backend)

        response = do_auth(self.backend, "return_to")

        self.assertEqual(self.strategy.session_get("return_to"), "/after-login")
        self.assertEqual(response.url, "/auth")
