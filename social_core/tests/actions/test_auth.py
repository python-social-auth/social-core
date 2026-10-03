import unittest
from unittest.mock import patch

from social_core.actions import do_auth
from social_core.backends.base import BaseAuth
from social_core.tests.models import TestStorage, User
from social_core.tests.strategy import TestStrategy


class InitiationBackend(BaseAuth):
    name = "initiation"

    def auth_url(self) -> str:
        return "/auth"


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
