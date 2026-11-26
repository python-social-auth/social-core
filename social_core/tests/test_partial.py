from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock, patch

from social_core.backends.base import BaseAuth
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthSessionError
from social_core.pipeline.partial import partial, partial_step
from social_core.pipeline.utils import partial_store
from social_core.utils import (
    PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME,
    PARTIAL_TOKEN_SESSION_NAME,
    module_member,
    partial_pipeline_data,
)

from .models import TestPartial, TestStorage, User
from .strategy import TestStrategy

if TYPE_CHECKING:
    from typing import Never, assert_type

    from social_core.pipeline.partial import PartialStep
    from social_core.strategy import BaseStrategy


@dataclass
class HTMLResponse:
    """A framework response that, unlike a redirect, has no URL."""

    content: str


class PartialDecoratorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.mock_current_partial_token = Mock()
        self.mock_current_partial = Mock(token=self.mock_current_partial_token)
        self.mock_current_partial.data = {}

        self.mock_strategy = Mock()
        self.mock_strategy.request_data.return_value = {}
        self.mock_backend = Mock()
        self.mock_pipeline_index = Mock()
        self.mock_partial_store = Mock()
        self.mock_strategy.storage.partial.store = self.mock_partial_store

        self.mock_session_set = Mock()
        self.mock_strategy.session_set = self.mock_session_set

    def test_save_to_session(self) -> None:
        # GIVEN
        expected_response = Mock()

        @partial_step(save_to_session=True)
        def decorated_func(*args, **kwargs):
            return expected_response

        # WHEN
        with patch(
            "social_core.pipeline.partial.partial_prepare",
            return_value=self.mock_current_partial,
        ):
            response = decorated_func(
                self.mock_strategy, self.mock_backend, self.mock_pipeline_index
            )

            # THEN
            self.assertEqual(expected_response, response)

            self.assertEqual(1, self.mock_partial_store.call_count)
            self.assertEqual(
                (self.mock_current_partial,), self.mock_partial_store.call_args[0]
            )

            self.assertEqual(1, self.mock_session_set.call_count)
            self.assertEqual(
                (PARTIAL_TOKEN_SESSION_NAME, self.mock_current_partial_token),
                self.mock_session_set.call_args[0],
            )
            self.assertFalse(
                self.mock_current_partial.data[PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME]
            )

    def test_allow_external_resume(self) -> None:
        # GIVEN
        expected_response = Mock()

        @partial_step(save_to_session=True, allow_external_resume=True)
        def decorated_func(*args, **kwargs):
            return expected_response

        # WHEN
        with patch(
            "social_core.pipeline.partial.partial_prepare",
            return_value=self.mock_current_partial,
        ):
            response = decorated_func(
                self.mock_strategy, self.mock_backend, self.mock_pipeline_index
            )

            # THEN
            self.assertEqual(expected_response, response)
            self.assertTrue(
                self.mock_current_partial.data[PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME]
            )

    def test_not_to_save_to_session(self) -> None:
        # GIVEN
        expected_response = Mock()

        @partial_step(save_to_session=False)
        def decorated_func(*args, **kwargs):
            return expected_response

        # WHEN
        with patch(
            "social_core.pipeline.partial.partial_prepare",
            return_value=self.mock_current_partial,
        ):
            response = decorated_func(
                self.mock_strategy, self.mock_backend, self.mock_pipeline_index
            )

            # THEN
            self.assertEqual(expected_response, response)

            self.assertEqual(1, self.mock_partial_store.call_count)
            self.assertEqual(
                (self.mock_current_partial,), self.mock_partial_store.call_args[0]
            )

            self.assertEqual(0, self.mock_session_set.call_count)

    def test_save_to_session_by_backward_compatible_decorator(self) -> None:
        # GIVEN
        expected_response = Mock()

        @partial
        def decorated_func(*args, **kwargs):
            return expected_response

        # WHEN
        with patch(
            "social_core.pipeline.partial.partial_prepare",
            return_value=self.mock_current_partial,
        ):
            response = decorated_func(
                self.mock_strategy, self.mock_backend, self.mock_pipeline_index
            )

            # THEN
            self.assertEqual(expected_response, response)

            self.assertEqual(1, self.mock_partial_store.call_count)
            self.assertEqual(
                (self.mock_current_partial,), self.mock_partial_store.call_args[0]
            )

            self.assertEqual(1, self.mock_session_set.call_count)
            self.assertEqual(
                (PARTIAL_TOKEN_SESSION_NAME, self.mock_current_partial_token),
                self.mock_session_set.call_args[0],
            )

    def test_not_to_save_to_session_when_the_response_is_a_dict(self) -> None:
        # GIVEN
        expected_response = {"test_key": "test_value"}

        @partial_step(save_to_session=True)
        def decorated_func(*args, **kwargs):
            return expected_response

        # WHEN
        response = decorated_func(
            self.mock_strategy, self.mock_backend, self.mock_pipeline_index
        )

        # THEN
        self.assertEqual(expected_response, response)
        self.assertEqual(0, self.mock_partial_store.call_count)
        self.assertEqual(0, self.mock_session_set.call_count)

    def test_response_type_follows_strategy(self) -> None:
        # GIVEN
        expected_response = HTMLResponse("<form></form>")
        self.mock_strategy.html.return_value = expected_response

        # Type checkers verify that a step returning the strategy's response
        # type can be decorated, and that the wrapper preserves that type.
        @partial_step(save_to_session=False)
        def decorated_func(
            strategy: BaseStrategy[HTMLResponse], *args: object, **kwargs: object
        ) -> HTMLResponse | dict[str, Any]:
            return strategy.html("<form></form>")

        # WHEN
        with patch(
            "social_core.pipeline.partial.partial_prepare",
            return_value=self.mock_current_partial,
        ):
            response = decorated_func(
                self.mock_strategy, self.mock_backend, self.mock_pipeline_index
            )

        if TYPE_CHECKING:
            assert_type(decorated_func, PartialStep[HTMLResponse])
            assert_type(response, dict[str, Any] | HTMLResponse)

        # THEN
        self.assertIs(expected_response, response)
        self.assertEqual(1, self.mock_partial_store.call_count)

    def test_response_free_step_returns_dict(self) -> None:
        # GIVEN
        expected_response = {"test_key": "test_value"}

        # Without a response type to infer, the wrapper still returns a dict.
        @partial_step(save_to_session=False)
        def decorated_func(*args: object, **kwargs: object) -> dict[str, Any] | None:
            return expected_response

        # WHEN
        response = decorated_func(
            self.mock_strategy, self.mock_backend, self.mock_pipeline_index
        )

        if TYPE_CHECKING:
            assert_type(decorated_func, PartialStep[Never])
            assert_type(response, dict[str, Any])

        # THEN
        self.assertEqual(expected_response, response)
        self.assertEqual(0, self.mock_partial_store.call_count)


class PartialResumeNewResponseTestCase(unittest.TestCase):
    def test_new_response_does_not_resume_paused_pipeline(self) -> None:
        # Most callbacks do not carry the ID_KEY, so the backend has to
        # recognize its own provider response. Each case is the session of the
        # pending request, if the protocol keeps one, and the callback.
        cases: tuple[tuple[str, dict[str, Any], dict[str, str]], ...] = (
            (
                "social_core.backends.github.GithubOAuth2",
                {"github_oauth2_state_state": {"state": "state", "timestamp": 0}},
                {"code": "code", "state": "state"},
            ),
            (
                "social_core.backends.twitter.TwitterOAuth",
                {"twitterunauthorized_token_name": ["oauth_token=token"]},
                {"oauth_token": "token", "oauth_verifier": "verifier"},
            ),
            (
                "social_core.backends.twitter.TwitterOAuth",
                {},
                {"denied": "token"},
            ),
            (
                "social_core.backends.open_id.OpenIdAuth",
                {"openid_state": "state"},
                {"redirect_state": "state", "openid.mode": "id_res"},
            ),
            (
                "social_core.backends.lastfm.LastFmAuth",
                {"lastfm_state": {"state": "state", "user_id": "1"}},
                {"redirect_state": "state", "token": "token"},
            ),
            (
                "social_core.backends.discourse.DiscourseAuth",
                {"discourse_nonce": "nonce"},
                {"sso": "payload", "sig": "signature"},
            ),
            (
                "social_core.backends.google_onetap.GoogleOneTap",
                {},
                {"credential": "id-token", "g_csrf_token": "csrf"},
            ),
            (
                "social_core.backends.vk.VKIDOAuth2",
                {},
                {"payload": '{"code": "code", "state": "state"}'},
            ),
            (
                "social_core.backends.vk.VKAppOAuth2",
                {},
                {"viewer_id": "2", "auth_key": "signature"},
            ),
            (
                "social_core.backends.odnoklassniki.OdnoklassnikiApp",
                {},
                {"logged_user_id": "2", "auth_sig": "signature"},
            ),
            (
                "social_core.backends.github.GithubAppAuth",
                {},
                {"code": "code", "installation_id": "2", "setup_action": "install"},
            ),
        )
        self.addCleanup(TestPartial.reset_cache)
        self.addCleanup(User.reset_cache)
        for path, session, response in cases:
            for request_data, resumed in ((response, False), ({"answer": "42"}, True)):
                with self.subTest(backend=path, response=response, resumed=resumed):
                    user = User("foobar")
                    strategy = TestStrategy(TestStorage)
                    backend = module_member(path)(strategy)
                    saved: dict[str, Any] = {"uid": "1", "user": user}
                    if backend.ASSOCIATION_ONLY:
                        saved[backend.association_user_id_key()] = str(user.id)
                    paused = partial_store(strategy, backend, 0, **saved)
                    strategy.session_set(PARTIAL_TOKEN_SESSION_NAME, paused.token)
                    for name, value in session.items():
                        strategy.session_set(name, value)
                    strategy.set_request_data(request_data, backend)

                    result = partial_pipeline_data(backend, user)

                    self.assertEqual(result is not None, resumed)
                    self.assertEqual(
                        TestPartial.load(paused.token) is not None, resumed
                    )


class AuthenticatedPartialInitiatorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        TestPartial.reset_cache()
        User.reset_cache()
        self.addCleanup(TestPartial.reset_cache)
        self.addCleanup(User.reset_cache)
        self.strategy = TestStrategy(TestStorage)
        self.backend = BaseAuth(self.strategy)
        self.user = User("initiator")
        self.partial = partial_store(self.strategy, self.backend, 0, user=self.user)
        self.partial.kwargs[self.backend.association_user_id_key()] = str(self.user.id)
        self.strategy.session_set(PARTIAL_TOKEN_SESSION_NAME, self.partial.token)

    def test_logged_out_resumer_cannot_adopt_authenticated_partial(self) -> None:
        with self.assertRaises(AuthSessionError) as caught:
            partial_pipeline_data(self.backend)
        self.assertEqual(caught.exception.code, "user_mismatch")

    def test_original_user_can_resume(self) -> None:
        self.assertIsNotNone(partial_pipeline_data(self.backend, self.user))


class OAuth2PendingCallbackTestCase(unittest.TestCase):
    def test_list_state_uses_the_same_value_as_callback_validation(self) -> None:
        backend = BaseOAuth2(TestStrategy(TestStorage))
        state = backend.get_or_create_state()
        assert state is not None
        self.assertTrue(backend.answers_pending_request({"state": [state]}))
        self.assertFalse(backend.answers_pending_request({"state": ["other", state]}))
        self.assertFalse(backend.answers_pending_request({"state": []}))
