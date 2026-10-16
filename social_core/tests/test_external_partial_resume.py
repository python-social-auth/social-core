import unittest
from unittest.mock import Mock

from social_core.utils import (
    PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME,
    PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
    PARTIAL_TOKEN_PENDING_SESSION_NAME,
    PARTIAL_TOKEN_SESSION_NAME,
    partial_pipeline_result,
)

from .models import TestPartial
from .models import User as TestUser


class ExternalPartialResumeUserBindingTest(unittest.TestCase):
    def test_rejects_authenticated_user_for_anonymous_flow(self) -> None:
        backend = self._backend(session_kwargs={"user": None})

        result = partial_pipeline_result(backend, TestUser("confirmer"))

        self.assertIsNone(result.partial)
        self.assertIsNone(result.response)
        self.assertTrue(result.halt)
        backend.strategy.partial_pipeline_external_resume_confirmation.assert_not_called()

    def test_rejects_different_authenticated_user(self) -> None:
        backend = self._backend(session_kwargs={"user": TestUser("initiator")})

        result = partial_pipeline_result(backend, TestUser("confirmer"))

        self.assertIsNone(result.partial)
        self.assertIsNone(result.response)
        self.assertTrue(result.halt)
        backend.strategy.partial_pipeline_external_resume_confirmation.assert_not_called()

    def test_accepts_matching_authenticated_user(self) -> None:
        initiator = TestUser("initiator")
        confirmer = TestUser("confirmer")
        confirmer.id = initiator.id
        response = object()
        backend = self._backend(session_kwargs={"user": initiator})
        backend.strategy.partial_pipeline_external_resume_confirmation.return_value = (
            response
        )

        result = partial_pipeline_result(backend, confirmer)

        self.assertIsNone(result.partial)
        self.assertEqual(result.response, response)
        self.assertFalse(result.halt)

    def test_confirmed_resume_rejects_user_authenticated_after_prompt(self) -> None:
        backend = self._backend(session_kwargs={"user": None}, confirmed=True)

        result = partial_pipeline_result(backend, TestUser("confirmer"))

        self.assertIsNone(result.partial)
        self.assertIsNone(result.response)
        self.assertTrue(result.halt)
        self.assertIsNone(backend.strategy.partial_load.return_value.kwargs["user"])

    def test_confirmed_resume_preserves_initiating_user(self) -> None:
        initiator = TestUser("initiator")
        confirmer = TestUser("confirmer")
        confirmer.id = initiator.id
        backend = self._backend(session_kwargs={"user": initiator}, confirmed=True)

        result = partial_pipeline_result(backend, confirmer)

        self.assertIsNotNone(result.partial)
        assert result.partial is not None
        self.assertIs(result.partial.kwargs["user"], initiator)

    def _backend(self, session_kwargs, *, confirmed: bool = False):
        backend = Mock()
        backend.ID_KEY = "email"
        backend.name = "mock-backend"
        backend.id_key.return_value = "email"

        request_data = (
            {"partial_pipeline_confirm": "1"}
            if confirmed
            else {
                "partial_token": "external-token",
                "verification_code": "123456",
            }
        )
        pending_resume = (
            {
                "token": "external-token",
                "request": {
                    "partial_token": "external-token",
                    "verification_code": "123456",
                },
            }
            if confirmed
            else {}
        )

        strategy = Mock()
        strategy.request = None
        strategy.get_request_data.return_value = request_data
        strategy.to_session_value.side_effect = lambda value: value
        strategy.from_session_value.side_effect = lambda value: value
        session_values = {
            PARTIAL_TOKEN_SESSION_NAME: None,
            PARTIAL_TOKEN_PENDING_SESSION_NAME: pending_resume.get("token"),
            PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME: pending_resume.get("request"),
        }
        strategy.session_get.side_effect = lambda name, default=None: (
            session_values.get(name, default)
        )
        partial = TestPartial.prepare(
            backend.name, 0, {"args": [], "kwargs": session_kwargs}
        )
        partial.token = "external-token"
        partial.data[PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME] = True
        strategy.partial_load.return_value = partial
        strategy.redirect.return_value = Mock()
        strategy.partial_pipeline_external_resume_confirmation.return_value = None
        strategy.partial_pipeline_external_resume_confirmed.return_value = True

        backend.strategy = strategy
        backend.setting.side_effect = lambda _name, default=None: default
        return backend
