import unittest
from typing import Protocol, cast
from unittest.mock import Mock, patch

from social_core.pipeline.mail import mail_validation
from social_core.utils import (
    PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME,
    PARTIAL_TOKEN_SESSION_NAME,
)

from .models import TestPartial, TestStorage
from .strategy import Redirect, TestStrategy


class PartialStepWrapper(Protocol):
    def __call__(
        self,
        strategy: TestStrategy,
        backend: object,
        pipeline_index: int,
        *args: object,
        **kwargs: object,
    ) -> object: ...


def call_partial_step(
    step: PartialStepWrapper,
    strategy: TestStrategy,
    backend: object,
    pipeline_index: int,
    **kwargs: object,
) -> object:
    return step(strategy, backend, pipeline_index, **kwargs)


class MailValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        TestPartial.reset_cache()

    def test_mail_validation_partial_allows_external_resume(self) -> None:
        strategy = TestStrategy(TestStorage)
        strategy.set_settings({"SOCIAL_AUTH_EMAIL_VALIDATION_URL": "/validate"})
        mail_validation_wrapper = cast("PartialStepWrapper", mail_validation)
        backend = Mock()
        backend.name = "email"
        backend.strategy = strategy
        backend.REQUIRES_EMAIL_VALIDATION = True

        with patch.object(strategy, "send_email_validation") as send_email_validation:
            response = call_partial_step(
                mail_validation_wrapper,
                strategy,
                backend,
                0,
                details={"email": "foo@example.com"},
                is_new=True,
            )

        assert isinstance(response, Redirect)
        self.assertEqual(response.url, "/validate")
        token = cast("str", strategy.session_get(PARTIAL_TOKEN_SESSION_NAME))
        partial = TestPartial.load(token)
        self.assertIsNotNone(partial)
        assert partial is not None
        self.assertTrue(partial.data[PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME])
        send_email_validation.assert_called_once_with(backend, "foo@example.com", token)

    def test_mail_validation_uses_partial_request_data(self) -> None:
        strategy = TestStrategy(TestStorage)
        mail_validation_wrapper = cast("PartialStepWrapper", mail_validation)
        backend = Mock()
        backend.name = "email"
        backend.strategy = strategy
        backend.REQUIRES_EMAIL_VALIDATION = True

        with patch.object(strategy, "validate_email", return_value=True) as validate:
            response = call_partial_step(
                mail_validation_wrapper,
                strategy,
                backend,
                0,
                details={"email": "foo@example.com"},
                is_new=True,
                request={"verification_code": "123456"},
            )

        self.assertEqual(response, {})
        validate.assert_called_once_with("foo@example.com", "123456")
