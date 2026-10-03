import unittest
from datetime import datetime, timedelta, timezone
from typing import Protocol, cast
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

from social_core.pipeline.mail import mail_validation
from social_core.utils import (
    PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME,
    PARTIAL_TOKEN_SESSION_NAME,
)

from .models import TestCode, TestPartial, TestStorage
from .strategy import Redirect, TestStrategy


class EmailCodeExpiryTest(unittest.TestCase):
    def setUp(self) -> None:
        TestCode.reset_cache()
        self.strategy = TestStrategy(TestStorage)
        self.now = datetime(2026, 10, 26, tzinfo=timezone.utc)
        clock = patch("social_core.storage.datetime", wraps=datetime)
        self.addCleanup(clock.stop)
        clock.start().now.return_value = self.now
        self.code = TestCode.make_code("foo@example.com")

    def test_creation_timestamp(self) -> None:
        self.assertEqual(self.code.timestamp, self.now)
        self.assertEqual(TestCode.get_code(self.code.code).timestamp, self.now)

    def test_default_lifetime(self) -> None:
        for age, expected in (
            (timedelta(days=7, microseconds=-1), True),
            (timedelta(days=7), False),
            (timedelta(days=8), False),
        ):
            with self.subTest(age=age):
                self.code.timestamp = self.now - age
                self.code.verified = False
                self.assertEqual(
                    self.strategy.validate_email(self.code.email, self.code.code),
                    expected,
                )
                self.assertEqual(self.code.verified, expected)

    def test_custom_lifetime(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_EMAIL_VALIDATION_EXPIRED_THRESHOLD": 60}
        )
        self.code.timestamp = self.now - timedelta(seconds=60)
        self.assertFalse(self.strategy.validate_email(self.code.email, self.code.code))
        self.assertFalse(self.code.verified)
        self.code.timestamp += timedelta(microseconds=1)
        self.assertTrue(self.strategy.validate_email(self.code.email, self.code.code))

    def test_disabled_expiry(self) -> None:
        for threshold in (None, 0):
            for timestamp in (None, self.now - timedelta(days=30)):
                with self.subTest(threshold=threshold, timestamp=timestamp):
                    self.strategy.set_settings(
                        {"SOCIAL_AUTH_EMAIL_VALIDATION_EXPIRED_THRESHOLD": threshold}
                    )
                    self.code.timestamp = timestamp
                    self.code.verified = False
                    self.assertTrue(
                        self.strategy.validate_email(self.code.email, self.code.code)
                    )
                    self.assertFalse(
                        self.strategy.validate_email(self.code.email, self.code.code)
                    )

    def test_undated_code(self) -> None:
        self.code.timestamp = None
        self.assertFalse(self.strategy.validate_email(self.code.email, self.code.code))
        self.assertFalse(self.code.verified)

    def test_naive_and_non_utc_timestamps(self) -> None:
        for timestamp in (
            self.now.replace(tzinfo=None),
            self.now.astimezone(timezone(timedelta(hours=2))),
        ):
            with self.subTest(timestamp=timestamp):
                self.code.timestamp = timestamp - timedelta(days=7)
                self.assertFalse(
                    self.strategy.validate_email(self.code.email, self.code.code)
                )
                self.code.timestamp += timedelta(seconds=1)
                self.assertTrue(
                    self.strategy.validate_email(self.code.email, self.code.code)
                )
                self.code.verified = False

    def test_lifetime_across_daylight_saving_time(self) -> None:
        self.code.timestamp = (self.now - timedelta(days=7)).astimezone(
            ZoneInfo("Europe/Prague")
        )
        self.assertFalse(self.strategy.validate_email(self.code.email, self.code.code))
        self.assertFalse(self.code.verified)

    def test_invalid_code_and_email(self) -> None:
        self.assertFalse(self.strategy.validate_email(self.code.email, "missing"))
        self.assertFalse(
            self.strategy.validate_email("other@example.com", self.code.code)
        )
        self.assertFalse(self.code.verified)

    def test_code_must_match(self) -> None:
        with patch.object(TestCode, "get_code", return_value=self.code):
            self.assertFalse(self.strategy.validate_email(self.code.email, "other"))
        self.assertFalse(self.code.verified)

    def test_code_is_single_use(self) -> None:
        self.assertTrue(self.strategy.validate_email(self.code.email, self.code.code))
        self.assertFalse(self.strategy.validate_email(self.code.email, self.code.code))


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

        with (
            strategy.pipeline_request_data({"verification_code": "123456"}),
            patch.object(strategy, "validate_email", return_value=True) as validate,
        ):
            response = call_partial_step(
                mail_validation_wrapper,
                strategy,
                backend,
                0,
                details={"email": "foo@example.com"},
                is_new=True,
            )

        self.assertEqual(response, {})
        validate.assert_called_once_with("foo@example.com", "123456")
