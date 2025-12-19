import unittest

from social_core.backends.base import BaseAuth
from social_core.exceptions import (
    SocialAuthImproperlyConfiguredError,
    StrategyMissingBackendError,
)

from .strategy import TestStrategy


class StrategyNoneStorageTestCase(unittest.TestCase):
    """Test that BaseStrategy can be initialized with None storage and raises
    appropriate exceptions when storage-dependent methods are called."""

    def setUp(self) -> None:
        self.strategy = TestStrategy(None)

    def test_strategy_initialization_with_none(self) -> None:
        """Test that strategy can be initialized with None storage"""
        with self.assertRaises(StrategyMissingBackendError):
            self.assertIsNone(self.strategy.storage)

    def test_create_user_raises_error(self) -> None:
        """Test that create_user raises StrategyMissingBackendError with None storage"""
        with self.assertRaises(StrategyMissingBackendError) as cm:
            self.strategy.create_user("testuser")
        self.assertEqual(
            str(cm.exception), "Strategy storage backend is not configured"
        )

    def test_get_user_raises_error(self) -> None:
        """Test that get_user raises StrategyMissingBackendError with None storage"""
        with self.assertRaises(StrategyMissingBackendError) as cm:
            self.strategy.get_user(1)
        self.assertEqual(
            str(cm.exception), "Strategy storage backend is not configured"
        )

    def test_clean_partial_pipeline_raises_error(self) -> None:
        """Test that clean_partial_pipeline raises StrategyMissingBackendError with None storage"""
        with self.assertRaises(StrategyMissingBackendError) as cm:
            self.strategy.clean_partial_pipeline("token123")
        self.assertEqual(
            str(cm.exception), "Strategy storage backend is not configured"
        )

    def test_send_email_validation_raises_error(self) -> None:
        """Test that send_email_validation raises StrategyMissingBackendError with None storage"""
        backend = BaseAuth(self.strategy)
        with self.assertRaises(SocialAuthImproperlyConfiguredError):
            self.strategy.send_email_validation(backend, "test@example.com")

    def test_validate_email_raises_error(self) -> None:
        """Test that validate_email raises StrategyMissingBackendError with None storage"""
        with self.assertRaises(StrategyMissingBackendError) as cm:
            self.strategy.validate_email("test@example.com", "code123")
        self.assertEqual(
            str(cm.exception), "Strategy storage backend is not configured"
        )

    def test_authenticate_raises_error(self) -> None:
        """Test that authenticate raises StrategyMissingBackendError with None storage"""
        backend = BaseAuth(self.strategy)
        with self.assertRaises(StrategyMissingBackendError) as cm:
            self.strategy.authenticate(backend)
        self.assertEqual(
            str(cm.exception), "Strategy storage backend is not configured"
        )

    def test_methods_without_storage_work(self) -> None:
        """Test that methods not requiring storage still work"""
        # These methods should work fine without storage
        self.assertEqual(len(self.strategy.random_string(5)), 5)
        self.assertEqual(self.strategy.get_language(), "")
        self.assertIsInstance(self.strategy.get_pipeline(), (list, tuple))
