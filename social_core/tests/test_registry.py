import unittest

from social_core.exceptions import (
    DefaultStrategyMissingError,
)
from social_core.registry import REGISTRY

from .strategy import TestStrategy


class StrategyRegistryTestCase(unittest.TestCase):
    def test_missing(self) -> None:
        with self.assertRaises(DefaultStrategyMissingError):
            self.assertIsNotNone(REGISTRY.default_strategy)

    def test_set(self) -> None:
        REGISTRY.default_strategy = TestStrategy(None)
        try:
            self.assertIsInstance(REGISTRY.default_strategy, TestStrategy)
        finally:
            REGISTRY.reset()
