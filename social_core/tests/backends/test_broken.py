import unittest

from social_core.backends.base import BaseAuth
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy


class BrokenBackendAuth(BaseAuth):
    name = "broken"


class BrokenBackendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = BrokenBackendAuth(TestStrategy(TestStorage))

    def tearDown(self) -> None:
        self.backend = None

    def test_auth_url(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, "Implement in subclass"):
            self.backend.auth_url()

    def test_auth_html(self) -> None:
        self.assertEqual(self.backend.auth_html(), "Implement in subclass")

    def test_auth_complete(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, "Implement in subclass"):
            self.backend.auth_complete()

    def test_get_user_details(self) -> None:
        with self.assertRaisesRegex(NotImplementedError, "Implement in subclass"):
            self.backend.get_user_details(None)
