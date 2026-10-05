"""Verify signature comparisons preserve authentication failure behavior."""

import hashlib
import hmac
import time
import unittest

from social_core.backends.discourse import DiscourseAuth
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.backends.telegram import TelegramAuth
from social_core.exceptions import AuthResponseError
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy


class SignatureComparisonTest(unittest.TestCase):
    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings({"SOCIAL_AUTH_SECRET": "secret"})

    def test_telegram_invalid_hashes_are_signature_failures(self):
        self.strategy.set_settings({"SOCIAL_AUTH_TELEGRAM_BOT_TOKEN": "secret"})
        backend = TelegramAuth(self.strategy)
        invalid_values: tuple[object, ...] = (
            "wrong",
            "é",
            "",
            [],
            {},
            True,
            123,
            b"hash",
        )
        for value in invalid_values:
            with (
                self.subTest(hash=value),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.verify_data({"auth_date": int(time.time()), "hash": value})
            self.assertEqual(caught.exception.code, "invalid_signature")
            self.assertEqual(caught.exception.stage, "callback")

    def test_telegram_valid_hash_is_accepted(self):
        self.strategy.set_settings({"SOCIAL_AUTH_TELEGRAM_BOT_TOKEN": "secret"})
        auth_date = int(time.time())
        signature = hmac.new(
            hashlib.sha256(b"secret").digest(),
            f"auth_date={auth_date}\nid=42".encode(),
            hashlib.sha256,
        ).hexdigest()
        TelegramAuth(self.strategy).verify_data(
            {"auth_date": auth_date, "id": "42", "hash": signature}
        )

    def test_discourse_hmac_mismatch_is_a_signature_failure(self):
        backend = DiscourseAuth(self.strategy)
        invalid_values: tuple[object, ...] = (
            None,
            "",
            "wrong",
            "é",
            [],
            {},
            True,
            123,
            b"signature",
        )
        for signature in invalid_values:
            self.strategy.request_data().update({"sso": "payload", "sig": signature})
            with (
                self.subTest(signature=signature),
                self.assertRaises(AuthResponseError) as caught,
            ):
                backend.auth_complete()
            self.assertEqual(caught.exception.code, "invalid_signature")
            self.assertEqual(caught.exception.stage, "callback")

    def test_oidc_at_hash_comparison_rejects_invalid_values(self):
        backend = OpenIdConnectAuth(self.strategy)
        access_token = "access-token"
        key = {"alg": "RS256"}
        expected_hash = backend.calc_at_hash(access_token, key["alg"])
        self.assertTrue(
            backend.validate_at_hash({"at_hash": expected_hash}, access_token, key)
        )
        invalid_values: tuple[object, ...] = (
            None,
            "",
            "wrong",
            "é",
            [],
            {},
            True,
            123,
            expected_hash.encode(),
        )
        for value in invalid_values:
            with self.subTest(at_hash=value):
                self.assertIs(
                    backend.validate_at_hash({"at_hash": value}, access_token, key),
                    False,
                )

    def test_oidc_at_hash_validation_bypasses_are_preserved(self):
        backend = OpenIdConnectAuth(self.strategy)
        self.assertIs(backend.validate_at_hash({}, "access-token", {}), True)
        backend.VALIDATE_AT_HASH = False
        self.assertIs(
            backend.validate_at_hash({"at_hash": []}, "access-token", {}), True
        )
