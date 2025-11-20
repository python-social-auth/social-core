"""Tests for UserMixin.expiration_timedelta() method."""

from __future__ import annotations

import time
import unittest
from datetime import datetime, timedelta, timezone
from typing import cast

from social_core.exceptions import InvalidExpiryValue
from social_core.tests.models import TestUserSocialAuth, User


class ExpirationTimedeltaTestCase(unittest.TestCase):
    """Test cases for expiration_timedelta method."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        self.user = User(username="test_user")

    def tearDown(self) -> None:
        """Clean up test data."""
        User.reset_cache()
        TestUserSocialAuth.reset_cache()

    def test_no_extra_data(self) -> None:
        """Test with no extra_data."""
        social = TestUserSocialAuth(self.user, "test-provider", "123")
        self.assertIsNone(social.expiration_timedelta())

    def test_no_expiration_fields(self) -> None:
        """Test when extra_data has no expiration fields."""
        social = TestUserSocialAuth(
            self.user, "test-provider", "123", extra_data={"some_field": "value"}
        )
        self.assertIsNone(social.expiration_timedelta())

    def test_expires_on_absolute_timestamp_future(self) -> None:
        """Test expires_on with future timestamp."""
        now = datetime.now(timezone.utc)
        future_time = now + timedelta(hours=1)
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires_on": int(future_time.timestamp())},
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should be approximately 1 hour (with some tolerance)
        self.assertAlmostEqual(result.total_seconds(), 3600, delta=2)

    def test_expires_on_absolute_timestamp_past(self) -> None:
        """Test expires_on with past timestamp (expired token)."""
        now = datetime.now(timezone.utc)
        past_time = now - timedelta(hours=1)
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires_on": int(past_time.timestamp())},
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should be negative (approximately -1 hour)
        self.assertLess(result.total_seconds(), 0)
        self.assertAlmostEqual(result.total_seconds(), -3600, delta=2)

    def test_expires_in_with_auth_time(self) -> None:
        """Test expires_in with auth_time (relative expiration)."""
        auth_time = int(time.time()) - 1800  # 30 minutes ago
        expires_in = 3600  # Token valid for 1 hour from auth_time
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires_in": expires_in, "auth_time": auth_time},
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should be approximately 30 minutes remaining (1 hour - 30 minutes)
        self.assertAlmostEqual(result.total_seconds(), 1800, delta=2)

    def test_expires_in_without_auth_time(self) -> None:
        """Test expires_in without auth_time (treat as seconds from now)."""
        expires_in = 3600  # 1 hour from now
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires_in": expires_in},
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should be approximately 1 hour
        self.assertAlmostEqual(result.total_seconds(), 3600, delta=2)

    def test_expires_as_absolute_timestamp_future(self) -> None:
        """Test expires field with large value (absolute timestamp) in future."""
        now = datetime.now(timezone.utc)
        future_time = now + timedelta(hours=2)
        # Timestamp values are typically > 1 billion (year 2001+)
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires": int(future_time.timestamp())},
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should be approximately 2 hours
        self.assertAlmostEqual(result.total_seconds(), 7200, delta=2)

    def test_expires_as_absolute_timestamp_past(self) -> None:
        """Test expires field with expired absolute timestamp (the original bug)."""
        now = datetime.now(timezone.utc)
        past_time = now - timedelta(hours=1)
        # This tests the bug: expired timestamp should still be recognized as timestamp
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires": int(past_time.timestamp())},
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should be negative (approximately -1 hour)
        self.assertLess(result.total_seconds(), 0)
        self.assertAlmostEqual(result.total_seconds(), -3600, delta=2)

    def test_expires_as_relative_seconds_with_auth_time(self) -> None:
        """Test expires field with small value (relative seconds) with auth_time."""
        auth_time = int(time.time()) - 1800  # 30 minutes ago
        expires = 3600  # 1 hour from auth_time
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires": expires, "auth_time": auth_time},
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should be approximately 30 minutes remaining
        self.assertAlmostEqual(result.total_seconds(), 1800, delta=2)

    def test_expires_as_relative_seconds_without_auth_time(self) -> None:
        """Test expires field with small value (relative seconds) without auth_time."""
        expires = 7200  # 2 hours
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires": expires},
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should be approximately 2 hours
        self.assertAlmostEqual(result.total_seconds(), 7200, delta=2)

    def test_expires_priority_order(self) -> None:
        """Test that expires_on takes priority over expires_in and expires."""
        now = datetime.now(timezone.utc)
        future_time = now + timedelta(hours=3)
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={
                "expires_on": int(future_time.timestamp()),
                "expires_in": 7200,  # 2 hours
                "expires": 3600,  # 1 hour
            },
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should use expires_on (3 hours), not expires_in or expires
        self.assertAlmostEqual(result.total_seconds(), 10800, delta=2)

    def test_expires_in_priority_over_expires(self) -> None:
        """Test that expires_in takes priority over expires."""
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={
                "expires_in": 7200,  # 2 hours
                "expires": 3600,  # 1 hour
            },
        )
        result = cast("timedelta", social.expiration_timedelta())
        self.assertIsNotNone(result)
        # Should use expires_in (2 hours), not expires
        self.assertAlmostEqual(result.total_seconds(), 7200, delta=2)

    def test_invalid_expires_value(self) -> None:
        """Test with invalid expires value raises exception."""
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires": "invalid"},
        )
        with self.assertRaises(InvalidExpiryValue) as cm:
            social.expiration_timedelta()
        self.assertEqual(cm.exception.field_name, "expires")
        self.assertEqual(cm.exception.value, "invalid")

    def test_invalid_expires_on_value(self) -> None:
        """Test with invalid expires_on value raises exception."""
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={
                "expires_on": "invalid",
                "expires_in": 3600,
            },
        )
        with self.assertRaises(InvalidExpiryValue) as cm:
            social.expiration_timedelta()
        self.assertEqual(cm.exception.field_name, "expires_on")
        self.assertEqual(cm.exception.value, "invalid")

    def test_heuristic_threshold_boundary(self) -> None:
        """Test the heuristic threshold (2 years = 63072000 seconds)."""
        # Value just above threshold should be treated as timestamp
        now = datetime.now(timezone.utc)
        # Use a timestamp value (year 2025)
        timestamp_value = int(now.timestamp())
        social1 = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires": timestamp_value},
        )
        result1 = cast("timedelta", social1.expiration_timedelta())
        self.assertIsNotNone(result1)
        # Should be close to 0 (current time)
        self.assertAlmostEqual(result1.total_seconds(), 0, delta=2)

        # Value below threshold should be treated as relative
        relative_value = 86400  # 1 day in seconds
        social2 = TestUserSocialAuth(
            self.user,
            "test-provider",
            "456",
            extra_data={"expires": relative_value},
        )
        result2 = cast("timedelta", social2.expiration_timedelta())
        self.assertIsNotNone(result2)
        # Should be approximately 1 day
        self.assertAlmostEqual(result2.total_seconds(), 86400, delta=2)

    def test_access_token_expired_with_valid_token(self) -> None:
        """Test access_token_expired() with valid token."""
        now = datetime.now(timezone.utc)
        future_time = now + timedelta(hours=1)
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires_on": int(future_time.timestamp())},
        )
        self.assertFalse(social.access_token_expired())

    def test_access_token_expired_with_expired_token(self) -> None:
        """Test access_token_expired() with expired token."""
        now = datetime.now(timezone.utc)
        past_time = now - timedelta(hours=1)
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires_on": int(past_time.timestamp())},
        )
        self.assertTrue(social.access_token_expired())

    def test_access_token_expired_within_threshold(self) -> None:
        """Test access_token_expired() with token expiring within threshold."""
        now = datetime.now(timezone.utc)
        # Token expires in 3 seconds (within the 5 second threshold)
        near_future = now + timedelta(seconds=3)
        social = TestUserSocialAuth(
            self.user,
            "test-provider",
            "123",
            extra_data={"expires_on": int(near_future.timestamp())},
        )
        self.assertTrue(social.access_token_expired())
