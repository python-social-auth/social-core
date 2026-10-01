from unittest import TestCase

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthException
from social_core.pipeline.social_auth import associate_user, social_user

from .models import TestStorage, TestUserSocialAuth, User
from .strategy import TestStrategy


class MigratingBackend(BaseAuth):
    name = "migrating"
    ID_KEY = "stable_id"
    LEGACY_ID_KEYS = ("email",)
    MUTABLE_ID_KEYS = ("email",)


class IdentifierMigrationTest(TestCase):
    def setUp(self) -> None:
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        self.strategy = TestStrategy(TestStorage)
        self.backend = MigratingBackend(self.strategy)
        self.victim = User("victim")

    def test_legacy_uid_is_migrated_by_default(self) -> None:
        legacy = TestUserSocialAuth(self.victim, self.backend.name, "old@example.com")

        result = social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            legacy_uids=["old@example.com"],
        )

        self.assertIs(result["social"], legacy)
        self.assertEqual(legacy.uid, "stable-victim")
        self.assertEqual(legacy.id_key, "stable_id")

    def test_strict_mode_rejects_unverified_legacy_uid(self) -> None:
        legacy = TestUserSocialAuth(self.victim, self.backend.name, "old@example.com")
        self.strategy.set_settings(
            {"SOCIAL_AUTH_ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION": False}
        )

        result = social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            legacy_uids=["old@example.com"],
        )

        self.assertIsNone(result["social"])
        self.assertEqual(legacy.uid, "old@example.com")
        self.assertEqual(legacy.id_key, "")

    def test_strict_mode_rejects_unknown_key_for_current_uid(self) -> None:
        legacy = TestUserSocialAuth(self.victim, self.backend.name, "stable-victim")
        self.strategy.set_settings(
            {"SOCIAL_AUTH_ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION": False}
        )

        result = social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
        )

        self.assertIsNone(result["social"])
        self.assertEqual(legacy.id_key, "")

    def test_stable_extra_data_migrates_in_strict_mode(self) -> None:
        legacy = TestUserSocialAuth(
            self.victim,
            self.backend.name,
            "old@example.com",
            extra_data={"stable_id": "stable-victim"},
        )
        self.strategy.set_settings(
            {"SOCIAL_AUTH_ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION": False}
        )

        result = social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            legacy_uids=["changed@example.com"],
        )

        self.assertIs(result["social"], legacy)
        self.assertEqual(legacy.uid, "stable-victim")
        self.assertEqual(legacy.id_key, "stable_id")

    def test_reclaimed_legacy_uid_does_not_match_after_migration(self) -> None:
        legacy = TestUserSocialAuth(self.victim, self.backend.name, "old@example.com")
        social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            legacy_uids=["old@example.com"],
        )

        result = social_user(
            self.backend,
            "stable-attacker",
            id_key="stable_id",
            legacy_uids=["old@example.com"],
        )

        self.assertIsNone(result["social"])
        self.assertEqual(legacy.uid, "stable-victim")

    def test_new_association_records_id_key(self) -> None:
        result = associate_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            user=self.victim,
        )

        assert result is not None
        self.assertEqual(result["social"].id_key, "stable_id")

    def test_ambiguous_extra_data_fails_closed(self) -> None:
        TestUserSocialAuth(
            self.victim,
            self.backend.name,
            "legacy-one",
            extra_data={"stable_id": "stable-victim"},
        )
        TestUserSocialAuth(
            User("other"),
            self.backend.name,
            "legacy-two",
            extra_data={"stable_id": "stable-victim"},
        )

        with self.assertRaisesRegex(AuthException, "Multiple social-auth"):
            social_user(
                self.backend,
                "stable-victim",
                id_key="stable_id",
                legacy_uids=[],
            )
