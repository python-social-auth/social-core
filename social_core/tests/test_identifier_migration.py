from types import SimpleNamespace
from unittest import TestCase

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthAssociationError
from social_core.pipeline.social_auth import associate_user, social_uid, social_user
from social_core.tests.exception_helpers import assert_auth_error
from social_core.utils import module_member

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

        with assert_auth_error(
            self, AuthAssociationError, "identifier_migration_conflict"
        ):
            social_user(
                self.backend,
                "stable-victim",
                id_key="stable_id",
                legacy_uids=[],
            )


class BackendIdentifierMigrationTest(TestCase):
    cases = (
        (
            "social_core.backends.okta.OktaOAuth2",
            {"username": "legacy"},
            {"sub": "stable", "preferred_username": "legacy"},
            "sub",
        ),
        (
            "social_core.backends.google.GoogleOAuth2",
            {"email": "legacy@example.com"},
            {"sub": "stable", "email": "legacy@example.com"},
            "sub",
        ),
        (
            "social_core.backends.google.GoogleOAuth",
            {"email": "legacy@example.com"},
            {"id": "stable", "email": "legacy@example.com"},
            "id",
        ),
        (
            "social_core.backends.google_onetap.GoogleOneTap",
            {"email": "legacy@example.com"},
            {"sub": "stable", "email": "legacy@example.com"},
            "sub",
        ),
        (
            "social_core.backends.trello.TrelloOAuth",
            {"username": "legacy"},
            {"id": "stable", "username": "legacy"},
            "id",
        ),
        (
            "social_core.backends.qiita.QiitaOAuth2",
            {"username": "legacy"},
            {"id": "legacy", "permanent_id": 123},
            "permanent_id",
        ),
        (
            "social_core.backends.keycloak.KeycloakOAuth2",
            {"username": "legacy"},
            {"sub": "stable", "preferred_username": "legacy"},
            "sub",
        ),
        (
            "social_core.backends.cognito.CognitoOAuth2",
            {"username": "legacy"},
            {"sub": "stable", "username": "legacy"},
            "sub",
        ),
        (
            "social_core.backends.dailymotion.DailymotionOAuth2",
            {"username": "legacy"},
            {"id": "stable", "screenname": "legacy"},
            "id",
        ),
        (
            "social_core.backends.mailru.MRGOAuth2",
            {"email": "legacy@example.com"},
            {"id": "stable", "email": "legacy@example.com"},
            "id",
        ),
        (
            "social_core.backends.arcgis.ArcGISOAuth2",
            {"username": "legacy"},
            {"id": "stable", "username": "legacy"},
            "id",
        ),
    )

    oidc_cases = (
        "social_core.backends.okta_openidconnect.OktaOpenIdConnect",
        "social_core.backends.fence.Fence",
        "social_core.backends.cas.CASOpenIdConnectAuth",
        "social_core.backends.google_openidconnect.GoogleOpenIdConnect",
    )

    openid_cases = (
        ("social_core.backends.suse.OpenSUSEOpenId", "nickname", "legacy"),
        ("social_core.backends.ubuntu.UbuntuOpenId", "nickname", "legacy"),
        (
            "social_core.backends.yandex.YandexOpenId",
            "email",
            "legacy@example.com",
        ),
    )

    def setUp(self) -> None:
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        self.strategy = TestStrategy(TestStorage)

    def assert_migrates(self, path, details, response, id_key, stable="stable") -> None:
        backend = module_member(path)(self.strategy)
        victim = User("victim")
        legacy_uid = next(iter(backend.get_legacy_user_ids(details, response)))
        legacy = TestUserSocialAuth(victim, backend.name, legacy_uid)

        identifiers = social_uid(backend, details, response)
        result = social_user(backend, **identifiers)

        self.assertIs(result["social"], legacy)
        self.assertEqual(legacy.uid, str(stable))
        self.assertEqual(legacy.id_key, id_key)

    def test_mapping_backends_migrate_legacy_identifiers(self) -> None:
        for path, details, response, id_key in self.cases:
            with self.subTest(path=path):
                self.assert_migrates(
                    path,
                    details,
                    response,
                    id_key,
                    response[id_key],
                )
                User.reset_cache()
                TestUserSocialAuth.reset_cache()

    def test_oidc_backends_migrate_legacy_identifiers(self) -> None:
        for path in self.oidc_cases:
            with self.subTest(path=path):
                backend = module_member(path)(self.strategy)
                backend.id_token = {"sub": "stable"}
                details = {
                    "username": "legacy",
                    "email": "legacy@example.com",
                }
                response = {
                    "sub": "stable",
                    "preferred_username": "legacy",
                    "username": "legacy@example.com",
                    "email": "legacy@example.com",
                }
                victim = User("victim")
                legacy_uid = backend.get_legacy_user_ids(details, response)[0]
                legacy = TestUserSocialAuth(victim, backend.name, legacy_uid)

                identifiers = social_uid(backend, details, response)
                result = social_user(backend, **identifiers)

                self.assertIs(result["social"], legacy)
                self.assertEqual(legacy.uid, "stable")
                self.assertEqual(legacy.id_key, "sub")
                User.reset_cache()
                TestUserSocialAuth.reset_cache()

    def test_openid_backends_migrate_profile_identifiers(self) -> None:
        response = SimpleNamespace(identity_url="https://provider.example/id/stable")
        for path, legacy_key, legacy_uid in self.openid_cases:
            with self.subTest(path=path):
                details = {legacy_key: legacy_uid}
                self.assert_migrates(
                    path,
                    details,
                    response,
                    "identity_url",
                    response.identity_url,
                )
                User.reset_cache()
                TestUserSocialAuth.reset_cache()
