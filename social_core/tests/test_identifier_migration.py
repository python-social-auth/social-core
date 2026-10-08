from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from social_core.backends.base import BaseAuth
from social_core.backends.fence import Fence
from social_core.backends.google import GoogleOAuth2
from social_core.backends.qiita import QiitaOAuth2
from social_core.exceptions import (
    AuthAssociationError,
    AuthConfigurationError,
    AuthResponseError,
)
from social_core.identifiers import UNVERIFIED_LEGACY_TRANSITIONS
from social_core.pipeline.social_auth import associate_user, social_uid, social_user
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
        self.backend: BaseAuth = MigratingBackend(self.strategy)
        self.victim = User("victim")

    def candidate(self, *, id_key="email", extra_data=None, uid="old@example.com"):
        return TestUserSocialAuth(
            self.victim, self.backend.name, uid, extra_data=extra_data, id_key=id_key
        )

    def authenticate(self, **kwargs):
        return social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            legacy_identifiers=[("email", "old@example.com")],
            **kwargs,
        )

    def assert_conflict(self):
        return self.assertRaisesRegex(AuthAssociationError, "")

    def test_verified_keyed_and_empty_key_migration(self) -> None:
        for key in ("email", ""):
            with self.subTest(key=key):
                TestUserSocialAuth.reset_cache()
                legacy = self.candidate(
                    id_key=key, extra_data={"stable_id": "stable-victim"}
                )
                with patch.object(
                    TestUserSocialAuth,
                    "get_social_auth_by_extra_data",
                    side_effect=AssertionError("JSON search"),
                ):
                    result = self.authenticate()
                self.assertIs(result["social"], legacy)
                self.assertEqual(
                    (legacy.uid, legacy.id_key), ("stable-victim", "stable_id")
                )

    def test_missing_evidence_stops_authentication_by_default(self) -> None:
        legacy = self.candidate()
        with self.assert_conflict() as caught:
            self.authenticate()
        self.assertEqual(caught.exception.code, "identifier_migration_conflict")
        self.assertEqual(legacy.uid, "old@example.com")

    def test_explicit_unverified_opt_in(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_MIGRATING_ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION": True}
        )
        legacy = self.candidate()
        self.assertIs(self.authenticate()["social"], legacy)

    def test_invalid_or_conflicting_evidence_cannot_be_bypassed(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION": True}
        )
        invalid_values: tuple[object, ...] = ("other", None, True, [], {}, "")
        for value in invalid_values:
            with self.subTest(value=value):
                TestUserSocialAuth.reset_cache()
                self.candidate(extra_data={"stable_id": value})
                with self.assert_conflict():
                    self.authenticate()

    def test_multiple_candidates_fail_closed(self) -> None:
        self.candidate(extra_data={"stable_id": "stable-victim"})
        self.candidate(
            id_key="login", uid="old-name", extra_data={"stable_id": "stable-victim"}
        )
        with self.assert_conflict():
            social_user(
                self.backend,
                "stable-victim",
                id_key="stable_id",
                legacy_identifiers=[
                    ("email", "old@example.com"),
                    ("login", "old-name"),
                ],
            )

    def test_same_candidate_is_deduplicated(self) -> None:
        legacy = self.candidate(id_key="", extra_data={"stable_id": "stable-victim"})
        result = social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            legacy_identifiers=[
                ("email", "old@example.com"),
                ("login", "old@example.com"),
            ],
        )
        self.assertIs(result["social"], legacy)

    def test_current_identity_avoids_legacy_lookups(self) -> None:
        current = self.candidate(id_key="stable_id", uid="stable-victim")
        with patch.object(
            TestUserSocialAuth,
            "get_social_auth",
            wraps=TestUserSocialAuth.get_social_auth,
        ) as lookup:
            self.assertIs(self.authenticate()["social"], current)
        lookup.assert_called_once_with("migrating", "stable-victim", id_key="stable_id")

    def test_new_user_never_searches_extra_data(self) -> None:
        with patch.object(
            TestUserSocialAuth,
            "get_social_auth_by_extra_data",
            side_effect=AssertionError("JSON search"),
        ):
            self.assertTrue(self.authenticate()["is_new"])

    def test_changed_old_identifier_is_not_recovered_by_json_search(self) -> None:
        self.candidate(
            uid="previous@example.com", extra_data={"stable_id": "stable-victim"}
        )
        self.assertTrue(self.authenticate()["is_new"])

    def test_wrong_authenticated_user_does_not_mutate_candidate(self) -> None:
        legacy = self.candidate(extra_data={"stable_id": "stable-victim"})
        with self.assert_conflict():
            self.authenticate(user=User("another-user"))
        self.assertEqual(legacy.uid, "old@example.com")

    def test_reclaimed_old_identifier_fails_after_migration(self) -> None:
        self.candidate(extra_data={"stable_id": "stable-victim"})
        self.authenticate()
        result = social_user(
            self.backend,
            "stable-attacker",
            id_key="stable_id",
            legacy_identifiers=[("email", "old@example.com")],
        )
        self.assertIsNone(result["social"])

    def test_new_association_records_key(self) -> None:
        result = associate_user(
            self.backend, "stable-victim", user=self.victim, id_key="stable_id"
        )
        assert result is not None
        self.assertEqual(result["social"].id_key, "stable_id")

    def test_compatibility_unkeyed_pipeline_argument(self) -> None:
        legacy = self.candidate(id_key="", extra_data={"stable_id": "stable-victim"})
        result = social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            legacy_uids=["old@example.com"],
        )
        self.assertIs(result["social"], legacy)

    def test_numeric_evidence(self) -> None:
        legacy = self.candidate(extra_data={"stable_id": 123})
        result = social_user(
            self.backend,
            "123",
            id_key="stable_id",
            legacy_identifiers=[("email", "old@example.com")],
        )
        self.assertIs(result["social"], legacy)

    def test_configured_keys_work_with_explicit_current_key(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_MIGRATING_ID_KEY": "sub",
                "SOCIAL_AUTH_MIGRATING_LEGACY_ID_KEYS": ["login", "email", "sub"],
            }
        )
        response = {"sub": "123", "email": "old@example.com", "login": "old-name"}
        identifiers = social_uid(self.backend, {}, response)
        self.assertEqual(
            identifiers["legacy_identifiers"],
            [("email", "old@example.com"), ("login", "old-name")],
        )
        self.assertEqual(
            self.backend.get_legacy_user_ids({}, response),
            ["old@example.com", "old-name"],
        )

    def test_overridden_legacy_uid_hook_participates_with_keyed_hook(self) -> None:
        class CustomBackend(MigratingBackend):
            def get_legacy_user_ids(self, details, response) -> list[str]:
                return [*super().get_legacy_user_ids(details, response), "custom-old"]

        self.backend = CustomBackend(self.strategy)
        legacy = self.candidate(
            id_key="", uid="custom-old", extra_data={"stable_id": "stable-victim"}
        )
        identifiers = social_uid(
            self.backend, {}, {"stable_id": "stable-victim", "email": "old@example.com"}
        )
        self.assertEqual(identifiers["legacy_uids"], ["old@example.com", "custom-old"])
        self.assertIs(social_user(self.backend, **identifiers)["social"], legacy)
        self.assertEqual((legacy.uid, legacy.id_key), ("stable-victim", "stable_id"))

    def test_overridden_legacy_uid_hook_still_requires_evidence(self) -> None:
        with patch.object(
            self.backend, "get_legacy_user_ids", return_value=["custom-old"]
        ):
            identifiers = social_uid(self.backend, {}, {"stable_id": "stable-victim"})
        legacy = self.candidate(id_key="", uid="custom-old")
        with self.assert_conflict():
            social_user(self.backend, **identifiers)
        self.assertEqual((legacy.uid, legacy.id_key), ("custom-old", ""))

    def test_unkeyed_fallback_does_not_bypass_configured_key_policy(self) -> None:
        self.backend = GoogleOAuth2(self.strategy)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH2_LEGACY_ID_KEYS": ["custom"]}
        )
        legacy = self.candidate(id_key="", uid="old-custom")
        identifiers = social_uid(
            self.backend, {}, {"sub": "stable-victim", "custom": "old-custom"}
        )
        with self.assert_conflict():
            social_user(self.backend, **identifiers)
        self.assertEqual((legacy.uid, legacy.id_key), ("old-custom", ""))

    def test_restored_partial_identifier_pairs(self) -> None:
        legacy = self.candidate(extra_data={"stable_id": "stable-victim"})
        result = social_user(
            self.backend,
            "stable-victim",
            id_key="stable_id",
            legacy_identifiers=[["email", "old@example.com"]],
        )
        self.assertIs(result["social"], legacy)

    def test_missing_claim_skipped_and_other_errors_propagate(self) -> None:
        self.assertEqual(self.backend.get_legacy_user_identifiers({}, {}), [])
        with (
            patch.object(
                self.backend,
                "get_user_id_for_key",
                side_effect=AuthResponseError(self.backend, code="invalid_claim"),
            ),
            self.assertRaises(AuthResponseError),
        ):
            self.backend.get_legacy_user_identifiers({}, {})

    def test_invalid_configured_keys(self) -> None:
        for keys in ("email", None, [1], [""]):
            with self.subTest(keys=keys):
                self.strategy.set_settings(
                    {"SOCIAL_AUTH_MIGRATING_LEGACY_ID_KEYS": keys}
                )
                with self.assertRaises(AuthConfigurationError):
                    self.backend.get_legacy_user_identifiers({}, {})

    def test_audited_defaults_are_transition_specific(self) -> None:
        self.assertEqual(len(UNVERIFIED_LEGACY_TRANSITIONS), 20)
        for name, (path, old_key, new_key) in UNVERIFIED_LEGACY_TRANSITIONS.items():
            with self.subTest(backend=name):
                backend = module_member(path)(self.strategy)
                self.assertTrue(
                    backend.allow_unverified_legacy_uid_migration(old_key, new_key)
                )
                self.assertFalse(
                    backend.allow_unverified_legacy_uid_migration("custom", new_key)
                )
                self.assertFalse(
                    backend.allow_unverified_legacy_uid_migration(old_key, "custom")
                )

    def test_builtin_missing_evidence_compatibility(self) -> None:
        self.backend = GoogleOAuth2(self.strategy)
        legacy = TestUserSocialAuth(
            self.victim, self.backend.name, "old@example.com", id_key="email"
        )
        result = social_user(
            self.backend,
            "stable-victim",
            id_key="sub",
            legacy_identifiers=[("email", "old@example.com")],
        )
        self.assertIs(result["social"], legacy)

    def test_builtin_unkeyed_current_uid_migration(self) -> None:
        self.backend = GoogleOAuth2(self.strategy)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH2_USE_UNIQUE_USER_ID": True}
        )
        legacy = self.candidate(id_key="", uid="stable-victim")
        identifiers = social_uid(
            self.backend, {}, {"sub": "stable-victim", "email": "old@example.com"}
        )
        result = social_user(self.backend, **identifiers)
        self.assertIs(result["social"], legacy)
        self.assertEqual((legacy.uid, legacy.id_key), ("stable-victim", "sub"))

    def test_builtin_unkeyed_current_uid_respects_strict_policy(self) -> None:
        self.backend = GoogleOAuth2(self.strategy)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH2_ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION": False}
        )
        legacy = self.candidate(id_key="", uid="stable-victim")
        with self.assert_conflict():
            social_user(
                self.backend, **social_uid(self.backend, {}, {"sub": "stable-victim"})
            )
        self.assertEqual(legacy.id_key, "")

    def test_builtin_unkeyed_current_uid_rejects_conflicting_evidence(self) -> None:
        self.backend = GoogleOAuth2(self.strategy)
        legacy = self.candidate(
            id_key="", uid="stable-victim", extra_data={"sub": "someone-else"}
        )
        with self.assert_conflict():
            social_user(
                self.backend, **social_uid(self.backend, {}, {"sub": "stable-victim"})
            )
        self.assertEqual(legacy.id_key, "")

    def test_builtin_mismatching_evidence_cannot_use_default_allowance(self) -> None:
        self.backend = GoogleOAuth2(self.strategy)
        TestUserSocialAuth(
            self.victim,
            self.backend.name,
            "old@example.com",
            id_key="email",
            extra_data={"sub": "someone-else"},
        )
        with self.assert_conflict():
            social_user(
                self.backend,
                "stable-victim",
                id_key="sub",
                legacy_identifiers=[("email", "old@example.com")],
            )

    def test_explicit_false_and_configuration_changes_require_evidence(self) -> None:
        backend = GoogleOAuth2(self.strategy)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH2_ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION": False}
        )
        self.assertFalse(backend.allow_unverified_legacy_uid_migration("email", "sub"))
        self.strategy.set_settings({"SOCIAL_AUTH_GOOGLE_OAUTH2_ID_KEY": "custom"})
        self.assertFalse(
            backend.allow_unverified_legacy_uid_migration("email", "custom")
        )
        self.assertFalse(
            QiitaOAuth2(self.strategy).allow_unverified_legacy_uid_migration(
                "id", "permanent_id"
            )
        )

    def test_custom_subclass_does_not_inherit_unsafe_default(self) -> None:
        class CustomGoogle(GoogleOAuth2):
            pass

        self.assertFalse(
            CustomGoogle(self.strategy).allow_unverified_legacy_uid_migration(
                "email", "sub"
            )
        )

    def test_oidc_alias_evidence_and_alias_conflicts(self) -> None:
        self.backend = Fence(self.strategy)
        legacy = TestUserSocialAuth(
            self.victim,
            self.backend.name,
            "old",
            id_key="username",
            extra_data={"id": "stable"},
        )
        result = social_user(
            self.backend,
            "stable",
            id_key="sub",
            legacy_identifiers=[("username", "old")],
        )
        self.assertIs(result["social"], legacy)
        TestUserSocialAuth.reset_cache()
        TestUserSocialAuth(
            self.victim,
            self.backend.name,
            "old",
            id_key="username",
            extra_data={"sub": "stable", "id": "other"},
        )
        with self.assert_conflict():
            social_user(
                self.backend,
                "stable",
                id_key="sub",
                legacy_identifiers=[("username", "old")],
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
        legacy = TestUserSocialAuth(
            victim,
            backend.name,
            legacy_uid,
            extra_data={backend.get_stored_user_id_keys(id_key)[-1]: str(stable)},
        )

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
                legacy = TestUserSocialAuth(
                    victim, backend.name, legacy_uid, extra_data={"sub": "stable"}
                )

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
