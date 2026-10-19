import json
from typing import cast
from unittest.mock import patch

from social_core.exceptions import (
    AuthAssociationError,
    AuthConfigurationError,
    AuthResponseError,
)
from social_core.pipeline import DEFAULT_AUTH_PIPELINE
from social_core.pipeline.social_auth import social_uid, social_user
from social_core.tests.models import TestUserSocialAuth, User

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class MailChimpOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.mailchimp.MailChimpOAuth2"
    user_data_url = "https://login.mailchimp.com/oauth2/metadata"
    expected_username = "ada"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "accountname": "Example",
            "api_endpoint": "https://us1.api.mailchimp.com",
            "login": {
                "login_id": "456",
                "login_name": "ada",
                "email": "ada@example.com",
            },
            "role": "owner",
            "user_id": "123",
        }
    )

    def setUp(self) -> None:
        super().setUp()
        self.strategy.set_settings({"SOCIAL_AUTH_PIPELINE": DEFAULT_AUTH_PIPELINE})

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_rejects_backend_account_wide_id_key(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_MAILCHIMP_ID_KEY": "user_id"})

        with self.assertRaises(AuthConfigurationError) as caught:
            self.mailchimp_login("123", "456", "ada")

        self.assertEqual(
            (caught.exception.code, caught.exception.parameter),
            ("invalid_setting", "ID_KEY"),
        )
        self.assertEqual(len(User.cache), 0)

    def test_rejects_global_account_wide_id_key(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_ID_KEY": "user_id"})

        with self.assertRaises(AuthConfigurationError) as caught:
            self.mailchimp_login("123", "456", "ada")

        self.assertEqual(
            (caught.exception.code, caught.exception.parameter),
            ("invalid_setting", "ID_KEY"),
        )
        self.assertEqual(len(User.cache), 0)

    def test_accepts_explicit_scoped_id_key(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_MAILCHIMP_ID_KEY": "mailchimp_identity"}
        )

        user = self.mailchimp_login("123", "456", "ada")

        self.assertEqual(user.social[0].uid, "123:456")

    def mailchimp_login(self, account_id: str, login_id: str, name: str) -> User:
        self.user_data_body = json.dumps(
            {
                "accountname": "Example",
                "api_endpoint": "https://us1.api.mailchimp.com",
                "login": {
                    "login_id": login_id,
                    "login_name": name,
                    "email": f"{name}@example.com",
                },
                "role": "owner",
                "user_id": account_id,
            }
        )
        self.access_token_body = json.dumps(
            {"access_token": f"token-{login_id}", "token_type": "bearer"}
        )
        return cast("User", self.do_start())

    def test_account_and_login_form_identity(self) -> None:
        user = self.mailchimp_login("123", "456", "ada")

        self.assertEqual(
            (user.social[0].uid, user.social[0].id_key),
            ("123:456", "mailchimp_identity"),
        )
        self.assertEqual(user.social[0].extra_data["user_id"], "123")
        self.assertEqual(user.social[0].extra_data["login"]["login_id"], "456")

    def test_two_logins_on_one_account_have_separate_local_users(self) -> None:
        owner = self.mailchimp_login("123", "456", "ada")
        manager = self.mailchimp_login("123", "789", "bea")

        self.assertIsNot(manager, owner)
        self.assertEqual(
            (owner.social[0].uid, manager.social[0].uid), ("123:456", "123:789")
        )
        self.assertEqual(owner.social[0].extra_data["access_token"], "token-456")
        self.assertEqual(manager.social[0].extra_data["access_token"], "token-789")

    def test_one_login_on_two_accounts_has_separate_associations(self) -> None:
        first = self.mailchimp_login("123", "456", "ada")
        second = self.mailchimp_login("999", "456", "ada")

        self.assertIsNot(first, second)
        self.assertEqual(
            (first.social[0].uid, second.social[0].uid), ("123:456", "999:456")
        )

    def test_missing_identifiers_fail_closed(self) -> None:
        for account_id, login_id, claim in (
            (None, "456", "user_id"),
            ("123", None, "login.login_id"),
            ("123", "", "login.login_id"),
        ):
            with self.subTest(claim=claim):
                self.user_data_body = json.dumps(
                    {
                        "user_id": account_id,
                        "login": {
                            "login_id": login_id,
                            "login_name": "ada",
                            "email": "ada@example.com",
                        },
                    }
                )
                with self.assertRaises(AuthResponseError) as caught:
                    self.do_start()
                self.assertEqual(
                    (caught.exception.code, caught.exception.claim),
                    ("missing_claim", claim),
                )

    def test_matching_legacy_login_migrates(self) -> None:
        owner = User("ada", email="ada@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "mailchimp",
            "123",
            id_key="user_id",
            extra_data={"login": {"login_id": "456", "login_name": "ada"}},
        )

        user = self.mailchimp_login("123", "456", "ada")

        self.assertIs(user, owner)
        self.assertEqual((legacy.uid, legacy.id_key), ("123:456", "mailchimp_identity"))
        self.assertEqual(len(User.cache), 1)

    def test_mismatched_legacy_login_creates_separate_user(self) -> None:
        owner = User("ada", email="ada@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "mailchimp",
            "123",
            id_key="user_id",
            extra_data={"login": {"login_id": "456", "login_name": "ada"}},
        )

        other = self.mailchimp_login("123", "789", "bea")

        self.assertIsNot(other, owner)
        self.assertEqual((legacy.uid, legacy.id_key), ("123", "user_id"))
        self.assertEqual(other.social[0].uid, "123:789")

    def test_legacy_lookup_rejects_another_identity_context(self) -> None:
        owner = User("ada", email="ada@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "mailchimp",
            "123",
            id_key="user_id",
            extra_data={"login": {"login_id": "456"}},
        )
        response = {
            "user_id": "123",
            "mailchimp_identity": "123:456",
            "login": {"login_id": "456"},
        }

        for uid, id_key in (("123:456", "user_id"), ("wrong", "mailchimp_identity")):
            with self.subTest(uid=uid, id_key=id_key):
                self.assertIsNone(
                    self.backend.get_legacy_social_auth(uid, id_key, response)
                )
                self.assertEqual((legacy.uid, legacy.id_key), ("123", "user_id"))

    def test_legacy_row_without_login_id_requires_recovery(self) -> None:
        owner = User("ada", email="ada@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "mailchimp",
            "123",
            id_key="user_id",
            extra_data={"login": {"login_name": "ada"}},
        )

        with self.assertRaises(AuthAssociationError) as caught:
            self.mailchimp_login("123", "456", "ada")

        self.assertEqual(caught.exception.code, "identifier_migration_conflict")
        self.assertEqual((legacy.uid, legacy.id_key), ("123", "user_id"))

    def test_authenticated_owner_can_relink_legacy_row_without_login_id(self) -> None:
        owner = User("ada", email="ada@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "mailchimp",
            "123",
            id_key="user_id",
            extra_data={"login": {"login_name": "ada"}},
        )
        response = {
            "user_id": "123",
            "mailchimp_identity": "123:456",
            "login": {"login_id": "456"},
        }
        identity = social_uid(self.backend, {}, response)

        result = social_user(self.backend, user=owner, response=response, **identity)

        self.assertIs(result["social"], legacy)
        self.assertEqual((legacy.uid, legacy.id_key), ("123:456", "mailchimp_identity"))

    def test_rejected_link_does_not_rekey_legacy_association(self) -> None:
        owner = User("ada", email="ada@example.com")
        other = User("bea", email="bea@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "mailchimp",
            "123",
            id_key="user_id",
            extra_data={"login": {"login_id": "456", "login_name": "ada"}},
        )
        response = {
            "user_id": "123",
            "mailchimp_identity": "123:456",
            "login": {"login_id": "456"},
        }
        identity = social_uid(self.backend, {}, response)

        with self.assertRaises(AuthAssociationError) as caught:
            social_user(self.backend, user=other, response=response, **identity)

        self.assertEqual(caught.exception.code, "identity_in_use")
        self.assertIs(legacy.user, owner)
        self.assertEqual((legacy.uid, legacy.id_key), ("123", "user_id"))

    def test_null_metadata_cannot_create_an_identity(self) -> None:
        with patch.object(self.backend, "get_json", return_value=None):
            self.assertIsNone(self.backend.user_data("token"))
