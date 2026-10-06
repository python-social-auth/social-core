from __future__ import annotations

from unittest import TestCase
from unittest.mock import Mock, patch

from social_core.backends.azuread import AzureADOAuth2
from social_core.backends.base import BaseAuth
from social_core.backends.cas import CASOpenIdConnectAuth
from social_core.backends.discourse import DiscourseAuth
from social_core.backends.keycloak import KeycloakOAuth2
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthConfigurationError, AuthResponseError
from social_core.groups import group_sync_targets
from social_core.pipeline.social_auth import social_details
from social_core.pipeline.user import sync_groups
from social_core.pipeline.utils import partial_prepare
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy


class GroupsTest(TestCase):
    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.backend = KeycloakOAuth2(self.strategy)

    def configure(self, **kwargs) -> None:
        self.strategy.set_settings(
            {f"SOCIAL_AUTH_KEYCLOAK_{key}": value for key, value in kwargs.items()}
        )

    def test_extraction_is_opt_in(self) -> None:
        self.assertIsNone(self.backend.get_user_groups({"groups": ["admin"]}))
        self.configure(GROUPS_KEY="groups")
        self.assertEqual(
            self.backend.get_user_groups({"groups": ["a", "a", "b"]}), ["a", "b"]
        )
        self.assertEqual(self.backend.get_user_groups({"groups": []}), [])

    def test_missing_and_malformed_claims(self) -> None:
        value: object
        self.configure(GROUPS_KEY="groups")
        with self.assertRaises(AuthResponseError) as caught:
            self.backend.get_user_groups({})
        self.assertEqual(caught.exception.code, "missing_claim")
        self.configure(GROUPS_MISSING_AS_EMPTY=True)
        self.assertEqual(self.backend.get_user_groups({}), [])
        for value in (None, "admin", {}, [1], [""], ["admin", None]):
            with self.subTest(value=value), self.assertRaises(AuthResponseError):
                self.backend.get_user_groups({"groups": value})

    def test_invalid_claim_selection_and_missing_policy_are_configuration_errors(
        self,
    ) -> None:
        key: object
        for key in ("", [], 1):
            self.configure(GROUPS_KEY=key)
            with self.subTest(key=key), self.assertRaises(AuthConfigurationError):
                self.backend.get_user_groups({})
        self.configure(GROUPS_KEY="groups", GROUPS_MISSING_AS_EMPTY="false")
        with self.assertRaises(AuthConfigurationError):
            self.backend.get_user_groups({})

    def test_allow_list_and_email_policy(self) -> None:
        self.configure(
            GROUPS_KEY="groups",
            ALLOW_GROUPS=["a", "b"],
            WHITELISTED_DOMAINS=["example.com"],
        )
        self.assertTrue(
            self.backend.auth_allowed({"groups": ["b"]}, {"email": "user@example.com"})
        )
        self.assertFalse(
            self.backend.auth_allowed({"groups": []}, {"email": "user@example.com"})
        )
        self.assertFalse(
            self.backend.auth_allowed(
                {"groups": ["a"]}, {"email": "user@elsewhere.com"}
            )
        )
        self.configure(GROUPS_KEY=None)
        with self.assertRaises(AuthConfigurationError):
            self.backend.auth_allowed({}, {})

    def test_cas_legacy_allow_list(self) -> None:
        backend = CASOpenIdConnectAuth(self.strategy)
        self.strategy.set_settings({"SOCIAL_AUTH_CAS_ALLOW_GROUPS": ["users"]})
        self.assertTrue(backend.auth_allowed({"groups": ["users"]}, {}))
        self.assertFalse(backend.auth_allowed({}, {}))
        self.assertEqual(backend.get_user_groups({}), [])

    def test_invalid_allow_list_is_a_configuration_error(self) -> None:
        value: object
        self.configure(GROUPS_KEY="groups")
        for value in (None, "admin", {}, [1], [""]):
            self.configure(ALLOW_GROUPS=value)
            with (
                self.subTest(value=value),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                self.backend.auth_allowed({"groups": ["admin"]}, {})
            self.assertEqual(caught.exception.code, "invalid_setting")
            self.assertEqual(caught.exception.parameter, "ALLOW_GROUPS")

    def test_cas_extraction_requires_group_handling(self) -> None:
        backend = CASOpenIdConnectAuth(self.strategy)
        response = {"groups": "users"}
        self.assertIsNone(backend.get_user_groups(response))
        self.assertTrue(backend.auth_allowed(response, {}))
        for setting, value in (
            ("ALLOW_GROUPS", ["users"]),
            ("GROUPS_MAP", {"users": ["Users"]}),
            ("GROUPS_ENABLED", True),
        ):
            self.strategy.set_settings(
                {
                    "SOCIAL_AUTH_CAS_ALLOW_GROUPS": [],
                    "SOCIAL_AUTH_CAS_GROUPS_MAP": {},
                    "SOCIAL_AUTH_CAS_GROUPS_ENABLED": False,
                    f"SOCIAL_AUTH_CAS_{setting}": value,
                }
            )
            with self.subTest(setting=setting):
                self.assertEqual(
                    backend.get_user_groups({"groups": ["users"]}), ["users"]
                )
                with self.assertRaises(AuthResponseError):
                    backend.get_user_groups(response)

    def test_azure_roles_ignore_group_overage(self) -> None:
        backend = AzureADOAuth2(self.strategy)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AZUREAD_OAUTH2_GROUPS_KEY": "groups",
                "SOCIAL_AUTH_AZUREAD_OAUTH2_GROUPS_MISSING_AS_EMPTY": True,
            }
        )
        for response in (
            {"hasgroups": True},
            {"_claim_names": {"groups": "src1"}},
            {"groups": ["partial"], "hasgroups": True},
        ):
            with self.subTest(response=response), self.assertRaises(AuthResponseError):
                backend.get_user_groups(response)
        self.strategy.set_settings({"SOCIAL_AUTH_AZUREAD_OAUTH2_GROUPS_KEY": "roles"})
        self.assertEqual(
            backend.get_user_groups({"hasgroups": True, "roles": ["reviewer"]}),
            ["reviewer"],
        )

    def test_oidc_overage_never_falls_back_to_userinfo(self) -> None:
        backend = OpenIdConnectAuth(self.strategy)
        self.strategy.set_settings({"SOCIAL_AUTH_OIDC_GROUPS_KEY": "groups"})
        backend.id_token = {"sub": "user", "_claim_names": {"groups": "src"}}
        with self.assertRaises(AuthResponseError):
            backend.get_user_groups({"sub": "user", "groups": ["partial"]})

    def test_malformed_overage_metadata_is_not_an_empty_membership_list(self) -> None:
        value: object
        self.configure(GROUPS_KEY="groups", GROUPS_MISSING_AS_EMPTY=True)
        for value in (None, "groups", []):
            with (
                self.subTest(value=value),
                self.assertRaises(AuthResponseError) as caught,
            ):
                self.backend.get_user_groups({"_claim_names": value})
            self.assertEqual(caught.exception.code, "invalid_claim")
            self.assertEqual(caught.exception.claim, "_claim_names")

    def test_oidc_userinfo_overage_prevents_synchronization(self) -> None:
        backend = OpenIdConnectAuth(self.strategy)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_OIDC_GROUPS_KEY": "groups",
                "SOCIAL_AUTH_OIDC_GROUPS_MISSING_AS_EMPTY": True,
            }
        )
        backend.id_token = {"sub": "user"}
        for indicator in ({"hasgroups": True}, {"_claim_names": {"groups": "src"}}):
            with (
                self.subTest(indicator=indicator),
                patch.object(self.strategy, "sync_user_groups") as synchronize,
            ):
                with self.assertRaises(AuthResponseError) as caught:
                    backend.run_pipeline(
                        [
                            "social_core.pipeline.social_auth.social_details",
                            "social_core.pipeline.user.sync_groups",
                        ],
                        details={},
                        response={"sub": "user", **indicator},
                        user=Mock(),
                    )
                self.assertEqual(caught.exception.code, "invalid_claim")
                synchronize.assert_not_called()
        self.assertEqual(backend.get_user_groups({"sub": "user"}), [])
        backend.id_token = {"sub": "user", "groups": []}
        self.assertEqual(
            backend.get_user_groups({"sub": "user", "hasgroups": True}), []
        )

    def test_oidc_precedence_and_userinfo_subject(self) -> None:
        backend = OpenIdConnectAuth(self.strategy)
        self.strategy.set_settings({"SOCIAL_AUTH_OIDC_GROUPS_KEY": "groups"})
        backend.id_token = {"sub": "user", "groups": []}
        self.assertEqual(backend.get_user_groups({"sub": "user", "groups": ["a"]}), [])
        backend.id_token = {"sub": "user"}
        self.assertEqual(
            backend.get_user_groups({"sub": "user", "groups": ["a"]}), ["a"]
        )
        for response in ({"groups": ["a"]}, {"sub": "other", "groups": ["a"]}):
            with self.subTest(response=response), self.assertRaises(AuthResponseError):
                backend.get_user_groups(response)

    def test_groups_are_separate_and_survive_partial_resume(self) -> None:
        self.configure(GROUPS_KEY="groups")
        response = {"preferred_username": "user", "groups": ["a"]}
        result = social_details(self.backend, {}, response)
        self.assertNotIn("groups", result["details"])
        self.assertEqual(result["groups"], ["a"])
        partial = partial_prepare(
            self.strategy, self.backend, 1, response=response, **result
        )
        self.assertEqual(partial.data["kwargs"]["groups"], ["a"])

    def test_mapping_targets_and_disabled_extraction(self) -> None:
        self.configure(GROUPS_MAP={"a": ["A", "Shared"], "b": ["B", "Shared"]})
        self.assertEqual(
            group_sync_targets(self.backend, ["a", "unknown"], {}),
            ({"A", "Shared"}, {"A", "B", "Shared"}),
        )
        self.assertEqual(group_sync_targets(self.backend, [], {})[0], set())
        with self.assertRaises(AuthConfigurationError):
            group_sync_targets(self.backend, None, {})

    def test_unconfigured_mapping_does_not_require_extraction_or_strategy_support(
        self,
    ) -> None:
        self.assertEqual(group_sync_targets(self.backend, None, {}), (set(), set()))
        self.strategy.sync_user_groups(Mock(), None, backend=self.backend, response={})

    def test_invalid_mapping_and_competing_ownership(self) -> None:
        mapping: object
        for mapping in (None, [], {"a": "A"}, {"": ["A"]}, {"a": [True]}):
            with (
                self.subTest(mapping=mapping),
                self.assertRaises(AuthConfigurationError),
            ):
                self.configure(GROUPS_MAP=mapping)
                group_sync_targets(self.backend, [], {})
        self.configure(GROUPS_MAP={"a": ["A"]})
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": [
                    "social_core.backends.gitlab.GitLabOAuth2"
                ],
                "SOCIAL_AUTH_GITLAB_GROUPS_MAP": {"b": ["A"]},
            }
        )
        with self.assertRaises(AuthConfigurationError):
            group_sync_targets(self.backend, ["a"], {})

    def test_sync_step_and_unsupported_strategy(self) -> None:
        strategy = Mock()
        user = Mock()
        sync_groups(strategy, self.backend, {}, user=user, groups=["a"], action="login")
        strategy.sync_user_groups.assert_called_once_with(
            user, ["a"], backend=self.backend, response={}, action="login"
        )
        strategy.reset_mock()
        sync_groups(strategy, self.backend, {}, user=None, groups=["a"])
        with patch.object(self.backend, "ASSOCIATION_ONLY", True):
            sync_groups(strategy, self.backend, {}, user=user, groups=["a"])
        strategy.sync_user_groups.assert_not_called()
        self.configure(GROUPS_MAP={"a": ["A"]})
        with self.assertRaises(AuthConfigurationError):
            self.strategy.sync_user_groups(
                user, ["a"], backend=self.backend, response={}
            )

    def test_discourse_groups_leave_details(self) -> None:
        backend = DiscourseAuth(self.strategy)
        response = {"groups": "translators,reviewers"}
        self.assertNotIn("groups", backend.get_user_details(response))
        self.assertIsNone(backend.get_user_groups(response))
        self.strategy.set_settings({"SOCIAL_AUTH_DISCOURSE_GROUPS_ENABLED": True})
        self.assertEqual(
            backend.get_user_groups(response), ["translators", "reviewers"]
        )
        self.assertEqual(backend.get_user_groups({"groups": ""}), [])

    def test_base_backend_does_not_extract_groups(self) -> None:
        self.assertIsNone(BaseAuth(self.strategy).get_user_groups({"groups": ["a"]}))
