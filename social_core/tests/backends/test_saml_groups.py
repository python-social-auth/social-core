"""External memberships and policy scoping for SAML identity providers."""

import sys
import unittest
from unittest.mock import patch

from social_core.exceptions import AuthConfigurationError, AuthResponseError
from social_core.groups import group_sync_targets

from .base import BaseBackendTest
from .test_saml import SAML_MODULE_ENABLED


@unittest.skipIf(
    "__pypy__" in sys.builtin_module_names, "dm.xmlsec not compatible with pypy"
)
@unittest.skipUnless(SAML_MODULE_ENABLED, "Only run if onelogin.saml2 is installed")
class SAMLGroupTest(BaseBackendTest):
    backend_path = "social_core.backends.saml.SAMLAuth"

    def test_groups_and_policy_are_scoped_to_idp(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_SAML_ENABLED_IDPS": {
                    "first": {
                        "attr_groups": "teams",
                        "allow_groups": ["reviewers"],
                        "groups_map": {"reviewers": [1]},
                    },
                    "second": {"attr_groups": "roles", "groups_missing_as_empty": True},
                }
            }
        )
        first = {
            "idp_name": "first",
            "attributes": {"teams": ["reviewers", "translators", "reviewers"]},
        }
        self.assertEqual(
            self.backend.get_user_groups(first), ["reviewers", "translators"]
        )
        self.assertTrue(self.backend.auth_allowed(first, {}))
        self.assertFalse(
            self.backend.auth_allowed(
                {"idp_name": "first", "attributes": {"teams": []}}, {}
            )
        )
        self.assertEqual(
            self.backend.get_user_groups({"idp_name": "second", "attributes": {}}), []
        )
        self.assertEqual(
            self.backend.get_user_groups(
                {"idp_name": "second", "attributes": {"roles": "reviewers"}}
            ),
            ["reviewers"],
        )
        self.assertEqual(
            self.backend.get_group_setting("GROUPS_MAP", first), {"reviewers": [1]}
        )
        with self.assertRaises(AuthResponseError):
            self.backend.get_user_groups({"idp_name": "first", "attributes": {}})

    def test_dynamic_idp_mapping_claims_ownership(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": [
                    self.backend_path,
                    "social_core.backends.keycloak.KeycloakOAuth2",
                ],
                "SOCIAL_AUTH_SAML_ENABLED_IDPS": {},
                "SOCIAL_AUTH_KEYCLOAK_GROUPS_MAP": {"reviewers": [42]},
            }
        )
        # Dynamic IdPs are resolved by get_idp without static ENABLED_IDPS entries.
        with patch.object(self.backend, "get_idp") as get_idp:
            get_idp.return_value.conf = {"groups_map": {"translators": [42]}}
            with self.assertRaises(AuthConfigurationError):
                group_sync_targets(
                    self.backend, ["translators"], {"idp_name": "dynamic"}
                )
            self.strategy.set_settings({"SOCIAL_AUTH_KEYCLOAK_GROUPS_MAP": {}})
            self.assertEqual(
                group_sync_targets(
                    self.backend, ["translators"], {"idp_name": "dynamic"}
                ),
                ({42}, {42}),
            )

    def test_invalid_idp_group_attribute_is_a_configuration_error(self) -> None:
        key: object
        for key in ("", 1, []):
            self.strategy.set_settings(
                {"SOCIAL_AUTH_SAML_ENABLED_IDPS": {"first": {"attr_groups": key}}}
            )
            with (
                self.subTest(key=key),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                self.backend.get_user_groups({"idp_name": "first", "attributes": {}})
            self.assertEqual(caught.exception.code, "invalid_setting")
            self.assertEqual(caught.exception.parameter, "GROUPS_KEY")

    def test_active_static_mapping_is_not_a_competing_owner(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_SAML_ENABLED_IDPS": {
                    "first": {"groups_map": {"translators": [42]}},
                    "second": {"groups_map": {"reviewers": [43]}},
                }
            }
        )
        self.assertEqual(
            group_sync_targets(self.backend, ["translators"], {"idp_name": "first"}),
            ({42}, {42}),
        )
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_SAML_ENABLED_IDPS": {
                    "first": {"groups_map": {"translators": [42]}},
                    "second": {"groups_map": {"reviewers": [42]}},
                }
            }
        )
        with self.assertRaises(AuthConfigurationError):
            group_sync_targets(self.backend, ["translators"], {"idp_name": "first"})
