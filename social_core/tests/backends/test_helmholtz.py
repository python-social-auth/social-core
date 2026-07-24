import json

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest

OIDC_CONFIG = """
    {
      "authorization_endpoint": "https://login.helmholtz.de/oauth2-as/oauth2-authz",
      "token_endpoint": "https://login.helmholtz.de/oauth2/token",
      "introspection_endpoint": "https://login.helmholtz.de/oauth2/introspect",
      "revocation_endpoint": "https://login.helmholtz.de/oauth2/revoke",
      "issuer": "https://login.helmholtz.de/oauth2",
      "jwks_uri": "https://login.helmholtz.de/oauth2/jwk",
      "scopes_supported": [
        "openid",
        "display_name",
        "sn",
        "single-logout",
        "offline_access",
        "voperson_id",
        "voperson_external_affiliation",
        "entitlements",
        "org_domain",
        "email",
        "profile",
        "credentials",
        "eduperson_scoped_affiliation",
        "eduperson_entitlement",
        "eduperson_principal_name",
        "eduperson_unique_id",
        "eduperson_assurance",
        "sys:scim:read_profile",
        "sys:scim:read_memberships",
        "sys:scim:read_self_group"
      ],
      "response_types_supported": [
        "code",
        "token",
        "id_token",
        "code id_token",
        "id_token token",
        "code token",
        "code id_token token"
      ],
      "response_modes_supported": [
        "query",
        "fragment"
      ],
      "grant_types_supported": [
        "authorization_code",
        "implicit"
      ],
      "code_challenge_methods_supported": [
        "plain",
        "S256"
      ],
      "request_uri_parameter_supported": true,
      "subject_types_supported": [
        "public"
      ],
      "userinfo_endpoint": "https://login.helmholtz.de/oauth2/userinfo",
      "id_token_signing_alg_values_supported": [
        "RS256",
        "ES256"
      ]
    }
"""


class HelmholtzOpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.helmholtz.HelmholtzOpenIdConnect"
    issuer = "https://login.helmholtz.de/oauth2"
    openid_config_body = OIDC_CONFIG
    expected_username = "donald"
    user_data_url = "https://login.helmholtz.de/oauth2/userinfo"
    user_id = "42234223-4223-4223-4223-422342234223"
    user_data_body = json.dumps(
        {
            "sub": user_id,
            "preferred_username": "donald",
            "name": "Donald Duck",
            "given_name": "Donald",
            "family_name": "Duck",
            "email": "donald.duck@duckburg.edu",
            "email_verified": True,
            "eduperson_entitlement": [
                "urn:geant:helmholtz.de:group:Helmholtz-member#login.helmholtz.de",
                "urn:geant:helmholtz.de:group:HIFIS#login.helmholtz.de",
            ],
            "eduperson_scoped_affiliation": [
                "employee@login.helmholtz.de",
                "member@login.helmholtz.de",
            ],
            "voperson_id": "42234223422342234223422342234223@login.helmholtz.de",
        }
    )

    def pre_complete_callback(self, start_url) -> None:
        self.access_token_kwargs.setdefault("subject", self.user_id)
        super().pre_complete_callback(start_url)

    def test_login(self) -> None:
        self.do_login()

    def test_get_user_details(self) -> None:
        assert self.user_data_body is not None
        details = self.backend.get_user_details(json.loads(self.user_data_body))
        self.assertEqual(details["username"], "donald")
        self.assertEqual(details["email"], "donald.duck@duckburg.edu")
        self.assertEqual(details["fullname"], "Donald Duck")
        self.assertEqual(details["first_name"], "Donald")
        self.assertEqual(details["last_name"], "Duck")

    def test_entitlements_empty(self) -> None:
        self.assertEqual(self.backend.entitlement_allowed([]), True)

    def test_entitlements_allowed(self) -> None:
        self.backend.ALLOWED_ENTITLEMENTS = [
            "urn:geant:helmholtz.de:group:HIFIS#login.helmholtz.de"
        ]
        self.assertEqual(
            self.backend.entitlement_allowed(
                [
                    "urn:geant:helmholtz.de:group:HIFIS#login.helmholtz.de",
                    "urn:geant:helmholtz.de:group:Helmholtz-member#login.helmholtz.de",
                ]
            ),
            True,
        )

    def test_auth_allowed_default_entitlement_key(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_HELMHOLTZ_ALLOWED_ENTITLEMENTS": [
                    "urn:geant:helmholtz.de:group:HIFIS#login.helmholtz.de"
                ],
            }
        )
        response = {
            "eduperson_entitlement": [
                "urn:geant:helmholtz.de:group:HIFIS#login.helmholtz.de"
            ]
        }
        self.assertTrue(self.backend.auth_allowed(response, {}))
        self.assertFalse(self.backend.auth_allowed({}, {}))

    def test_auth_allowed_custom_entitlement_key(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_HELMHOLTZ_ENTITLEMENT_KEY": "entitlements",
                "SOCIAL_AUTH_HELMHOLTZ_ALLOWED_ENTITLEMENTS": [
                    "urn:geant:helmholtz.de:group:HIFIS#login.helmholtz.de"
                ],
            }
        )
        response = {
            "entitlements": ["urn:geant:helmholtz.de:group:HIFIS#login.helmholtz.de"],
            # present under the default key but must be ignored:
            "eduperson_entitlement": [],
        }
        self.assertTrue(self.backend.auth_allowed(response, {}))
        self.assertFalse(self.backend.auth_allowed({"entitlements": []}, {}))

    def test_entitlements_not_allowed(self) -> None:
        self.backend.ALLOWED_ENTITLEMENTS = [
            "urn:geant:helmholtz.de:group:some-other-group#login.helmholtz.de"
        ]
        self.assertEqual(
            self.backend.entitlement_allowed(
                ["urn:geant:helmholtz.de:group:HIFIS#login.helmholtz.de"]
            ),
            False,
        )
