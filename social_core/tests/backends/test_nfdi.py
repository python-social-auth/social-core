import json
from typing import cast

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest

OIDC_CONFIG_ACADEMIC_ID = """
    {
      "issuer": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud",
      "authorization_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/auth",
      "token_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/token",
      "introspection_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/token/introspect",
      "userinfo_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/userinfo",
      "end_session_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/logout",
      "frontchannel_logout_session_supported": true,
      "frontchannel_logout_supported": true,
      "jwks_uri": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/certs",
      "check_session_iframe": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/login-status-iframe.html",
      "grant_types_supported": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "client_credentials",
        "urn:openid:params:grant-type:ciba",
        "urn:ietf:params:oauth:grant-type:device_code"
      ],
      "acr_values_supported": [
        "0",
        "1"
      ],
      "response_types_supported": [
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
      ],
      "subject_types_supported": [
        "public",
        "pairwise"
      ],
      "id_token_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "id_token_encryption_alg_values_supported": [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5"
      ],
      "id_token_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512"
      ],
      "userinfo_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
        "none"
      ],
      "userinfo_encryption_alg_values_supported": [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5"
      ],
      "userinfo_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512"
      ],
      "request_object_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
        "none"
      ],
      "request_object_encryption_alg_values_supported": [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5"
      ],
      "request_object_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512"
      ],
      "response_modes_supported": [
        "query",
        "fragment",
        "form_post",
        "query.jwt",
        "fragment.jwt",
        "form_post.jwt",
        "jwt"
      ],
      "registration_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/clients-registrations/openid-connect",
      "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
      ],
      "token_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "introspection_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
      ],
      "introspection_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "authorization_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "authorization_encryption_alg_values_supported": [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5"
      ],
      "authorization_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512"
      ],
      "claims_supported": [
        "aud",
        "sub",
        "iss",
        "auth_time",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "email",
        "acr"
      ],
      "claim_types_supported": [
        "normal"
      ],
      "claims_parameter_supported": true,
      "scopes_supported": [
        "initials",
        "address",
        "goeidToSub",
        "MPGR_entryUUID_as_preferred_username",
        "org",
        "userservices",
        "accounttype",
        "oxUserId",
        "basic",
        "employeenumber",
        "syncAndShareInstance",
        "phone",
        "roles",
        "gwdg-internal-role",
        "microprofile-jwt",
        "oxContextId",
        "emailCS",
        "goesternMatrikelnummer",
        "vpngroupsNetworkroles",
        "subVPNUserType",
        "acr",
        "owncloud",
        "displayName_to_preferred_username",
        "usRoles",
        "profile",
        "goeId",
        "offline_access",
        "userContextId",
        "goesternSAMAccountName",
        "goesternQuellSystem",
        "userServices_to_authorities",
        "memberOfGoeId",
        "openid",
        "email",
        "nfdi_attributes",
        "memberofdisplayname",
        "syncAttribute1",
        "prefuid",
        "AuthnContextClassRef",
        "web-origins",
        "mailAddresses",
        "uniElectionHash"
      ],
      "request_parameter_supported": true,
      "request_uri_parameter_supported": true,
      "require_request_uri_registration": true,
      "code_challenge_methods_supported": [
        "plain",
        "S256"
      ],
      "tls_client_certificate_bound_access_tokens": true,
      "revocation_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/revoke",
      "revocation_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
      ],
      "revocation_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "backchannel_logout_supported": true,
      "backchannel_logout_session_supported": true,
      "device_authorization_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/auth/device",
      "backchannel_token_delivery_modes_supported": [
        "poll",
        "ping"
      ],
      "backchannel_authentication_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/ext/ciba/auth",
      "backchannel_authentication_request_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "ES256",
        "RS256",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "require_pushed_authorization_requests": false,
      "pushed_authorization_request_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/ext/par/request",
      "mtls_endpoint_aliases": {
        "token_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/token",
        "revocation_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/revoke",
        "introspection_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/token/introspect",
        "device_authorization_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/auth/device",
        "registration_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/clients-registrations/openid-connect",
        "userinfo_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/userinfo",
        "pushed_authorization_request_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/ext/par/request",
        "backchannel_authentication_endpoint": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud/protocol/openid-connect/ext/ciba/auth"
      },
      "authorization_response_iss_parameter_supported": true
    }
"""

OIDC_CONFIG_DIDMOS = """
    {
      "version": "3.0",
      "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post"
      ],
      "claims_parameter_supported": true,
      "request_parameter_supported": false,
      "request_uri_parameter_supported": false,
      "require_request_uri_registration": false,
      "grant_types_supported": [
        "authorization_code",
        "implicit"
      ],
      "frontchannel_logout_supported": false,
      "frontchannel_logout_session_supported": false,
      "backchannel_logout_supported": false,
      "backchannel_logout_session_supported": false,
      "issuer": "https://auth.didmos.nfdi-aai.de",
      "authorization_endpoint": "https://auth.didmos.nfdi-aai.de/OIDC/authorization",
      "jwks_uri": "https://auth.didmos.nfdi-aai.de/OIDC/jwks",
      "response_types_supported": [
        "code",
        "id_token token"
      ],
      "id_token_signing_alg_values_supported": [
        "RS256"
      ],
      "response_modes_supported": [
        "fragment",
        "query"
      ],
      "subject_types_supported": [
        "public"
      ],
      "claim_types_supported": [
        "normal"
      ],
      "claims_supported": [
        "email",
        "sub",
        "preferred_username",
        "name",
        "given_name",
        "family_name",
        "schac_home_organization",
        "eduperson_scoped_affiliation",
        "voperson_external_affiliation",
        "eduperson_assurance",
        "voperson_id",
        "eduperson_unique_id",
        "voperson_verified_email",
        "entitlements",
        "voperson_policy_agreement",
        "orcid",
        "voperson_external_id",
        "eduperson_principal_name",
        "eduperson_target_id",
        "session_id"
      ],
      "scopes_supported": [
        "eduperson_assurance",
        "schac_home_organization",
        "profile",
        "voperson_policy_agreement",
        "voperson_external_affiliation",
        "eduperson_target_id",
        "eduperson_unique_id",
        "voperson_id",
        "email",
        "voperson_verified_email",
        "entitlements",
        "openid",
        "voperson_external_id",
        "eduperson_scoped_affiliation",
        "orcid"
      ],
      "token_endpoint": "https://auth.didmos.nfdi-aai.de/OIDC/token",
      "registration_endpoint": "https://auth.didmos.nfdi-aai.de/OIDC/registration",
      "end_session_endpoint": "https://auth.didmos.nfdi-aai.de/didmos/logout",
      "code_challenge_methods_supported": [
        "S256",
        "S384",
        "S512"
      ],
      "userinfo_endpoint": "https://auth.didmos.nfdi-aai.de/OIDC/userinfo"
    }
"""

OIDC_CONFIG_REGAPP = """
    {
      "response_types_supported": [
        "code",
        "id_token",
        "code id_token"
      ],
      "request_uri_parameter_supported": true,
      "introspection_endpoint": "https://regapp.nfdi-aai.de/oidc/realms/nfdi/protocol/openid-connect/tokeninfo",
      "grant_types_supported": [
        "authorization_code",
        "refresh_token"
      ],
      "scopes_supported": [
        "openid",
        "profile",
        "email"
      ],
      "issuer": "https://regapp.nfdi-aai.de/oidc/realms/nfdi",
      "authorization_endpoint": "https://regapp.nfdi-aai.de/oidc/realms/nfdi/protocol/openid-connect/auth",
      "userinfo_endpoint": "https://regapp.nfdi-aai.de/oidc/realms/nfdi/protocol/openid-connect/userinfo",
      "claims_supported": [
        "sub",
        "iss",
        "aud",
        "mail",
        "name"
      ],
      "jwks_uri": "https://regapp.nfdi-aai.de/oidc/realms/nfdi/protocol/openid-connect/certs",
      "subject_types_supported": [
        "pairwise",
        "public"
      ],
      "id_token_signing_alg_values_supported": [
        "RS256"
      ],
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "private_key_jwt",
        "client_secret_basic"
      ],
      "response_modes_supported": [
        "query",
        "fragment"
      ],
      "token_endpoint": "https://regapp.nfdi-aai.de/oidc/realms/nfdi/protocol/openid-connect/token"
    }
"""

OIDC_CONFIG_UNITY = """
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

OIDC_CONFIG_UNITY_PUNCH = """
    {
      "authorization_endpoint": "https://login.helmholtz.de/punch-oauth2-as/oauth2-authz",
      "token_endpoint": "https://login.helmholtz.de/punch-oauth2/token",
      "introspection_endpoint": "https://login.helmholtz.de/punch-oauth2/introspect",
      "revocation_endpoint": "https://login.helmholtz.de/punch-oauth2/revoke",
      "issuer": "https://login.helmholtz.de/punch-oauth2",
      "jwks_uri": "https://login.helmholtz.de/punch-oauth2/jwk",
      "scopes_supported": [
        "openid",
        "display_name",
        "sn",
        "single-logout",
        "offline_access",
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
      "userinfo_endpoint": "https://login.helmholtz.de/punch-oauth2/userinfo",
      "id_token_signing_alg_values_supported": [
        "RS256",
        "ES256"
      ]
    }
"""


class NFDIOpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.nfdi.HelmholtzOpenIdConnect"
    issuer = "https://login.helmholtz.de/oauth2"
    openid_config_body = OIDC_CONFIG_UNITY
    expected_username = "donald"
    user_data_url = "https://login.helmholtz.de/oauth2/userinfo"
    user_data_body = json.dumps(
        {
            "display_name": "Donald Duck",
            "eduperson_assurance": [
                "https://refeds.org/assurance",
                "https://refeds.org/assurance/ID/unique",
                "https://refeds.org/assurance/ID/eppn-unique-no-reassign",
                "https://refeds.org/assurance/ATP/ePA-1d",
                "https://refeds.org/assurance/ATP/ePA-1m",
                "https://refeds.org/assurance/IAP/local-enterprise",
                "https://refeds.org/assurance/IAP/low",
                "https://refeds.org/assurance/IAP/medium",
                "https://refeds.org/assurance/profile/cappuccino",
                "https://aarc-project.eu/policy/authn-assurance/assam",
            ],
            "eduperson_entitlement": [
                "urn:mace:dir:entitlement:common-lib-terms",
                "http://bwidm.de/entitlement/bwLSDF-SyncShare",
                "urn:canard:mouseton.edu:group:KIT#login.mouseton.edu",
                "urn:canard:h-df.de:group:m-team:feudal-developers#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:Arbeitskreise#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:HIFIS:Associates#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:Arbeitskreise:AG IT Services#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:Helmholtz-member#login.mouseton.edu",
                "urn:canard:h-df.de:group:m-team#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:Helmholtz-all#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:HIFIS#login.mouseton.edu",
            ],
            "eduperson_principal_name": "lo0018@duckburg.edu",
            "eduperson_scoped_affiliation": [
                "employee@login.mouseton.edu",
                "member@login.mouseton.edu",
            ],
            "eduperson_unique_id": "42234223422342234223422342234223@login.mouseton.edu",
            "email": "donald.hardt@duckburg.edu",
            "email_verified": True,
            "entitlements": [
                "urn:mace:dir:entitlement:common-lib-terms",
                "http://duckburg.edu/entitlement/sync-and-share",
                "urn:canard:mouseton.edu:group:KIT#login.mouseton.edu",
                "urn:canard:duckburg.edu:group:m-team:developers#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:Workgroup:IT Services#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:mouseton-member#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:m-team#login.mouseton.edu",
                "urn:canard:mouseton.edu:group:mouseton-all#login.mouseton.edu",
            ],
            "family_name": "Duck",
            "given_name": "Donald",
            "iss": "https://login.mouseton.edu/oauth2",
            "name": "Donald Duck",
            "org_domain": "duckburg.edu",
            "preferred_username": "donald",
            "sn": "Duck",
            "ssh_public_key": "ssh-ed25519 AAAAC3N4224224224224224224224224224224224224224224224224224224223ym/ donald@home\n",
            "sub": "42234223-4223-4223-4223-422342234223",
            "voperson_external_affiliation": [
                "employee@duckburg.edu",
                "faculty@duckburg.edu",
                "member@duckburg.edu",
            ],
            "voperson_id": "42234223422342234223422342234223@login.mouseton.edu",
        }
    )

    def test_do_not_override_endpoint(self) -> None:
        self.backend.OIDC_ENDPOINT = self.issuer
        self.assertEqual(self.backend.oidc_endpoint(), self.issuer)

    def test_entitlements_empty(self) -> None:
        self.assertEqual(self.backend.entitlement_allowed([]), True)

    def test_entitlements_allowed(self) -> None:
        self.backend.ALLOWED_ENTITLEMENTS = ["foo", "baz"]
        self.assertEqual(self.backend.entitlement_allowed(["foo", "bar"]), True)

    def test_entitlements_not_allowed(self) -> None:
        self.backend.ALLOWED_ENTITLEMENTS = ["baz"]
        self.assertEqual(self.backend.entitlement_allowed(["foo"]), False)

    def test_get_user_details(self) -> None:
        testdata = self.backend.get_user_details(
            json.loads(cast("str", self.user_data_body))
        )
        self.assertEqual(testdata["username"], "donald")
        self.assertEqual(testdata["email"], "donald.hardt@duckburg.edu")
        self.assertEqual(testdata["fullname"], "Donald Duck")
        self.assertEqual(testdata["first_name"], "Donald")
        self.assertEqual(testdata["last_name"], "Duck")

    def test_login(self) -> None:
        self.do_login()
