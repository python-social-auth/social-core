import json

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest


class LifeScienceEoscOpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.lifescience_eosc.LifeScienceEoscOpenIdConnect"
    issuer = "https://login.aai.lifescience-ri.eu/cas/oidc"
    user_data_url = "https://login.aai.lifescience-ri.eu/cas/oidc/oidcProfile"
    openid_config_body = """
    {
        "DPopSigningAlgValuesSupported": [
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512"
        ],
        "acr_values_supported": [],
        "authorization_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/oidcAuthorize",
        "authorization_response_iss_parameter_supported": false,
        "backchannel_authentication_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/oidcCiba",
        "backchannel_authentication_request_signing_alg_values_supported": [
            "none",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES384",
            "ES512",
            "HS256",
            "HS384",
            "HS512"
        ],
        "backchannel_logout_session_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_token_delivery_modes_supported": [
            "poll",
            "ping",
            "push"
        ],
        "backchannel_user_code_parameter_supported": false,
        "claim_types_supported": [
            "normal"
        ],
        "claims_in_verified_claims_supported": null,
        "claims_parameter_supported": true,
        "claims_supported": [
            "sub",
            "email",
            "email_verified",
            "name",
            "family_name",
            "given_name",
            "preferred_username",
            "perun_api",
            "perun_admin",
            "perun_sub",
            "eduperson_entitlement",
            "fromidp_voPersonUniqueID",
            "fromidp_eduPersonUniqueId",
            "fromidp_eduPersonPrincipalName",
            "idp_identifier"
        ],
        "code_challenge_methods_supported": [
            "plain",
            "S256"
        ],
        "device_authorization_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/oidcAccessToken",
        "documents_supported": null,
        "documents_validation_methods_supported": null,
        "documents_verification_methods_supported": null,
        "dpop_signing_alg_values_supported": [
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512"
        ],
        "electronic_records_supported": null,
        "end_session_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/oidcLogout",
        "evidence_supported": null,
        "frontchannel_logout_session_supported": true,
        "frontchannel_logout_supported": true,
        "grant_types_supported": [
            "authorization_code",
            "password",
            "client_credentials",
            "refresh_token",
            "urn:openid:params:grant-type:ciba",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:uma-ticket"
        ],
        "id_token_encryption_alg_values_supported": [
            "RSA1_5",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "A128KW",
            "A192KW",
            "A256KW",
            "A128GCMKW",
            "A192GCMKW",
            "A256GCMKW",
            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW"
        ],
        "id_token_encryption_enc_values_supported": [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM"
        ],
        "id_token_signing_alg_values_supported": [
            "none",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES384",
            "ES512",
            "HS256",
            "HS384",
            "HS512"
        ],
        "introspection_encryption_alg_values_supported": [
            "RSA1_5",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "A128KW",
            "A192KW",
            "A256KW",
            "A128GCMKW",
            "A192GCMKW",
            "A256GCMKW",
            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW"
        ],
        "introspection_encryption_enc_values_supported": [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM"
        ],
        "introspection_endpoint": "https://tip.login.aai.lifescience-ri.eu/",
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic"
        ],
        "introspection_signing_alg_values_supported": [
            "none",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES384",
            "ES512",
            "HS256",
            "HS384",
            "HS512"
        ],
        "issuer": "https://login.aai.lifescience-ri.eu/cas/oidc",
        "jwks_uri": "https://login.aai.lifescience-ri.eu/cas/oidc/jwks",
        "native_sso_supported": true,
        "prompt_values_supported": [
            "none",
            "login",
            "consent"
        ],
        "pushed_authorization_request_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/oidcPushAuthorize",
        "registration_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/register",
        "request_object_encryption_alg_values_supported": [
            "RSA1_5",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "A128KW",
            "A192KW",
            "A256KW",
            "A128GCMKW",
            "A192GCMKW",
            "A256GCMKW",
            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW"
        ],
        "request_object_encryption_enc_values_supported": [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM"
        ],
        "request_object_signing_alg_values_supported": [
            "none",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES384",
            "ES512",
            "HS256",
            "HS384",
            "HS512"
        ],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "require_pushed_authorization_requests": false,
        "response_modes_supported": [
            "query",
            "fragment",
            "form_post",
            "query.jwt",
            "form_post.jwt",
            "fragment.jwt"
        ],
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "id_token token",
            "device_code"
        ],
        "revocation_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/revoke",
        "scopes_supported": [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
            "device_sso",
            "client_configuration_scope",
            "uma_authorization",
            "uma_protection",
            "client_registration_scope",
            "perun_api",
            "perun_admin",
            "perun_sub",
            "eduperson_entitlement",
            "all_attributes"
        ],
        "subject_types_supported": [
            "public",
            "pairwise"
        ],
        "tls_client_certificate_bound_access_tokens": false,
        "token_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/oidcAccessToken",
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "tls_client_auth"
        ],
        "trust_frameworks_supported": null,
        "userinfo_encryption_alg_values_supported": [
            "RSA1_5",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "A128KW",
            "A192KW",
            "A256KW",
            "A128GCMKW",
            "A192GCMKW",
            "A256GCMKW",
            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW"
        ],
        "userinfo_encryption_enc_values_supported": [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM"
        ],
        "userinfo_endpoint": "https://login.aai.lifescience-ri.eu/cas/oidc/oidcProfile",
        "userinfo_signing_alg_values_supported": [
            "none",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES384",
            "ES512",
            "HS256",
            "HS384",
            "HS512"
        ],
        "verified_claims_supported": true
    }
    """
    expected_username = "foo@lifescience-ri.eu"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "preferred_username": "foo@lifescience-ri.eu",
            "email": "foo@bar.com",
            "name": "Foo Bar",
        }
    )
    allow_invalid_at_hash = True

    def test_login(self) -> None:
        self.do_login()


    def test_get_user_details(self) -> None:
        response = {
            "preferred_username": "foo@lifescience-ri.eu",
            "email": "email@example.com",
            "name": "Foo Bar",
        }
        details = self.backend.get_user_details(response)
        self.assertEqual(
            details,
            {
                "username": "foo@lifescience-ri.eu",
                "email": "email@example.com",
                "fullname": "Foo Bar",
                "first_name": "Foo",
                "last_name": "Bar",
            },
        )

    def test_get_user_details_empty_name(self) -> None:
        response = {
            "preferred_username": "foo@lifescience-ri.eu",
            "email": "email@example.com",
        }
        details = self.backend.get_user_details(response)
        self.assertEqual(
            details,
            {
                "username": "foo@lifescience-ri.eu",
                "email": "email@example.com",
                "fullname": "",
                "first_name": "",
                "last_name": "",
            },
        )

    def test_get_user_details_custom_username_key(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_CESID_USERNAME_KEY": "preferred_username"}
        )
        response = {
            "eduperson_unique_id": "12345@cesnet.cz",
            "preferred_username": "foo@lifescience-ri.eu",
            "email": "email@example.com",
            "name": "Foo Bar",
        }
        details = self.backend.get_user_details(response)
        self.assertEqual(details["username"], "foo@lifescience-ri.eu")

    def test_extra_data(self) -> None:
        self.backend.id_token = {
            "iss": self.issuer,
            "sub": "12345",
            "aud": self.client_key,
        }
        response = {
            "expires_in": 3600,
            "refresh_token": "refresh-123",
            "id_token": "id-token-xyz",
            "other_tokens": ["token1", "token2"],
            "ignored_field": "ignore_me",
        }
        extra = self.backend.extra_data(
            user=None,
            uid="12345",
            response=response,
            details={},
            pipeline_kwargs={"is_new": True},
        )
        self.assertEqual(extra["expires_in"], 3600)
        self.assertEqual(extra["refresh_token"], "refresh-123")
        self.assertEqual(extra["id_token"], "id-token-xyz")
        self.assertEqual(extra["other_tokens"], ["token1", "token2"])
        self.assertNotIn("ignored_field", extra)

    def test_default_scope(self) -> None:
        self.assertEqual(self.backend.get_scope(), ["openid", "email"])

    def test_validate_at_hash(self) -> None:
        self.assertFalse(self.backend.VALIDATE_AT_HASH)