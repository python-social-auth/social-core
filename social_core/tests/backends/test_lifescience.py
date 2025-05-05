import json

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest


class LifeScienceOpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.lifescience.LifeScienceOpenIdConnect"
    issuer = "https://login.aai.lifescience-ri.eu/oidc/"
    user_data_url = "https://login.aai.lifescience-ri.eu/oidc/userinfo"
    openid_config_body = """
    {
        "request_parameter_supported": true,
        "claims_parameter_supported": false,
        "introspection_endpoint": "https://login.aai.lifescience-ri.eu/oidc/introspect",
        "scopes_supported": [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
            "perun_api",
            "eduperson_principal_name",
            "country",
            "eduperson_assurance",
            "negotiator_api",
            "beacon_network_api",
            "beacon_api",
            "ssh_public_key",
            "crypt4ghPublicKeys",
            "gpgPublicKeys",
            "negotiator_monitoring",
            "eduperson_entitlement",
            "voperson_external_affiliation",
            "ga4gh_passport_v1",
            "perun_admin",
            "eduperson_orcid",
            "elixir_eduperson_unique_id",
            "elixir_eduperson_principal_name",
            "schac_home_organization",
            "eduperson_scoped_affiliation",
            "voperson_current_external_affiliation",
            "authenticating_entity",
            "minio_policies",
            "max_user_authentication_capability",
            "voperson_external_id",
            "eduperson_unique_id"
        ],
        "issuer": "https://login.aai.lifescience-ri.eu/oidc/",
        "acr_values_supported": [
            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "https://refeds.org/profile/sfa",
            "https://refeds.org/profile/mfa"
        ],
        "userinfo_encryption_enc_values_supported": [
            "XC20P",
            "A256CBC+HS512",
            "A256GCM",
            "A192GCM",
            "A128GCM",
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128CBC+HS256"
        ],
        "id_token_encryption_enc_values_supported": [
            "XC20P",
            "A256CBC+HS512",
            "A256GCM",
            "A192GCM",
            "A128GCM",
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128CBC+HS256"
        ],
        "authorization_endpoint": "https://login.aai.lifescience-ri.eu/oidc/authorize",
        "request_object_encryption_enc_values_supported": [
            "XC20P",
            "A256CBC+HS512",
            "A256GCM",
            "A192GCM",
            "A128GCM",
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128CBC+HS256"
        ],
        "device_authorization_endpoint": "https://login.aai.lifescience-ri.eu/oidc/devicecode",
        "userinfo_signing_alg_values_supported": [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
        ],
        "claims_supported": [
            "schac_home_organization",
            "sub",
            "country",
            "zoneinfo",
            "negotiator_monitoring",
            "voperson_external_affiliation",
            "birthdate",
            "beacon_api",
            "elixir_eduperson_unique_id",
            "gender",
            "preferred_username",
            "locale",
            "eduperson_principal_name",
            "eduperson_entitlement",
            "elixir_eduperson_principal_name",
            "minio_policies",
            "updated_at",
            "crypt4ghPublicKeys",
            "nickname",
            "eduperson_scoped_affiliation",
            "eduperson_unique_id",
            "voperson_current_external_affiliation",
            "email",
            "voperson_external_id",
            "website",
            "email_verified",
            "address",
            "profile",
            "phone_number_verified",
            "max_user_authentication_capability",
            "given_name",
            "middle_name",
            "picture",
            "ssh_public_key",
            "authenticating_entity",
            "beacon_network_api",
            "name",
            "phone_number",
            "eduperson_assurance",
            "perun_admin",
            "family_name",
            "ga4gh_passport_v1",
            "perun_api",
            "negotiator_api",
            "gpgPublicKeys",
            "eduperson_orcid"
        ],
        "claim_types_supported": [
            "normal"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none"
        ],
        "token_endpoint": "https://login.aai.lifescience-ri.eu/oidc/token",
        "response_types_supported": [
            "code",
            "token id_token"
        ],
            "request_uri_parameter_supported": false,
            "userinfo_encryption_alg_values_supported": [
            "RSA-OAEP-512",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
            "RSA-OAEP-384"
        ],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "end_session_endpoint": "https://login.aai.lifescience-ri.eu/oidc/endsession",
        "revocation_endpoint": "https://login.aai.lifescience-ri.eu/oidc/revoke",
        "userinfo_endpoint": "https://login.aai.lifescience-ri.eu/oidc/userinfo",
        "token_endpoint_auth_signing_alg_values_supported": [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
        ],
        "require_request_uri_registration": false,
        "code_challenge_methods_supported": [
            "plain",
            "S256",
            "none"
        ],
        "id_token_encryption_alg_values_supported": [
            "RSA-OAEP-512",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
            "RSA-OAEP-384"
        ],
        "jwks_uri": "https://login.aai.lifescience-ri.eu/oidc/jwk",
        "subject_types_supported": [
            "public"
        ],
        "id_token_signing_alg_values_supported": [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "none"
        ],
        "registration_endpoint": "https://login.aai.lifescience-ri.eu/oidc/register",
        "request_object_signing_alg_values_supported": [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
        ],
        "request_object_encryption_alg_values_supported": [
            "RSA-OAEP-512",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
            "RSA-OAEP-384"
        ]
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

    def test_login(self):
        self.do_login()
