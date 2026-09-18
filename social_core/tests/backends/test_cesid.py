from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest


class CesidOpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.cesid.CesidOpenIdConnect"
    issuer = "https://login.cesid.cesnet.cz/cas/oidc"
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
    "authorization_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/oidcAuthorize",
    "authorization_response_iss_parameter_supported": false,
    "backchannel_authentication_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/oidcCiba",
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
        "idp_identifier",
        "entitlements",
        "eduperson_entitlement_extended"
    ],
    "code_challenge_methods_supported": [
        "plain",
        "S256"
    ],
    "device_authorization_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/oidcAccessToken",
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
    "end_session_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/oidcLogout",
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
    "introspection_endpoint": "https://tip.login.cesid.cesnet.cz/",
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
    "issuer": "https://login.cesid.cesnet.cz/cas/oidc",
    "jwks_uri": "https://login.cesid.cesnet.cz/cas/oidc/jwks",
    "native_sso_supported": true,
    "prompt_values_supported": [
        "none",
        "login",
        "consent"
    ],
    "pushed_authorization_request_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/oidcPushAuthorize",
    "registration_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/register",
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
    "revocation_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/revoke",
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
        "eduperson_entitlement_extended",
        "entitlements",
        "all_attributes"
    ],
    "subject_types_supported": [
        "public",
        "pairwise"
    ],
    "tls_client_certificate_bound_access_tokens": false,
    "token_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/oidcAccessToken",
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
    "userinfo_endpoint": "https://login.cesid.cesnet.cz/cas/oidc/oidcProfile",
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
    skip_invalid_at_hash = allow_invalid_at_hash = True
