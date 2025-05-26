from social_core.backends.egi_checkin import EGICheckinOpenIdConnect

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import OpenIdConnectTest


class EGICheckinOpenIdConnectTest(
    OpenIdConnectTest[EGICheckinOpenIdConnect], BaseAuthUrlTestMixin
):
    backend_path = "social_core.backends.egi_checkin.EGICheckinOpenIdConnect"
    issuer = "https://aai.egi.eu/auth/realms/egi"
    openid_config_body = """
    {
       "issuer": "https://aai.egi.eu/auth/realms/egi",
       "authorization_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/auth",
       "token_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/token",
       "introspection_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/token/introspect",
       "userinfo_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/userinfo",
       "end_session_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/logout",
       "frontchannel_logout_session_supported": true,
       "frontchannel_logout_supported": true,
       "jwks_uri": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/certs",
       "check_session_iframe": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/login-status-iframe.html",
       "grant_types_supported": [
           "authorization_code",
           "implicit",
           "refresh_token",
           "password",
           "client_credentials",
           "urn:ietf:params:oauth:grant-type:device_code",
           "urn:openid:params:grant-type:ciba",
           "urn:ietf:params:oauth:grant-type:token-exchange"
       ],
       "acr_values_supported": ["0", "1"],
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
       "subject_types_supported": ["public", "pairwise"],
       "id_token_signing_alg_values_supported": [
           "PS384",
           "ES384",
           "RS384",
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
           "ES384",
           "RS384",
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
           "ES384",
           "RS384",
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
       "registration_endpoint": "https://aai.egi.eu/auth/realms/egi/clients-registrations/openid-connect",
       "token_endpoint_auth_methods_supported": [
           "private_key_jwt",
           "client_secret_basic",
           "client_secret_post",
           "tls_client_auth",
           "client_secret_jwt"
       ],
       "token_endpoint_auth_signing_alg_values_supported": [
           "PS384",
           "ES384",
           "RS384",
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
           "ES384",
           "RS384",
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
           "ES384",
           "RS384",
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
           "acr",
           "cert_entitlement",
           "eduperson_assurance",
           "eduperson_entitlement",
           "eduperson_scoped_affiliation",
           "eduperson_unique_id",
           "email",
           "email_verified",
           "family_name",
           "given_name",
           "name",
           "orcid",
           "preferred_username",
           "ssh_public_key",
           "sub",
           "voperson_external_affiliation",
           "voperson_id",
           "voperson_verified_email"
       ],
       "claim_types_supported": ["normal"],
       "claims_parameter_supported": true,
       "scopes_supported": [
           "openid",
           "voperson_external_affiliation",
           "email",
           "orcid",
           "aarc",
           "cert_entitlement",
           "eduperson_scoped_affiliation",
           "voperson_id",
           "ssh_public_key",
           "profile",
           "offline_access",
           "eduperson_unique_id",
           "eduperson_entitlement"
       ],
       "request_parameter_supported": true,
       "request_uri_parameter_supported": true,
       "require_request_uri_registration": true,
       "code_challenge_methods_supported": ["plain", "S256"],
       "tls_client_certificate_bound_access_tokens": true,
       "revocation_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/revoke",
       "revocation_endpoint_auth_methods_supported": [
           "private_key_jwt",
           "client_secret_basic",
           "client_secret_post",
           "tls_client_auth",
           "client_secret_jwt"
       ],
       "revocation_endpoint_auth_signing_alg_values_supported": [
           "PS384",
           "ES384",
           "RS384",
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
       "device_authorization_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/auth/device",
       "backchannel_token_delivery_modes_supported": ["poll", "ping"],
       "backchannel_authentication_request_signing_alg_values_supported": [
           "PS384",
           "ES384",
           "RS384",
           "ES256",
           "RS256",
           "ES512",
           "PS256",
           "PS512",
           "RS512"
       ],
       "require_pushed_authorization_requests": false,
       "mtls_endpoint_aliases": {
           "token_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/token",
           "revocation_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/revoke",
           "introspection_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/token/introspect",
           "device_authorization_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/auth/device",
           "registration_endpoint": "https://aai.egi.eu/auth/realms/egi/clients-registrations/openid-connect",
           "userinfo_endpoint": "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/userinfo"
       }
    }
    """

    def test_do_not_override_endpoint(self):
        self.backend.OIDC_ENDPOINT = self.issuer
        self.assertEqual(self.backend.oidc_endpoint(), self.issuer)

    def test_checkin_env_prod(self):
        self.assertEqual(
            self.backend.oidc_endpoint(), "https://aai.egi.eu/auth/realms/egi"
        )

    def test_checkin_env_demo(self):
        self.backend.CHECKIN_ENV = "demo"
        self.assertEqual(
            self.backend.oidc_endpoint(), "https://aai-demo.egi.eu/auth/realms/egi"
        )

    def test_checkin_env_dev(self):
        self.backend.CHECKIN_ENV = "dev"
        self.assertEqual(
            self.backend.oidc_endpoint(), "https://aai-dev.egi.eu/auth/realms/egi"
        )

    def test_entitlements_empty(self):
        self.assertEqual(self.backend.entitlement_allowed([]), True)

    def test_entitlements_allowed(self):
        self.backend.ALLOWED_ENTITLEMENTS = ["foo", "baz"]
        self.assertEqual(self.backend.entitlement_allowed(["foo", "bar"]), True)

    def test_entitlements_not_allowed(self):
        self.backend.ALLOWED_ENTITLEMENTS = ["baz"]
        self.assertEqual(self.backend.entitlement_allowed(["foo"]), False)
