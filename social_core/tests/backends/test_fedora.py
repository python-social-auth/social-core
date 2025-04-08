# pyright: reportAttributeAccessIssue=false

import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .test_open_id_connect import OpenIdConnectTestMixin


class FedoraOpenIdConnectTest(OpenIdConnectTestMixin, OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.fedora.FedoraOpenIdConnect"
    user_data_url = "https://id.fedoraproject.org/openidc/UserInfo"
    issuer = "https://id.fedoraproject.org/openidc/"
    openid_config_body = json.dumps(
        {
            "issuer": "https://id.fedoraproject.org/openidc/",
            "authorization_endpoint": "https://id.fedoraproject.org/openidc/Authorization",
            "token_endpoint": "https://id.fedoraproject.org/openidc/Token",
            "token_introspection_endpoint": "https://id.fedoraproject.org/openidc/TokenInfo",
            "introspection_endpoint": "https://id.fedoraproject.org/openidc/TokenInfo",
            "userinfo_endpoint": "https://id.fedoraproject.org/openidc/UserInfo",
            "jwks_uri": "https://id.fedoraproject.org/openidc/Jwks",
            "scopes_supported": [
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "https://id.fedoraproject.org/scope/groups",
                "https://id.fedoraproject.org/scope/agreements",
                "https://id.fedoraproject.org/scope/fas-attributes",
                "https://github.com/jmflinuxtx/kerneltest-harness/oidc/upload_test_run",
                "https://src.fedoraproject.org/push",
                "https://waiverdb.fedoraproject.org/oidc/create-waiver",
                "https://fedoraproject.org/wiki/api",
            ],
            "response_types_supported": ["code", "id_token", "token", "token id_token"],
            "response_modes_supported": [
                "query",
                "fragment",
                "form_post",
                "oob",
                "none",
            ],
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "refresh_token",
            ],
            "acr_values_supported": ["0"],
            "subject_types_supported": ["pairwise", "public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "id_token_encryption_alg_values_supported": [],
            "id_token_encryption_enc_values_supported": [],
            "userinfo_signing_alg_values_supported": ["RS256"],
            "userinfo_encryption_alg_values_supported": [],
            "userinfo_encryption_enc_values_supported": [],
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
                "PS512",
                "EdDSA",
                "ES256K",
                "none",
            ],
            "request_object_encryption_alg_values_supported": [],
            "request_object_encryption_enc_values_supported": [],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
            "display_values_supported": ["page", "popup"],
            "claim_types_supported": ["normal"],
            "claims_supported": [
                "sub",
                "name",
                "given_name",
                "family_name",
                "middle_name",
                "nickname",
                "preferred_username",
                "profile",
                "picture",
                "website",
                "email",
                "email_verified",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "phone_number",
                "phone_number_verified",
                "address",
                "updated_at",
            ],
            "service_documentation": "https://fedoraproject.org/wiki/Infrastructure/Authentication/",
            "ui_locales_supported": ["en"],
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "require_request_uri_registration": False,
            "op_policy_uri": "https://fedoraproject.org/wiki/Legal:PrivacyPolicy/",
            "op_tos_uri": "https://fedoraproject.org/wiki/Legal:PrivacyPolicy/",
        }
    )
