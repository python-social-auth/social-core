"""
Copyright (c) 2015 Microsoft Open Technologies, Inc.

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Azure AD OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/azuread.html
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, cast

import jwt

from social_core.exceptions import AuthMissingParameter, AuthTokenError
from social_core.utils import cache

from .oauth import BaseOAuth2


class AzureADOAuth2(BaseOAuth2):
    name = "azuread-oauth2"
    SCOPE_SEPARATOR = " "
    BASE_URL = "https://{authority_host}/{tenant_id}"
    AUTHORIZATION_URL = "{base_url}/oauth2/authorize"
    ACCESS_TOKEN_URL = "{base_url}/oauth2/token"
    OPENID_CONFIGURATION_URL = "{base_url}/.well-known/openid-configuration"
    REDIRECT_STATE = False
    DEFAULT_SCOPE = ["openid", "profile", "user_impersonation", "email"]
    JWT_ALGORITHMS = ["RS256"]
    EXTRA_DATA = [
        ("access_token", "access_token"),
        ("id_token", "id_token"),
        ("refresh_token", "refresh_token"),
        ("expires_in", "expires_in"),
        ("expires_on", "expires_on"),
        ("not_before", "not_before"),
        ("given_name", "first_name"),
        ("family_name", "last_name"),
        ("token_type", "token_type"),
    ]

    @property
    def authority_host(self):
        return self.setting("AUTHORITY_HOST", "login.microsoftonline.com")

    @property
    def tenant_id(self) -> str:
        return "common"

    @property
    def base_url(self) -> str:
        return self.BASE_URL.format(
            authority_host=self.authority_host, tenant_id=self.tenant_id
        )

    def get_authorization_url_format(self) -> dict[str, str]:
        return {"base_url": self.base_url}

    def get_access_token_url_format(self) -> dict[str, str]:
        return {"base_url": self.base_url}

    def openid_configuration_url(self) -> str:
        url = cast(
            "str",
            self.setting("OPENID_CONFIGURATION_URL", self.OPENID_CONFIGURATION_URL),
        )
        return url.format(
            authority_host=self.authority_host,
            base_url=self.base_url,
            tenant_id=self.tenant_id,
        )

    @cache(ttl=86400)
    def get_openid_configuration(self, url: str) -> dict[str, Any]:
        return self.get_json(url)

    def openid_configuration(self) -> dict[str, Any]:
        configuration = self.get_openid_configuration(self.openid_configuration_url())
        return cast("dict[str, Any]", configuration)

    def jwks_uri(self) -> str:
        uri = self.setting("JWKS_URI") or self.openid_configuration().get("jwks_uri")
        if not isinstance(uri, str):
            raise AuthMissingParameter(self, "jwks_uri")
        return uri

    @cache(ttl=86400)
    def get_jwks_keys_for_uri(self, uri: str) -> list[dict[str, Any]]:
        jwks = self.get_json(uri)
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise AuthMissingParameter(self, "keys")
        return cast("list[dict[str, Any]]", keys)

    def get_jwks_keys(self) -> list[dict[str, Any]]:
        return self.get_jwks_keys_for_uri(self.jwks_uri())

    def get_user_id(self, details, response):
        """Use upn as unique id"""
        upn = response.get("upn")
        if upn is None:
            raise AuthMissingParameter(self, "upn")
        return upn

    def get_user_details(self, response):
        """Return user details from Azure AD account"""
        fullname, first_name, last_name = (
            response.get("name", ""),
            response.get("given_name", ""),
            response.get("family_name", ""),
        )
        return {
            "username": fullname,
            "email": response.get("email", response.get("upn")),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        response = kwargs.get("response")
        if response and response.get("id_token"):
            id_token = response.get("id_token")
        else:
            id_token = access_token

        return self.validate_and_return_id_token(id_token)

    def get_unverified_claims(self, id_token: str) -> dict[str, Any]:
        try:
            return jwt.decode(
                id_token,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_iss": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError as error:
            raise AuthTokenError(self, error) from error

    def resolve_tenant_issuer(
        self, issuer: str, claims: dict[str, Any], parameter: str
    ) -> str:
        if "{tenantid}" not in issuer and "{tenantId}" not in issuer:
            return issuer

        tenant_id = claims.get("tid")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise AuthMissingParameter(self, parameter)
        return issuer.replace("{tenantid}", tenant_id).replace("{tenantId}", tenant_id)

    def get_id_token_issuer(self, claims: dict[str, Any]) -> str:
        issuer = self.openid_configuration().get("issuer")
        if not isinstance(issuer, str):
            raise AuthMissingParameter(self, "issuer")
        return self.resolve_tenant_issuer(issuer, claims, "tid")

    def get_id_token_key(self, id_token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as error:
            raise AuthTokenError(self, error) from error

        key_id = header.get("kid")
        if not key_id:
            raise AuthMissingParameter(self, "kid")

        for key in self.get_jwks_keys():
            if key.get("kid") == key_id:
                return key

        cast("Any", self.get_jwks_keys_for_uri).invalidate()
        for key in self.get_jwks_keys():
            if key.get("kid") == key_id:
                return key
        raise AuthTokenError(self, "Signature key not found")

    def validate_key_issuer(self, key: dict[str, Any], claims: dict[str, Any]) -> None:
        key_issuer = key.get("issuer")
        if not isinstance(key_issuer, str):
            return

        expected_issuer = self.resolve_tenant_issuer(key_issuer, claims, "tid")
        if expected_issuer != claims.get("iss"):
            raise AuthTokenError(self, "Token issuer does not match signing key issuer")

    def get_jwt_algorithms(self) -> list[str]:
        return cast("list[str]", self.setting("JWT_ALGORITHMS", self.JWT_ALGORITHMS))

    def validate_and_return_id_token(self, id_token: str) -> dict[str, Any]:
        unverified_claims = self.get_unverified_claims(id_token)
        key = self.get_id_token_key(id_token)
        self.validate_key_issuer(key, unverified_claims)

        if "alg" not in key:
            key = {**key, "alg": self.get_jwt_algorithms()[0]}

        try:
            return jwt.decode(
                id_token,
                key=jwt.PyJWK(key).key,
                algorithms=self.get_jwt_algorithms(),
                audience=self.setting("KEY"),
                issuer=self.get_id_token_issuer(unverified_claims),
                leeway=cast("int", self.setting("JWT_LEEWAY", default=0)),
            )
        except jwt.PyJWTError as error:
            raise AuthTokenError(self, error) from error

    def auth_extra_arguments(self):
        """Return extra arguments needed on auth process."""
        extra_arguments = super().auth_extra_arguments()
        resource = self.setting("RESOURCE")
        if resource:
            extra_arguments.update({"resource": resource})
        return extra_arguments

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Return access_token and extra defined names to store in
        extra_data field"""
        data = super().extra_data(user, uid, response, details, pipeline_kwargs)
        data["resource"] = self.setting("RESOURCE")
        return data

    def refresh_token_params(self, token, *args, **kwargs):
        client_secret = cast("str | None", self.setting("SECRET"))
        params = {
            "client_id": self.setting("KEY"),
            "refresh_token": token,
            "grant_type": "refresh_token",
            "resource": self.setting("RESOURCE"),
        }

        if client_secret:
            params["client_secret"] = client_secret
            return params

        assertion = self.client_assertion(required=True)
        params.update(
            {
                "client_assertion_type": self.client_assertion_type(),
                "client_assertion": assertion,
            }
        )

        return params

    def get_auth_token(self, user_id):
        """Return the access token for the given user, after ensuring that it
        has not expired, or refreshing it if so."""
        user = self.get_user(user_id=user_id)
        access_token = user.social_user.access_token
        expires_on = user.social_user.extra_data["expires_on"]
        if expires_on <= int(time.time()):
            new_token_response = self.refresh_token(token=access_token)
            access_token = new_token_response["access_token"]
        return access_token

    def auth_complete_params(self, state=None):
        params = super().auth_complete_params(state)
        if params.get("client_secret"):
            return params

        assertion = self.client_assertion(required=True)
        params.update(
            {
                "client_assertion_type": self.client_assertion_type(),
                "client_assertion": assertion,
            }
        )
        return params

    def client_assertion(self, *, required: bool = False) -> str | None:
        if cast("str | None", self.setting("SECRET")):
            return None

        assertion = self.setting("CLIENT_ASSERTION")
        if assertion:
            return assertion

        token_path = (
            os.environ.get(
                "OAUTH2_FEDERATED_TOKEN_FILE"
            )  # supports OAUTH2_ naming convention
            or os.environ.get("AZURE_FEDERATED_TOKEN_FILE")  # canonical name
            or self.setting("FEDERATED_TOKEN_FILE")
        )
        if not token_path:
            if required:
                raise AuthMissingParameter(self, "client_assertion")
            return None

        try:
            assertion = Path(token_path).read_text(encoding="utf-8").strip()
        except OSError as error:
            if required:
                raise AuthMissingParameter(self, "client_assertion") from error
            return None

        if not assertion:
            if required:
                raise AuthMissingParameter(self, "client_assertion")
            return None

        return assertion

    def client_assertion_type(self) -> str:
        return cast(
            "str",
            self.setting(
                "CLIENT_ASSERTION_TYPE",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
        )


class AzureADOAuth2V2(AzureADOAuth2):
    """Version of the AzureADOAuth2 backend that uses the v2.0 API endpoints,
    supporting users with personal Microsoft accounts, if the app settings
    allow them."""

    name = "azuread-oauth2-v2"
    AUTHORIZATION_URL = "{base_url}/oauth2/v2.0/authorize"
    ACCESS_TOKEN_URL = "{base_url}/oauth2/v2.0/token"
    OPENID_CONFIGURATION_URL = "{base_url}/v2.0/.well-known/openid-configuration"
    DEFAULT_SCOPE = ["User.Read profile openid email"]
