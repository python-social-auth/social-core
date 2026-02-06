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

from .oauth import BaseOAuth2


class AzureADOAuth2(BaseOAuth2):
    name = "azuread-oauth2"
    SCOPE_SEPARATOR = " "
    BASE_URL = "https://{authority_host}/{tenant_id}"
    AUTHORIZATION_URL = "{base_url}/oauth2/authorize"
    ACCESS_TOKEN_URL = "{base_url}/oauth2/token"
    REDIRECT_STATE = False
    DEFAULT_SCOPE = ["openid", "profile", "user_impersonation", "email"]
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

        try:
            decoded_id_token = jwt.decode(id_token, options={"verify_signature": False})
        except (jwt.DecodeError, jwt.ExpiredSignatureError) as de:
            raise AuthTokenError(self, de) from de
        return decoded_id_token

    def auth_extra_arguments(self):
        """Return extra arguments needed on auth process. The defaults can be
        overridden by GET parameters."""
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
    DEFAULT_SCOPE = ["User.Read profile openid email"]
