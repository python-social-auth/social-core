"""
Sign In With Apple authentication backend.

Docs:
    * https://developer.apple.com/documentation/signinwithapplerestapi
    * https://developer.apple.com/documentation/signinwithapplerestapi/tokenresponse

Settings:
    * `TEAM` - your team id;
    * `KEY` - your key id;
    * `CLIENT` - your client id;
    * `AUDIENCE` - a list of authorized client IDs, defaults to [CLIENT].
                   Use this if you need to accept both service and bundle id to
                   be able to login both via iOS and ie a web form.
    * `SECRET` - your secret key;
    * `SCOPE` (optional) - e.g. `['name', 'email']`;
    * `EMAIL_AS_USERNAME` - use apple email is username is set, use apple id
                            otherwise.
    * `AppleIdAuth.TOKEN_TTL_SEC` - time before JWT token expiration, seconds.
    * `SOCIAL_AUTH_APPLE_ID_INACTIVE_USER_LOGIN` - allow inactive users email to
                                                   login
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, cast

import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWTError

from social_core.backends.oauth import BaseOAuth2
from social_core.backends.utils import jwt_error
from social_core.exceptions import AuthResponseError

_USER_NAME_KEY = "_apple_user_name"

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class AppleIdAuth(BaseOAuth2):
    name = "apple-id"
    title = "Apple"
    icon = "apple.svg"

    JWK_URL = "https://appleid.apple.com/auth/keys"
    AUTHORIZATION_URL = "https://appleid.apple.com/auth/authorize"
    ACCESS_TOKEN_URL = "https://appleid.apple.com/auth/token"
    RESPONSE_MODE = None

    ID_KEY = "sub"
    TOKEN_KEY = "id_token"
    STATE_PARAMETER = True
    REDIRECT_STATE = False
    SCOPE_SEPARATOR = "%20"

    ID_TOKEN_ISSUER = "https://appleid.apple.com"
    TOKEN_AUDIENCE = "https://appleid.apple.com"
    TOKEN_TTL_SEC = 6 * 30 * 24 * 60 * 60

    def get_audience(self):
        client_id = self.setting("CLIENT")
        return self.setting("AUDIENCE", default=[client_id])

    def auth_params(self, *args, **kwargs):
        """
        Apple requires to set `response_mode` to `form_post` if `scope`
        parameter is passed.
        """
        params = super().auth_params(*args, **kwargs)
        if self.RESPONSE_MODE:
            params["response_mode"] = self.RESPONSE_MODE
        elif self.get_scope():
            params["response_mode"] = "form_post"
        return params

    def get_private_key(self) -> str:
        """
        Return contents of the private key file. Override this method to provide
        secret key from another source if needed.
        """
        return cast("str", self.setting("SECRET"))

    def generate_client_secret(self):
        now = int(time.time())
        client_id = self.data.get("client_id", self.setting("CLIENT"))
        team_id = self.setting("TEAM")
        key_id = self.setting("KEY")
        private_key = self.get_private_key()

        headers = {"kid": key_id}
        payload = {
            "iss": team_id,
            "iat": now,
            "exp": now + self.TOKEN_TTL_SEC,
            "aud": self.TOKEN_AUDIENCE,
            "sub": client_id,
        }

        return jwt.encode(payload, key=private_key, algorithm="ES256", headers=headers)

    def get_key_and_secret(self) -> tuple[str, str]:
        client_id = cast("str", self.data.get("client_id", self.setting("CLIENT")))
        client_secret = self.generate_client_secret()
        return client_id, client_secret

    def get_apple_jwk(self, kid=None) -> str:
        """
        Return a single Apple public key as JWK JSON.

        If ``kid`` is not provided, use the first key in the response.
        """
        response = self.get_json(url=self.JWK_URL, stage="token_validation")
        keys = response.get("keys") if isinstance(response, dict) else None

        if (
            not isinstance(keys, list)
            or not keys
            or any(not isinstance(key, dict) for key in keys)
        ):
            raise AuthResponseError(
                self,
                "Invalid jwk response",
                code="malformed_response",
                stage="token_validation",
            )

        if kid:
            key = next((key for key in keys if key.get("kid") == kid), None)
            if key is None:
                raise AuthResponseError(
                    self,
                    "Unable to find Apple public key",
                    code="malformed_response",
                    stage="token_validation",
                )
            return json.dumps(key)
        return json.dumps(keys[0])

    def decode_id_token(self, id_token):
        """
        Decode and validate JWT token from apple and return payload including
        user data.
        """
        if not id_token:
            raise AuthResponseError(
                self,
                "Missing id_token parameter",
                code="missing_claim",
                stage="token_validation",
            )

        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
            public_key = cast(
                "RSAPublicKey", RSAAlgorithm.from_jwk(self.get_apple_jwk(kid))
            )

            decoded = jwt.decode(
                id_token,
                key=public_key,
                audience=self.get_audience(),
                issuer=self.ID_TOKEN_ISSUER,
                algorithms=["RS256"],
            )
        except PyJWTError as error:
            raise jwt_error(self, error) from error

        return decoded

    def get_user_details(self, response):
        if _USER_NAME_KEY in response:
            name = response[_USER_NAME_KEY]
        else:
            name = json.loads(self.data.get("user", "{}")).get("name", {})
        fullname = ""
        first_name = name.get("firstName", "")
        last_name = name.get("lastName", "")

        email = response.get("email", "")
        apple_id = response.get(self.id_key(), "")
        # prevent updating User with empty strings
        user_details = {
            "fullname": fullname or None,
            "first_name": first_name or None,
            "last_name": last_name or None,
            "email": email,
        }
        if email and self.setting("EMAIL_AS_USERNAME"):
            user_details["username"] = email
        if apple_id and not self.setting("EMAIL_AS_USERNAME"):
            user_details["username"] = apple_id

        return user_details

    def do_auth(self, access_token, *args, **kwargs):
        response = kwargs.pop("response", None) or {}
        jwt_string = response.get(self.TOKEN_KEY) or access_token

        if not jwt_string:
            raise AuthResponseError(
                self,
                "Missing id_token parameter",
                code="missing_claim",
                stage="callback",
            )

        decoded_data = self.decode_id_token(jwt_string).copy()
        # Apple sends the name separately from the token. Preserve it before
        # the pipeline can pause and resume with a different request.
        decoded_data[_USER_NAME_KEY] = json.loads(self.data.get("user", "{}")).get(
            "name", {}
        )
        return super().do_auth(access_token, *args, response=decoded_data, **kwargs)
