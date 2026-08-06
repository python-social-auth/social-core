"""
Ping Auth OpenID Connect backend
"""

from typing import cast

import jwt
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidTokenError,
    PyJWTError,
)
from jwt.utils import base64url_decode

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthTokenError


class PingOpenIdConnect(OpenIdConnectAuth):
    name = "ping"
    # OIDC_ENDPOINT has the form 'https://auth.pingone.com/<APP ID>/as'
    OIDC_ENDPOINT = ""
    REDIRECT_STATE = False
    RESPONSE_TYPE = "code"
    USERNAME_KEY = "preferred_username"

    def find_valid_key(self, id_token):
        for key in self.get_jwks_keys():
            if "alg" not in key:
                key["alg"] = "RS256"
            rsakey = jwt.PyJWK(key)
            message, encoded_sig = id_token.rsplit(".", 1)
            decoded_sig = base64url_decode(encoded_sig.encode("utf-8"))
            if rsakey.Algorithm.verify(
                message.encode("utf-8"), rsakey.key, decoded_sig
            ):
                return key
        return None

    def decode_and_validate_id_token(self, id_token, access_token):
        """Validate a Ping ID token's signature and self-contained claims."""
        client_id, _client_secret = self.get_key_and_secret()

        try:
            key = self.find_valid_key(id_token)
        except PyJWTError as error:
            raise AuthTokenError(self, str(error)) from error

        if not key:
            raise AuthTokenError(self, "Signature verification failed")

        if "alg" not in key:
            key["alg"] = "RS256"

        try:
            rsakey = jwt.PyJWK(key)
            claims = jwt.decode(
                id_token,
                rsakey.key,
                algorithms=self.JWT_ALGORITHMS,
                audience=client_id,
                issuer=self.id_token_issuer(),
                options=self.JWT_DECODE_OPTIONS,
                leeway=cast("int", self.setting("JWT_LEEWAY", self.JWT_LEEWAY)),
            )
        except ExpiredSignatureError as error:
            raise AuthTokenError(self, "Signature has expired") from error
        except InvalidAudienceError as error:
            # compatibility with jose error message
            raise AuthTokenError(self, "Invalid audience") from error
        except InvalidTokenError as error:
            raise AuthTokenError(self, str(error)) from error
        except PyJWTError as error:
            raise AuthTokenError(self, "Invalid signature") from error

        self.validate_authorized_party(claims, client_id)
        if not self.validate_at_hash(claims, access_token, key):
            raise AuthTokenError(self, "Invalid access token")

        return claims

    def get_user_details(self, response):
        username_key = self.setting("USERNAME_KEY", default=self.USERNAME_KEY)
        fullname, first_name, last_name = self.get_user_names(
            first_name=response.get("given_name"), last_name=response.get("family_name")
        )
        return {
            "username": response.get(username_key),
            "email": response.get("email"),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }
