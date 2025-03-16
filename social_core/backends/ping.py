"""
Ping Auth OpenID Connect backend
"""

from jose import jwk, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from jose.utils import base64url_decode

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
            rsakey = jwk.construct(key, algorithm="RS256")
            message, encoded_sig = id_token.rsplit(".", 1)
            decoded_sig = base64url_decode(encoded_sig.encode("utf-8"))
            if rsakey.verify(message.encode("utf-8"), decoded_sig):
                return key
        return None

    def validate_and_return_id_token(self, id_token, access_token):
        """
        Validates the id_token according to the steps at
        http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation.
        """
        client_id, client_secret = self.get_key_and_secret()

        key = self.find_valid_key(id_token)

        if not key:
            raise AuthTokenError(self, "Signature verification failed")

        rsakey = jwk.construct(key, algorithm="RS256")

        try:
            claims = jwt.decode(
                id_token,
                rsakey.to_pem().decode("utf-8"),
                algorithms=self.JWT_ALGORITHMS,
                audience=client_id,
                issuer=self.id_token_issuer(),
                access_token=access_token,
                options=self.JWT_DECODE_OPTIONS,
            )
        except ExpiredSignatureError:
            raise AuthTokenError(self, "Signature has expired")
        except JWTClaimsError as error:
            raise AuthTokenError(self, str(error))
        except JWTError:
            raise AuthTokenError(self, "Invalid signature")

        self.validate_claims(claims)

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
