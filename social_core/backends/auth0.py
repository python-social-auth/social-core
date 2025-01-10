"""
Auth0 implementation based on:
https://auth0.com/docs/quickstart/webapp/django/01-login
"""

import jwt

from .oauth import BaseOAuth2


class Auth0OAuth2(BaseOAuth2):
    """Auth0 OAuth authentication backend"""

    name = "auth0"
    SCOPE_SEPARATOR = " "
    ACCESS_TOKEN_METHOD = "POST"
    EXTRA_DATA = [("picture", "picture")]

    def api_path(self, path=""):
        """Build API path for Auth0 domain"""
        return "https://{domain}/{path}".format(
            domain=self.setting("DOMAIN"), path=path
        )

    def authorization_url(self):
        return self.api_path("authorize")

    def access_token_url(self):
        return self.api_path("oauth/token")

    def get_user_id(self, details, response):
        """Return current user id."""
        return details["user_id"]

    def get_user_details(self, response):
        # Obtain JWT and the keys to validate the signature
        id_token = response.get("id_token")
        jwks = self.get_json(self.api_path(".well-known/jwks.json"))
        issuer = self.api_path()
        audience = self.setting("KEY")  # CLIENT_ID
        try:
            # it could be a set of JWKs
            keys = jwt.PyJWKSet.from_dict(jwks).keys
        except jwt.PyJWKSetError:
            # let any error raise from here
            # try to get single JWK
            keys = [jwt.PyJWK.from_dict(jwks, "RS256")]

        signature_error = None
        for key in keys:
            try:
                payload = jwt.decode(
                    id_token,
                    key.key,
                    algorithms=["RS256"],
                    audience=audience,
                    issuer=issuer,
                )
            except (jwt.InvalidSignatureError, jwt.InvalidAlgorithmError) as ex:
                signature_error = ex
            else:
                break
        else:
            assert signature_error is not None
            # raise last esception found during iteration
            raise signature_error

        fullname, first_name, last_name = self.get_user_names(payload["name"])
        return {
            "username": payload["nickname"],
            "email": payload["email"],
            "email_verified": payload.get("email_verified", False),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "picture": payload["picture"],
            "user_id": payload["sub"],
        }
