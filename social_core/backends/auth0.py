"""
Auth0 implementation based on:
https://auth0.com/docs/quickstart/webapp/django/01-login
"""

from typing import TYPE_CHECKING

import jwt

from social_core.backends.utils import jwt_error
from social_core.exceptions import AuthResponseError
from social_core.utils import cache

from .oauth import BaseOAuth2

if TYPE_CHECKING:
    from typing import Any


class Auth0OAuth2(BaseOAuth2):
    """Auth0 OAuth authentication backend"""

    name = "auth0"
    title = "Auth0"
    icon = "auth0.svg"
    ID_KEY = "user_id"
    DEFAULT_SCOPE = ["openid", "profile", "email"]
    SCOPE_SEPARATOR = " "
    EXTRA_DATA = [("picture", "picture")]

    def api_path(self, path="") -> str:
        """Build API path for Auth0 domain"""
        return f"https://{self.setting('DOMAIN')}/{path}"

    def authorization_url(self):
        return self.api_path("authorize")

    def access_token_url(self):
        return self.api_path("oauth/token")

    def get_user_id(self, details, response):
        """Return current user id."""
        return self.get_user_id_from_sources(details)

    @cache(ttl=86400)
    def get_jwks_keys_for_uri(self, uri: str) -> list[jwt.PyJWK]:
        """Cache parsed signing keys separately for each Auth0 domain."""
        jwks = self.get_json(uri)
        try:
            return jwt.PyJWKSet.from_dict(jwks).keys
        except jwt.PyJWKSetError:
            # Preserve support for endpoints returning a single JWK.
            return [jwt.PyJWK.from_dict(jwks, "RS256")]

    def _decode_id_token(self, id_token: str, keys: list[jwt.PyJWK]) -> dict:
        signature_error = None
        for key in keys:
            try:
                return jwt.decode(
                    id_token,
                    key.key,
                    algorithms=["RS256"],
                    audience=self.setting("KEY"),  # CLIENT_ID
                    issuer=self.api_path(),
                )
            except (jwt.InvalidSignatureError, jwt.InvalidAlgorithmError) as error:
                signature_error = error
        assert signature_error is not None
        raise signature_error

    def get_user_details(self, response):
        # Obtain JWT and the keys to validate the signature
        id_token = response.get("id_token")
        if id_token is None:
            raise AuthResponseError(
                self,
                "Missing id_token in Auth0 token response",
                code="missing_claim",
                claim="id_token",
                stage="token_validation",
            )
        jwks_uri = self.api_path(".well-known/jwks.json")
        cached_keys: Any = self.get_jwks_keys_for_uri
        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
            keys = self.get_jwks_keys_for_uri(jwks_uri)
            if kid is not None and not any(key.key_id == kid for key in keys):
                # Pick up rotated signing keys without waiting for cache expiry.
                keys = cached_keys.refresh(self, jwks_uri)
            try:
                payload = self._decode_id_token(id_token, keys)
            except jwt.InvalidSignatureError:
                if kid is not None:
                    raise
                # Tokens without a key ID can only signal rotation by failing
                # signature verification with every cached key. Retry once.
                keys = cached_keys.refresh(self, jwks_uri)
                payload = self._decode_id_token(id_token, keys)
        except jwt.PyJWTError as error:
            raise jwt_error(self, error) from error

        fullname = payload["name"]
        first_name = ""
        last_name = ""
        details = {
            "username": payload["nickname"],
            "email": payload["email"],
            "email_verified": payload.get("email_verified", False),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "picture": payload["picture"],
            "user_id": payload["sub"],
        }
        id_key = self.id_key()
        if id_key not in details:
            user_id = payload.get(id_key)
            if user_id is None:
                raise AuthResponseError(
                    self,
                    f"Missing configured user ID claim {id_key}",
                    code="missing_claim",
                    stage="user_info",
                )
            details[id_key] = user_id
        return details
