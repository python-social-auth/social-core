import hmac
import time
from six.moves.urllib.parse import urlencode
from base64 import b64encode, b64decode
from hashlib import sha256

from .base import BaseAuth
from ..exceptions import AuthException, AuthTokenError
from ..utils import parse_qs


class DiscourseAuth(BaseAuth):
    name = "discourse"
    EXTRA_DATA = ["username", "name", "avatar_url"]

    def auth_url(self):
        """Return redirect url"""
        return_url = self.redirect_uri
        nonce = self.strategy.random_string(64)
        self.add_nonce(nonce)

        payload = "nonce=" + nonce + "&return_sso_url=" + return_url
        base_64_payload = b64encode(payload)
        payload_signature = hmac.new(
            self.setting("SECRET"), base_64_payload, sha256
        ).hexdigest()
        encoded_params = urlencode(
            {"sso": base_64_payload, "sig": payload_signature}
        )
        return (
            self.setting("SERVER_URL")
            + "/session/sso_provider?"
            + encoded_params
        )

    def get_user_id(self, details, response):
        return response["email"]

    def get_user_details(self, response):
        results = {
            "username": response.get("username"),
            "email": response.get("email"),
            "name": response.get("name"),
            "groups": response.get("groups", "").split(","),
            "is_staff": response.get("admin") == "true" or
                        response.get("moderator") == "true",
            "is_superuser": response.get("admin") == "true",
        }
        return results

    def add_nonce(self, nonce):
        self.strategy.storage.nonce.use(
            self.setting("SERVER_URL"), time.time(), nonce
        )

    def get_nonce(self, nonce):
        return self.strategy.storage.nonce.get(
            self.setting("SERVER_URL"),
            nonce,
        )

    def delete_nonce(self, nonce):
        self.strategy.storage.nonce.delete(nonce)

    def auth_complete(self, request, *args, **kwargs):
        sso_params = request.GET.get("sso")
        sso_signature = request.GET.get("sig")
        param_signature = hmac.new(
            self.setting("SECRET"), sso_params, sha256
        ).hexdigest()

        if not hmac.compare_digest(str(sso_signature), str(param_signature)):
            raise AuthException("Could not verify discourse login")

        decoded_params = b64decode(sso_params)

        # Validate the nonce to ensure the request was not modified
        response = parse_qs(decoded_params)
        nonce_obj = self.get_nonce(response.get("nonce"))
        if nonce_obj:
            self.delete_nonce(nonce_obj)
        else:
            raise AuthTokenError(self, "Incorrect id_token: nonce")

        kwargs.update({"sso": "", "sig": "", "backend": self, "response": response})

        return self.strategy.authenticate(*args, **kwargs)
