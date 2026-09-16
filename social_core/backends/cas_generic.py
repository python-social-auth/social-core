"""
Generic CAS backend

Backend to authenticat with a generic CAS server.
"""

from __future__ import annotations

from cas import CASClient, CASClientV1, CASClientV2, CASClientV3, CASClientWithSAMLV1

from social_core.exceptions import AuthTokenError, SocialAuthImproperlyConfiguredError

from .base import BaseAuth


class CasAuth(BaseAuth):
    name = "cas"

    ID_KEY = "cas_user"
    SERVER_URL: str | None = None

    def auth_url(self) -> str:
        client = self.get_cas_client()

        url = client.get_login_url()
        self.log_debug(f"Redirecting to CAS login: {url}")
        return url

    def get_cas_client(
        self,
    ) -> CASClientV1 | CASClientV2 | CASClientV3 | CASClientWithSAMLV1:
        """
        initializes the CASClient according to
        the CAS_* settings
        """
        server_url = self.setting("SERVER_URL", self.SERVER_URL)
        service_url = self.redirect_uri

        if not server_url:
            raise SocialAuthImproperlyConfiguredError

        version = self.setting("VERSION", 3)
        kwargs = {
            "service_url": service_url,
            "server_url": server_url,
            "extra_login_params": self.setting("EXTRA_LOGIN_PARAMS", []),
        }

        # ty checks don't like __new__ to return a different type
        return CASClient.__new__(CASClient, version=version, **kwargs)

    def auth_complete(self, *args, **kwargs):
        client = self.get_cas_client()
        ticket = self.strategy.request_data().get("ticket")
        user, attributes, _pgtiou = client.verify_ticket(ticket)
        if user is None or attributes is None:
            raise AuthTokenError(self, "Token verification did not succeed")
        kwargs.update({"response": attributes | {"cas_user": user}, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)

    def get_user_details(self, response):
        return {
            "username": response.get(self.id_key()),
            "email": response.get(self.setting("EMAIL_FIELD", "email")),
            "fullname": response.get(self.setting("NAME_FIELD", "name")),
        }
