"""
Generic CAS backend

Backend to authenticat with a generic CAS server.
"""

from __future__ import annotations

from cas import CASClient

from social_core.exceptions import AuthTokenError, SocialAuthImproperlyConfiguredError

from .base import BaseAuth


class CasAuth(BaseAuth):
    name = "cas"

    ID_KEY = "uid"
    SERVER_URL: str | None = None

    def auth_url(self) -> str:
        client = self.get_cas_client()

        url = client.get_login_url()
        self.log_debug(f"Redirecting to CAS login: {url}")
        return url

    def get_cas_client(
        self,
    ) -> CASClient:
        """
        initializes the CASClient according to
        the CAS_* settings
        """
        server_url = self.setting("SERVER_URL", self.SERVER_URL)
        service_url = self.redirect_uri

        if not server_url:
            raise SocialAuthImproperlyConfiguredError

        kwargs = {
            "service_url": service_url,
            "version": self.setting("VERSION", 3),
            "server_url": server_url,
            "extra_login_params": self.setting("EXTRA_LOGIN_PARAMS", []),
        }

        return CASClient(**kwargs)

    def auth_complete(self, *args, **kwargs):
        client = self.get_cas_client()
        ticket = self.strategy.request_data().get("ticket")
        user, attributes, _pgtiou = client.verify_ticket(ticket)
        if user is None:
            raise AuthTokenError(self, "Token verification did not succeed")
        kwargs.update({"response": attributes, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)

    def get_user_details(self, response):
        return {
            "username": response.get(self.id_key()),
            "email": response.get(self.setting("EMAIL_FIELD", "email")),
            "fullname": response.get(self.setting("NAME_FIELD", "name")),
        }
