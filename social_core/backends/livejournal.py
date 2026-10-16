"""
LiveJournal OpenId backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/livejournal.html
"""

from urllib.parse import urlsplit

from social_core.exceptions import AuthInputError

from .open_id import OpenIdAuth


class LiveJournalOpenId(OpenIdAuth):
    """LiveJournal OpenID authentication backend"""

    name = "livejournal"
    title = "LiveJournal"

    def requires_openid_provider_binding(self) -> bool:
        return True

    def get_user_details(self, response):
        """Generate username from identity url"""
        values = super().get_user_details(response)
        values["username"] = (
            values.get("username")
            or urlsplit(response.identity_url).netloc.split(".", 1)[0]
        )
        return values

    def openid_url(self) -> str:
        """Returns LiveJournal authentication URL"""
        username = self.data.get("openid_lj_user")
        if not username:
            raise AuthInputError(
                self,
                parameter="openid_lj_user",
                code="missing_parameter",
                stage="begin",
            )
        url = f"https://{username}.livejournal.com"
        try:
            parsed = urlsplit(url)
            valid_port = parsed.port is None
        except ValueError:
            parsed = None
            valid_port = False
        valid_host = (
            parsed is not None
            and parsed.hostname is not None
            and parsed.hostname.endswith(".livejournal.com")
        )
        valid_shape = (
            parsed is not None
            and valid_port
            and not any((parsed.path, parsed.query, parsed.fragment))
        )
        if not (self._is_https_url(url) and valid_host and valid_shape):
            raise AuthInputError(
                self,
                parameter="openid_lj_user",
                code="invalid_parameter",
                stage="begin",
            )
        return url
