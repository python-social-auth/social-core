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
        if not self.data.get("openid_lj_user"):
            raise AuthInputError(
                self,
                parameter="openid_lj_user",
                code="missing_parameter",
                stage="begin",
            )
        return f"https://{self.data['openid_lj_user']}.livejournal.com"
