"""
Steam OpenId backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/steam.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from social_core.exceptions import AuthResponseError

from .open_id import OpenIdAuth

if TYPE_CHECKING:
    from social_core.store import OpenIdStore

USER_INFO = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?"


class SteamOpenId(OpenIdAuth):
    name = "steam"
    title = "Steam"
    URL = "https://steamcommunity.com/openid"

    def get_user_id(self, details, response):
        """Return the validated Steam ID from the asserted OpenID URL.

        The ID is protocol-derived, so the configurable ID_KEY does not apply.
        """
        return self._user_id(response)

    def get_user_details(self, response):
        player = self.get_json(
            USER_INFO,
            params={
                "key": self.setting("API_KEY"),
                "steamids": self._user_id(response),
            },
        )
        if len(player["response"]["players"]) > 0:
            player = player["response"]["players"][0]
            details = {
                "username": player.get("personaname"),
                "email": "",
                "fullname": None,
                "first_name": None,
                "last_name": None,
                "player": player,
            }
        else:
            details = {}
        return details

    def get_consumer_store(self) -> OpenIdStore | None:
        # Steam seems to support stateless mode only, ignore store
        return None

    def _user_id(self, response):
        if not response.identity_url.startswith(self.URL):
            raise AuthResponseError(
                self,
                "Openid identifier mismatch",
                code="invalid_claim",
                stage="user_info",
            )
        user_id = response.identity_url.rsplit("/", 1)[-1]
        if not user_id.isdigit():
            raise AuthResponseError(
                self, "Missing Steam Id", code="missing_claim", stage="user_info"
            )
        return user_id
