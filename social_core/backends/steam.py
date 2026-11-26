"""
Steam OpenId backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/steam.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from openid.message import OPENID2_NS

from social_core.backends.base import ResponseT_co
from social_core.exceptions import AuthResponseError

from .open_id import OpenIdAuth

if TYPE_CHECKING:
    from social_core.store import OpenIdStore

USER_INFO = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?"


class SteamOpenId(OpenIdAuth[ResponseT_co]):
    name = "steam"
    title = "Steam"
    URL = "https://steamcommunity.com/openid"

    def auth_complete(self, *args, **kwargs):
        # The OpenID consumer runs discovery on the claimed identifier before
        # it verifies the signature, so refuse identifiers outside Steam's
        # namespace (and OpenID 1 responses, which take it from return_to).
        if self.data.get("openid.mode") == "id_res":
            claimed_id = self.data.get("openid.claimed_id")
            if (
                self.data.get("openid.ns") != OPENID2_NS
                or not isinstance(claimed_id, str)
                or not claimed_id.startswith(f"{self.URL}/")
            ):
                raise AuthResponseError(
                    self,
                    "Openid identifier mismatch",
                    claim="claimed_id",
                    code="invalid_claim",
                    stage="callback",
                )
        return super().auth_complete(*args, **kwargs)

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
