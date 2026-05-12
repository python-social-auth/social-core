import datetime
import json
from urllib.parse import parse_qsl, urlencode, urlsplit

import responses

from social_core.exceptions import AuthFailed

from .open_id import OpenIdTest

INFO_URL = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?"
JANRAIN_NONCE = datetime.datetime.now(datetime.timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)


class SteamOpenIdTest(OpenIdTest):
    backend_path = "social_core.backends.steam.SteamOpenId"
    expected_username = "foobar"
    discovery_body = """<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
    <XRD>
        <Service priority="0">
            <Type>http://specs.openid.net/auth/2.0/server</Type>
            <URI>https://steamcommunity.com/openid/login</URI>
        </Service>
    </XRD>
</xrds:XRDS>"""
    user_discovery_body = """<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
    <XRD>
        <Service priority="0">
            <Type>http://specs.openid.net/auth/2.0/signon</Type>
            <URI>https://steamcommunity.com/openid/login</URI>
        </Service>
    </XRD>
</xrds:XRDS>"""
    server_response = urlencode(
        {
            "janrain_nonce": JANRAIN_NONCE,
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "id_res",
            "openid.op_endpoint": "https://steamcommunity.com/openid/login",
            "openid.claimed_id": "https://steamcommunity.com/openid/id/123",
            "openid.identity": "https://steamcommunity.com/openid/id/123",
            "openid.return_to": "http://myapp.com/complete/steam",
            "openid.response_nonce": (f"{JANRAIN_NONCE}oD4UZ3w9chOAiQXk0AqDipqFYRA="),
            "openid.assoc_handle": "1234567890",
            "openid.signed": (
                "signed,op_endpoint,claimed_id,identity,return_to,"
                "response_nonce,assoc_handle"
            ),
            "openid.sig": "1az53vj9SVdiBwhk8%2BFQ68R2plo=",
        }
    )
    player_details = json.dumps(
        {
            "response": {
                "players": [
                    {
                        "steamid": "123",
                        "primaryclanid": "1234",
                        "timecreated": 1360768416,
                        "personaname": "foobar",
                        "personastate": 0,
                        "communityvisibilitystate": 3,
                        "profileurl": ("http://steamcommunity.com/profiles/123/"),
                        "avatar": (
                            "http://media.steampowered.com/steamcommunity/"
                            "public/images/avatars/fe/"
                            "fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb.jpg"
                        ),
                        "avatarfull": (
                            "http://media.steampowered.com/steamcommunity/"
                            "public/images/avatars/fe/"
                            "fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_full.jpg"
                        ),
                        "avatarmedium": (
                            "http://media.steampowered.com/steamcommunity/"
                            "public/images/avatars/fe/"
                            "fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb"
                            "_medium.jpg"
                        ),
                        "lastlogoff": 1360790014,
                    }
                ]
            }
        }
    )

    def _login_setup(self, user_url=None) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_STEAM_API_KEY": "123abc"})
        user_url = user_url or "https://steamcommunity.com/openid/id/123"
        responses.add(
            responses.GET,
            user_url,
            status=200,
            body=self.user_discovery_body,
        )
        self.add_openid_response(
            "GET",
            user_url,
            body=self.user_discovery_body,
            content_type="application/xrds+xml",
        )
        responses.add(responses.GET, INFO_URL, status=200, body=self.player_details)

    def get_server_response(self, inputs: dict[str, str | None]) -> str:
        params = dict(parse_qsl(self.server_response))
        return_to = inputs["openid.return_to"]
        assert return_to, "The OpenID return_to value must be set in the test"
        params["openid.return_to"] = return_to
        params["janrain_nonce"] = dict(parse_qsl(urlsplit(return_to).query))[
            "janrain_nonce"
        ]
        return urlencode(params)

    def test_login(self) -> None:
        self._login_setup()
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self._login_setup()
        self.do_partial_pipeline()


class SteamOpenIdMissingSteamIdTest(SteamOpenIdTest):
    server_response = urlencode(
        {
            "janrain_nonce": JANRAIN_NONCE,
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "id_res",
            "openid.op_endpoint": "https://steamcommunity.com/openid/login",
            "openid.claimed_id": "https://steamcommunity.com/openid/BROKEN",
            "openid.identity": "https://steamcommunity.com/openid/BROKEN",
            "openid.return_to": "http://myapp.com/complete/steam",
            "openid.response_nonce": (f"{JANRAIN_NONCE}oD4UZ3w9chOAiQXk0AqDipqFYRA="),
            "openid.assoc_handle": "1234567890",
            "openid.signed": (
                "signed,op_endpoint,claimed_id,identity,return_to,"
                "response_nonce,assoc_handle"
            ),
            "openid.sig": "1az53vj9SVdiBwhk8%2BFQ68R2plo=",
        }
    )

    def test_login(self) -> None:
        self._login_setup(user_url="https://steamcommunity.com/openid/BROKEN")
        with self.assertRaisesRegex(AuthFailed, "Missing Steam Id"):
            self.do_login()

    def test_partial_pipeline(self) -> None:
        self._login_setup(user_url="https://steamcommunity.com/openid/BROKEN")
        with self.assertRaisesRegex(AuthFailed, "Missing Steam Id"):
            self.do_partial_pipeline()


class SteamOpenIdFakeSteamIdTest(SteamOpenIdTest):
    server_response = urlencode(
        {
            "janrain_nonce": JANRAIN_NONCE,
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "id_res",
            "openid.op_endpoint": "https://steamcommunity.com/openid/login",
            "openid.claimed_id": "https://fakesteamcommunity.com/openid/123",
            "openid.identity": "https://fakesteamcommunity.com/openid/123",
            "openid.return_to": "http://myapp.com/complete/steam",
            "openid.response_nonce": (f"{JANRAIN_NONCE}oD4UZ3w9chOAiQXk0AqDipqFYRA="),
            "openid.assoc_handle": "1234567890",
            "openid.signed": (
                "signed,op_endpoint,claimed_id,identity,return_to,"
                "response_nonce,assoc_handle"
            ),
            "openid.sig": "1az53vj9SVdiBwhk8%2BFQ68R2plo=",
        }
    )

    def test_login(self) -> None:
        self._login_setup(user_url="https://fakesteamcommunity.com/openid/123")
        with self.assertRaisesRegex(AuthFailed, "Openid identifier mismatch"):
            self.do_login()

    def test_partial_pipeline(self) -> None:
        self._login_setup(user_url="https://fakesteamcommunity.com/openid/123")
        with self.assertRaisesRegex(AuthFailed, "Openid identifier mismatch"):
            self.do_partial_pipeline()
