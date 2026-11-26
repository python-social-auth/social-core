import json
from typing import Any

from .oauth import BaseAuthUrlTestMixin, OAuth2Test, VerifiedEmailWhitelistTestMixin


class DiscordOAuth2Test(
    OAuth2Test, BaseAuthUrlTestMixin, VerifiedEmailWhitelistTestMixin
):
    backend_path = "social_core.backends.discord.DiscordOAuth2"
    user_data_url = "https://discord.com/api/users/@me"
    expected_username = "foobar"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "Bearer",
            "expires_in": 604800,
            "refresh_token": "foobar-refresh",
            "scope": "identify email",
        }
    )
    user_data_body = json.dumps(
        {
            "id": "80351110224678912",
            "username": "foobar",
            "discriminator": "0",
            "global_name": "Foo Bar",
            "avatar": "8342729096ea3675442027381ff50dfe",
            "verified": True,
            "email": "foobar@example.com",
        }
    )

    def user_data_with_email(self, *, verified: bool) -> dict[str, Any]:
        assert self.user_data_body is not None
        return {**json.loads(self.user_data_body), "verified": verified}

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
