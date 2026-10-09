import json
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

from social_core.pipeline.social_auth import social_uid

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

if TYPE_CHECKING:
    from social_core.tests.models import User


class HubSpotOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.hubspot.HubSpotOAuth2"
    user_data_url = "https://api.hubapi.com/oauth/v1/access-tokens/foobar"
    access_token_body = json.dumps(
        {"access_token": "foobar", "refresh_token": "refresh", "expires_in": 1800}
    )
    user_data_body = json.dumps(
        {
            "user_id": 111,
            "hub_id": 1001,
            "app_id": 33333,
            "user": "person@example.com",
            "hub_domain": "example.hubspot.com",
            "scopes": ["oauth"],
            "expires_in": 1800,
            "token_type": "access",
        }
    )

    def test_login_uses_portal_and_user_identifier(self) -> None:
        user = cast("User", self.do_start())
        self.assertEqual(
            (user.social[0].uid, user.social[0].id_key),
            ("1001:111", "hubspot_identity"),
        )
        self.assertEqual(user.social[0].extra_data["hub_id"], 1001)
        self.assertEqual(user.social[0].extra_data["user_id"], 111)

    def test_same_user_id_in_different_portals_is_distinct(self) -> None:
        identities = []
        for hub_id in (1001, 2002):
            with patch.object(
                self.backend,
                "get_json",
                return_value={"hub_id": hub_id, "user_id": 111},
            ):
                response = self.backend.user_data("token")
            assert response is not None
            identities.append(social_uid(self.backend, {}, response)["uid"])
        self.assertEqual(identities, ["1001:111", "2002:111"])
