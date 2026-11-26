import json
from typing import Any

from .oauth import (
    BaseAuthUrlTestMixin,
    OAuth2StateTestMixin,
    OAuth2Test,
    VerifiedEmailWhitelistTestMixin,
)


class EventbriteAuth2Test(
    OAuth2Test,
    OAuth2StateTestMixin,
    BaseAuthUrlTestMixin,
    VerifiedEmailWhitelistTestMixin,
):
    backend_path = "social_core.backends.eventbrite.EventbriteOAuth2"
    user_data_url = "https://www.eventbriteapi.com/v3/users/me"
    expected_username = "sean+awesome@eventbrite.com"
    whitelisted_email = expected_username
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "first_name": "sean",
            "last_name": "rose",
            "name": "sean rose",
            "access_token": "YQEN5H2W2OTKQZWZMYER",
            "emails": [
                {
                    "verified": True,
                    "email": "sean+awesome2@eventbrite.com",
                    "primary": False,
                },
                {
                    "verified": True,
                    "email": "sean+awesome@eventbrite.com",
                    "primary": True,
                },
            ],
            "token_type": "bearer",
            "image_id": None,
            "is_public": False,
            "id": "128559602587",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def user_data_with_email(self, *, verified: bool) -> dict[str, Any]:
        assert self.user_data_body is not None
        user_data = json.loads(self.user_data_body)
        # Only the primary address counts, the verified secondary one does not
        user_data["emails"][1]["verified"] = verified
        return user_data
