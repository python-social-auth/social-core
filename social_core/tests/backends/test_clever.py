import json

import responses

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class CleverOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.clever.CleverOAuth2"
    expected_username = "ada"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})

    def auth_handlers(self, start_url: str) -> str:
        target_url = super().auth_handlers(start_url)
        responses.add(
            responses.GET,
            "https://api.clever.com/v3.0/me",
            body=json.dumps({"data": {"id": "user-id"}}),
            content_type="application/json",
        )
        responses.add(
            responses.GET,
            "https://api.clever.com/v3.0/users/user-id",
            body=json.dumps(
                {
                    "data": {
                        "id": "user-id",
                        "name": {"first": "Ada", "last": "Lovelace"},
                        "email": "ada@example.com",
                        "roles": {
                            "student": {"credentials": {"district_username": "ada"}}
                        },
                    }
                }
            ),
            content_type="application/json",
        )
        return target_url

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
