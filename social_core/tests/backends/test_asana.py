import json

from social_core.pipeline.social_auth import social_uid

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class AsanaOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.asana.AsanaOAuth2"
    user_data_url = "https://app.asana.com/api/1.0/users/me"
    expected_username = "erlich@bachmanity.com"
    access_token_body = json.dumps({"access_token": "aviato", "token_type": "bearer"})
    # https://asana.com/developers/api-reference/users
    user_data_body = json.dumps(
        {
            "data": {
                "gid": "12345",
                "name": "Erlich Bachman",
                "email": "erlich@bachmanity.com",
                "photo": None,
                "workspaces": [{"gid": "123456", "name": "Pied Piper"}],
            }
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual((user.social[0].uid, user.social[0].id_key), ("12345", "gid"))

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_distinct_users_have_distinct_identifiers(self) -> None:
        identifiers = [
            social_uid(self.backend, {}, {"gid": gid})["uid"]
            for gid in ("12345", "67890")
        ]
        self.assertEqual(identifiers, ["12345", "67890"])
