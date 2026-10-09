import json

from social_core.pipeline.social_auth import social_uid

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class MonzoOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.monzo.MonzoOAuth2"
    user_data_url = "https://api.monzo.com/accounts"
    expected_username = "user_00001"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "client_id": "client_id",
            "expires_in": 21600,
            "refresh_token": "refresh_token",
            "token_type": "Bearer",
            "user_id": "user_00001",
        }
    )
    user_data_body = json.dumps(
        {
            "accounts": [
                {
                    "id": "acc_00001",
                    "description": "Personal Account",
                    "created": "2015-11-13T12:17:42Z",
                }
            ]
        }
    )

    def test_login_uses_token_user_identifier(self) -> None:
        user = self.do_login()
        self.assertEqual(
            (user.social[0].uid, user.social[0].id_key),
            ("user_00001", "user_id"),
        )

    def test_distinct_token_users_have_distinct_identifiers(self) -> None:
        identifiers = [
            social_uid(self.backend, {}, {"user_id": user_id})["uid"]
            for user_id in ("user_00001", "user_00002")
        ]
        self.assertEqual(identifiers, ["user_00001", "user_00002"])
