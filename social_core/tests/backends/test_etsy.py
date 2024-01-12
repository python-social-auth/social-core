import json

from .oauth import OAuth2PkceS256Test


class EtsyOAuth2Mixin:
    backend_path = "social_core.backends.etsy.EtsyOAuth2"
    access_token_body = json.dumps(
        {
            "access_token": "dummy_user_id.dummy_access_token",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "dummy_user_id.dummy_refresh_token",
        }
    )
    refresh_token_body = json.dumps(
        {
            "access_token": "dummy_user_id.dummy_access_token_refreshed",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "dummy_user_id.dummy_refresh_token_refreshed",
        }
    )

    user_data_url = "https://openapi.etsy.com/v3/application/users/dummy_user_id"
    user_data_body = json.dumps(
        {
            "user_id": "dummy_user_id",
            "primary_email": "amitray@developer.com",
            "first_name": "Amit",
            "last_name": "Ray",
            "image_url_75x75": "http://www.gravatar.com/avatar/af7d968fe79ea45271e3100391824b79.jpg?s=48&d=mm",
        }
    )
    expected_username = "dummy_user_id"

    def test_login(self):
        user = self.do_login()
        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "dummy_user_id")
        self.assertEqual(social.extra_data["first_name"], "Amit")
        self.assertEqual(social.extra_data["last_name"], "Ray")
        self.assertEqual(social.extra_data["primary_email"], "amitray@developer.com")
        self.assertEqual(
            social.extra_data["image_url_75x75"],
            "http://www.gravatar.com/avatar/af7d968fe79ea45271e3100391824b79.jpg?s=48&d=mm",
        )
        self.assertEqual(
            social.extra_data["access_token"], "dummy_user_id.dummy_access_token"
        )
        self.assertEqual(social.extra_data["token_type"], "bearer")
        self.assertEqual(social.extra_data["expires_in"], 3600)
        self.assertEqual(
            social.extra_data["refresh_token"], "dummy_user_id.dummy_refresh_token"
        )

    def test_refresh_token(self):
        _, social = self.do_refresh_token()

        self.assertEqual(social.uid, "dummy_user_id")
        self.assertEqual(social.extra_data["first_name"], "Amit")
        self.assertEqual(social.extra_data["last_name"], "Ray")
        self.assertEqual(social.extra_data["primary_email"], "amitray@developer.com")
        self.assertEqual(
            social.extra_data["image_url_75x75"],
            "http://www.gravatar.com/avatar/af7d968fe79ea45271e3100391824b79.jpg?s=48&d=mm",
        )
        self.assertEqual(
            social.extra_data["access_token"],
            "dummy_user_id.dummy_access_token_refreshed",
        )
        self.assertEqual(social.extra_data["token_type"], "bearer")
        self.assertEqual(social.extra_data["expires_in"], 3600)
        self.assertEqual(
            social.extra_data["refresh_token"],
            "dummy_user_id.dummy_refresh_token_refreshed",
        )


class EtsyOAuth2TestPkceS256(
    EtsyOAuth2Mixin,
    OAuth2PkceS256Test,
):
    pass
