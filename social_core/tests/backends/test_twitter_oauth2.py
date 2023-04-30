import json

from .oauth import OAuth2Test


class TwitterOAuth2Test(OAuth2Test):
    backend_path = "social_core.backends.twitter_oauth2.TwitterOAuth2"
    user_data_url = "https://api.twitter.com/2/users/me"
    access_token_body = json.dumps({
        "token_type": "bearer",
        "expires_in": 7200,
        "access_token": "foobar",
        "scope": "users.read",
    })
    user_data_body = json.dumps({
        "data": {
            "id": "1234567890123456789",
            "username": "twitter_username",
            "name": "first last",
            "created_at": "2023-03-06T06:18:59.000Z",
        }
    })

    expected_username = "twitter_username"

    def test_login(self):
        user = self.do_login()

        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.extra_data["first_name"], "first")
        self.assertEqual(social.extra_data["last_name"], "last")
        self.assertEqual(social.extra_data["fullname"], "first last")
        self.assertEqual(social.extra_data["created_at"], "2023-03-06T06:18:59.000Z")

    def test_partial_pipeline(self):
        user = self.do_partial_pipeline()
        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.extra_data["first_name"], "first")
        self.assertEqual(social.extra_data["last_name"], "last")
        self.assertEqual(social.extra_data["fullname"], "first last")
        self.assertEqual(social.extra_data["created_at"], "2023-03-06T06:18:59.000Z")
