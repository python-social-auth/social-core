import json

from .oauth import OAuth2Test


class TwitterOAuth2Test(OAuth2Test):
    backend_path = "social_core.backends.twitter_oauth2.TwitterOAuth2"
    user_data_url = "https://api.twitter.com/2/users/me"
    access_token_body = json.dumps(
        {
            "token_type": "bearer",
            "expires_in": 7200,
            "access_token": "foobar",
            "scope": "users.read",
        }
    )
    user_data_body = json.dumps(
        {
            "data": {
                "id": "1234567890123456789",
                "username": "twitter_username",
                "name": "first last",
                "created_at": "2023-03-06T06:18:59.000Z",
                "public_metrics": {
                    "followers_count": 69,
                    "following_count": 129,
                    "tweet_count": 40,
                    "listed_count": 0,
                },
                "profile_image_url": "profile_image_url",
                "verified_type": "none",
                "pinned_tweet_id": "9876543210987654321",
                "url": "url",
                "verified": False,
                "protected": False,
                "description": "description str",
                "entities": {
                    "url": {
                        "urls": [
                            {
                                "start": 0,
                                "end": 23,
                                "url": "entities-url-urls-url",
                                "expanded_url": "entities-url-urls-expanded_url",
                                "display_url": "entities-url-urls-display_url",
                            }
                        ]
                    },
                    "description": {
                        "urls": [
                            {
                                "start": 133,
                                "end": 156,
                                "url": "entities-description-urls-url",
                                "expanded_url": "entities-description-urls-expanded_url",
                                "display_url": "entities-description-urls-display_url",
                            }
                        ],
                        "hashtags": [
                            {
                                "start": 36,
                                "end": 44,
                                "tag": "entities-description-hashtags-tag",
                            }
                        ],
                    },
                },
            },
        },
    )

    expected_username = "twitter_username"

    def test_login(self):
        user = self.do_login()

        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "1234567890123456789")
        self.assertEqual(social.extra_data["first_name"], "first")
        self.assertEqual(social.extra_data["last_name"], "last")
        self.assertEqual(social.extra_data["fullname"], "first last")
        self.assertEqual(social.extra_data["created_at"], "2023-03-06T06:18:59.000Z")

    def test_partial_pipeline(self):
        user = self.do_partial_pipeline()
        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "1234567890123456789")
        self.assertEqual(social.extra_data["first_name"], "first")
        self.assertEqual(social.extra_data["last_name"], "last")
        self.assertEqual(social.extra_data["fullname"], "first last")
        self.assertEqual(social.extra_data["created_at"], "2023-03-06T06:18:59.000Z")
