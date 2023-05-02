import json

import httpretty

from social_core.exceptions import AuthException

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
                    "listed_count": 7,
                },
                "profile_image_url": "https://social-core-test-url.com/image.png",
                "verified_type": "none",
                "pinned_tweet_id": "9876543210987654321",
                "url": "https://social-core-test-url.com",
                "verified": False,
                "protected": True,
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
        self.assertEqual(social.extra_data["verified"], False)
        self.assertEqual(social.extra_data["verified_type"], "none")
        self.assertEqual(social.extra_data["protected"], True)
        self.assertEqual(social.extra_data["description"], "description str")
        self.assertEqual(social.extra_data["url"], "https://social-core-test-url.com")
        self.assertEqual(social.extra_data["pinned_tweet_id"], "9876543210987654321")
        self.assertEqual(
            social.extra_data["profile_image_url"],
            "https://social-core-test-url.com/image.png",
        )
        self.assertEqual(social.extra_data["public_metrics"]["followers_count"], 69)
        self.assertEqual(social.extra_data["public_metrics"]["following_count"], 129)
        self.assertEqual(social.extra_data["public_metrics"]["tweet_count"], 40)
        self.assertEqual(social.extra_data["public_metrics"]["listed_count"], 7)

    def test_partial_pipeline(self):
        user = self.do_partial_pipeline()
        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "1234567890123456789")
        self.assertEqual(social.extra_data["first_name"], "first")
        self.assertEqual(social.extra_data["last_name"], "last")
        self.assertEqual(social.extra_data["fullname"], "first last")
        self.assertEqual(social.extra_data["created_at"], "2023-03-06T06:18:59.000Z")
        self.assertEqual(social.extra_data["verified"], False)
        self.assertEqual(social.extra_data["verified_type"], "none")
        self.assertEqual(social.extra_data["protected"], True)
        self.assertEqual(social.extra_data["description"], "description str")
        self.assertEqual(social.extra_data["url"], "https://social-core-test-url.com")
        self.assertEqual(social.extra_data["pinned_tweet_id"], "9876543210987654321")
        self.assertEqual(
            social.extra_data["profile_image_url"],
            "https://social-core-test-url.com/image.png",
        )
        self.assertEqual(social.extra_data["public_metrics"]["followers_count"], 69)
        self.assertEqual(social.extra_data["public_metrics"]["following_count"], 129)
        self.assertEqual(social.extra_data["public_metrics"]["tweet_count"], 40)
        self.assertEqual(social.extra_data["public_metrics"]["listed_count"], 7)


class TwitterOAuth2TestMissingOptionalValue(OAuth2Test):
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

        self.assertIsNone(social.extra_data.get("created_at"))
        self.assertIsNone(social.extra_data.get("verified"))
        self.assertIsNone(social.extra_data.get("verified_type"))
        self.assertIsNone(social.extra_data.get("protected"))
        self.assertIsNone(social.extra_data.get("description"))
        self.assertIsNone(social.extra_data.get("url"))
        self.assertIsNone(social.extra_data.get("pinned_tweet_id"))
        self.assertIsNone(social.extra_data.get("profile_image_url"))
        self.assertIsNone(social.extra_data.get("public_metrics"))


class TwitterOAuth2TestPkcePlain(TwitterOAuth2Test):
    def test_login(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_TWITTER_OAUTH2_PKCE_CODE_CHALLENGE_METHOD": "plain"}
        )

        self.do_login()

        requests = httpretty.latest_requests()
        auth_request = [
            r for r in requests if "https://twitter.com/i/oauth2/authorize" in r.url
        ][0]
        code_challenge = auth_request.querystring.get("code_challenge")[0]
        code_challenge_method = auth_request.querystring.get("code_challenge_method")[0]
        self.assertIsNotNone(code_challenge)
        self.assertEqual(code_challenge_method, "plain")

        auth_complete = [
            r for r in requests if "https://api.twitter.com/2/oauth2/token" in r.url
        ][0]
        code_verifier = auth_complete.parsed_body.get("code_verifier")[0]
        self.assertEqual(code_challenge, code_verifier)


class TwitterOAuth2TestPkceS256(TwitterOAuth2Test):
    def test_login(self):
        # use default value of PKCE_CODE_CHALLENGE_METHOD (s256)
        self.do_login()

        requests = httpretty.latest_requests()
        auth_request = [
            r for r in requests if "https://twitter.com/i/oauth2/authorize" in r.url
        ][0]
        code_challenge = auth_request.querystring.get("code_challenge")[0]
        code_challenge_method = auth_request.querystring.get("code_challenge_method")[0]
        self.assertIsNotNone(code_challenge)
        self.assertEqual(code_challenge_method, "s256")

        auth_complete = [
            r for r in requests if "https://api.twitter.com/2/oauth2/toke" in r.url
        ][0]
        code_verifier = auth_complete.parsed_body.get("code_verifier")[0]
        self.assertEqual(
            self.backend.generate_code_challenge(code_verifier, "s256"), code_challenge
        )


class TwitterOAuth2TestInvalidCodeChallengeMethod(TwitterOAuth2Test):
    def test_login__error(self):
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_TWITTER_OAUTH2_PKCE_CODE_CHALLENGE_METHOD": "invalidmethodname"
            }
        )

        with self.assertRaises(AuthException):
            self.do_login()
