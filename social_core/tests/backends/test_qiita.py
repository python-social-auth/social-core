import json

from social_core.exceptions import AuthException

from .oauth import OAuth2Test


class QiitaOAuth2Test(OAuth2Test):
    backend_path = "social_core.backends.qiita.QiitaOAuth2"
    user_data_url = "https://qiita.com/api/v2/authenticated_user"
    expected_username = "foobar"

    access_token_body = json.dumps({"token": "foobar", "token_type": "bearer"})

    user_data_body = json.dumps(
        {
            "id": "foobar",
            "name": "Foo Bar",
            "description": "Hello, world.",
            "facebook_id": "qiita",
            "followees_count": 100,
            "followers_count": 200,
            "github_login_name": "qiitan",
            "items_count": 300,
            "linkedin_id": "qiita",
            "location": "Tokyo, Japan",
            "organization": "Qiita Inc.",
            "permanent_id": 12345,
            "profile_image_url": "https://s3-ap-northeast-1.amazonaws.com/qiita-image-store/0/88"
            "/ccf90b557a406157dbb9d2d7e543dae384dbb561/large.png?1575443439",
            "team_only": False,
            "twitter_screen_name": "qiita",
            "website_url": "https://qiita.com",
            "image_monthly_upload_limit": 1048576,
            "image_monthly_upload_remaining": 524288,
        }
    )

    def test_login(self):
        user = self.do_login()
        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "foobar")
        self.assertEqual(social.extra_data["permanent_id"], 12345)

    def test_partial_pipeline(self):
        user = self.do_partial_pipeline()
        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "foobar")
        self.assertEqual(social.extra_data["permanent_id"], 12345)


class QiitaOAuth2TestIdentifiedByPermanentId(QiitaOAuth2Test):
    def test_login(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_QIITA_IDENTIFIED_BY_PERMANENT_ID": True}
        )

        user = self.do_login()
        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "12345")
        self.assertEqual(social.extra_data["permanent_id"], 12345)

    def test_partial_pipeline(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_QIITA_IDENTIFIED_BY_PERMANENT_ID": True}
        )

        user = self.do_partial_pipeline()
        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "12345")
        self.assertEqual(social.extra_data["permanent_id"], 12345)


class QiitaOAuth2TestIdentifiedByPermanentIdAuthException(QiitaOAuth2Test):
    user_data_body = json.dumps(
        {
            "id": "foobar",
            "name": "Foo Bar",
        }
    )

    def test_login(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_QIITA_IDENTIFIED_BY_PERMANENT_ID": True}
        )

        with self.assertRaises(AuthException):
            self.do_login()

    def test_partial_pipeline(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_QIITA_IDENTIFIED_BY_PERMANENT_ID": True}
        )

        with self.assertRaises(AuthException):
            self.do_partial_pipeline()
