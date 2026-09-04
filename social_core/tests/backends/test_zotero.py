from urllib.parse import urlencode

from social_core.exceptions import AuthMissingParameter

from .oauth import OAuth1AuthUrlTestMixin, OAuth1Test


class ZoteroOAuth1Test(OAuth1Test, OAuth1AuthUrlTestMixin):
    backend_path = "social_core.backends.zotero.ZoteroOAuth"
    expected_username = "FooBar"
    access_token_body = urlencode(
        {
            "oauth_token": "foobar",
            "oauth_token_secret": "rodgsNDK4hLJU1504Atk131G",
            "userID": "123456_abcdef",
            "username": "FooBar",
        }
    )
    request_token_body = urlencode(
        {
            "oauth_token_secret": "foobar-secret",
            "oauth_token": "foobar",
            "oauth_callback_confirmed": "true",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_login_with_configured_access_token_id(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_ZOTERO_ID_KEY": "custom_id"})
        self.access_token_body = urlencode(
            {
                "oauth_token": "foobar",
                "oauth_token_secret": "rodgsNDK4hLJU1504Atk131G",
                "userID": "123456_abcdef",
                "username": "FooBar",
                "custom_id": "configured",
            }
        )

        user = self.do_login()

        self.assertEqual(user.social[0].uid, "configured")

    def test_configured_id_uses_normalized_details_fallback(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_ZOTERO_ID_KEY": "custom_id"})

        self.assertEqual(
            self.backend.get_user_id(
                {"custom_id": "normalized"},
                {"access_token": {}},
            ),
            "normalized",
        )

    def test_missing_configured_id_raises_missing_parameter(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_ZOTERO_ID_KEY": "missing_id"})

        with self.assertRaisesRegex(AuthMissingParameter, "missing_id"):
            self.backend.get_user_id({}, {"access_token": {}})

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
