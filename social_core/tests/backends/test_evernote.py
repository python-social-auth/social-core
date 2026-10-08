from urllib.parse import urlencode

from requests import HTTPError

from social_core.exceptions import AuthProviderError

from .oauth import OAuth1AuthUrlTestMixin, OAuth1Test


class EvernoteOAuth1Test(OAuth1Test, OAuth1AuthUrlTestMixin):
    backend_path = "social_core.backends.evernote.EvernoteOAuth"
    expected_username = "101010"
    access_token_body = urlencode(
        {
            "edam_webApiUrlPrefix": "https://www.evernote.com/shard/s1/",
            "edam_shard": "s1",
            "oauth_token": "foobar",
            "edam_expires": "1395118279645",
            "edam_userId": "101010",
            "edam_noteStoreUrl": "https://www.evernote.com/shard/s1/notestore",
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

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class EvernoteOAuth1CanceledTest(EvernoteOAuth1Test):
    access_token_status = 401

    def test_login(self) -> None:
        with self.assertRaises(AuthProviderError) as cm:
            self.do_login()
        assert isinstance(cm.exception.__cause__, HTTPError)
        self.assertIsNotNone(cm.exception.__cause__.response)

    def test_partial_pipeline(self) -> None:
        with self.assertRaises(AuthProviderError) as cm:
            self.do_partial_pipeline()
        assert isinstance(cm.exception.__cause__, HTTPError)
        self.assertIsNotNone(cm.exception.__cause__.response)


class EvernoteOAuth1ErrorTest(EvernoteOAuth1Test):
    access_token_status = 500

    def test_login(self) -> None:
        with self.assertRaises(AuthProviderError):
            self.do_login()

    def test_partial_pipeline(self) -> None:
        with self.assertRaises(AuthProviderError):
            self.do_partial_pipeline()
