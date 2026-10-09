import json
from urllib.parse import urlencode

from social_core.exceptions import AuthResponseError
from social_core.tests.models import TestUserSocialAuth, User

from .oauth import OAuth1AuthUrlTestMixin, OAuth1Test


class UpworkOAuth1Test(OAuth1Test, OAuth1AuthUrlTestMixin):
    backend_path = "social_core.backends.upwork.UpworkOAuth"
    user_data_url = "https://www.upwork.com/api/auth/v1/info.json"
    expected_username = "10101010"
    access_token_body = urlencode(
        {"oauth_token": "foobar", "oauth_token_secret": "foobar-secret"}
    )
    request_token_body = urlencode(
        {
            "oauth_token_secret": "foobar-secret",
            "oauth_token": "foobar",
            "oauth_callback_confirmed": "true",
        }
    )
    user_data_body = json.dumps(
        {
            "info": {
                "portrait_32_img": "",
                "capacity": {
                    "buyer": "no",
                    "affiliate_manager": "no",
                    "provider": "yes",
                },
                "company_url": "",
                "has_agency": "1",
                "portrait_50_img": "",
                "portrait_100_img": "",
                "location": {"city": "New York", "state": "", "country": "USA"},
                "ref": "9755314",
                "profile_url": "https://www.upwork.com/users/~10101010",
            },
            "auth_user": {
                "timezone": "USA/New York",
                "first_name": "Foo",
                "last_name": "Bar",
                "timezone_offset": "10000",
            },
            "server_time": "1111111111",
        }
    )

    def test_login_fails_without_documented_account_identifier(self) -> None:
        with self.assertRaises(AuthResponseError) as caught:
            self.do_start()
        self.assertEqual(caught.exception.code, "missing_claim")
        self.assertFalse(User.cache)
        self.assertFalse(TestUserSocialAuth.cache_by_uid)
