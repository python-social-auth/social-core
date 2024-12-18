import json
from urllib.parse import urlencode

from httpretty import HTTPretty

from .oauth import OAuth1AuthUrlTestMixin, OAuth1Test


class DiscsogsOAuth1Test(OAuth1Test, OAuth1AuthUrlTestMixin):
    _test_token = "lalala123boink"
    backend_path = "social_core.backends.discogs.DiscogsOAuth1"
    expected_username = "rodneyfool"
    raw_complete_url = (
        f"/complete/{0}/?oauth_verifier=wimblewomblefartfart&oauth_token={_test_token}"
    )

    access_token_body = json.dumps(
        {"access_token": _test_token, "token_type": "bearer"}
    )
    request_token_body = urlencode(
        {
            "oauth_token": _test_token,
            "oauth_token_secret": "xyz789",
            "oauth_callback_confirmed": "true",
        }
    )

    user_data_body = json.dumps(
        {
            "profile": "I am a software developer for Discogs.\r\n\r\n[img=http://i.imgur.com/IAk3Ukk.gif]",
            "wantlist_url": "https://api.discogs.com/users/rodneyfool/wants",
            "rank": 149,
            "num_pending": 61,
            "id": 1578108,
            "num_for_sale": 0,
            "home_page": "",
            "location": "I live in the good ol' Pacific NW",
            "collection_folders_url": "https://api.discogs.com/users/rodneyfool/collection/folders",
            "username": expected_username,
            "collection_fields_url": "https://api.discogs.com/users/rodneyfool/collection/fields",
            "releases_contributed": 5,
            "registered": "2012-08-15T21:13:36-07:00",
            "rating_avg": 3.47,
            "num_collection": 78,
            "releases_rated": 116,
            "num_lists": 0,
            "name": "Rodney",
            "num_wantlist": 160,
            "inventory_url": "https://api.discogs.com/users/rodneyfool/inventory",
            "avatar_url": "http://www.gravatar.com/avatar/55502f40dc8b7c769880b10874abc9d0?s=52&r=pg&d=mm",
            "banner_url": (
                "https://img.discogs.com/dhuJe-pRJmod7hN3cdVi2PugEh4=/1600x400/"
                "filters:strip_icc():format(jpeg)/discogs-banners/B-1578108-user-1436314164-9231.jpg.jpg"
            ),
            "uri": "https://www.discogs.com/user/rodneyfool",
            "resource_url": "https://api.discogs.com/users/rodneyfool",
            "buyer_rating": 100.00,
            "buyer_rating_stars": 5,
            "buyer_num_ratings": 144,
            "seller_rating": 100.00,
            "seller_rating_stars": 5,
            "seller_num_ratings": 21,
            "curr_abbr": "USD",
        }
    )

    def _mock(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            uri="https://api.discogs.com/oauth/identity",
            status=200,
            body=json.dumps(
                {
                    "id": 1,
                    "username": self.expected_username,
                    "resource_url": f"https://api.discogs.com/users/{self.expected_username}",
                    "consumer_name": "SocialCore Discogs Test",
                }
            ),
        )
        HTTPretty.register_uri(
            HTTPretty.GET,
            f"https://api.discogs.com/users/{self.expected_username}",
            status=200,
            body=self.user_data_body,
        )

    def test_login(self):
        self._mock()
        self.do_login()

    def test_partial_pipeline(self):
        self._mock()
        self.do_partial_pipeline()
