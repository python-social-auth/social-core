import json
from unittest.mock import patch

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class SoundcloudOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.soundcloud.SoundcloudOAuth2"
    user_data_url = "https://api.soundcloud.com/me"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "website": None,
            "myspace_name": None,
            "public_favorites_count": 0,
            "followings_count": 0,
            "full_name": "Foo Bar",
            "id": 10101010,
            "city": None,
            "track_count": 0,
            "playlist_count": 0,
            "discogs_name": None,
            "private_tracks_count": 0,
            "followers_count": 0,
            "online": True,
            "username": "foobar",
            "description": None,
            "subscriptions": [],
            "kind": "user",
            "quota": {
                "unlimited_upload_quota": False,
                "upload_seconds_left": 7200,
                "upload_seconds_used": 0,
            },
            "website_title": None,
            "primary_email_confirmed": False,
            "permalink_url": "http://soundcloud.com/foobar",
            "private_playlists_count": 0,
            "permalink": "foobar",
            "upload_seconds_left": 7200,
            "country": None,
            "uri": "https://api.soundcloud.com/users/10101010",
            "avatar_url": "https://a1.sndcdn.com/images/default_avatar_large.png?ca77017",
            "plan": "Free",
        }
    )

    def test_login(self):
        """Test standard login flow"""
        assert self.user_data_body is not None
        with patch.object(
            self.backend, "user_data", return_value=json.loads(self.user_data_body)
        ):
            self.do_login()

    def test_partial_pipeline(self):
        """Test partial pipeline flow"""
        assert self.user_data_body is not None
        with patch.object(
            self.backend, "user_data", return_value=json.loads(self.user_data_body)
        ):
            self.do_partial_pipeline()

    def test_user_data(self):
        """Test user_data method with Authorization header"""
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_SOUNDCLOUD_KEY": "test_client_id",
                "SOCIAL_AUTH_SOUNDCLOUD_SECRET": "test_client_secret",
            }
        )

        # Mock the HTTP request to the user data endpoint
        with patch("social_core.backends.base.BaseAuth.request") as mock_request:
            assert self.user_data_body is not None
            mock_request.return_value.json.return_value = json.loads(
                self.user_data_body
            )
            response = self.backend.user_data(access_token="foobar")  # noqa: S106

            # Verify the request was made with the correct parameters
            mock_request.assert_called_once_with(
                "https://api.soundcloud.com/me",
                headers={"Authorization": "OAuth foobar"},
                params={"format": "json"},
                method="GET",
                data=None,
                auth=None,
            )

            # Verify the response data
            self.assertEqual(response["username"], self.expected_username)
            self.assertEqual(response["permalink_url"], "http://soundcloud.com/foobar")
            self.assertEqual(response["id"], 10101010)
            self.assertEqual(response["full_name"], "Foo Bar")
