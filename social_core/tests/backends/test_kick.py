import json

from .oauth import OAuth2Test


class KickOAuth2Test(OAuth2Test):
    backend_path = "social_core.backends.kick.KickOAuth2"
    user_data_url = "https://api.kick.com/public/v1/users"
    expected_username = "foobar"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
            "refresh_token": "refresh_foobar",
            "expires_in": 3600,
            "scope": "user:read",
        }
    )
    # The API returns data in a 'data' field with an array of users
    user_data_body = json.dumps(
        {
            "data": [
                {
                    "user_id": 123456,
                    "name": "foobar",
                    "email": "foobar@example.com",
                    "profile_picture": "https://example.com/avatar.jpg",
                }
            ],
            "message": "Success",
        }
    )

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
