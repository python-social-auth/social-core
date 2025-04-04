import json

from .oauth import OAuth2Test


class KickOAuth2Test(OAuth2Test):
    backend_path = 'social_core.backends.kick.KickOAuth2'
    user_data_url = 'https://api.kick.com/v1/user'
    expected_username = 'foobar'
    access_token_body = json.dumps({
        'access_token': 'foobar',
        'token_type': 'bearer',
        'refresh_token': 'refresh_foobar',
        'expires_in': 3600,
        'scope': 'user.read'
    })
    user_data_body = json.dumps({
        'id': '123456',
        'username': 'foobar',
        'email': 'foobar@example.com',
        'display_name': 'Foo Bar'
    })

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
