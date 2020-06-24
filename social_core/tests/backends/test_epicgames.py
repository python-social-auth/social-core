import json

from six.moves.urllib_parse import urlencode

from .oauth import OAuth2Test, OAuth1Test

class EpicGamesOAuth1Test(OAuth2Test):
    backend_path = 'social_core.backends.epicgames.EpicGamesOAuth2'
    user_data_url = 'https://api.epicgames.dev/epic/oauth/v1/userInfo'
    expected_username = 'foobar'
    access_token_body = json.dumps({
        'access_token': 'foobar',
        'token_type': 'bearer'
    })
    request_token_body = urlencode({
        'oauth_token_secret': 'foobar-secret',
        'oauth_token': 'foobar',
        'oauth_callback_confirmed': 'true'
    })
    user_data_body =  json.dumps({
        'email': 'foobar@gmail.com',
        'screen_name': 'foobar'
    })

    def test_login(self):
        self.do_login()

# class EpicGamesOAuth1Test(OAuth1Test):
#     backend_path = 'social_core.backends.epicgames.EpicGamesOAuth'
#     user_data_url = 'https://api.epicgames.dev/epic/oauth/v1/userInfo'
#     expected_username = 'foobar'
#     access_token_body = json.dumps({
#         'access_token': 'foobar',
#         'token_type': 'bearer'
#     })
#     request_token_body = urlencode({
#         'oauth_token_secret': 'foobar-secret',
#         'oauth_token': 'foobar',
#         'oauth_callback_confirmed': 'true'
#     })
#     user_data_body =  json.dumps({
#         'email': 'foobar@gmail.com',
#         'screen_name': 'foobar'
#     })
#
#     def test_login(self):
#         self.do_login()

    #python -m pytest test_epicgames.py
