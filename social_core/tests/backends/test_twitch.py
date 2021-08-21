import json
from .oauth import OAuth2Test
from .open_id_connect import OpenIdConnectTestMixin


class TwitchOpenIdConnectTest(OpenIdConnectTestMixin, OAuth2Test):
    backend_path = 'social_core.backends.twitch.TwitchOpenIdConnect'
    user_data_url = 'https://id.twitch.tv/oauth2/userinfo'
    issuer = 'https://id.twitch.tv/oauth2'
    expected_username = 'test_user1'
    openid_config_body = json.dumps({
        'authorization_endpoint': 'https://id.twitch.tv/oauth2/authorize',
        'claims_parameter_supported': True,
        'claims_supported': [
            'iss',
            'azp',
            'preferred_username',
            'updated_at',
            'aud',
            'exp',
            'iat',
            'picture',
            'sub',
            'email',
            'email_verified',
        ],
        'id_token_signing_alg_values_supported': [
            'RS256',
        ],
        'issuer': 'https://id.twitch.tv/oauth2',
        'jwks_uri': 'https://id.twitch.tv/oauth2/keys',
        'response_types_supported': [
            'id_token',
            'code',
            'token',
            'code id_token',
            'token id_token',
        ],
        'scopes_supported': [
            'openid',
        ],
        'subject_types_supported': [
            'public',
        ],
        'token_endpoint': 'https://id.twitch.tv/oauth2/token',
        'token_endpoint_auth_methods_supported': [
            'client_secret_post',
        ],
        'userinfo_endpoint': 'https://id.twitch.tv/oauth2/userinfo',
    })


class TwitchOAuth2Test(OAuth2Test):
    backend_path = 'social_core.backends.twitch.TwitchOAuth2'
    user_data_url = 'https://api.twitch.tv/kraken/user/'
    expected_username = 'test_user1'
    access_token_body = json.dumps({
        'access_token': 'foobar',
    })
    user_data_body = json.dumps({
        'type': 'user',
        'name': 'test_user1',
        'created_at': '2011-06-03T17:49:19Z',
        'updated_at': '2012-06-18T17:19:57Z',
        'logo': 'http://static-cdn.jtvnw.net/jtv_user_pictures/'
                'test_user1-profile_image-62e8318af864d6d7-300x300.jpeg',
        '_id': 22761313,
        'display_name': 'test_user1',
        'bio': 'test bio woo I\'m a test user',
        'email': 'asdf@asdf.com',
        'email_verified': True,
        'partnered': True,
        'twitter_connected': False,
        'notifications': {
            'push': True,
            'email': True
        }
    })

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
