"""
Kakao OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/kakao.html
"""
from .oauth import BaseOAuth2


class KakaoOAuth2(BaseOAuth2):
    """Kakao OAuth authentication backend"""
    name = 'kakao'
    AUTHORIZATION_URL = 'https://kauth.kakao.com/oauth/authorize'
    ACCESS_TOKEN_URL = 'https://kauth.kakao.com/oauth/token'
    ACCESS_TOKEN_METHOD = 'POST'
    REDIRECT_STATE = False

    def get_user_id(self, details, response):
        return response['id']

    def get_user_details(self, response):
        """Return user details from Kakao account"""
        nickname = response.get('properties').get('nickname') if response.get('properties') else ''
        email = response.get('kaccount_email', '')
        return {
            'username': nickname,
            'email': email,
            'fullname': nickname,
            'first_name': '',
            'last_name': ''
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json('https://kapi.kakao.com/v1/user/me',
                             params={'access_token': access_token})

    def auth_complete_params(self, state=None):
        return {
            'grant_type': 'authorization_code',
            'code': self.data.get('code', ''),
            'client_id': self.get_key_and_secret()[0],
        }
