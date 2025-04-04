"""
Kick OAuth2 backend, docs at:
    https://docs.kick.com/getting-started/generating-tokens-oauth2-flow
"""

from .oauth import BaseOAuth2PKCE


class KickOAuth2(BaseOAuth2PKCE):
    """Kick OAuth2 authentication backend"""
    name = 'kick'
    HOSTNAME = 'id.kick.com'
    API_HOSTNAME = 'kick.com'
    AUTHORIZATION_URL = f'https://{HOSTNAME}/oauth/authorize'
    ACCESS_TOKEN_URL = f'https://{HOSTNAME}/oauth/token'
    REFRESH_TOKEN_URL = f'https://{HOSTNAME}/oauth/token'
    REVOKE_TOKEN_URL = f'https://{HOSTNAME}/oauth/revoke'
    DEFAULT_SCOPE = ['user.read']
    SCOPE_SEPARATOR = ' '
    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = 'S256'
    EXTRA_DATA = [
        ('access_token', 'access_token'),
        ('refresh_token', 'refresh_token'),
        ('expires_in', 'expires'),
        ('token_type', 'token_type'),
        ('scope', 'scope')
    ]

    def get_user_details(self, response):
        """Return user details from Kick account"""
        return {
            'username': response.get('username'),
            'email': response.get('email') or '',
            'fullname': response.get('display_name') or '',
            'first_name': '',
            'last_name': ''
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = f'https://api.{self.API_HOSTNAME}/v1/user'
        auth_header = {'Authorization': f'Bearer {access_token}'}
        return self.get_json(url, headers=auth_header)
