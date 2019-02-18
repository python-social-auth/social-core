"""
Auth0 implementation based on https://auth0.com/docs/quickstart/webapp/django/01-login
"""
from urllib import request
from jose import jwt
from .oauth import BaseOAuth2


class Auth0OAuth2(BaseOAuth2):
    """Auth0 OAuth authentication backend"""
    name = 'auth0'
    SCOPE_SEPARATOR = ' '
    ACCESS_TOKEN_METHOD = 'POST'
    EXTRA_DATA = [
        ('picture', 'picture')
    ]

    def auth_extra_arguments(self):
        """Return extra arguments needed on request-token process"""
        return self.setting('AUTH_EXTRA_ARGUMENTS', {})

    def authorization_url(self):
        return 'https://' + self.setting('DOMAIN') + '/authorize'

    def access_token_url(self):
        return 'https://' + self.setting('DOMAIN') + '/oauth/token'

    def get_user_id(self, details, response):
        """Return current user id."""
        return details['user_id']

    def get_user_details(self, response):
        # Obtain JWT and the keys to validate the signature
        id_token = response.get('id_token')
        jwks = request.urlopen('https://' + self.setting('DOMAIN') + '/.well-known/jwks.json')
        issuer = 'https://' + self.setting('DOMAIN') + '/'
        audience = self.setting('KEY')  # CLIENT_ID
        payload = jwt.decode(id_token, jwks.read().decode('utf-8'), algorithms=['RS256'], audience=audience, issuer=issuer)

        return {'username': payload['nickname'],
                'email': payload['email'],
                'first_name': payload['name'],
                'picture': payload['picture'],
                'user_id': payload['sub']}
