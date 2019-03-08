"""
Okta OAuth2 and OpenIdConnect:
    https://python-social-auth.readthedocs.io/en/latest/backends/okta.html
"""
import sys
if sys.version_info[0] < 3:
    import urlparse as urlparse
else:
    import urllib.parse as urlparse

import requests
from six.moves.urllib.parse import urljoin

from ..utils import append_slash
from social_core.backends.oauth import BaseOAuth2
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthTokenError

class OktaMixin(object):
    def api_url(self):
        return append_slash(self.setting('API_URL'))

    def authorization_url(self):
        return self._url('v1/authorize')

    def access_token_url(self):
        return self._url('v1/token')

    def _url(self, path):
        return urljoin(append_slash(self.setting('API_URL')), path)

    def oidc_config(self):
        return self.get_json(self._url('/.well-known/openid-configuration?client_id='+self.setting('KEY')))

class OktaOAuth2(OktaMixin, BaseOAuth2):
    """Okta OAuth authentication backend"""
    name = 'okta-oauth2'
    REDIRECT_STATE = False
    ACCESS_TOKEN_METHOD = 'POST'
    SCOPE_SEPARATOR = ' '

    DEFAULT_SCOPE = [
        'openid', 'profile'
    ]
    EXTRA_DATA = [
        ('refresh_token', 'refresh_token', True),
        ('expires_in', 'expires'),
        ('token_type', 'token_type', True)
    ]

    def get_user_details(self, response):
        """Return user details from Okta account"""
        return {'username': response.get('preferred_username'),
                'email': response.get('preferred_username') or '',
                'first_name': response.get('given_name'),
                'last_name': response.get('family_name')}

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from Okta"""
        return self.get_json(
            self._url('v1/userinfo'),
            headers={
                'Authorization': 'Bearer %s' % access_token,
            }
        )

class OktaOpenIdConnect(OktaOAuth2, OpenIdConnectAuth):
    """Okta OpenID-Connect authentication backend"""
    name = 'okta-openidconnect'
    REDIRECT_STATE = False
    RESPONSE_TYPE = 'code'

    def request_access_token(self, *args, **kwargs):
        """
        Retrieve the access token. Also, validate the id_token and
        store it (temporarily).
        """
        response = self.get_json(*args, **kwargs)
        self.id_token = self.validate_and_return_id_token(
            response['id_token'],
            response['access_token']
        )
        return response

    def validate_and_return_id_token(self, id_token, access_token):
        """
        Validates the id_token using Okta.
        """
        client_id, client_secret = self.get_key_and_secret()

        tokendata = requests.request("POST", self._url('v1/introspect'),
                                     data="client_id=%s&client_secret=%s&token=%s&token_type_hint=%s" %
                                          (client_id, client_secret, id_token, 'id_token'),
                                     headers={'Content-Type': "application/x-www-form-urlencoded"}).json()

        if not tokendata['active']:
            raise AuthTokenError(self, 'Signature verification failed')

        return id_token





