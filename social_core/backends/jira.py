"""
Atlassian Jira Server OAuth backend, docs at:
    https://developer.atlassian.com/cloud/jira/platform/jira-rest-api-oauth-authentication/
"""
import six

from oauthlib.oauth1 import SIGNATURE_RSA, SIGNATURE_TYPE_QUERY, SIGNATURE_TYPE_AUTH_HEADER
from requests_oauthlib import OAuth1
from .oauth import BaseOAuth1
from ..exceptions import AuthTokenError


class JiraOAuth(BaseOAuth1):
    """Jira OAuth1 Authentication backend"""
    name = 'jira'
    ID_KEY = 'accountId'
    _ACCESS_TOKEN_URL = '{scheme}://{host}/plugins/servlet/oauth/access-token'
    _AUTHORIZATION_URL = '{scheme}://{host}/plugins/servlet/oauth/authorize'
    _REQUEST_TOKEN_URL = '{scheme}://{host}/plugins/servlet/oauth/request-token'
    _USER_DETAILS_URL = '{scheme}://{host}/rest/api/2/myself'
    ACCESS_TOKEN_METHOD = 'POST'

    def auth_url(self):
        token = self.get_unauthorized_token()
        return self.AUTHORIZATION_URL + '?oauth_token=' + token.get('oauth_token')

    def get_unauthorized_token(self):
        return self.get_json(
            self.REQUEST_TOKEN_URL,
            auth=self.oauth_auth()
        )

    def access_token_url(self):
        return self._ACCESS_TOKEN_URL.format(**self.jira_url_params)

    def authorization_url(self):
        return self._AUTHORIZATION_URL.format(**self.jira_url_params)

    @property
    def REQUEST_TOKEN_URL(self):
        return self._REQUEST_TOKEN_URL.format(**self.jira_url_params)

    @property
    def USER_DETAILS_URL(self):
        return self._USER_DETAILS_URL.format(**self.jira_url_params)

    @property
    def jira_url_params(self):
        return {
            'host': self.setting('HOST'),
            'scheme': self.setting('SCHEME', 'https'),
        }

    def oauth_auth(self, token=None, oauth_verifier=None,
                   signature_type=SIGNATURE_TYPE_AUTH_HEADER):
        key, secret = self.get_key_and_secret()
        oauth_verifier = oauth_verifier or self.data.get('oauth_verifier')
        if token:
            resource_owner_key = token.get('oauth_token')
            resource_owner_secret = token.get('oauth_token_secret')
            if not resource_owner_key:
                raise AuthTokenError(self, 'Missing oauth_token')
            if not resource_owner_secret:
                raise AuthTokenError(self, 'Missing oauth_token_secret')
        else:
            resource_owner_key = None
            resource_owner_secret = None
        # decoding='utf-8' produces errors with python-requests on Python3
        # since the final URL will be of type bytes
        decoding = None if six.PY3 else 'utf-8'
        state = self.get_or_create_state()
        return OAuth1(
            key,
            secret,
            resource_owner_key=resource_owner_key,
            resource_owner_secret=resource_owner_secret,
            callback_uri=self.get_redirect_uri(state),
            decoding=decoding,
            signature_method=SIGNATURE_RSA,
            signature_type=SIGNATURE_TYPE_QUERY,
            rsa_key=self.setting('RSA_PRIVATE_KEY')
        )

    def user_data(self, access_token, *args, **kwargs):
        return self.get_json(
            self.USER_DETAILS_URL,
            auth=self.oauth_auth(access_token)
        )

    def get_user_details(self, response):
        name = response.get('name') or ''
        full_name = response.get('displayName') or ''
        _, first_name, last_name = self.get_user_names(full_name)
        return {
            'username': name,
            'email': response.get('emailAddress'),
            'fullname': full_name,
            'first_name': first_name,
            'last_name': last_name
        }
