import json
from urllib import urlencode
from urllib2 import urlopen
from social_core.backends.oauth import BaseOAuth2

class TCSOAuth2(BaseOAuth2):
    name = 'tcs'

    """
    Set this value to the 4-character identifier of your associationdatabase.com
    oauth2 provider web app.
    """
    AUTH_EXTRA_ARGUMENTS = {
    'org_id': 'CHANGE-ME'
    }

    ACCESS_TOKEN_METHOD = 'POST'
    REDIRECT_STATE = False
    BASE_URL = 'https://associationdatabase.com'
    AUTHORIZATION_URL = BASE_URL + '/oauth/authorize'
    ACCESS_TOKEN_URL = BASE_URL + '/oauth/token'
    USER_QUERY = BASE_URL + '/api/user?'
    SCOPE_SEPARATOR = ' '
    DEFAULT_SCOPE = ['public', 'write']

    def authorization_url(self):
        url = self.AUTHORIZATION_URL
        return url

    def access_token_url(self):
        url = self.ACCESS_TOKEN_URL
        return url

    def get_user_id(self, details, response):
        return details.get('username')

    def get_username(self, strategy, details, backend, user=None, *args, **kwargs):
        return details.get('username')

    def user_query(self):
        url = self.USER_QUERY
        return url

    def urlopen(self, url):
        return urlopen(url).read().decode("utf-8")

    def auth_extra_arguments(self):
        extra_arguments = self.AUTH_EXTRA_ARGUMENTS
        return extra_arguments

    def get_user_details(self, response):
        access_token = response.get('access_token')
        user_details = self.user_data(access_token)
        username = str(user_details.get('id'))
        email = user_details.get('email_address', '')
        first_name = user_details.get('first_name')
        last_name = user_details.get('last_name')
        fullname = first_name + ' ' + last_name

        retval = dict([
            ('username', username),
            ('email', email),
            ('fullname', fullname),
            ('first_name', first_name),
            ('last_name', last_name)
        ])

        return retval

    def user_data(self, access_token, *args, **kwargs):
        url = self.user_query() + urlencode({
            'access_token': access_token
        })
        return json.loads(self.urlopen(url))
