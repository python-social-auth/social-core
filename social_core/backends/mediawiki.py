"""
MediaWiki OAuth1 backend
========================

Usage
-----

In addition to the general setup you need to define the
following parameters. In Django's settings.py you would
use for English Wikipedia::

    SOCIAL_AUTH_MEDIAWIKI_KEY = <consumer_key>
    SOCIAL_AUTH_MEDIAWIKI_SECRET = <consumer_secret>
    REQUEST_TOKEN_URL =
        'https://en.wikipedia.org/w/index.php?title=Special:OAuth/initiate'
    AUTHORIZATION_URL =
        'https://en.wikipedia.org/w/index.php?title=Special:Oauth/authorize'
    ACCESS_TOKEN_URL =
        'https://en.wikipedia.org/w/index.php?title=Special:Oauth/token'
    IDENTIFY_URL =
        'https://en.wikipedia.org/w/index.php'

If users should only be prompeted once for permission use:

    AUTHORIZATION_URL =
        'https://en.wikipedia.org/w/index.php?title=Special:Oauth/authenticate'

General documentation
---------------------

https://www.mediawiki.org/wiki/Extension:OAuth

Developer documentation
-----------------------

https://www.mediawiki.org/wiki/OAuth/For_Developers
"""

import jwt
import requests
import six
from requests_oauthlib import OAuth1
from six import b
from six.moves.urllib.parse import parse_qs, urlencode
from .oauth import BaseOAuth1


class MediaWiki(BaseOAuth1):

    """
    Handles the handshake with Mediawiki and fetching of user data.
    """

    name = 'mediawiki'
    REQUEST_TOKEN_URL = 'https://en.wikipedia.org/w/index.php' + \
                        '?title=Special:OAuth/initiate'
    AUTHORIZATION_URL = 'https://en.wikipedia.org/w/index.php' + \
                        '?title=Special:Oauth/authorize'
    ACCESS_TOKEN_URL = 'https://en.wikipedia.org/w/index.php' + \
                       '?title=Special:Oauth/token'
    IDENTIFY_URL = 'https://en.wikipedia.org/w/index.php' + \
                   '?title=Special:OAuth/identify'

    def unauthorized_token(self):
        """
        Return request for unauthorized token (first stage)

        Mediawiki request token is requested from e.g.:
         * https://en.wikipedia.org/w/index.php?title=Special:OAuth/initiate
         * 'callback_uri' needs to be 'oob'
        """
        params = self.request_token_extra_arguments()
        params.update(self.get_scope_argument())
        key, secret = self.get_key_and_secret()
        decoding = None if six.PY3 else 'utf-8'

        response = self.request(
            self.setting('REQUEST_TOKEN_URL'),
            params=params,
            auth=OAuth1(key, secret, callback_uri='oob',
                        decoding=decoding),
            method=self.REQUEST_TOKEN_METHOD
        )

        content = response.content.decode()

        return content

    def oauth_authorization_request(self, token):
        """
        Generates the URL for the authorization link

        For English Wikipedia the URL is either:
         * https://en.wikipedia.org/w/index.php
                ?title=Special:Oauth/authorize'
         * https://en.wikipedia.org/w/index.php
                ?title=Special:Oauth/authenticate'
        """
        if not isinstance(token, dict):
            token = parse_qs(token)

        params = {}

        oauth_token = token.get(self.OAUTH_TOKEN_PARAMETER_NAME)[0]
        params[self.OAUTH_TOKEN_PARAMETER_NAME] = oauth_token

        state = self.get_or_create_state()
        params[self.REDIRECT_URI_PARAMETER_NAME] = self.get_redirect_uri(state)

        base_url, oauth_title_param = self.setting('AUTHORIZATION_URL').split('?')
        _, oauth_title = oauth_title_param.split('=')

        params['title'] = oauth_title

        return '{0}?{1}'.format(base_url, urlencode(params))

    def access_token(self, token):
        """
        Fetches the Mediawiki access token.
        """
        url = self.access_token_url()
        url_base, title = url.split('?')
        _, title_param = title.split('=')
        auth_token = self.oauth_auth(token)

        response = requests.post(url=url_base,
                                 params={'title': title_param},
                                 auth=auth_token)

        credentials = parse_qs(response.content)
        oauth_token_key = credentials.get(b('oauth_token'))[0]
        oauth_token_secret = credentials.get(b('oauth_token_secret'))[0]
        oauth_token_key = oauth_token_key.decode()
        oauth_token_secret = oauth_token_secret.decode()

        access_token = {'oauth_token': oauth_token_key,
                        'oauth_token_secret': oauth_token_secret}
        return access_token

    def get_user_details(self, token):
        """
        Gets the user details from Special:OAuth/identify
        """
        key, secret = self.get_key_and_secret()
        access_token = token['access_token']

        auth = OAuth1(key, client_secret=secret,
                      resource_owner_key=access_token['oauth_token'],
                      resource_owner_secret=access_token['oauth_token_secret'])

        base_url, oauth_title_param = self.setting('IDENTIFY_URL').split('?')
        _, oauth_title = oauth_title_param.split('=')

        response = requests.post(url=base_url,
                                 params={'title': oauth_title},
                                 auth=auth)

        try:
            identity = jwt.decode(response.content, secret,
                                  audience=key, algorithms=['HS256'],
                                  leeway=10.0)
        except jwt.InvalidTokenError as exception:
            raise Exception('An error occurred while trying to read json ' +
                            'content: {0}'.format(exception))

        data = {'username': identity['username'],
                'userID': identity['sub']}

        return data

    def get_user_id(self, details, response):
        """
        Get the unique Mediawiki user ID.
        """
        return details['userID']
