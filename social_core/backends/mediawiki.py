"""
MediaWiki OAuth1 backend
========================

Usage
-----

In addition to the general setup you need to define the
following parameters. In Django's settings.py you would
use for Wikimedia Meta-Wiki::

    SOCIAL_AUTH_MEDIAWIKI_KEY = <consumer_key>
    SOCIAL_AUTH_MEDIAWIKI_SECRET = <consumer_secret>
    SOCIAL_AUTH_MEDIAWIKI_URL = 'https://meta.wikimedia.org/w/index.php'

In the OAuth consumer registration you can choose the option to:

    Allow consumer to specify a callback in requests
    and use "callback" URL above as a required prefix

This is preferable. If your URL is `https://myurl.org/` use
the following option::

    SOCIAL_AUTH_MEDIAWIKI_CALLBACK = \
          'https://myurl.org/oauth/complete/mediawiki'

But it is also possible to use::

    SOCIAL_AUTH_MEDIAWIKI_CALLBACK = 'oob'

General documentation
---------------------

https://www.mediawiki.org/wiki/Extension:OAuth

Developer documentation
-----------------------

https://www.mediawiki.org/wiki/OAuth/For_Developers

Code based on
-------------

https://github.com/mediawiki-utilities/python-mwoauth
"""

import jwt
import re
import requests
import six
import time
from requests_oauthlib import OAuth1
from six import b
from six.moves.urllib.parse import parse_qs, urlencode, urlparse
from .oauth import BaseOAuth1


class MediaWiki(BaseOAuth1):

    """
    Handles the handshake with Mediawiki and fetching of user data.
    """

    name = 'mediawiki'
    MEDIAWIKI_URL = 'https://meta.wikimedia.org/w/index.php'
    SOCIAL_AUTH_MEDIAWIKI_CALLBACK = 'oob'

    def unauthorized_token(self):
        """
        Return request for unauthorized token (first stage)

        Mediawiki request token is requested from e.g.:
         * https://en.wikipedia.org/w/index.php?title=Special:OAuth/initiate
        """
        params = self.request_token_extra_arguments()
        params.update(self.get_scope_argument())
        params['title'] = 'Special:OAuth/initiate'
        key, secret = self.get_key_and_secret()
        decoding = None if six.PY3 else 'utf-8'

        response = self.request(
            self.setting('MEDIAWIKI_URL'),
            params=params,
            auth=OAuth1(key, secret,
                        callback_uri=self.setting('CALLBACK'),
                        decoding=decoding),
            method=self.REQUEST_TOKEN_METHOD)

        content = response.content.decode()

        return content

    def oauth_authorization_request(self, token):
        """
        Generates the URL for the authorization link
        """
        if not isinstance(token, dict):
            token = parse_qs(token)

        params = {}

        oauth_token = token.get(self.OAUTH_TOKEN_PARAMETER_NAME)[0]
        params[self.OAUTH_TOKEN_PARAMETER_NAME] = oauth_token

        state = self.get_or_create_state()
        params[self.REDIRECT_URI_PARAMETER_NAME] = self.get_redirect_uri(state)

        base_url = self.setting('MEDIAWIKI_URL')

        params['title'] = 'Special:Oauth/authenticate'

        return '{0}?{1}'.format(base_url, urlencode(params))

    def access_token(self, token):
        """
        Fetches the Mediawiki access token.
        """
        auth_token = self.oauth_auth(token)

        response = requests.post(url=self.setting('MEDIAWIKI_URL'),
                                 params={'title': 'Special:Oauth/token'},
                                 auth=auth_token)

        credentials = parse_qs(response.content)
        oauth_token_key = credentials.get(b('oauth_token'))[0]
        oauth_token_secret = credentials.get(b('oauth_token_secret'))[0]
        oauth_token_key = oauth_token_key.decode()
        oauth_token_secret = oauth_token_secret.decode()

        access_token = {'oauth_token': oauth_token_key,
                        'oauth_token_secret': oauth_token_secret}
        return access_token

    def force_unicode(self, value):
        """
        Return string in unicode.
        """
        if type(value) == six.text_type:
            return value
        else:
            if six.PY3:
                return str(value, "unicode-escape")
            else:
                return unicode(value, "unicode-escape")

    def get_user_details(self, response):
        """
        Gets the user details from Special:OAuth/identify
        """
        key, secret = self.get_key_and_secret()
        access_token = response['access_token']
        leeway = 10.0

        auth = OAuth1(key, client_secret=secret,
                      resource_owner_key=access_token['oauth_token'],
                      resource_owner_secret=access_token['oauth_token_secret'])

        req_resp = requests.post(url=self.setting('MEDIAWIKI_URL'),
                                 params={'title': 'Special:OAuth/identify'},
                                 auth=auth)

        try:
            identity = jwt.decode(req_resp.content, secret,
                                  audience=key, algorithms=['HS256'],
                                  leeway=leeway)
        except jwt.InvalidTokenError as exception:
            raise Exception('An error occurred while trying to read json ' +
                            'content: {0}'.format(exception))

        issuer = urlparse(identity['iss']).netloc
        expected_domain = urlparse(self.setting('MEDIAWIKI_URL')).netloc

        if not issuer == expected_domain:
            raise Exception("Unexpected issuer " +
                            "{0}, expected {1}".format(issuer, expected_domain))

        now = time.time()
        issued_at = float(identity['iat'])
        if not now >= (issued_at - leeway):
            raise Exception("Identity issued {0} ".format(issued_at - now) +
                            "seconds in the future!")

        authorization_header = self.force_unicode(
            req_resp.request.headers['Authorization'])
        request_nonce = re.search(r'oauth_nonce="(.*?)"',
                                  authorization_header).group(1)

        if identity['nonce'] != request_nonce:
            raise Exception('Replay attack detected:' +
                            '{0} != {1}'.format(identity['nonce'],
                                                request_nonce))

        data = {'username': identity['username'],
                'userID': identity['sub']}

        return data

    def get_user_id(self, details, response):
        """
        Get the unique Mediawiki user ID.
        """
        return details['userID']
