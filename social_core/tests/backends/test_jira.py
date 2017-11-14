import json
import os

# from httpretty import HTTPretty
from .oauth import OAuth1Test


class JiraOAuthTest(OAuth1Test):
    backend_path = 'social_core.backends.jira.JiraOAuth'
    expected_username = 'foobar'
    request_token_body = json.dumps({
        'oauth_token_secret': 'foobar-secret',
        'oauth_token': 'foobar',
    })
    access_token_body = json.dumps({
        'access_token': 'foobar',
        'token_type': 'bearer'
    })
    user_data_url = 'https://www.example.com/rest/api/2/myself'
    user_data_body = json.dumps({
        u'self': u'https://www.example.com/jira/rest/api/2/user?username=foobar',
        u'key': u'foobar',
        u'accountId': u'99:27935d01-92a7-4687-8272-a9b8d3b2ae2e',
        u'name': u'foobar',
        u'emailAddress': u'foobar@example.com',
        u'avatarUrls': {
            u'48x48': u'https://www.example.com/jira/secure/useravatar?size=large&ownerId=foobar',
            u'24x24': u'https://www.example.com/jira/secure/useravatar?size=small&ownerId=foobar',
            u'16x16': u'https://www.example.com/jira/secure/useravatar?size=xsmall&ownerId=foobar',
            u'32x32': u'https://www.example.com/jira/secure/useravatar?size=medium&ownerId=foobar'
        },
        u'displayName': u'Foobar F. User',
        u'active': True,
        u'timeZone': u'Australia/Sydney',
        u'groups': {u'size': 3, u'items': []},
        u'applicationRoles': {u'size': 1, u'items': []}
    })

    def setUp(self):
        super(JiraOAuthTest, self).setUp()
        test_root = os.path.dirname(os.path.dirname(__file__))
        self.private_key = open(os.path.join(test_root, 'testkey.pem'), 'r').read().strip()
        self.strategy.set_settings({
            'SOCIAL_AUTH_JIRA_SCHEME': 'https',
            'SOCIAL_AUTH_JIRA_HOST': 'www.example.com',
            'SOCIAL_AUTH_JIRA_RSA_PRIVATE_KEY': self.private_key,
        })

    def test_login(self):
        self.do_login()
