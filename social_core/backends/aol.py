"""
AOL OpenId backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/aol.html
"""
from urllib.parse import urlsplit

from social_core.exceptions import AuthMissingParameter

from .open_id import OpenIdAuth


class AOLOpenId(OpenIdAuth):
    name = 'aol'

    def get_user_details(self, response):
        """Generate username from identity url"""
        values = super(AOLOpenId, self).get_user_details(response)
        values['username'] = values.get('username') or urlsplit(response.identity_url).path[1:]
        return values

    def openid_url(self):
        """Returns AOL authentication URL"""
        if not self.data.get('openid_aol_user'):
            raise AuthMissingParameter(self, 'openid_aol_user')
        return 'http://openid.aol.com/{0}'.format(self.data['openid_aol_user'])
