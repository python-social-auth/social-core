from social.backends.oauth import BaseOAuth2

# https://github.com/python-social-auth/social-docs/blob/master/docs/backends/implementation.rst#oauth
# https://support.zendesk.com/hc/en-us/articles/203663836-Using-OAuth-authentication-with-your-application


class ZendeskOAuth2(BaseOAuth2):
    name = 'zendesk'
    AUTHORIZATION_URL = 'https://{subdomain}.zendesk.com/oauth/authorizations/new'
    ACCESS_TOKEN_URL = 'https://{subdomain}.zendesk.com/oauth/tokens'
    ACCESS_TOKEN_METHOD = 'POST'
    DEFAULT_SCOPE = ['read']
    REDIRECT_STATE = False
    STATE_PARAMETER = True

    def _set_subdomain(self, url):
        return url.format(subdomain=self.setting('SUBDOMAIN'))

    def authorization_url(self):
        return self._set_subdomain(self.AUTHORIZATION_URL)

    def access_token_url(self):
        return self._set_subdomain(self.ACCESS_TOKEN_URL)

    def get_user_id(self, details, response):
        return details['id']

    def get_user_details(self, response):
        """Loads user data from service"""
        user = response['user']

        try:
            first_name, last_name = user['name'].split(' ', 1)
        except ValueError:
            first_name = user['name']
            last_name = ''

        user['fullname'] = user['name']
        user['first_name'] = first_name
        user['last_name'] = last_name

        return user

    def user_data(self, access_token, *args, **kwargs):
        url = self._set_subdomain('https://{subdomain}.zendesk.com/api/v2/users/me.json')
        auth_header = {"Authorization": "Bearer %s" % access_token}
        try:
            return self.get_json(url, headers=auth_header)
        except ValueError:
            return None

    def auth_html(self):
        return None
