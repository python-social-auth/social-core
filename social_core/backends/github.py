"""
Github OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/github.html
"""
from urllib.parse import urljoin

from requests import HTTPError

from .oauth import BaseOAuth2
from ..exceptions import AuthFailed


class GithubOAuth2(BaseOAuth2):
    """Github OAuth authentication backend"""
    name = 'github'
    API_URL = 'https://api.github.com/'
    AUTHORIZATION_URL = 'https://github.com/login/oauth/authorize'
    ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
    ACCESS_TOKEN_METHOD = 'POST'
    SCOPE_SEPARATOR = ','
    REDIRECT_STATE = False
    STATE_PARAMETER = True
    SEND_USER_AGENT = True
    EXTRA_DATA = [
        ('id', 'id'),
        ('expires', 'expires'),
        ('login', 'login')
    ]

    def api_url(self):
        return self.API_URL

    def get_user_details(self, response):
        """Return user details from Github account"""
        fullname, first_name, last_name = self.get_user_names(
            response.get('name')
        )
        return {'username': response.get('login'),
                'email': response.get('email') or '',
                'fullname': fullname,
                'first_name': first_name,
                'last_name': last_name}

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        data = self._user_data(access_token)
        if not data.get('email'):
            try:
                emails = self._user_data(access_token, '/emails')
            except (HTTPError, ValueError, TypeError):
                emails = []

            if emails:
                email = emails[0]
                primary_emails = [
                    e for e in emails
                    if not isinstance(e, dict) or e.get('primary')
                ]
                if primary_emails:
                    email = primary_emails[0]
                if isinstance(email, dict):
                    email = email.get('email', '')
                data['email'] = email
        return data

    def _user_data(self, access_token, path=None):
        url = urljoin(self.api_url(), 'user{0}'.format(path or ''))
        return self.get_json(url, headers={'Authorization': 'token {0}'.format(access_token)})


class GithubMemberOAuth2(GithubOAuth2):
    no_member_string = ''

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        user_data = super().user_data(access_token, *args, **kwargs)
        headers = {'Authorization': 'token {0}'.format(access_token)}
        try:
            self.request(self.member_url(user_data), headers=headers)
        except HTTPError as err:
            # if the user is a member of the organization, response code
            # will be 204, see http://bit.ly/ZS6vFl
            if err.response.status_code != 204:
                raise AuthFailed(self,
                                 'User doesn\'t belong to the organization')
        return user_data

    def member_url(self, user_data):
        raise NotImplementedError('Implement in subclass')


class GithubOrganizationOAuth2(GithubMemberOAuth2):
    """Github OAuth2 authentication backend for organizations"""
    name = 'github-org'
    no_member_string = 'User doesn\'t belong to the organization'

    def member_url(self, user_data):
        return urljoin(
            self.api_url(),
            'orgs/{org}/members/{username}'.format(
                org=self.setting('NAME'),
                username=user_data.get('login')
            )
        )


class GithubTeamOAuth2(GithubMemberOAuth2):
    """Github OAuth2 authentication backend for teams"""
    name = 'github-team'
    no_member_string = 'User doesn\'t belong to the team'

    def member_url(self, user_data):
        return urljoin(
            self.api_url(),
            'teams/{team_id}/members/{username}'.format(
                team_id=self.setting('ID'),
                username=user_data.get('login')
            )
        )


class GithubAppAuth(GithubOAuth2):
    """GitHub App OAuth authentication backend"""
    name = 'github-app'

    def validate_state(self):
        """
        Scenario 1: user clicks an icon/button on your website and initiates
                    social login. This works exacltly like standard OAuth and we
                    have `state` and `redirect_uri`.

        Scenario 2: user starts from http://github.com/apps/your-app and clicks
                    'Install & Authorize' button! They still get a temporary
                    `code` (used to fetch `access_token`) but there's no `state`
                    or `redirect_uri` here.

        Note: Scenario 2 only happens when your GitHub App is configured
              with `Request user authorization (OAuth) during installation`
              turned on! This causes GitHub to redirect the person back to
              `/complete/github/`. If the above setting is turned off then
              GitHub will redirect to another URL called Setup URL and the
              person may need to login first before they can continue!
        """
        if self.data.get('installation_id') and self.data.get('setup_action'):
            return None

        return super().validate_state()
