"""
Slack OAuth2 backend, docs at:
    http://psa.matiasaguirre.net/docs/backends/slack.html
    https://api.slack.com/docs/oauth
"""
from .oauth import BaseOAuth2


class SlackOAuth2(BaseOAuth2):
    """Slack OAuth authentication backend"""
    name = 'slack'
    AUTHORIZATION_URL = 'https://slack.com/oauth/authorize'
    ACCESS_TOKEN_URL = 'https://slack.com/api/oauth.access'
    ACCESS_TOKEN_METHOD = 'POST'
    DEFAULT_SCOPE = ['identity.basic', 'identity.email']
    SCOPE_SEPARATOR = ','
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ('id', 'id'),
        ('name', 'name'),
        ('real_name', 'real_name')
    ]

    def get_user_details(self, response):
        """Return user details from Slack account"""
        # Build the username with the team $username@$team_url
        # Necessary to get unique names for all of slack
        user = response['user']
        team = response.get('team')
        name = user['name']
        email = user.get('email')
        username = email and email.split('@', 1)[0] or name
        fullname, first_name, last_name = self.get_user_names(name)

        if self.setting('USERNAME_WITH_TEAM', True) and team and 'name' in team:
            name = '{0}@{1}'.format(name, response['team']['name'])

        return {
            'username': username,
            'email': email,
            'fullname': fullname,
            'first_name': first_name,
            'last_name': last_name
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json('https://slack.com/api/users.identity',
                             params={'token': access_token})
