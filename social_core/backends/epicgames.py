
from .oauth import BaseOAuth1, BaseOAuth2

class EpicGamesOAuth2(BaseOAuth2):
    name = 'epicgames'
    ID_KEY = 'user_id'
    AUTHORIZATION_URL = 'https://www.epicgames.com/id/authorize'
    ACCESS_TOKEN_URL = 'https://api.epicgames.dev/epic/oauth/v1/token'
    ACCESS_TOKEN_METHOD = 'POST'
    USER_DETAILS_URL = 'https://api.epicgames.dev/epic/oauth/v1/userInfo'
    REDIRECT_STATE = True

    def get_user_details(self, response):
        return {'username': response.get('screen_name', ''),
                'email': response.get('email', ''),
                'account_id':response.get('account_id','')}

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json(self.USER_DETAILS_URL, params={
            'access_token': access_token
        })
