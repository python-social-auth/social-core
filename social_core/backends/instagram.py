"""
Instagram OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/instagram.html
"""
import hmac

from hashlib import sha256

from .oauth import BaseOAuth2


class InstagramOAuth2(BaseOAuth2):
    name = 'instagram'
    RESPONSE_TYPE = None
    REDIRECT_STATE = False
    SCOPE_SEPARATOR = ','
    AUTHORIZATION_URL = 'https://api.instagram.com/oauth/authorize'
    ACCESS_TOKEN_URL = 'https://api.instagram.com/oauth/access_token'
    USER_DATA_URL = 'https://graph.instagram.com/me/'
    REFRESH_TOKEN_URL = 'https://graph.instagram.com/refresh_access_token'
    ACCESS_TOKEN_METHOD = 'POST'

    def get_user_id(self, details, response):
        # https://developers.facebook.com/docs/instagram-basic-display-api/reference/me
        user_id = response.get('id') or {}
        return user_id

    def get_user_details(self, response):
        """Return user details from Instagram account"""
        # https://developers.facebook.com/docs/instagram-basic-display-api/reference/me
        fullname, first_name, last_name = self.get_user_names(
            user.get('full_name', '')
        )
        return {'username': response.get('username', response.get('name')),
                'email': response.get('email', ''),
                'fullname': fullname,
                'first_name': first_name,
                'last_name': last_name}

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        params = self.setting('PROFILE_EXTRA_PARAMS', {})
        params['access_token'] = access_token
        return self.get_json(self.USER_DATA_URL,
                             params=params)

    def process_error(self, data):
        super(InstagramOAuth2, self).process_error(data)
        if data.get('error_code'):
            raise AuthCanceled(self, data.get('error_message') or
                                     data.get('error_code'))

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        self.process_error(self.data)
        if not self.data.get('code'):
            raise AuthMissingParameter(self, 'code')
        state = self.validate_state()
        key, secret = self.get_key_and_secret()
        response = self.request(ACCESS_TOKEN_URL, params={
            'client_id': key,
            'client_secret': secret,
            'code': self.data['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': self.get_redirect_uri(state),
        })
        access_token = response['access_token']
        return self.do_auth(access_token, response, *args, **kwargs)


    def refresh_token_params(self, token, *args, **kwargs):
        return {
            'access_token': token,
            'grant_type': 'ig_refresh_token',
        }
