"""
Bungie OAuth2 backend
"""
from social_core.backends.oauth import BaseOAuth2
from django.conf import settings


class BungieOAuth2(BaseOAuth2):

    name = 'bungie'
    ID_KEY = 'membership_id'
    AUTHORIZATION_URL = 'https://www.bungie.net/en/oauth/authorize/'
    ACCESS_TOKEN_URL = 'https://www.bungie.net/platform/app/oauth/token/'
    REFRESH_TOKEN_URL = 'https://www.bungie.net/platform/app/oauth/token/'
    ACCESS_TOKEN_METHOD = 'POST'
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ('refresh_token', 'refresh_token', True),
        ('access_token', 'access_token', True),
        ('expires_in', 'expires'),
        ('membership_id', 'membership_id'),
        ('refresh_expires_in', 'refresh_expires_in')
    ]

    def auth_html(self):
        """Abstract Method Inclusion"""
        pass

    def auth_headers(self):
        """Adds X-API-KEY and Origin"""
        return {'X-API-KEY': settings.SOCIAL_AUTH_BUNGIE_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': settings.SOCIAL_AUTH_BUNGIE_ORIGIN,
                'Accept': 'application/json'
                }

    def make_bungie_request(self, url, access_token, kwargs):
        """Helper function to get username data keyed off displayName"""
        print('ENTERING MAKE BUNGIE REQUEST')
        headers = self.auth_headers()
        print(repr(headers))
        auth_header = {'Authorization': 'Bearer ' + access_token}
        headers.update(auth_header)
        import requests as python_requests
        r = python_requests.get(url, headers=headers)
        this_json = r.json()
        return this_json

    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        print('ENTERING AUTH COMPLETE')
        self.process_error(self.data)
        state = self.validate_state()
        # print('authcomplete', kwargs)
        response = self.request_access_token(
            self.access_token_url(),
            data=self.auth_complete_params(state),
            headers=self.auth_headers(),
            auth=self.auth_complete_credentials(),
            method=self.ACCESS_TOKEN_METHOD
        )
        self.process_error(response)
        return self.do_auth(response['access_token'], response=response, *args, **kwargs)

    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        print('ENTERING DO AUTH')
        data = self.user_data(access_token, *args, **kwargs)
        response = kwargs.get('response') or {}
        response.update(data or {})
        if 'access_token' not in response:
            response['Response']['access_token']['value'] = access_token
        kwargs.update({'response': response, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)

    def user_data(self, access_token, *args, **kwargs):
        """Grab user profile information from Bunige"""
        print('ENTERING USER_DATA')
        # print('kwargs', kwargs)
        # print('access_token: ', access_token)
        membership_id = kwargs['response']['membership_id']
        url = 'https://www.bungie.net/Platform/User/GetMembershipsById/' + str(membership_id) + '/254/'
        this_json = self.make_bungie_request(url, access_token, kwargs)
        # print('this json', this_json)
        username = this_json['Response']['bungieNetUser']['displayName']
        bnId = this_json['Response']['destinyMemberships'][0]['membershipId']
        return {'username': username, 'uid': membership_id, 'bnId': bnId}

    def get_user_details(self, response, *args, **kwargs):
        """Return user details from Bungie account"""
        print('ENTERING GET USER DETAILS')
        # Get Username from Bungie's Display Name
        username = response['username']
        uid = response['uid']
        bnId = response['bnId']
        # print(username)
        # Check Guardian Table for Email Address.
        from UserInterface.models import Guardian
        this_return = Guardian.objects.filter(membershipid=uid).values('email')
        email = this_return[0]['email']
        return {
            'first_name': username,
            'username': username,
            'uid': uid,
            'bnId': bnId,
            'email': email,
        }

    def auth_allowed(self, response, details):
        """Return True if the user should be allowed to authenticate, by
        default check if email is whitelisted (if there's a whitelist)
        Here we check the guardian table for the presence of the membership id
        for whitelisting."""
        print('ENTERING BUNGIE AUTH ALLOWED')
        # print('response', response)
        from UserInterface.models import Guardian
        these_membership_ids = Guardian.objects.values_list('membershipid', flat=True)
        this_membership_id = response['membership_id']
        # print('these_membership_ids', these_membership_ids)
        # type(these_membership_ids)
        # allowed = False
        if this_membership_id in these_membership_ids:
            allowed = True
        else:
            allowed = False
        # print('ALLOWED:', allowed)
        return allowed
