"""
    ID4me OpenID Connect backend, description at: https://id4me.org/for-developers/
"""
import datetime
import json
import re
from calendar import timegm

import dns
import jwt
import requests
from dns.resolver import NXDOMAIN, Timeout
from jose import jwk, jwt
from jose.jwt import JWTError, JWTClaimsError, ExpiredSignatureError
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthUnreachableProvider, AuthForbidden, AuthMissingParameter, AuthTokenError
from social_core.utils import handle_http_errors


class ID4meAssociation(object):
    """ Use Association model to save the client account."""

    def __init__(self, handle, secret='', issued=0, lifetime=0, assoc_type=''):
        self.handle = handle  # as client_id and client_secret
        self.secret = secret.encode()  # not use
        self.issued = issued  # not use
        self.lifetime = lifetime  # not use
        self.assoc_type = assoc_type  # as state

    def __str__(self):
        return self.handle


def is_valid_domain(domain):
    if domain[-1] == ".":
        domain = domain[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in domain.split("."))


class ID4meBackend(OpenIdConnectAuth):
    name = 'id4me'
    EXTRA_DATA = ['sub', 'iss', 'clp']
    JWT_DECODE_OPTIONS = dict(verify_at_hash=False)

    def __init__(self, *args, **kwargs):
        super(ID4meBackend, self).__init__(*args, **kwargs)

    def get_identity_record(self, identity):
        try:
            response = dns.resolver.query('_openid.' + identity, 'TXT', lifetime=5).response.answer
        except NXDOMAIN or Timeout:
            raise AuthUnreachableProvider(self)
        if not response:
            raise AuthUnreachableProvider(self)
        records = response[0]
        if not records:
            raise AuthUnreachableProvider(self)
        record = records[-1].strings[0].decode()
        return {item.split("=")[0]: item.split("=")[1] for item in record.split(";")}

    def get_association(self, issuer):
        try:
            return self.strategy.storage.association.get(server_url=issuer)[0]
        except IndexError:
            return None

    @handle_http_errors
    def get_key_and_secret(self):
        iau = self.strategy.session_get(self.name + '_authority')
        association = self.get_association(iau)
        if not association:
            issuer_configuration = self.oidc_config_authority()
            response = requests.post(issuer_configuration['registration_endpoint'], json={
                'client_name': self.setting('SOCIAL_AUTH_ID4ME_CLIENT_NAME', ''),
                'redirect_uris': [self.get_redirect_uri()],
                'id_token_signed_response_alg': 'RS256',
                'userinfo_signed_response_alg': 'RS256'
            })

            if response.status_code != 200:
                error = response.text
                raise AuthUnreachableProvider(self)
            association = ID4meAssociation(response.text)
            self.strategy.storage.association.store(iau, association)
        data = json.loads(association.handle)
        return data['client_id'], data['client_secret']

    def state_token(self):
        return self.strategy.random_string(30)

    def get_or_create_state(self):
        if self.STATE_PARAMETER or self.REDIRECT_STATE:
            name = self.name + '_state'
            state = self.strategy.session_get(name)
            if state is None:
                state = self.state_token()
                self.strategy.session_set(name, state)
        else:
            state = None
        return state

    def get_scope(self):
        scope = self.setting('SCOPE', {})
        if not scope:
            scope = self.DEFAULT_SCOPE
        return scope

    def get_scope_argument(self):
        param = {'scope': 'openid'}
        scope = self.get_scope()
        if scope:
            param['claims'] = json.dumps({'userinfo': scope})
        return param

    def oidc_config_authority(self):
        return self.get_json('https://' + self.strategy.session_get(self.name + '_authority') +
                             '/.well-known/openid-configuration')

    def oidc_config_agent(self):
        return self.get_json('https://' + self.strategy.session_get(self.name + '_agent') +
                             '/.well-known/openid-configuration')

    def authorization_url(self):
        return self.oidc_config_authority().get('authorization_endpoint')

    def access_token_url(self):
        return self.oidc_config_authority().get('token_endpoint')

    def id_token_issuer(self):
        return [self.strategy.session_get(self.name + '_authority'),
                'https://' + self.strategy.session_get(self.name + '_authority'),
                self.strategy.session_get(self.name + '_authority').replace('https://', '')]

    def userinfo_url(self):
        return self.oidc_config_agent().get('userinfo_endpoint')

    def jwks_uri(self):
        return self.oidc_config_authority().get('jwks_uri')

    def get_agent_keys(self):
        return self.request(self.oidc_config_agent().get('jwks_uri')).json()['keys']

    def get_jwks_keys(self):
        keys = self.get_remote_jwks_keys()
        return keys

    def find_valid_key(self, id_token):
        for key in self.get_jwks_keys():
            header = jwt.get_unverified_header(id_token)
            if header['kid'] == key['kid']:
                if 'alg' not in key:
                    key['alg'] = 'RS256'
                return key

    def find_agent_valid_key(self, id_token):
        for key in self.get_agent_keys():
            header = jwt.get_unverified_header(id_token)
            if header['kid'] == key['kid']:
                if 'alg' not in key:
                    key['alg'] = 'RS256'
                return key

    def auth_params(self, state=None):
        client_id, client_secret = self.get_key_and_secret()
        params = {
            'client_id': client_id,
            'redirect_uri': self.get_redirect_uri(state)
        }
        if self.STATE_PARAMETER and state:
            params['state'] = state
        if self.RESPONSE_TYPE:
            params['response_type'] = self.RESPONSE_TYPE

        params.update({
            'client_id': client_id,
            'redirect_uri': self.get_redirect_uri(state)
        })
        if self.strategy.session_get(self.name + '_identity'):
            params['login_hint'] = self.strategy.session_get(self.name + '_identity')
        if self.STATE_PARAMETER and state:
            params['state'] = state
        if self.RESPONSE_TYPE:
            params['response_type'] = self.RESPONSE_TYPE
        return params

    def auth_url(self):
        identity = None
        if self.data.get('identity', ''):
            identity = self.data.get('identity')
        if not identity and not self.setting('SOCIAL_AUTH_ID4ME_DEFAULT_IAU', None):
            raise AuthMissingParameter(self, 'identity')
        if not identity:
            self.strategy.session_set(self.name + '_authority', self.setting('SOCIAL_AUTH_ID4ME_DEFAULT_IAU'))
            return super(ID4meBackend, self).auth_url()
        if not is_valid_domain(identity):
            raise AuthForbidden(self)
        openid_configuration = self.get_identity_record(identity)
        if 'v' not in openid_configuration or openid_configuration['v'] != 'OID1':
            raise AuthUnreachableProvider(self)
        if 'iss' not in openid_configuration:
            raise AuthUnreachableProvider(self)
        if (self.setting('SOCIAL_AUTH_ID4ME_DEFAULT_IAU', None) and
                openid_configuration['iss'] != self.setting('SOCIAL_AUTH_ID4ME_DEFAULT_IAU')):
            raise AuthForbidden(self)
        self.strategy.session_set(self.name + '_authority', openid_configuration['iss'])
        self.strategy.session_set(self.name + '_identity', identity)
        return super(ID4meBackend, self).auth_url()

    def auth_complete_params(self, state=None):
        data = {
            'grant_type': 'authorization_code',
            'code': self.data.get('code', ''),
            'redirect_uri': self.get_redirect_uri()
        }
        return '&'.join(["{}={}".format(key, value) for key, value in data.items()])

    def auth_complete_credentials(self):
        return self.get_key_and_secret()

    def validate_and_return_id_token(self, id_token, access_token):
        claims = super(ID4meBackend, self).validate_and_return_id_token(id_token, access_token)
        if self.setting('SOCIAL_AUTH_ID4ME_DEFAULT_IAU', None):
            self.strategy.session_set(self.name + '_identity', claims.get('id4me.identifier', ''))
        identity = self.strategy.session_get(self.name + '_identity')
        openid_configuration = self.get_identity_record(identity)
        if 'v' not in openid_configuration or openid_configuration['v'] != 'OID1':
            raise AuthUnreachableProvider(self)
        if 'clp' not in openid_configuration:
            raise AuthUnreachableProvider(self)
        self.strategy.session_set(self.name + '_agent', openid_configuration['clp'])

        return claims

    def validate_claims(self, id_token):
        utc_timestamp = timegm(datetime.datetime.utcnow().utctimetuple())

        if utc_timestamp > id_token['exp']:
            raise AuthTokenError(self, 'Incorrect id_token: exp')

    def validate_and_return_user_token(self, user_token):
        client_id, client_secret = self.get_key_and_secret()
        key = self.find_agent_valid_key(user_token)

        if not key:
            raise AuthTokenError(self, 'Signature verification failed')

        alg = key['alg']
        rsakey = jwk.construct(key)

        try:
            return jwt.decode(
                user_token,
                rsakey.to_pem().decode('utf-8'),
                algorithms=[alg],
                audience=client_id,
                issuer=[self.strategy.session_get(self.name + '_agent'),
                        'https://' + self.strategy.session_get(self.name + '_agent'),
                        self.strategy.session_get(self.name + '_authority').replace('https://', '')]
            )
        except ExpiredSignatureError:
            raise AuthTokenError(self, 'Signature has expired')
        except JWTClaimsError as error:
            raise AuthTokenError(self, str(error))
        except JWTError:
            raise

    @handle_http_errors
    def user_data(self, access_token, *args, **kwargs):
        user_token = requests.get(self.userinfo_url(), headers={
            'Authorization': 'Bearer {0}'.format(access_token)
        }).text
        return self.validate_and_return_user_token(user_token)

    def get_user_details(self, response):
        data = {
            self.setting('SOCIAL_AUTH_ID4ME_SCOPE_MAPPING', '')[key]: value for key, value in response.items()
            if key in self.setting('SOCIAL_AUTH_ID4ME_SCOPE_MAPPING', '')
        }
        data.update(response.items())
        data['iss'] = self.strategy.session_get(self.name + '_authority')
        data['clp'] = self.strategy.session_get(self.name + '_agent')
        data['sub'] = response['sub']
        return data
