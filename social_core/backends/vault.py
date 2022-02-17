"""
Backend for Hashicorp Vault OIDC Identity Provider in Vault 1.9+
https://www.vaultproject.io/docs/secrets/identity/oidc-provider
"""
import base64

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.utils import cache



class VaultOpenIdConnect(OpenIdConnectAuth):
    """Vault OIDC authentication backend

    You will need to configure at minimum:

    SOCIAL_AUTH_VAULT_OIDC_ENDPOINT = 'https://vault.example.net:8200/v1/identity/oidc/provider/default'
    SOCIAL_AUTH_VAULT_KEY = '<client_id>'
    SOCIAL_AUTH_VAULT_SECRET = '<client_secret>'

    You might also want to override defaults inherited from open_id_connect.py, particularly

    SOCIAL_AUTH_VAULT_USERNAME_KEY = 'preferred_username'
    SOCIAL_AUTH_VAULT_SCOPE = ['groups']

    You may need to set SOCIAL_AUTH_VAULT_VERIFY_SSL = False if your Vault server
    does not have its certificate signed by a trusted CA (e.g. with LetsEncrypt)

    On the Vault side, you will need to create a key and a provider:

    vault write identity/oidc/key/oidc-key \
        allowed_client_ids="*" \
        verification_ttl="24h" \
        rotation_period="24h" \
        algorithm="RS256"

    vault write identity/oidc/provider/default \
        allowed_client_ids="*" \
        scopes_supported="email,profile,groups"

    Vault is very flexible with regard to configuring claims and scopes,
    so it's up to you how you map entity and/or alias metadata to OIDC claims.
    Here is a suggestion, which exposes the entity name as "preferred_username"
    and takes the other claims from entity metadata:

    vault write identity/oidc/scope/profile \
      description="Provides user info" \
      template='{
        "preferred_username": {{identity.entity.name}},
        "name": {{identity.entity.metadata.name}},
        "given_name": {{identity.entity.metadata.given_name}},
        "family_name": {{identity.entity.metadata.family_name}}
    }'

    vault write identity/oidc/scope/email \
      description="Provides email address" \
      template='{
        "email": {{identity.entity.metadata.email}}
    }'

    vault write identity/oidc/scope/groups \
      description="Provides a list of group names" \
      template='{
        "groups": {{identity.entity.groups.names}}
    }'

    Finally you will need to create an assignment and some clients

    vault write identity/oidc/assignment/staff \
        group_ids="<comma-separated-group-ids>"

    vault write identity/oidc/client/my-app \
        redirect_uris="https://www.example.com/callback" \
        assignments="staff" \
        key="oidc-key" \
        id_token_ttl="30m" \
        access_token_ttl="1h"
    """
    name = 'vault'

    @property
    def OIDC_ENDPOINT(self):
        return self.setting('OIDC_ENDPOINT')

    def auth_headers(self):
        return {
            'Authorization': b'Basic ' + base64.urlsafe_b64encode(
                '{}:{}'.format(*self.get_key_and_secret()).encode()
            )
        }

    def auth_complete_params(self, state=None):
        return {
            'grant_type': 'authorization_code',  # request auth code
            'code': self.data.get('code', ''),  # server response code
            'redirect_uri': self.get_redirect_uri(state)
        }

    def get_user_details(self, response):
        username_key = self.setting('USERNAME_KEY', default=self.USERNAME_KEY)
        return {
            'username': response.get(username_key),
            'email': response.get('email'),
            'fullname': response.get('name'),
            'first_name': response.get('given_name'),
            'last_name': response.get('family_name'),
            'groups': response.get('groups'),
        }
