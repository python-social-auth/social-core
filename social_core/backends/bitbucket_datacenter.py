import base64
import hashlib

from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthException


class BitbucketDataCenterOAuth2(BaseOAuth2):
    """
    Implements client for Bitbucket Data Center OAuth 2.0 provider API.
    ref: https://confluence.atlassian.com/bitbucketserver/bitbucket-oauth-2-0-provider-api-1108483661.html
    """

    name = "bitbucket-datacenter-oauth2"
    ID_KEY = "id"
    SCOPE_SEPARATOR = " "
    ACCESS_TOKEN_METHOD = "POST"
    REFRESH_TOKEN_METHOD = "POST"
    REDIRECT_STATE = False
    STATE_PARAMETER = True
    USE_BASIC_AUTH = False
    EXTRA_DATA = [
        ("token_type", "token_type"),
        ("access_token", "access_token"),
        ("refresh_token", "refresh_token"),
        ("expires_in", "expires_in"),
        ("scope", "scope"),
        # extra user profile fields
        ("name", "name"),
        ("username", "username"),
        ("display_name", "display_name"),
        ("type", "type"),
        ("active", "active"),
        ("url", "url"),
    ]
    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = "s256"

    @property
    def server_base_oauth2_api_url(self):
        base_url = self.setting("URL")
        return f"{base_url}/rest/oauth2/latest"

    @property
    def server_base_rest_api_url(self):
        base_url = self.setting("URL")
        return f"{base_url}/rest/api/latest"

    def authorization_url(self):
        return f"{self.server_base_oauth2_api_url}/authorize"

    def access_token_url(self):
        return f"{self.server_base_oauth2_api_url}/token"

    def get_user_details(self, response):
        """Return user details for the Bitbucket Data Center account"""
        # `response` here is the return value of `user_data` method
        user_data = response
        _, first_name, last_name = self.get_user_names(user_data["displayName"])
        uid = self.get_user_id(details=None, response=response)
        return {
            "uid": uid,
            "first_name": first_name,
            "last_name": last_name,
            "email": user_data["emailAddress"],
            "name": user_data["name"],
            "username": user_data["slug"],
            "display_name": user_data["displayName"],
            "type": user_data["type"],
            "active": user_data["active"],
            "url": user_data["links"]["self"][0]["href"],
        }

    def user_data(self, access_token, *args, **kwargs):
        """Fetch user data from Bitbucket Data Center REST API"""
        # ref: https://developer.atlassian.com/server/bitbucket/rest/v815/api-group-system-maintenance/#api-api-latest-users-get
        response = self.get_json(
            f"{self.server_base_rest_api_url}/users",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        return response["values"][0]

    def create_code_verifier(self):
        name = self.name + "_code_verifier"
        code_verifier = self.strategy.random_string(48)
        self.strategy.session_set(name, code_verifier)
        return code_verifier

    def get_code_verifier(self):
        name = self.name + "_code_verifier"
        code_verifier = self.strategy.session_get(name)
        return code_verifier

    def generate_code_challenge(self, code_verifier, challenge_method):
        method = challenge_method.lower()
        if method == "s256":
            hashed = hashlib.sha256(code_verifier.encode()).digest()
            encoded = base64.urlsafe_b64encode(hashed)
            code_challenge = encoded.decode().replace("=", "")  # remove padding
            return code_challenge
        elif method == "plain":
            return code_verifier
        else:
            raise AuthException("Unsupported code challenge method.")

    def auth_params(self, state=None):
        params = super().auth_params(state=state)

        code_challenge_method = self.setting(
            "PKCE_CODE_CHALLENGE_METHOD",
            default=self.PKCE_DEFAULT_CODE_CHALLENGE_METHOD,
        )
        code_verifier = self.create_code_verifier()
        code_challenge = self.generate_code_challenge(
            code_verifier, code_challenge_method
        )
        params["code_challenge_method"] = code_challenge_method
        params["code_challenge"] = code_challenge
        return params

    def auth_complete_params(self, state=None):
        params = super().auth_complete_params(state=state)

        code_verifier = self.get_code_verifier()
        params["code_verifier"] = code_verifier

        return params
