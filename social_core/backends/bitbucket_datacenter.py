from social_core.backends.oauth import BaseOAuth2PKCE


class BitbucketDataCenterOAuth2(BaseOAuth2PKCE):
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
    # ref: https://confluence.atlassian.com/bitbucketserver/bitbucket-oauth-2-0-provider-api-1108483661.html#BitbucketOAuth2.0providerAPI-scopes # noqa
    DEFAULT_SCOPE = ["PUBLIC_REPOS"]
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
    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = "s256"  # can be "plain" or "s256"
    PKCE_DEFAULT_CODE_VERIFIER_LENGTH = 48  # must be b/w 43-127 chars
    USE_PKCE = True

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
        # ref: https://developer.atlassian.com/server/bitbucket/rest/v815/api-group-system-maintenance/#api-api-latest-users-get # noqa
        response = self.get_json(
            f"{self.server_base_rest_api_url}/users",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        return response["values"][0]
