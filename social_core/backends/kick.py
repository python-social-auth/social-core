"""
Kick OAuth2 backend, docs at:
    https://docs.kick.com/getting-started/generating-tokens-oauth2-flow
"""

from .oauth import BaseOAuth2PKCE


class KickOAuth2(BaseOAuth2PKCE):
    """Kick OAuth2 authentication backend"""

    name = "kick"
    HOSTNAME = "id.kick.com"
    API_HOSTNAME = "api.kick.com"
    AUTHORIZATION_URL = f"https://{HOSTNAME}/oauth/authorize"
    ACCESS_TOKEN_URL = f"https://{HOSTNAME}/oauth/token"
    REFRESH_TOKEN_URL = f"https://{HOSTNAME}/oauth/token"
    REVOKE_TOKEN_URL = f"https://{HOSTNAME}/oauth/revoke"
    DEFAULT_SCOPE = ["user:read"]
    SCOPE_SEPARATOR = " "
    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = "S256"
    EXTRA_DATA = [
        ("access_token", "access_token"),
        ("refresh_token", "refresh_token"),
        ("expires_in", "expires"),
        ("token_type", "token_type"),
        ("scope", "scope"),
    ]

    def get_user_id(self, details, response):
        """
        Use Kick user id as unique id
        """
        return response.get("user_id")

    def get_user_details(self, response):
        """Return user details from Kick account"""
        return {
            "username": response.get(
                "name"
            ),  # API returns 'name' instead of 'username'
            "email": response.get("email") or "",
            "fullname": response.get("name") or "",  # Using 'name' as fullname
            "first_name": "",
            "last_name": "",
            "profile_picture": response.get("profile_picture") or "",
            "user_id": response.get("user_id"),
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = f"https://{self.API_HOSTNAME}/public/v1/users"
        auth_header = {"Authorization": f"Bearer {access_token}"}
        response = self.get_json(url, headers=auth_header)
        # The API returns data in a 'data' field with an array of users
        # For the authenticated user (when no user IDs are specified), we get the first item
        if response and "data" in response and response["data"]:
            return response["data"][0]
        return {}
