"""
Discord Auth OAuth2 backend, docs at:
    https://discord.com/developers/docs/topics/oauth2
"""

from .oauth import BaseOAuth2


class DiscordOAuth2(BaseOAuth2):
    name = "discord"
    HOSTNAME = "discord.com"
    AUTHORIZATION_URL = f"https://{HOSTNAME}/api/oauth2/authorize"
    ACCESS_TOKEN_URL = f"https://{HOSTNAME}/api/oauth2/token"
    ACCESS_TOKEN_METHOD = "POST"
    REVOKE_TOKEN_URL = f"https://{HOSTNAME}/api/oauth2/token/revoke"
    REVOKE_TOKEN_METHOD = "GET"
    DEFAULT_SCOPE = ["identify"]
    SCOPE_SEPARATOR = "+"
    REDIRECT_STATE = False
    EXTRA_DATA = [("expires_in", "expires"), ("refresh_token", "refresh_token")]

    def get_user_details(self, response):
        return {
            "username": response.get("username"),
            "email": response.get("email") or "",
        }

    def user_data(self, access_token, *args, **kwargs):
        url = f"https://{self.HOSTNAME}/api/users/@me"
        auth_header = {"Authorization": f"Bearer {access_token}"}
        return self.get_json(url, headers=auth_header)
