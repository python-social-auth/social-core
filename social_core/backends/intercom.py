from social_core.backends.oauth import BaseOAuth2


class IntercomOAuth2(BaseOAuth2):
    """Intercom OAuth2 authentication backend"""

    name = "intercom"
    AUTHORIZATION_URL = "https://app.intercom.io/oauth"
    ACCESS_TOKEN_URL = "https://api.intercom.io/auth/eagle/token"
    SCOPE_SEPARATOR = "+"
    ACCESS_TOKEN_METHOD = "POST"
    EXTRA_DATA = [("id", "id"), ("avatar", "avatar")]

    def get_user_details(self, response):
        """Return user details from Intercom account"""
        return {
            "email": response.get("email") or "",
            "first_name": response.get("name"),
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json("https://api.intercom.io/me", headers={
            "Authorization": "Bearer {0}'".format(access_token),
            "Accept": "application/json"
        })
