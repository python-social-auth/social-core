from .oauth import BaseOAuth2


class CleverOAuth2(BaseOAuth2):
    """
    Clever OAuth authentication backend.

    Docs: https://dev.clever.com/docs/classroom-with-oauth
    """

    name = "clever"
    AUTHORIZATION_URL = "https://clever.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://clever.com/oauth/tokens"
    ACCESS_TOKEN_METHOD = "POST"
    REDIRECT_STATE = False
    STATE_PARAMETER = False
    SCOPE_SEPARATOR = " "

    def get_user_id(self, details, response):
        """Return user unique id provided by service"""
        return response.get("data", {}).get("id")

    def get_user_type(self, data):
        return next(iter(data.get("data", {}).get("roles", {}).keys()))

    def get_user_details(self, response):
        """Return user details from Classlink account"""
        fullname, first_name, last_name = self.get_user_names(
            first_name=response.get("data", {}).get("name", {}).get("first", None),
            last_name=response.get("data", {}).get("name", {}).get("last", None),
        )
        email = response.get("data", {}).get("email")
        username = (
            response.get("data", {})
            .get("roles", {})
            .get(self.get_user_type(response), {})
            .get("credentials", {})
            .get("district_username", email.split("@", 1)[0])
        )
        return {
            "username": username,
            "email": email,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "user_type": self.get_user_type(response),
        }

    def user_data(self, token, *args, **kwargs):
        """Loads user data from service"""
        identity_url = "https://api.clever.com/v3.0/me"
        user_details_url = "https://api.clever.com/v3.0/users"
        auth_header = {"Authorization": f"Bearer {token}"}
        try:
            response = self.get_json(identity_url, headers=auth_header)
            user_id = response.get("data", {}).get("id")
            user_details_url = f"https://api.clever.com/v3.0/users/{user_id}"
            return self.get_json(user_details_url, headers=auth_header)
        except ValueError:
            return None
