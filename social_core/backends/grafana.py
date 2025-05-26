from social_core.backends.oauth import BaseOAuth2


class GrafanaOAuth2(BaseOAuth2):
    """Grafana OAuth authentication backend"""

    name = "grafana"
    AUTHORIZATION_URL = "https://grafana.com/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://grafana.com/api/oauth2/token"
    DEFAULT_SCOPE = ["profile", "email"]
    SCOPE_SEPARATOR = ","
    USER_DETAILS_URL = "https://grafana.com/api/oauth2/user"

    def get_user_details(self, response):
        """Return user details from Grafana account"""
        return {
            "username": response.get("login"),
            "email": response.get("email") or "",
            "first_name": response.get("name"),
            "last_name": "-",
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json(
            self.USER_DETAILS_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
