from urllib.parse import urlencode

from .oauth import BaseOAuth2


class WLCGOAuth2(BaseOAuth2):
    """
    WLCG IAM Authentication Backend
    """

    name = "wlcg"
    API_URL = "https://wlcg.cloud.cnaf.infn.it"
    AUTHORIZATION_URL = "https://wlcg.cloud.cnaf.infn.it/authorize"
    ACCESS_TOKEN_URL = "https://wlcg.cloud.cnaf.infn.it/token"
    REFRESH_TOKEN_URL = "https://wlcg.cloud.cnaf.infn.it/token"
    ACCESS_TOKEN_METHOD = "POST"
    DEFAULT_SCOPE = ["openid", "email", "profile", "wlcg", "offline_access"]
    REDIRECT_STATE = False

    def get_user_details(self, response):
        """Return user details from WLCG IAM service"""
        fullname, first_name, last_name = self.get_user_names(
            first_name=response.get("given_name"), last_name=response.get("family_name")
        )
        return {
            "username": response.get("email"),
            "email": response.get("email"),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = "https://wlcg.cloud.cnaf.infn.it/userinfo?" + urlencode(
            {"access_token": access_token}
        )
        return self.get_json(url)
