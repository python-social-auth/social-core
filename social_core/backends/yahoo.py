"""
Yahoo OpenId, OAuth1 and OAuth2 backends, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/yahoo.html
"""

from requests.auth import HTTPBasicAuth

from social_core.utils import handle_http_errors

from .oauth import BaseOAuth2


class YahooOAuth2(BaseOAuth2):
    """Yahoo OAuth2 authentication backend"""

    name = "yahoo-oauth2"
    ID_KEY = "sub"
    AUTHORIZATION_URL = "https://api.login.yahoo.com/oauth2/request_auth"
    ACCESS_TOKEN_URL = "https://api.login.yahoo.com/oauth2/get_token"
    EXTRA_DATA = [
        ("sub", "id"),
        ("access_token", "access_token"),
        ("expires_in", "expires_in"),
        ("refresh_token", "refresh_token"),
        ("token_type", "token_type"),
    ]

    def get_user_names(self, first_name, last_name):  # type: ignore[reportIncompatibleMethodOverride]
        if first_name or last_name:
            return f"{first_name} {last_name}", first_name, last_name
        return None, None, None

    def get_user_details(self, response):
        """
        Return user details from Yahoo Profile.
        To Get user email you need the profile private read permission.
        """

        fullname, first_name, last_name = self.get_user_names(
            first_name=response.get("given_name"), last_name=response.get("family_name")
        )

        email = response.get("email")
        return {
            "username": response.get("preferred_username", response.get("nickname")),
            "email": email,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""

        url = "https://api.login.yahoo.com/openid/v1/userinfo"

        return self.get_json(
            url, headers={"Authorization": f"Bearer {access_token}"}, method="GET"
        )

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        self.process_error(self.data)
        response = self.request_access_token(
            self.ACCESS_TOKEN_URL,
            auth=HTTPBasicAuth(*self.get_key_and_secret()),
            data=self.auth_complete_params(self.validate_state()),
            headers=self.auth_headers(),
            method=self.ACCESS_TOKEN_METHOD,
        )
        self.process_error(response)
        return self.do_auth(
            response["access_token"], *args, response=response, **kwargs
        )

    def refresh_token_params(self, token, *args, **kwargs):
        return {
            "refresh_token": token,
            "grant_type": "refresh_token",
            "redirect_uri": "oob",  # out of bounds
        }

    def refresh_token(self, token, *args, **kwargs):
        params = self.refresh_token_params(token, *args, **kwargs)
        url = self.REFRESH_TOKEN_URL or self.ACCESS_TOKEN_URL
        method = self.REFRESH_TOKEN_METHOD
        key = "params" if method == "GET" else "data"
        request_args = {"headers": self.auth_headers(), "method": method, key: params}
        request = self.request(
            url, auth=HTTPBasicAuth(*self.get_key_and_secret()), **request_args
        )
        return self.process_refresh_token_response(request, *args, **kwargs)

    def auth_complete_params(self, state=None):
        return {
            "grant_type": "authorization_code",  # request auth code
            "code": self.data.get("code", ""),  # server response code
            "redirect_uri": self.get_redirect_uri(state),
        }
