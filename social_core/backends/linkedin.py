"""
LinkedIn OAuth1 and OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/linkedin.html
"""
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthCanceled


class LinkedinOAuth2(BaseOAuth2):
    name = "linkedin-oauth2"
    AUTHORIZATION_URL = "https://www.linkedin.com/oauth/v2/authorization"
    ACCESS_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
    USER_DETAILS_URL = "https://api.linkedin.com/v2/userinfo?projection=({projection})"
    USER_EMAILS_URL = (
        "https://api.linkedin.com/v2/emailAddress"
        "?q=members&projection=(elements*(handle~))"
    )
    ACCESS_TOKEN_METHOD = "POST"
    REDIRECT_STATE = False
    DEFAULT_SCOPE = ["profile", "email", "openid"]
    EXTRA_DATA = [
        ("id", "sub"),
        ("expires_in", "exp"),
        ("firstName", "given_name"),
        ("lastName", "family_name"),
        ("emailAddress", "email"),
    ]

    def user_details_url(self):
        # use set() since LinkedIn fails when values are duplicated
        fields_selectors = list(
            set(
                ["sub", "given_name", "family_name", "name", "email"]
                + self.setting("FIELD_SELECTORS", [])
            )
        )
        # user sort to ease the tests URL mocking
        fields_selectors.sort()
        fields_selectors = ",".join(fields_selectors)
        return self.USER_DETAILS_URL.format(projection=fields_selectors)

    def user_emails_url(self):
        return self.USER_EMAILS_URL

    def user_data(self, access_token, *args, **kwargs):
        response = self.get_json(
            self.user_details_url(), headers=self.user_data_headers(access_token)
        )

        if "emailAddress" in set(self.setting("FIELD_SELECTORS", [])):
            emails = self.email_data(access_token, *args, **kwargs)
            if emails:
                response["emailAddress"] = emails[0]

        return response

    def email_data(self, access_token, *args, **kwargs):
        response = self.get_json(
            self.user_emails_url(), headers=self.user_data_headers(access_token)
        )
        email_addresses = []
        for element in response.get("elements", []):
            email_address = element.get("handle~", {}).get("email")
            email_addresses.append(email_address)
        return list(filter(None, email_addresses))

    def get_user_details(self, response):
        """Return user details from Linkedin account"""

        fullname, first_name, last_name = self.get_user_names(
            first_name=response["given_name"],
            last_name=response["family_name"],
            fullname=response.get("name"),
        )
        email = response.get("email", "")
        return {
            "username": first_name + last_name,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
        }

    def user_data_headers(self, access_token):
        headers = {}
        lang = self.setting("FORCE_PROFILE_LANGUAGE")
        if lang:
            headers["Accept-Language"] = (
                lang if lang is not True else self.strategy.get_language()
            )
        headers["Authorization"] = "Bearer {access_token}".format(
            access_token=access_token
        )
        return headers

    def request_access_token(self, *args, **kwargs):
        # LinkedIn expects a POST request with querystring parameters, despite
        # the spec http://tools.ietf.org/html/rfc6749#section-4.1.3
        kwargs["params"] = kwargs.pop("data")
        return super().request_access_token(*args, **kwargs)

    def process_error(self, data):
        super().process_error(data)
        if data.get("serviceErrorCode"):
            raise AuthCanceled(self, data.get("message") or data.get("status"))


class LinkedinMobileOAuth2(LinkedinOAuth2):
    name = "linkedin-mobile-oauth2"

    def user_data_headers(self, access_token):
        headers = super().user_data_headers(access_token)
        headers["x-li-src"] = "msdk"
        return headers
