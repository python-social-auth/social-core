"""
LinkedIn OAuth1 and OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/linkedin.html
"""

import datetime
from calendar import timegm

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthCanceled, AuthTokenError

from .oauth import BaseOAuth2


class LinkedinOpenIdConnect(OpenIdConnectAuth):
    """
    Linkedin OpenID Connect backend. Oauth2 has been deprecated as of August 1, 2023.
    https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2?context=linkedin/consumer/context
    """

    name = "linkedin-openidconnect"
    # Settings from https://www.linkedin.com/oauth/.well-known/openid-configuration
    OIDC_ENDPOINT = "https://www.linkedin.com/oauth"

    # https://developer.okta.com/docs/reference/api/oidc/#response-example-success-9
    # Override this value as it is not provided by Linkedin.
    # else our request falls back to basic auth which is not supported.
    TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_post"

    def validate_claims(self, id_token):
        """Copy of the regular validate_claims method without the nonce validation."""

        utc_timestamp = timegm(datetime.datetime.now(datetime.timezone.utc).timetuple())

        if "nbf" in id_token and utc_timestamp < id_token["nbf"]:
            raise AuthTokenError(self, "Incorrect id_token: nbf")

        # Verify the token was issued in the last 10 minutes
        iat_leeway = self.setting("ID_TOKEN_MAX_AGE", self.ID_TOKEN_MAX_AGE)
        if utc_timestamp > id_token["iat"] + iat_leeway:
            raise AuthTokenError(self, "Incorrect id_token: iat")

        # Skip the nonce validation for linkedin as it does not provide any nonce.
        # https://stackoverflow.com/questions/76889585/issues-with-sign-in-with-linkedin-using-openid-connect


class LinkedinOAuth2(BaseOAuth2):
    name = "linkedin-oauth2"
    AUTHORIZATION_URL = "https://www.linkedin.com/oauth/v2/authorization"
    ACCESS_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
    USER_DETAILS_URL = "https://api.linkedin.com/v2/userinfo?projection=({projection})"
    USER_EMAILS_URL = (
        "https://api.linkedin.com/v2/emailAddress"
        "?q=members&projection=(elements*(handle~))"
    )
    REDIRECT_STATE = False
    DEFAULT_SCOPE = ["email", "profile", "openid"]
    EXTRA_DATA = [
        ("id", "id"),
        ("expires_in", "expires"),
        ("firstName", "first_name"),
        ("lastName", "last_name"),
        ("refresh_token", "refresh_token"),
        ("refresh_token_expires_in", "refresh_expires_in"),
    ]

    def user_details_url(self):
        return self.USER_DETAILS_URL

    def user_emails_url(self):
        return self.USER_EMAILS_URL

    def user_data(self, access_token, *args, **kwargs):
        response = self.get_json(
            self.user_details_url(), headers=self.user_data_headers(access_token)
        )

        if "email" in set(self.setting("FIELD_SELECTORS", [])):
            emails = self.email_data(access_token, *args, **kwargs)
            if emails:
                response["email"] = emails[0]

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
        response = self.user_data(access_token=response["access_token"])
        fullname, first_name, last_name = self.get_user_names(
            first_name=response["given_name"],
            last_name=response["family_name"],
        )
        email = response.get("email", "")
        return {
            "id": response.get("sub", ""),
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
        headers["Authorization"] = f"Bearer {access_token}"
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
