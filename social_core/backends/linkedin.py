"""
LinkedIn OAuth1 and OAuth2 backend, docs at:
    https://python-social-auth.readthedocs.io/en/latest/backends/linkedin.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthProviderError, ErrorStage

from .oauth import BaseOAuth2

if TYPE_CHECKING:
    from collections.abc import Mapping

    from requests.auth import AuthBase


class LinkedinOpenIdConnect(OpenIdConnectAuth):
    """
    Linkedin OpenID Connect backend. Oauth2 has been deprecated as of August 1, 2023.
    https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2?context=linkedin/consumer/context
    """

    name = "linkedin-openidconnect"
    title = "LinkedIn"
    # Settings from https://www.linkedin.com/oauth/.well-known/openid-configuration
    OIDC_ENDPOINT = "https://www.linkedin.com/oauth"

    # https://developer.okta.com/docs/reference/api/oidc/#response-example-success-9
    # Override this value as it is not provided by Linkedin.
    # else our request falls back to basic auth which is not supported.
    TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_post"

    def validate_claims(self, id_token) -> None:
        """Validate temporal claims without requiring LinkedIn to supply a nonce."""
        self.validate_temporal_claims(id_token)
        # Skip the nonce validation for linkedin as it does not provide any nonce.
        # https://stackoverflow.com/questions/76889585/issues-with-sign-in-with-linkedin-using-openid-connect


class LinkedinOAuth2(BaseOAuth2):
    name = "linkedin-oauth2"
    title = "LinkedIn"
    AUTHORIZATION_URL = "https://www.linkedin.com/oauth/v2/authorization"
    ACCESS_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
    USER_DETAILS_URL = "https://api.linkedin.com/v2/me?projection=({projection})"
    USER_EMAILS_URL = (
        "https://api.linkedin.com/v2/emailAddress"
        "?q=members&projection=(elements*(handle~))"
    )
    REDIRECT_STATE = False
    DEFAULT_SCOPE = ["r_liteprofile"]
    EXTRA_DATA = [
        ("id", "id"),
        ("expires_in", "expires_in"),
        ("firstName", "first_name"),
        ("lastName", "last_name"),
        ("refresh_token", "refresh_token"),
        ("refresh_token_expires_in", "refresh_expires_in"),
    ]

    def user_details_url(self):
        # use set() since LinkedIn fails when values are duplicated
        fields_selectors = list(
            {
                "id",
                "firstName",
                "lastName",
                *cast("list[str]", self.setting("FIELD_SELECTORS", [])),
            }
        )
        # user sort to ease the tests URL mocking
        fields_selectors.sort()
        projection = ",".join(fields_selectors)
        return self.USER_DETAILS_URL.format(projection=projection)

    def user_emails_url(self):
        return self.USER_EMAILS_URL

    def user_data(self, access_token: str, *args, **kwargs) -> dict[str, Any] | None:
        response = self.get_json(
            self.user_details_url(), headers=self.user_data_headers(access_token)
        )

        if "emailAddress" in set(
            cast("list[str]", self.setting("FIELD_SELECTORS", []))
        ):
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
            email_address = element.get("handle~", {}).get("emailAddress")
            email_addresses.append(email_address)
        return list(filter(None, email_addresses))

    def get_user_details(self, response):
        """Return user details from Linkedin account"""

        def get_localized_name(name):
            """
            FirstName & Last Name object
            {
                  'localized': {
                     'en_US': 'Smith'
                  },
                  'preferredLocale': {
                     'country': 'US',
                     'language': 'en'
                  }
            }
            :return the localizedName from the lastName object
            """
            locale = f"{name['preferredLocale']['language']}_{name['preferredLocale']['country']}"
            return name["localized"].get(locale, "")

        fullname = ""
        first_name = get_localized_name(response["firstName"])
        last_name = get_localized_name(response["lastName"])
        email = response.get("emailAddress", "")
        return {
            "username": (first_name or "").strip() + (last_name or "").strip(),
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

    def request_access_token(  # noqa: PLR0913
        self,
        url: str,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | None = None,
        json: dict | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
        *,
        stage: ErrorStage = "token_exchange",
    ) -> dict[Any, Any]:
        # LinkedIn expects a POST request with querystring parameters, despite
        # the spec http://tools.ietf.org/html/rfc6749#section-4.1.3
        return super().request_access_token(
            url,
            method=method,
            stage=stage,
            headers=headers,
            data=data,
            json=json,
            auth=auth,
            params=data,
        )

    def process_error(self, data, *, stage: ErrorStage = "callback") -> None:
        super().process_error(data, stage=stage)
        if data.get("serviceErrorCode"):
            status = data.get("status")
            code = "http_error"
            if status == 429:
                code = "rate_limited"
            elif isinstance(status, int) and 500 <= status < 600:
                code = "unavailable"
            raise AuthProviderError(
                self,
                data.get("message"),
                provider_code=data["serviceErrorCode"],
                status_code=status,
                code=code,
                stage=stage,
            )


class LinkedinMobileOAuth2(LinkedinOAuth2):
    name = "linkedin-mobile-oauth2"
    title = "LinkedIn"

    def user_data_headers(self, access_token):
        headers = super().user_data_headers(access_token)
        headers["x-li-src"] = "msdk"
        return headers
