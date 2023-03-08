"""
CAS OIDC backend
https://apereo.github.io/cas/6.6.x/authentication/OIDC-Authentication.html

Backend for authenticating with Apereo CAS using OIDC. This backend handles
the minor implementation differences between the Apereo CAS OIDC server
implementation and the standard OIDC implementation in Python Social Auth.
"""

import logging

from .open_id_connect import OpenIdConnectAuth

logger = logging.getLogger("social")


class CASOpenIdConnectAuth(OpenIdConnectAuth):
    """
    Open ID Connect backends for use with Apereo CAS.
    Currently only the code response type is supported.

    It can also be directly instantiated as a generic OIDC backend.
    To use it you will need to set at minimum:

    SOCIAL_AUTH_CAS_OIDC_ENDPOINT = 'https://.....'  # endpoint without /.well-known/openid-configuration
    SOCIAL_AUTH_CAS_KEY = '<client_id>'
    SOCIAL_AUTH_CAS_SECRET = '<client_secret>'
    """

    name = "cas"
    STATE_PARAMETER = True

    def oidc_endpoint(self):
        endpoint = self.setting("OIDC_ENDPOINT", self.OIDC_ENDPOINT)
        logger.debug(f"backend: CAS, endpoint: {endpoint}")
        return endpoint

    def get_user_id(self, details, response):
        logger.debug(
            f"backend: CAS, method: get_user_id, details: {details}, {response}"
        )
        return details.get("username")

    def user_data(self, access_token, *args, **kwargs):
        data = self.get_json(
            self.userinfo_url(), headers={"Authorization": f"Bearer {access_token}"}
        )
        logger.debug(f"backend: CAS, user_data: {data}")
        return data.get("attributes", {})

    def get_user_details(self, response):
        username_key = self.setting("USERNAME_KEY", self.USERNAME_KEY)
        logger.debug(f"backend: CAS, username_key: {username_key}")
        attributes = self.user_data(response.get("access_token"))
        return {
            "username": attributes.get(username_key),
            "email": attributes.get("email"),
            "fullname": attributes.get("name"),
            "first_name": attributes.get("given_name"),
            "last_name": attributes.get("family_name"),
        }
