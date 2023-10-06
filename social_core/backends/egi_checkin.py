"""
Backend for OpenID Connect EGI Check-in
https://www.egi.eu/service/check-in/
"""

from social_core.backends.open_id_connect import OpenIdConnectAuth

CHECKIN_ENV_ENDPOINTS = {
    "prod": "https://aai.egi.eu/auth/realms/egi",
    "demo": "https://aai-demo.egi.eu/auth/realms/egi",
    "dev": "https://aai-dev.egi.eu/auth/realms/egi",
}


class EGICheckinOpenIdConnect(OpenIdConnectAuth):
    name = "egi-checkin"
    # Check-in provides 3 environments: production, demo and development
    # Set the one to use as "prod", "demo" or "dev"
    CHECKIN_ENV = "prod"
    # This is a opaque and unique id for every user that looks like an email
    # see https://docs.egi.eu/providers/check-in/sp/#1-community-user-identifier
    USERNAME_KEY = "voperson_id"
    EXTRA_DATA = [
        ("expires_in", "expires_in", True),
        ("refresh_token", "refresh_token", True),
        ("id_token", "id_token", True),
    ]
    # In order to get any scopes, you have to register your service with
    # Check-in, see documentation at https://docs.egi.eu/providers/check-in/sp/
    DEFAULT_SCOPE = [
        "openid",
        "profile",
        "email",
        "voperson_id",
        "eduperson_entitlement",
        "offline_access",
    ]
    # This is the list of entitlements that are allowed to login into the
    # service. A user with any of these will be allowed. If empty, all
    # users will be allowed
    ALLOWED_ENTITLEMENTS = []

    def oidc_endpoint(self):
        endpoint = self.setting("OIDC_ENDPOINT", self.OIDC_ENDPOINT)
        if endpoint:
            return endpoint
        checkin_env = self.setting("CHECKIN_ENV", self.CHECKIN_ENV)
        return CHECKIN_ENV_ENDPOINTS.get(checkin_env, "")

    def get_user_details(self, response):
        username_key = self.setting("USERNAME_KEY", default=self.USERNAME_KEY)
        fullname, first_name, last_name = self.get_user_names(
            response.get("name") or "",
            response.get("given_name") or "",
            response.get("family_name") or "",
        )
        return {
            "username": response.get(username_key),
            "email": response.get("email"),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def entitlement_allowed(self, user_entitlements):
        allowed = True
        allowed_ent = self.setting("ALLOWED_ENTITLEMENTS", self.ALLOWED_ENTITLEMENTS)
        if allowed_ent:
            allowed = any(e in user_entitlements for e in allowed_ent)
        return allowed

    def auth_allowed(self, response, details):
        """Check-in promotes the use of eduperson_entitlements for AuthZ, if
        ALLOWED_ENTITLEMENTS is defined then use them to allow or not users"""
        allowed = super().auth_allowed(response, details)
        if allowed:
            user_entitlements = response.get("eduperson_entitlement") or []
            allowed = self.entitlement_allowed(user_entitlements)
        return allowed
