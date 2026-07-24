"""
Backend for HelmholtzID Connect OPs of the HIFIS project
https://hifis.net/aai/
"""

from social_core.backends.open_id_connect import OpenIdConnectAuth


class HelmholtzOpenIdConnect(OpenIdConnectAuth):
    name = "helmholtz"
    OIDC_ENDPOINT = "https://login.helmholtz.de/oauth2"
    # In order to get any scopes, you have to register your service with
    # the OP
    USERNAME_KEY = "preferred_username"
    EXTRA_DATA = [
        ("expires_in", "expires_in", True),
        ("refresh_token", "refresh_token", True),
        ("id_token", "id_token", True),
    ]
    DEFAULT_SCOPE = [
        "openid",
        "profile",
        "email",
        "voperson_id",
        "eduperson_entitlement",
        # "entitlement",
        "eduperson_scoped_affiliation",
        "voperson_external_affiliation",
        "eduperson_assurance",
        # "offline_access",
    ]
    # This is the list of entitlements that are allowed to login into the
    # service. A user with any of these will be allowed. If empty, all
    # users will be allowed
    ALLOWED_ENTITLEMENTS: list[str] = []
    ENTITLEMENT_KEY = "eduperson_entitlement"

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
            entitlement_key = self.setting("ENTITLEMENT_KEY", self.ENTITLEMENT_KEY)
            user_entitlements = response.get(entitlement_key) or []
            allowed = self.entitlement_allowed(user_entitlements)
        return allowed
