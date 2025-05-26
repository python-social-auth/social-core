"""
Backend for OpenID Connect OPs of the German NFDI initiative
https://doc.nfdi-aai.de/

This is conceptually based on the egi_checkin backend
"""

from social_core.backends.open_id_connect import OpenIdConnectAuth

NFDI_ENDPOINTS = {
    # AcademicID
    "xcs": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud",
    "textplus": "https://keycloak.sso.gwdg.de/auth/realms/academiccloud",
    # didmos
    "mardi": "https://auth.didmos.nfdi-aai.de",
    "objects": "https://auth.didmos.nfdi-aai.de",
    "culture": "https://auth.aai.nfdi4culture.de",
    # regapp
    "cat": "https://regapp.nfdi-aai.de/oidc/realms/nfdi",
    "chem": "https://regapp.nfdi-aai.de/oidc/realms/nfdi",
    "datascience": "https://regapp.nfdi-aai.de/oidc/realms/nfdi",
    "energy": "https://regapp.nfdi-aai.de/oidc/realms/nfdi",
    "ing": "https://regapp.nfdi-aai.de/oidc/realms/nfdi",
    "matWerk": "https://regapp.nfdi-aai.de/oidc/realms/nfdi",
    # unity
    "daphne": "https://login.helmholtz.de/oauth2",
    "fairmat": "https://login.helmholtz.de/oauth2",
    "immuno": "https://login.helmholtz.de/oauth2",
    "punch": "https://login.helmholtz.de/punch-oauth2",
    "helmholtz": "https://login.helmholtz.de/oauth2",
    # infraproxy
    "infraproxy-staging": "https://infraproxy-staging.nfdi-aai.dfn.de",
    "infraproxy": "https://infraproxy.nfdi-aai.dfn.de",
    # eduid
    "eduid": "https://proxy.edu-id.dfn.de",
    "eduid-staging": "",
    # other
    # DataPLANT
    # GHGA
    # NFDI4Biodiversity
    # unassigned
    # BERD@NFDI
    # FAIRagro
    # KonsortSWD
    # NFDI4BIOIMAGE
    # NFDI4Earth
    # NFDI4Health
    # NFDI4Memory
    # NFDI4Microbiota
}


class NFDIOpenIdConnect(OpenIdConnectAuth):
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
        "orcid",
        # "offline_access",
    ]
    # This is the list of entitlements that are allowed to login into the
    # service. A user with any of these will be allowed. If empty, all
    # users will be allowed
    ALLOWED_ENTITLEMENTS: list[str] = []

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


# AcademicID
class XcsOpenIdConnect(NFDIOpenIdConnect):
    name = "xcs"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class TextplusOpenIdConnect(NFDIOpenIdConnect):
    name = "textplus"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


# didmos
class MardiOpenIdConnect(NFDIOpenIdConnect):
    name = "mardi"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class ObjectsOpenIdConnect(NFDIOpenIdConnect):
    name = "objects"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class CultureOpenIdConnect(NFDIOpenIdConnect):
    name = "culture"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]

    # regapp


class CatOpenIdConnect(NFDIOpenIdConnect):
    name = "cat"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class ChemOpenIdConnect(NFDIOpenIdConnect):
    name = "chem"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class DatascienceOpenIdConnect(NFDIOpenIdConnect):
    name = "datascience"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class EnergyOpenIdConnect(NFDIOpenIdConnect):
    name = "energy"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class IngOpenIdConnect(NFDIOpenIdConnect):
    name = "ing"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class MatWerkOpenIdConnect(NFDIOpenIdConnect):
    name = "matWerk"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


# unity
class DaphneOpenIdConnect(NFDIOpenIdConnect):
    name = "daphne"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class FairmatOpenIdConnect(NFDIOpenIdConnect):
    name = "fairmat"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class ImmunoOpenIdConnect(NFDIOpenIdConnect):
    name = "immuno"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class PunchOpenIdConnect(NFDIOpenIdConnect):
    name = "punch"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class HelmholtzOpenIdConnect(NFDIOpenIdConnect):
    name = "helmholtz"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


# infraproxy
class InfraproxyStagingOpenIdConnect(NFDIOpenIdConnect):
    name = "infraproxy-staging"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class InfraproxyOpenIdConnect(NFDIOpenIdConnect):
    name = "infraproxy"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


# eduid
class EduidOpenIdConnect(NFDIOpenIdConnect):
    name = "eduid"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]


class EduidStagingOpenIdConnect(NFDIOpenIdConnect):
    name = "eduid-staging"
    OIDC_ENDPOINT = NFDI_ENDPOINTS[name]
