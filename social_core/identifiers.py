"""Historical identifier transitions with a narrowly scoped compatibility policy."""

# social-core 5.2.0 did not store the new identifier as a usable scalar for
# these backends. Do not extend this list for future or configured transitions.
# Values are (backend class, historical key, current key).
UNVERIFIED_LEGACY_TRANSITIONS: dict[str, tuple[str, str, str]] = {
    "arcgis": ("social_core.backends.arcgis.ArcGISOAuth2", "username", "id"),
    "azuread-oauth2": ("social_core.backends.azuread.AzureADOAuth2", "upn", "sub"),
    "azuread-oauth2-v2": ("social_core.backends.azuread.AzureADOAuth2V2", "upn", "sub"),
    "azuread-v2-tenant-oauth2": (
        "social_core.backends.azuread_tenant.AzureADV2TenantOAuth2",
        "preferred_username",
        "sub",
    ),
    "cognito": ("social_core.backends.cognito.CognitoOAuth2", "username", "sub"),
    "deezer": ("social_core.backends.deezer.DeezerOAuth2", "name", "id"),
    "discourse": (
        "social_core.backends.discourse.DiscourseAuth",
        "email",
        "external_id",
    ),
    "google-oauth": ("social_core.backends.google.GoogleOAuth", "email", "id"),
    "google-oauth2": ("social_core.backends.google.GoogleOAuth2", "email", "sub"),
    "google-onetap": (
        "social_core.backends.google_onetap.GoogleOneTap",
        "email",
        "sub",
    ),
    "google-openidconnect": (
        "social_core.backends.google_openidconnect.GoogleOpenIdConnect",
        "email",
        "sub",
    ),
    "keycloak": ("social_core.backends.keycloak.KeycloakOAuth2", "username", "sub"),
    "mailru": ("social_core.backends.mailru.MRGOAuth2", "email", "id"),
    "okta-oauth2": (
        "social_core.backends.okta.OktaOAuth2",
        "preferred_username",
        "sub",
    ),
    "okta-openidconnect": (
        "social_core.backends.okta_openidconnect.OktaOpenIdConnect",
        "preferred_username",
        "sub",
    ),
    "opensuse": (
        "social_core.backends.suse.OpenSUSEOpenId",
        "nickname",
        "identity_url",
    ),
    "trello": ("social_core.backends.trello.TrelloOAuth", "username", "id"),
    "tumblr": ("social_core.backends.tumblr.TumblrOAuth", "name", "uuid"),
    "ubuntu": ("social_core.backends.ubuntu.UbuntuOpenId", "nickname", "identity_url"),
    "yandex-openid": (
        "social_core.backends.yandex.YandexOpenId",
        "email",
        "identity_url",
    ),
}


def identifier_matches(value: object, uid: str) -> bool:
    """Compare stored scalar identifiers without accepting nulls or booleans."""
    return (
        isinstance(value, (str, int))
        and not isinstance(value, bool)
        and str(value) == uid
        and bool(uid)
    )
