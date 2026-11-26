from __future__ import annotations

from typing import TYPE_CHECKING, Any

import jwt

from social_core.exceptions import AuthConfigurationError, AuthResponseError, ErrorStage
from social_core.utils import cache, module_member, user_is_authenticated

from .base import BaseAuth, ResponseT_co

if TYPE_CHECKING:
    from collections.abc import Iterable

# Cache for discovered backends, keyed by the AUTHENTICATION_BACKENDS value they
# were loaded from, so a lookup never returns a backend enabled elsewhere in
# the process. Backend classes are generic, so each can be instantiated with a
# strategy for any response type.
BACKENDSCACHE: dict[tuple[str, ...], dict[str, type[BaseAuth[Any]]]] = {}


def load_backends(
    backends: Iterable[str], force_load: bool = False
) -> dict[str, type[BaseAuth[Any]]]:
    """
    Load backends defined on SOCIAL_AUTH_AUTHENTICATION_BACKENDS, backends will
    be imported and cached on BACKENDSCACHE under the given setting value. The
    key in the returned dict will be the backend name, and the value is the
    backend class.

    Only subclasses of BaseAuth (and sub-classes) are considered backends.

    Previously there was a BACKENDS attribute expected on backends modules,
    this is not needed anymore since it's enough with the
    AUTHENTICATION_BACKENDS setting. BACKENDS was used because backends used to
    be split on two classes the authentication backend and another class that
    dealt with the auth mechanism with the provider, those classes are joined
    now.

    A force_load boolean argument is also provided so that get_backend
    below can retry a requested backend that may not yet be discovered.
    """
    configured = tuple(backends)
    loaded = None if force_load else BACKENDSCACHE.get(configured)
    if loaded is None:
        loaded = {}
        for auth_backend in configured:
            backend = module_member(auth_backend)
            if issubclass(backend, BaseAuth):
                loaded[backend.name] = backend
        BACKENDSCACHE[configured] = loaded
    return loaded


def get_backend(backends: Iterable[str], name: str) -> type[BaseAuth[Any]]:
    """Returns a backend by name. Only the backends referenced in the given
    AUTHENTICATION_BACKENDS are considered, they are stored in the
    BACKENDSCACHE cache dict. If not found, each of them is imported again
    and checked for the named backend, which is then stored in the cache for
    future access.
    """
    configured = tuple(backends)
    loaded = load_backends(configured)
    if name not in loaded:
        # Reload BACKENDS to ensure a missing backend hasn't been missed
        loaded = load_backends(configured, force_load=True)
    try:
        return loaded[name]
    except KeyError as error:
        raise AuthConfigurationError(
            None, name, code="backend_missing", parameter="backend"
        ) from error


def user_backends_data(user, backends, storage):
    """
    Will return backends data for given user, the return value will have the
    following keys:
        associated: UserSocialAuth model instances for currently associated
                    accounts
        not_associated: Not associated (yet) backend names
        backends: All backend names.

    If user is not authenticated, then 'associated' list is empty, and there's
    no difference between 'not_associated' and 'backends'.
    """
    available = list(load_backends(backends).keys())
    values = {"associated": [], "not_associated": available, "backends": available}
    if user_is_authenticated(user):
        associated = storage.user.get_social_auth_for_user(user)
        not_associated = list(set(available) - {assoc.provider for assoc in associated})
        values["associated"] = associated
        values["not_associated"] = not_associated
    return values


def load_oidc_config(
    backend: BaseAuth[object], url: str, *, stage: ErrorStage = "begin"
) -> dict:
    """Fetch and validate a discovery document before it can enter a cache."""
    response = backend.get_json(url, stage=stage)
    if not isinstance(response, dict):
        raise AuthResponseError(backend, code="malformed_response", stage=stage)
    return response


class OIDCDiscoveryMixin(BaseAuth[ResponseT_co]):
    """Share validated, cached discovery loading across OAuth2 and OIDC backends."""

    def oidc_config_url(self) -> str:
        raise NotImplementedError

    def oidc_config(self) -> dict:
        return self.get_openid_configuration(self.oidc_config_url())

    @cache(ttl=86400)
    def get_openid_configuration(self, url: str) -> dict:
        """Cache validated discovery documents separately for each URL."""
        return load_oidc_config(self, url)


def jwt_error(
    backend: BaseAuth[object],
    error: jwt.PyJWTError,
    *,
    stage: ErrorStage = "token_validation",
) -> AuthResponseError:
    """Translate JWT exception types, preserving claims without parsing messages."""

    claim = None
    if isinstance(error, jwt.ExpiredSignatureError):
        code, claim = "response_expired", "exp"
    elif isinstance(error, jwt.ImmatureSignatureError):
        code = "response_not_yet_valid"
    elif isinstance(error, (jwt.InvalidSignatureError, jwt.InvalidAlgorithmError)):
        code = "invalid_signature"
    elif isinstance(error, jwt.MissingRequiredClaimError):
        code, claim = "missing_claim", error.claim
    elif isinstance(error, jwt.InvalidAudienceError):
        code, claim = "invalid_claim", "aud"
    elif isinstance(error, jwt.InvalidIssuerError):
        code, claim = "invalid_claim", "iss"
    elif isinstance(error, jwt.exceptions.InvalidSubjectError):
        code, claim = "invalid_claim", "sub"
    else:
        code = "invalid_claim"
    return AuthResponseError(backend, error, code=code, claim=claim, stage=stage)
