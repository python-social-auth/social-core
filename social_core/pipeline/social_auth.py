from __future__ import annotations

from typing import TYPE_CHECKING

from social_core.exceptions import AuthAlreadyAssociated, AuthException, AuthForbidden

if TYPE_CHECKING:
    from social_core.backends.base import BaseAuth
    from social_core.storage import UserProtocol


def social_details(backend: BaseAuth, details, response, *args, **kwargs):
    return {"details": dict(backend.get_user_details(response), **details)}


def social_uid(backend: BaseAuth, details, response, *args, **kwargs):
    return {
        "uid": str(backend.get_user_id(details, response)),
        "id_key": backend.id_key(),
        "legacy_uids": backend.get_legacy_user_ids(details, response),
    }


def auth_allowed(backend: BaseAuth, details, response, *args, **kwargs) -> None:
    if not backend.auth_allowed(response, details):
        raise AuthForbidden(backend)


def _current_social_auth(backend, storage, provider, uid, id_key):
    social = storage.get_social_auth(provider, uid, id_key=id_key)
    if social is not None:
        return social, False
    try:
        social = storage.get_social_auth_by_extra_data(provider, id_key, uid, id_key="")
    except ValueError as err:
        raise AuthException(backend, str(err)) from err
    return social, social is not None


def _legacy_social_auth(backend, storage, provider, uid, legacy_uids):
    if not backend.setting("ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION", True):
        return None
    matches = []
    for legacy_uid in (uid, *legacy_uids):
        candidate = storage.get_social_auth(provider, legacy_uid, id_key="")
        if candidate is not None and candidate not in matches:
            matches.append(candidate)
    if len(matches) > 1:
        raise AuthException(backend, "Multiple legacy social-auth associations matched")
    if matches:
        backend.log_warning("migrating association from a legacy identifier")
        return matches[0]
    return None


def _migrate_social_auth(backend, storage, social, uid, id_key):
    try:
        migrated = storage.migrate_social_auth(social, uid, id_key)
    except Exception as err:
        is_integrity_error = backend.strategy.storage.is_integrity_error(err)
        if not isinstance(err, ValueError) and not is_integrity_error:
            raise
        raise AuthException(
            backend, "Social-auth identifier migration conflict"
        ) from err
    return migrated


def social_user(
    backend: BaseAuth,
    uid,
    user: UserProtocol | None = None,
    *args,
    id_key="",
    legacy_uids=(),
    **kwargs,
):
    provider = backend.name
    storage = backend.strategy.storage.user
    social, migrated = _current_social_auth(backend, storage, provider, uid, id_key)
    if social is None:
        social = _legacy_social_auth(backend, storage, provider, uid, legacy_uids)
        migrated = social is not None
    if social is not None and migrated:
        social = _migrate_social_auth(backend, storage, social, uid, id_key)
    if social:
        if user and social.user != user:
            raise AuthAlreadyAssociated(backend)
        if not user:
            user = social.user
    return {
        "social": social,
        "user": user,
        "is_new": user is None,
        "new_association": social is None,
    }


def associate_user(
    backend: BaseAuth,
    uid,
    user: UserProtocol | None = None,
    social=None,
    *args,
    id_key="",
    legacy_uids=(),
    **kwargs,
):
    if user and not social:
        try:
            storage = backend.strategy.storage.user
            social = storage.create_social_auth(user, uid, backend.name, id_key=id_key)
        # pylint: disable-next=broad-exception-caught
        except Exception as err:
            if not backend.strategy.storage.is_integrity_error(err):
                raise
            # Protect for possible race condition, those bastard with FTL
            # clicking capabilities, check issue #131:
            #   https://github.com/omab/django-social-auth/issues/131
            result = social_user(
                backend,
                uid,
                user,
                *args,
                id_key=id_key,
                legacy_uids=legacy_uids,
                **kwargs,
            )
            # Check if matching social auth really exists. In case it does
            # not, the integrity error probably had different cause than
            # existing entry and should not be hidden.
            if not result["social"]:
                raise
            return result
        return {"social": social, "user": social.user, "new_association": True}
    return None


def associate_by_email(
    backend: BaseAuth, details, user: UserProtocol | None = None, *args, **kwargs
):
    """
    Associate current auth with a user with the same email address in the DB.

    This pipeline entry is not 100% secure unless you know that the providers
    enabled enforce email verification on their side, otherwise a user can
    attempt to take over another user account by using the same (not validated)
    email address on some provider.  This pipeline entry is disabled by
    default.
    """
    if user:
        return None

    email = details.get("email")
    if email:
        # Try to associate accounts registered with the same email address,
        # only if it's a single object. AuthException is raised if multiple
        # objects are returned.
        users = list(backend.strategy.storage.user.get_users_by_email(email))
        if len(users) == 0:
            return None
        if len(users) > 1:
            raise AuthException(
                backend, "The given email address is associated with another account"
            )
        return {"user": users[0], "is_new": False}
    return None


def load_extra_data(
    backend: BaseAuth,
    details,
    response,
    uid,
    user: UserProtocol | None = None,
    *args,
    **kwargs,
) -> None:
    social = kwargs.get("social") or backend.strategy.storage.user.get_social_auth(
        backend.name, uid
    )
    if social:
        extra_data = backend.extra_data(user, uid, response, details, kwargs)
        social.set_extra_data(extra_data)
