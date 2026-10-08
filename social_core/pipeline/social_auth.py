from __future__ import annotations

from typing import TYPE_CHECKING

from social_core.exceptions import AuthAssociationError, AuthPolicyError
from social_core.identifiers import identifier_matches
from social_core.utils import normalize_user_names

if TYPE_CHECKING:
    from social_core.backends.base import BaseAuth
    from social_core.storage import UserProtocol


def social_details(backend: BaseAuth, details, response, *args, **kwargs):
    return {
        "details": dict(backend.get_user_details(response), **details),
        "groups": backend.get_user_groups(response),
    }


def social_names(backend: BaseAuth, details, *args, **kwargs):
    """Populate missing full or component names using provider details."""
    names = normalize_user_names(
        details.get("fullname"),
        details.get("first_name"),
        details.get("last_name"),
        firstlast_from_full=bool(backend.setting("FIRSTLAST_FROM_FULL", True)),
        full_from_firstlast=bool(backend.setting("FULL_FROM_FIRSTLAST", True)),
    )
    normalized = details.copy()
    # Derive meaningful names into missing or blank fields, without turning
    # unavailable components into empty values that would clear user fields.
    for name, value in zip(("fullname", "first_name", "last_name"), names, strict=True):
        if value:
            normalized[name] = value
        elif isinstance(normalized.get(name), str):
            normalized[name] = normalized[name].strip()
    return {"details": normalized}


def social_uid(backend: BaseAuth, details, response, *args, **kwargs):
    uid = str(backend.get_user_id(details, response))
    id_key = backend.id_key()
    identifiers = backend.get_legacy_user_identifiers(details, response)
    return {
        "uid": uid,
        "id_key": id_key,
        "legacy_identifiers": identifiers,
        "legacy_uids": list(
            dict.fromkeys(backend.get_legacy_user_ids(details, response))
        ),
    }


def auth_allowed(backend: BaseAuth, details, response, *args, **kwargs) -> None:
    if not backend.auth_allowed(response, details):
        raise AuthPolicyError(
            backend, code="authentication_disallowed", stage="pipeline"
        )


def _legacy_social_auth(
    backend, storage, provider, uid, id_key, legacy_identifiers, legacy_uids
):
    # Empty-key candidates cover integrations and rows not yet backfilled.
    lookups = [("", uid, "")]
    for old_key, old_uid in legacy_identifiers:
        old_uid = str(old_uid)
        if (old_key, old_uid) == (id_key, uid):
            continue
        lookups.extend(((old_key, old_uid, old_key), (old_key, old_uid, "")))
    keyed_uids = {str(old_uid) for _, old_uid in legacy_identifiers}
    lookups.extend(
        ("", str(old_uid), "")
        for old_uid in legacy_uids
        if str(old_uid) not in keyed_uids
    )
    matches = []
    matched_keys = []
    candidates = {}
    for old_key, old_uid, stored_key in lookups:
        lookup = (old_uid, stored_key)
        if lookup not in candidates:
            candidates[lookup] = storage.get_social_auth(
                provider, old_uid, id_key=stored_key
            )
        candidate = candidates[lookup]
        if candidate is not None:
            matched_keys.append(old_key)
            if candidate not in matches:
                matches.append(candidate)
    if len(matches) > 1:
        raise AuthAssociationError(
            backend,
            "Multiple legacy social-auth associations matched",
            code="identifier_migration_conflict",
            stage="pipeline",
        )
    if not matches:
        return None, None
    social = matches[0]
    evidence_key = None
    for key in backend.get_stored_user_id_keys(id_key):
        if key not in social.extra_data:
            continue
        if not identifier_matches(social.extra_data[key], uid):
            raise AuthAssociationError(
                backend,
                "Stored social-auth identifier evidence conflicts",
                code="identifier_migration_conflict",
                stage="pipeline",
            )
        if evidence_key is None:
            evidence_key = key
    if evidence_key is None:
        if not any(
            backend.allow_unverified_legacy_uid_migration(key, id_key)
            for key in matched_keys
        ):
            raise AuthAssociationError(
                backend,
                "Stored social-auth identifier evidence is missing; use account recovery or authenticated linking",
                code="identifier_migration_conflict",
                stage="pipeline",
            )
        backend.log_warning(
            "migrating association from an unverified legacy identifier"
        )
    return social, evidence_key


def _migrate_social_auth(backend, storage, social, uid, id_key, evidence_key):
    try:
        migrated = storage.migrate_social_auth(
            social, uid, id_key, evidence_key=evidence_key
        )
    except Exception as err:
        is_integrity_error = backend.strategy.storage.is_integrity_error(err)
        if not isinstance(err, ValueError) and not is_integrity_error:
            raise
        raise AuthAssociationError(
            backend,
            "Social-auth identifier migration conflict",
            code="identifier_migration_conflict",
            stage="pipeline",
        ) from err
    return migrated


def social_user(
    backend: BaseAuth,
    uid,
    user: UserProtocol | None = None,
    *args,
    id_key="",
    legacy_uids=(),
    legacy_identifiers=(),
    **kwargs,
):
    provider = backend.name
    storage = backend.strategy.storage.user
    uid = str(uid)
    social = storage.get_social_auth(provider, uid, id_key=id_key)
    if social is None:
        social, evidence_key = _legacy_social_auth(
            backend, storage, provider, uid, id_key, legacy_identifiers, legacy_uids
        )
        if social is not None:
            if user and social.user != user:
                raise AuthAssociationError(
                    backend, code="identity_in_use", stage="pipeline"
                )
            social = _migrate_social_auth(
                backend, storage, social, uid, id_key, evidence_key
            )
    if social:
        if user and social.user != user:
            raise AuthAssociationError(
                backend,
                code="identity_in_use",
                stage="pipeline",
                context={
                    "user_id": user.id,
                    "existing_user_id": social.user.id,
                    "uid": uid,
                },
            )
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
    legacy_identifiers=(),
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
                legacy_identifiers=legacy_identifiers,
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
            raise AuthAssociationError(
                backend,
                "The given email address is associated with another account",
                code="email_in_use",
                stage="pipeline",
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
