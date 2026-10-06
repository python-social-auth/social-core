"""Framework-independent extraction and mapping of external memberships."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthConfigurationError, AuthResponseError
from social_core.utils import module_member

if TYPE_CHECKING:
    from collections.abc import Mapping


def configured_group_key(backend: BaseAuth) -> str | None:
    """Validate the configured literal claim name before accessing claims."""
    key = backend.setting("GROUPS_KEY")
    if key is not None and (not isinstance(key, str) or not key):
        raise AuthConfigurationError(
            backend, code="invalid_setting", parameter="GROUPS_KEY", stage="pipeline"
        )
    return key


def check_group_overage(
    backend: BaseAuth, response: Mapping[str, Any], key: str
) -> None:
    """Never use an incomplete Entra group claim as an authoritative list."""
    if key != "groups":
        return
    claim_names = response.get("_claim_names", {})
    if not isinstance(claim_names, dict):
        raise AuthResponseError(
            backend, code="invalid_claim", claim="_claim_names", stage="user_info"
        )
    if "hasgroups" in response or "groups" in claim_names:
        raise AuthResponseError(
            backend,
            "Group membership exceeds the token limit",
            code="invalid_claim",
            claim="groups",
            stage="user_info",
        )


def read_groups(
    backend: BaseAuth,
    response: Mapping[str, Any],
    key: str,
    *,
    missing_as_empty: object = False,
    singleton: bool = False,
) -> list[str]:
    """Read an explicitly selected claim without conflating missing and empty."""
    if not isinstance(key, str) or not key:
        raise AuthConfigurationError(
            backend, code="invalid_setting", parameter="GROUPS_KEY", stage="pipeline"
        )
    if not isinstance(missing_as_empty, bool):
        raise AuthConfigurationError(
            backend,
            code="invalid_setting",
            parameter="GROUPS_MISSING_AS_EMPTY",
            stage="pipeline",
        )
    check_group_overage(backend, response, key)
    if key not in response:
        if missing_as_empty:
            return []
        raise AuthResponseError(
            backend, code="missing_claim", claim=key, stage="user_info"
        )
    value = response[key]
    if singleton and isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or any(
        not isinstance(group, str) or not group for group in value
    ):
        raise AuthResponseError(
            backend, code="invalid_claim", claim=key, stage="user_info"
        )
    return list(dict.fromkeys(value))


def validate_group_mapping(
    backend: BaseAuth, mapping: Any
) -> dict[str, list[str | int]]:
    """Validate portable mapping syntax; strategies validate local target types."""
    if not isinstance(mapping, dict) or any(
        not isinstance(key, str)
        or not key
        or not isinstance(targets, list)
        or any(
            isinstance(target, bool)
            or not isinstance(target, (str, int))
            or (isinstance(target, str) and not target)
            for target in targets
        )
        for key, targets in mapping.items()
    ):
        raise AuthConfigurationError(
            backend, code="invalid_setting", parameter="GROUPS_MAP", stage="pipeline"
        )
    return mapping


def group_sync_targets(
    backend: BaseAuth, groups: list[str] | None, response: dict[str, Any]
) -> tuple[set[str | int], set[str | int]]:
    """Resolve managed/desired targets and reject competing provider ownership."""
    mapping = validate_group_mapping(
        backend, backend.get_group_setting("GROUPS_MAP", response, {})
    )
    if not mapping:
        return set(), set()
    if groups is None:
        raise AuthConfigurationError(
            backend,
            code="missing_setting",
            parameter="group extraction",
            stage="pipeline",
        )
    managed = {target for targets in mapping.values() for target in targets}
    desired = {target for group in groups for target in mapping.get(group, [])}
    active_owner = (backend.name, backend.get_group_source(response))
    owners: dict[str | int, tuple[str, str]] = dict.fromkeys(managed, active_owner)
    backends = [backend]
    for path in backend.strategy.get_backends():
        backend_class = module_member(path)
        if issubclass(backend_class, BaseAuth) and backend_class.name != backend.name:
            backends.append(backend_class(backend.strategy))
    for candidate in backends:
        for source, candidate_mapping in candidate.get_group_mappings():
            candidate_mapping = validate_group_mapping(candidate, candidate_mapping)
            owner = (candidate.name, source)
            for targets in candidate_mapping.values():
                for target in targets:
                    if target in owners and owners[target] != owner:
                        raise AuthConfigurationError(
                            backend,
                            "A local group is managed by multiple identity providers",
                            code="invalid_setting",
                            parameter="GROUPS_MAP",
                            stage="pipeline",
                        )
                    owners[target] = owner
    return desired, managed
