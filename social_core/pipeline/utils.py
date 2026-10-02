from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from social_core.backends.base import BaseAuth
    from social_core.storage import PartialMixin, UserProtocol
    from social_core.strategy import BaseStrategy

SERIALIZABLE_TYPES = (dict, list, tuple, set, bool, type(None), int, str, bytes)


def is_dict_type(value):
    """Treat any dict, MergeDict, MultiDict instance as dict type"""
    # Check by class name to avoid importing Django MergeDict or
    # Werkzeug MultiDict
    return isinstance(value, dict) or value.__class__.__name__ in (
        "MergeDict",
        "MultiDict",
    )


def to_plain_dict(value) -> dict[str, Any]:
    if any(cls.__name__ == "MultiValueDict" for cls in value.__class__.mro()):
        dict_method = getattr(value, "dict", None)
        if callable(dict_method):
            return cast("dict[str, Any]", dict_method())
    return dict(value)


def partial_prepare(
    strategy: BaseStrategy,
    backend: BaseAuth,
    next_step,
    user: UserProtocol | None = None,
    social=None,
    *args,
    **kwargs,
) -> PartialMixin:
    storage = strategy.get_storage(stage="pipeline")
    kwargs.update(
        {
            "response": kwargs.get("response") or {},
            "details": kwargs.get("details") or {},
            "username": kwargs.get("username"),
            "uid": kwargs.get("uid"),
            "is_new": kwargs.get("is_new") or False,
            "new_association": kwargs.get("new_association") or False,
            "user": None if user is None else user.id,
            "social": (social and {"provider": social.provider, "uid": social.uid})
            or None,
        }
    )

    clean_args = [strategy.to_session_value(val) for val in args]

    # Clean any MergeDict data type from the values
    clean_kwargs = {}
    for name, value in kwargs.items():
        if name == "request":
            continue
        value = to_plain_dict(value) if is_dict_type(value) else value
        if isinstance(value, SERIALIZABLE_TYPES):
            clean_kwargs[name] = strategy.to_session_value(value)

    request_data = strategy.request_data()
    return storage.partial.prepare(
        backend.name,
        next_step,
        {
            "args": clean_args,
            "kwargs": clean_kwargs,
            "request_data": strategy.to_session_value(to_plain_dict(request_data)),
            "pipeline_type": backend.pipeline_type,
        },
    )


def partial_store(
    strategy: BaseStrategy, backend: BaseAuth, next_step, *args, **kwargs
) -> PartialMixin:
    storage = strategy.get_storage(stage="pipeline")
    partial = partial_prepare(strategy, backend, next_step, *args, **kwargs)
    return storage.partial.store(partial)


def partial_load(strategy: BaseStrategy, token: str) -> PartialMixin | None:
    storage = strategy.get_storage(stage="pipeline")
    partial = storage.partial.load(token)

    if partial:
        args = partial.args
        kwargs = partial.kwargs.copy()
        request_data = partial.data.pop("request_data", kwargs.get("request"))
        if request_data is not None:
            request_data = strategy.from_session_value(request_data)
            if isinstance(request_data, Mapping):
                partial.request_data = to_plain_dict(request_data)
        kwargs.pop("request", None)
        user = kwargs.get("user")
        social = kwargs.get("social")

        if isinstance(social, dict):
            kwargs["social"] = storage.user.get_social_auth(**social)

        if user:
            kwargs["user"] = storage.user.get_user(user)

        partial.args = [strategy.from_session_value(val) for val in args]
        partial.kwargs = {
            key: strategy.from_session_value(val) for key, val in kwargs.items()
        }
    return partial
