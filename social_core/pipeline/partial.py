from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING, Any

from social_core.utils import (
    PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME,
    PARTIAL_TOKEN_SESSION_NAME,
)

from .utils import partial_prepare

if TYPE_CHECKING:
    from collections.abc import Callable

    from social_core.backends.base import BaseAuth
    from social_core.strategy import BaseStrategy, HttpResponseProtocol


def partial_step(
    save_to_session: bool, allow_external_resume: bool = False
) -> Callable[
    [Callable[..., dict[str, Any] | HttpResponseProtocol | None]],
    Callable[..., dict[str, Any] | HttpResponseProtocol],
]:
    """Wraps func to behave like a partial pipeline step, any output
    that's not None or {} will be considered a response object and
    will be returned to user.

    The pipeline function will receive a current_partial object, it
    contains the partial pipeline data and a token that is used to
    identify it when it's continued, this is useful to build links
    with the token.

    The default value for this parameter is partial_token, but can be
    overridden by SOCIAL_AUTH_PARTIAL_PIPELINE_TOKEN_NAME setting.

    The token is also stored in the session under the
    PARTIAL_TOKEN_SESSION_NAME (partial_pipeline_token) key when the
    save_to_session parameter is True.

    Set allow_external_resume=True only for flows that intentionally resume
    from an external validation link, such as email validation.
    """

    # Step signatures vary, and the wrapper injects current_partial and other
    # keyword arguments, so input and output callables have different signatures.
    def decorator(
        func: Callable[..., dict[str, Any] | HttpResponseProtocol | None],
    ) -> Callable[..., dict[str, Any] | HttpResponseProtocol]:
        @wraps(func)
        def wrapper(
            strategy: BaseStrategy,
            backend: BaseAuth,
            pipeline_index: int,
            *args: Any,
            **kwargs: Any,
        ) -> dict[str, Any] | HttpResponseProtocol:
            current_partial = partial_prepare(
                strategy, backend, pipeline_index, *args, **kwargs
            )

            out = (
                func(
                    *args,
                    strategy=strategy,
                    backend=backend,
                    pipeline_index=pipeline_index,
                    current_partial=current_partial,
                    **kwargs,
                )
                or {}
            )

            if not isinstance(out, dict):
                current_partial.data[PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME] = (
                    allow_external_resume
                )
                strategy.storage.partial.store(current_partial)
                if save_to_session:
                    strategy.session_set(
                        PARTIAL_TOKEN_SESSION_NAME, current_partial.token
                    )
            return out

        return wrapper

    return decorator


# Backward compatible partial decorator, that stores the token in the session
partial = partial_step(save_to_session=True)
