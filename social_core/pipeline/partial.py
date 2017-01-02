from functools import wraps

from .utils import partial_prepare


def partial(func):
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
    partial_pipeline_token key.
    """
    @wraps(func)
    def wrapper(strategy, backend, pipeline_index, *args, **kwargs):
        current_partial = partial_prepare(strategy, backend, pipeline_index,
                                          *args, **kwargs)

        out = func(strategy=strategy,
                   backend=backend,
                   pipeline_index=pipeline_index,
                   current_partial=current_partial,
                   *args, **kwargs) or {}

        if not isinstance(out, dict):
            strategy.storage.partial.store(current_partial)
            strategy.session_set('partial_pipeline_token',
                                 current_partial.token)
        return out
    return wrapper
