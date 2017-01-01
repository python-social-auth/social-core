from functools import wraps


def partial(func):
    @wraps(func)
    def wrapper(strategy, pipeline_index, *args, **kwargs):
        out = func(strategy=strategy, pipeline_index=pipeline_index,
                    *args, **kwargs) or {}
        if not isinstance(out, dict):
            values = strategy.partial_to_session(pipeline_index, *args,
                                                 **kwargs)
            strategy.session_set('partial_pipeline', values)
        return out
    return wrapper
