from social_core.pipeline.partial import partial


@partial
def ask_for_password(strategy, *args, **kwargs):
    if strategy.session_get("password"):
        return {"password": strategy.session_get("password")}
    return strategy.redirect(strategy.build_absolute_uri("/password"))


@partial
def ask_for_slug(strategy, *args, **kwargs):
    if strategy.session_get("slug"):
        return {"slug": strategy.session_get("slug")}
    return strategy.redirect(strategy.build_absolute_uri("/slug"))


def set_password(strategy, user, *args, **kwargs) -> None:
    user.set_password(kwargs["password"])


def set_slug(strategy, user, *args, **kwargs) -> None:
    user.slug = kwargs["slug"]


def remove_user(strategy, user, *args, **kwargs):
    return {"user": None}


@partial
def set_user_from_kwargs(strategy, *args, **kwargs):
    if strategy.session_get("attribute"):
        assert kwargs["user"].id is not None
        return None
    return strategy.redirect(strategy.build_absolute_uri("/attribute"))


@partial
def set_user_from_args(strategy, user, *args, **kwargs):
    if strategy.session_get("attribute"):
        assert user.id is not None
        return None
    return strategy.redirect(strategy.build_absolute_uri("/attribute"))
