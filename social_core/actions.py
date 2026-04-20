from __future__ import annotations

from typing import TYPE_CHECKING, cast
from urllib.parse import quote

from .utils import (
    partial_pipeline_data,
    sanitize_redirect,
    setting_url,
    user_is_active,
    user_is_authenticated,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from .backends.base import BaseAuth
    from .storage import PipelineUserProtocol, UserMixin, UserProtocol
    from .strategy import HttpResponseProtocol


def _get_social_user(user: PipelineUserProtocol) -> UserMixin:
    social_user = user.social_user
    if social_user is None:
        raise ValueError("Expected social_user to be set during authentication")
    return social_user


def _login_user(
    backend: BaseAuth, login: Callable, authenticated_user: PipelineUserProtocol
) -> bool:
    social_user = _get_social_user(authenticated_user)
    is_new = authenticated_user.is_new
    login(backend, authenticated_user, social_user)
    backend.strategy.session_set("social_auth_last_login_backend", social_user.provider)
    return is_new


def _sanitize_redirect_url(backend: BaseAuth, url: str) -> str:
    if backend.setting("SANITIZE_REDIRECTS", True):
        allowed_hosts = [
            *cast("list[str]", backend.setting("ALLOWED_REDIRECT_HOSTS", [])),
            backend.strategy.request_host(),
        ]
        sanitized_url = sanitize_redirect(allowed_hosts, url) or backend.setting(
            "LOGIN_REDIRECT_URL"
        )
        if sanitized_url is None:
            raise ValueError("Disallowed URL")
        url = cast("str", sanitized_url)
    return url


def do_auth(backend: BaseAuth, redirect_name: str = "next") -> HttpResponseProtocol:
    # Save any defined next value into session
    data = backend.strategy.request_data(merge=False)

    # Save extra data into session.
    for field_name in cast(
        "list[str]", backend.setting("FIELDS_STORED_IN_SESSION", [])
    ):
        if field_name in data:
            backend.strategy.session_set(field_name, data[field_name])
        else:
            backend.strategy.session_set(field_name, None)

    if redirect_name in data:
        # Check and sanitize a user-defined GET/POST next field value
        redirect_uri = data[redirect_name]
        if backend.setting("SANITIZE_REDIRECTS", True):
            allowed_hosts = [
                *cast("list[str]", backend.setting("ALLOWED_REDIRECT_HOSTS", [])),
                backend.strategy.request_host(),
            ]
            redirect_uri = sanitize_redirect(allowed_hosts, redirect_uri)
        backend.strategy.session_set(
            redirect_name, redirect_uri or backend.setting("LOGIN_REDIRECT_URL")
        )
    return backend.start()


def do_complete(
    backend: BaseAuth,
    login: Callable,
    user: UserProtocol | None = None,
    redirect_name: str = "next",
    *args,
    **kwargs,
) -> HttpResponseProtocol:
    data = backend.strategy.request_data()

    is_authenticated = user_is_authenticated(user)
    partial_user = user if is_authenticated else None
    authenticated_user: UserProtocol | HttpResponseProtocol | None = partial_user

    partial = partial_pipeline_data(backend, partial_user, *args, **kwargs)
    if partial:
        authenticated_user = backend.continue_pipeline(partial)
        # clean partial data after usage
        backend.strategy.clean_partial_pipeline(partial.token)
    else:
        authenticated_user = backend.complete(
            *args, user=authenticated_user, redirect_name=redirect_name, **kwargs
        )

    # pop redirect value before the session is trashed on login(), but after
    # the pipeline so that the pipeline can change the redirect if needed
    redirect_value = backend.strategy.session_get(redirect_name, "") or data.get(
        redirect_name, ""
    )

    # check if the output value is something else than a user and just
    # return it to the client
    user_model = backend.strategy.storage.user.user_model()
    if authenticated_user and not isinstance(authenticated_user, user_model):
        return cast("HttpResponseProtocol", authenticated_user)

    authenticated_user = cast("PipelineUserProtocol | None", authenticated_user)
    url: str | None

    if is_authenticated:
        if not authenticated_user:
            url = setting_url(backend, redirect_value, "LOGIN_REDIRECT_URL")
        else:
            url = setting_url(
                backend,
                redirect_value,
                "NEW_ASSOCIATION_REDIRECT_URL",
                "LOGIN_REDIRECT_URL",
            )
    elif authenticated_user:
        # check if inactive users are allowed to login
        bypass_inactivation = backend.strategy.setting(
            "ALLOW_INACTIVE_USERS_LOGIN", False
        )
        if bypass_inactivation or user_is_active(authenticated_user):
            is_new = _login_user(backend, login, authenticated_user)

            if is_new:
                url = setting_url(
                    backend,
                    "NEW_USER_REDIRECT_URL",
                    redirect_value,
                    "LOGIN_REDIRECT_URL",
                )
            else:
                url = setting_url(backend, redirect_value, "LOGIN_REDIRECT_URL")
        else:
            if backend.setting("INACTIVE_USER_LOGIN", False):
                login(backend, authenticated_user, _get_social_user(authenticated_user))
            url = setting_url(
                backend, "INACTIVE_USER_URL", "LOGIN_ERROR_URL", "LOGIN_URL"
            )
    else:
        url = setting_url(backend, "LOGIN_ERROR_URL", "LOGIN_URL")

    if not url:
        raise ValueError("By this point URL has to have been set")

    if redirect_value and redirect_value != url:
        redirect_value = quote(redirect_value)
        url += f"{'&' if '?' in url else '?'}{redirect_name}={redirect_value}"

    url = _sanitize_redirect_url(backend, url)
    return backend.strategy.redirect(url)


def do_disconnect(
    backend: BaseAuth,
    user: UserProtocol,
    association_id=None,
    redirect_name: str = "next",
    *args,
    **kwargs,
):
    partial = partial_pipeline_data(backend, user, *args, **kwargs)
    if partial:
        if association_id and not partial.kwargs.get("association_id"):
            partial.extend_kwargs({"association_id": association_id})
        response = backend.disconnect(*partial.args, **partial.kwargs)
        # clean partial data after usage
        backend.strategy.clean_partial_pipeline(partial.token)
    else:
        response = backend.disconnect(
            *args, user=user, association_id=association_id, **kwargs
        )

    if isinstance(response, dict):
        url: str | None = backend.strategy.absolute_uri(
            backend.strategy.request_data().get(redirect_name, "")
            or backend.setting("DISCONNECT_REDIRECT_URL")
            or backend.setting("LOGIN_REDIRECT_URL")
        )
        if backend.setting("SANITIZE_REDIRECTS", True):
            allowed_hosts = [
                *cast("list[str]", backend.setting("ALLOWED_REDIRECT_HOSTS", [])),
                backend.strategy.request_host(),
            ]
            url = (
                sanitize_redirect(allowed_hosts, url)
                or backend.setting("DISCONNECT_REDIRECT_URL")
                or backend.setting("LOGIN_REDIRECT_URL")
            )
        if not url:
            raise ValueError("Disallowed URL")
        return backend.strategy.redirect(url)
    return response
