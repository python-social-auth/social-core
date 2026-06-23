from __future__ import annotations

import contextlib
import functools
import hmac
import logging
import re
import time
import unicodedata
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qs as battery_parse_qs
from urllib.parse import unquote, urlencode, urlparse, urlunparse

import requests

import social_core
from social_core.pipeline.utils import is_dict_type, to_plain_dict

from .exceptions import (
    AuthCanceled,
    AuthForbidden,
    AuthTokenError,
    AuthUnreachableProvider,
)

if TYPE_CHECKING:
    from .backends.base import BaseAuth
    from .storage import PartialMixin, UserProtocol
    from .strategy import BaseStrategy, HttpResponseProtocol

SETTING_PREFIX = "SOCIAL_AUTH"

PARTIAL_TOKEN_SESSION_NAME = "partial_pipeline_token"
PARTIAL_TOKEN_PENDING_SESSION_NAME = "partial_pipeline_pending_token"
PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME = "partial_pipeline_pending_request"
PARTIAL_TOKEN_PENDING_CONFIRMATION_SESSION_NAME = (
    "partial_pipeline_pending_confirmation"
)
PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME = "allow_external_resume"


social_logger = logging.getLogger("social")


@dataclass
class PartialPipelineResult:
    partial: PartialMixin | None = None
    response: HttpResponseProtocol | None = None
    halt: bool = False


@dataclass
class PartialPipelineSelection:
    token: str | None = None
    owns_token: bool = False
    pending_resume: bool = False


def module_member(name):
    mod, member = name.rsplit(".", 1)
    module = import_module(mod)
    return getattr(module, member)


def user_agent() -> str:
    """Builds a simple User-Agent string to send in requests"""
    return f"social-auth-{social_core.__version__}"


def url_add_parameters(
    url: str, params: dict[str, str] | None, _unquote_query: bool = False
) -> str:
    """Adds parameters to URL, parameter will be repeated if already present"""
    if params:
        fragments = list(urlparse(url))
        value = parse_qs(fragments[4])
        value.update(params)
        fragments[4] = urlencode(value)
        if _unquote_query:
            fragments[4] = unquote(fragments[4])
        url = urlunparse(fragments)
    return url


def to_setting_name(*names: str) -> str:
    return "_".join([name.upper().replace("-", "_") for name in names if name])


def setting_name(*names: str) -> str:
    return to_setting_name(*((SETTING_PREFIX, *names)))


def sanitize_redirect(hosts: list[str], redirect_to: str | Any) -> str | None:
    """
    Given a list of hostnames and an untrusted URL to redirect to,
    this method tests it to make sure it isn't garbage/harmful
    and returns it, else returns None, similar as how's it done
    on django.contrib.auth.views.
    """
    # Avoid redirect on evil URLs like ///evil.com and URLs containing
    # backslashes or control characters that browsers may normalize.
    if (
        not redirect_to
        or not isinstance(redirect_to, str)
        or redirect_to.startswith("///")
        or "\\" in redirect_to
        or any(unicodedata.category(char)[0] == "C" for char in redirect_to)
    ):
        return None

    try:
        parsed_url = urlparse(redirect_to)
        if parsed_url.scheme and parsed_url.scheme not in {"http", "https"}:
            return None
        if parsed_url.scheme and not parsed_url.netloc:
            return None
        # Don't redirect to a host that's not in the list
        netloc = parsed_url.netloc or hosts[0]
    except (IndexError, TypeError, AttributeError, ValueError):
        return None

    if netloc in hosts:
        return redirect_to
    return None


def user_is_authenticated(user: UserProtocol | None) -> bool:
    if user and hasattr(user, "is_authenticated"):
        if callable(user.is_authenticated):
            authenticated = user.is_authenticated()
        else:
            authenticated = user.is_authenticated
    elif user:
        authenticated = True
    else:
        authenticated = False
    return authenticated


def user_is_active(user: UserProtocol | None) -> bool:
    if user and hasattr(user, "is_active"):
        is_active = user.is_active() if callable(user.is_active) else user.is_active
    elif user:
        is_active = True
    else:
        is_active = False
    return is_active


# This slugify version was borrowed from django revision a61dbd6
def slugify(value):
    """Converts to lowercase, removes non-word characters (alphanumerics
    and underscores) and converts spaces to hyphens. Also strips leading
    and trailing whitespace."""
    value = (
        unicodedata.normalize("NFKD", str(value))
        .encode("ascii", "ignore")
        .decode("ascii")
    )
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def first(func, items):
    """Return the first item in the list for what func returns True"""
    for item in items:
        if func(item):
            return item
    return None


def parse_qs(value):
    """Like urlparse.parse_qs but transform list values to single items"""
    return drop_lists(battery_parse_qs(value))


def get_querystring(url: str):
    return parse_qs(urlparse(url).query)


def drop_lists(value):
    out = {}
    for key, val in value.items():
        val = val[0]
        if isinstance(key, bytes):
            key = str(key, "utf-8")
        if isinstance(val, bytes):
            val = str(val, "utf-8")
        out[key] = val
    return out


def _partial_pipeline_matches_request(
    backend: BaseAuth, partial: PartialMixin | None, request_data: dict[str, Any]
) -> bool:
    if not partial or partial.backend != backend.name:
        return False

    # Normally when resuming a pipeline, request_data will be empty. We only
    # need to check for a uid match if new data was provided (i.e. if current
    # request specifies the ID_KEY).
    id_key = backend.id_key()
    if id_key and id_key in request_data:
        id_from_partial = partial.kwargs.get("uid")
        id_from_request = request_data.get(id_key)

        return id_from_partial == id_from_request

    return True


def _extend_partial_pipeline(
    partial: PartialMixin,
    request_data: dict[str, Any],
    user: UserProtocol | None,
    kwargs: dict[str, Any],
) -> PartialMixin:
    if user:  # don't update user if it's None
        kwargs.setdefault("user", user)
    kwargs["request"] = request_data
    partial.extend_kwargs(kwargs)
    return partial


def _select_partial_pipeline_token(
    request_token: str | None,
    session_token: str | None,
    pending_token: str | None,
    confirmation_requested: bool,
) -> PartialPipelineSelection:
    if confirmation_requested and pending_token:
        selected_token = request_token or pending_token
        pending_resume = selected_token == pending_token
        return PartialPipelineSelection(
            token=selected_token,
            owns_token=pending_resume,
            pending_resume=pending_resume,
        )

    if request_token and request_token == session_token:
        return PartialPipelineSelection(token=request_token, owns_token=True)

    if request_token:
        return PartialPipelineSelection(token=request_token)

    return PartialPipelineSelection(token=session_token, owns_token=bool(session_token))


def _partial_pipeline_requires_confirmation(
    partial: PartialMixin,
    request_token: str | None,
    request_data: dict[str, Any],
    pending_resume: bool,
) -> bool:
    return bool(
        not pending_resume
        and partial.data.get(PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME)
        and (request_token or request_data)
    )


def _confirmed_partial_pipeline_request_data(
    backend: BaseAuth,
    request_data: dict[str, Any],
) -> dict[str, Any] | None:
    if not backend.strategy.partial_pipeline_external_resume_confirmed(
        backend, request_data
    ):
        return None

    pending_request_data = backend.strategy.from_session_value(
        backend.strategy.session_get(PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME, {})
        or {}
    )
    return {**pending_request_data, **request_data}


def _external_partial_pipeline_result(
    backend: BaseAuth,
    partial: PartialMixin,
    selected_token: str,
    request_data: dict[str, Any],
) -> PartialPipelineResult:
    response = backend.strategy.partial_pipeline_external_resume_confirmation(
        backend, partial, request_data
    )
    if response is None:
        return PartialPipelineResult(halt=True)

    backend.strategy.session_set(PARTIAL_TOKEN_PENDING_SESSION_NAME, selected_token)
    backend.strategy.session_set(
        PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
        backend.strategy.to_session_value(
            to_plain_dict(request_data) if is_dict_type(request_data) else request_data
        ),
    )
    return PartialPipelineResult(response=response)


def partial_pipeline_result(
    backend: BaseAuth,
    user: UserProtocol | None = None,
    partial_token: str | None = None,
    *args,
    **kwargs,
) -> PartialPipelineResult:
    request_data = backend.strategy.request_data()

    partial_argument_name = backend.setting(
        "PARTIAL_PIPELINE_TOKEN_NAME", "partial_token"
    )
    request_token = cast(
        "str | None", partial_token or request_data.get(partial_argument_name)
    )
    session_token = backend.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME, None)
    pending_token = backend.strategy.session_get(
        PARTIAL_TOKEN_PENDING_SESSION_NAME, None
    )

    confirmation_parameter = backend.setting(
        "PARTIAL_PIPELINE_EXTERNAL_RESUME_CONFIRMATION_PARAMETER",
        "partial_pipeline_confirm",
    )
    confirmation_requested = (
        bool(confirmation_parameter) and confirmation_parameter in request_data
    )

    selection = _select_partial_pipeline_token(
        request_token=request_token,
        session_token=session_token,
        pending_token=pending_token,
        confirmation_requested=confirmation_requested,
    )
    if not selection.token:
        return PartialPipelineResult()

    result = PartialPipelineResult(halt=bool(request_token or confirmation_requested))
    effective_request_data = request_data
    if selection.pending_resume:
        confirmed_request_data = _confirmed_partial_pipeline_request_data(
            backend, request_data
        )
        if confirmed_request_data is None:
            return PartialPipelineResult(halt=True)
        effective_request_data = confirmed_request_data

    partial: PartialMixin | None = backend.strategy.partial_load(selection.token)
    partial_matches = _partial_pipeline_matches_request(
        backend, partial, effective_request_data
    )
    if partial and partial_matches:
        if _partial_pipeline_requires_confirmation(
            partial,
            request_token,
            effective_request_data,
            selection.pending_resume,
        ):
            result = _external_partial_pipeline_result(
                backend, partial, selection.token, effective_request_data
            )
        elif selection.owns_token:
            result = PartialPipelineResult(
                partial=_extend_partial_pipeline(
                    partial, effective_request_data, user, kwargs
                )
            )
        elif partial.data.get(PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME):
            result = _external_partial_pipeline_result(
                backend, partial, selection.token, effective_request_data
            )
        else:
            result = PartialPipelineResult(halt=True)
    elif selection.owns_token:
        backend.strategy.clean_partial_pipeline(selection.token)

    return result


def partial_pipeline_data(
    backend: BaseAuth,
    user: UserProtocol | None = None,
    partial_token: str | None = None,
    *args,
    **kwargs,
) -> PartialMixin | None:
    return partial_pipeline_result(
        backend, user, partial_token, *args, **kwargs
    ).partial


def build_absolute_uri(host_url: str, path: str | None = None) -> str:
    """Build absolute URI with given (optional) path"""
    path = path or ""
    if path.startswith(("http://", "https://")):
        return path
    if host_url.endswith("/") and path.startswith("/"):
        path = path[1:]
    return host_url + path


def constant_time_compare(val1: str | bytes, val2: str | bytes) -> bool:
    """Compare two values and prevent timing attacks for cryptographic use."""
    if isinstance(val1, str):
        val1 = val1.encode("utf-8")
    if isinstance(val2, str):
        val2 = val2.encode("utf-8")
    return hmac.compare_digest(val1, val2)


def is_url(value: str | None) -> bool:
    return value is not None and value.startswith(("http://", "https://", "/"))


def setting_url(backend: BaseAuth, *names: str | None) -> str | None:
    for name in names:
        # Name can actually None, value or setting name
        if not name:
            continue
        if is_url(name):
            return name
        value = backend.setting(name)
        if is_url(value):
            return value
    return None


def handle_http_errors(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.HTTPError as err:
            social_logger.exception(
                "Request failed with %d: %s",
                err.response.status_code,
                err.response.text,
            )

            if err.response.status_code == 400:
                raise AuthCanceled(args[0], response=err.response) from err
            if err.response.status_code == 401:
                raise AuthForbidden(args[0]) from err
            if err.response.status_code == 503:
                raise AuthUnreachableProvider(args[0]) from err
            raise

    return wrapper


@contextlib.contextmanager
def wrap_access_token_error(backend: BaseAuth):
    try:
        yield
    except requests.HTTPError as error:
        if error.response.status_code == 401:
            raise AuthTokenError(
                backend, "Invalid key/secret, perhaps expired"
            ) from error
        raise


def append_slash(url: str) -> str:
    """Make sure we append a slash at the end of the URL otherwise we
    have issues with urljoin Example:
    >>> urlparse.urljoin('http://www.example.com/api/v3', 'user/1/')
    'http://www.example.com/api/user/1/'
    """
    if url and not url.endswith("/"):
        url = f"{url}/"
    return url


def get_strategy(strategy: str, storage: str, *args, **kwargs) -> BaseStrategy:
    Strategy = module_member(strategy)
    Storage = module_member(storage)
    return Strategy(Storage, *args, **kwargs)


class cache:
    """
    Cache decorator that caches the return value of a method for a
    specified time.

    It maintains a cache per class and method arguments, so subclasses have a
    different cache entry for the same cached method.
    """

    def __init__(self, ttl: int) -> None:
        self.ttl = ttl
        self.cache: dict[
            tuple[type, tuple[Any, ...], tuple[tuple[str, Any], ...]], Any
        ] = {}

    def __call__(self, fn):
        def wrapped(this, *args, **kwargs):
            now = time.time()
            last_updated = None
            cached_value = None
            cache_key = (this.__class__, args, tuple(sorted(kwargs.items())))
            if cache_key in self.cache:
                last_updated, cached_value = self.cache[cache_key]

            # ignoring this type issue is safe; if cached_value is returned, last_updated
            # is also set, but the type checker doesn't know it.
            if not cached_value or not last_updated or now - last_updated > self.ttl:
                try:
                    cached_value = fn(this, *args, **kwargs)
                    self.cache[cache_key] = (now, cached_value)
                # pylint: disable-next=broad-exception-caught
                except Exception:
                    # Use previously cached value when call fails, if available
                    if not cached_value:
                        raise
            return cached_value

        cast("Any", wrapped).invalidate = self._invalidate
        return wrapped

    def _invalidate(self) -> None:
        self.cache.clear()
