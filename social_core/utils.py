from __future__ import annotations

import functools
import hmac
import logging
import re
import sys
import time
import unicodedata
from typing import Any
from urllib.parse import parse_qs as battery_parse_qs
from urllib.parse import unquote, urlencode, urlparse, urlunparse

import requests

import social_core

from .exceptions import AuthCanceled, AuthForbidden, AuthUnreachableProvider

SETTING_PREFIX = "SOCIAL_AUTH"

PARTIAL_TOKEN_SESSION_NAME = "partial_pipeline_token"


social_logger = logging.getLogger("social")


def import_module(name):
    __import__(name)
    return sys.modules[name]


def module_member(name):
    mod, member = name.rsplit(".", 1)
    module = import_module(mod)
    return getattr(module, member)


def user_agent():
    """Builds a simple User-Agent string to send in requests"""
    return "social-auth-" + social_core.__version__


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


def sanitize_redirect(hosts, redirect_to):
    """
    Given a list of hostnames and an untrusted URL to redirect to,
    this method tests it to make sure it isn't garbage/harmful
    and returns it, else returns None, similar as how's it done
    on django.contrib.auth.views.
    """
    # Avoid redirect on evil URLs like ///evil.com
    if (
        not redirect_to
        or not hasattr(redirect_to, "startswith")
        or redirect_to.startswith("///")
    ):
        return None

    try:
        # Don't redirect to a host that's not in the list
        netloc = urlparse(redirect_to)[1] or hosts[0]
    except (TypeError, AttributeError):
        pass
    else:
        if netloc in hosts:
            return redirect_to


def user_is_authenticated(user):
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


def user_is_active(user):
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


def partial_pipeline_data(backend, user=None, partial_token=None, *args, **kwargs):
    request_data = backend.strategy.request_data()

    partial_argument_name = backend.setting(
        "PARTIAL_PIPELINE_TOKEN_NAME", "partial_token"
    )
    partial_token = (
        partial_token
        or request_data.get(partial_argument_name)
        or backend.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME, None)
    )

    if partial_token:
        partial = backend.strategy.partial_load(partial_token)
        partial_matches_request = False

        if partial and partial.backend == backend.name:
            partial_matches_request = True

            # Normally when resuming a pipeline, request_data will be empty. We
            # only need to check for a uid match if new data was provided (i.e.
            # if current request specifies the ID_KEY).
            if backend.ID_KEY and backend.ID_KEY in request_data:
                id_from_partial = partial.kwargs.get("uid")
                id_from_request = request_data.get(backend.ID_KEY)

                if id_from_partial != id_from_request:
                    partial_matches_request = False

        if partial_matches_request:
            if user:  # don't update user if it's None
                kwargs.setdefault("user", user)
            kwargs.setdefault("request", request_data)
            partial.extend_kwargs(kwargs)
            return partial
        backend.strategy.clean_partial_pipeline(partial_token)
        return None
    return None


def build_absolute_uri(host_url, path=None):
    """Build absolute URI with given (optional) path"""
    path = path or ""
    if path.startswith(("http://", "https://")):
        return path
    if host_url.endswith("/") and path.startswith("/"):
        path = path[1:]
    return host_url + path


def constant_time_compare(val1, val2):
    """Compare two values and prevent timing attacks for cryptographic use."""
    if isinstance(val1, str):
        val1 = val1.encode("utf-8")
    if isinstance(val2, str):
        val2 = val2.encode("utf-8")
    return hmac.compare_digest(val1, val2)


def is_url(value):
    return value and (value.startswith(("http://", "https://", "/")))


def setting_url(backend, *names):
    for name in names:
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
                raise AuthCanceled(args[0], response=err.response)
            if err.response.status_code == 401:
                raise AuthForbidden(args[0])
            if err.response.status_code == 503:
                raise AuthUnreachableProvider(args[0])
            raise

    return wrapper


def append_slash(url):
    """Make sure we append a slash at the end of the URL otherwise we
    have issues with urljoin Example:
    >>> urlparse.urljoin('http://www.example.com/api/v3', 'user/1/')
    'http://www.example.com/api/user/1/'
    """
    if url and not url.endswith("/"):
        url = f"{url}/"
    return url


def get_strategy(strategy, storage, *args, **kwargs):
    Strategy = module_member(strategy)
    Storage = module_member(storage)
    return Strategy(Storage, *args, **kwargs)


class cache:
    """
    Cache decorator that caches the return value of a method for a
    specified time.

    It maintains a cache per class, so subclasses have a different cache entry
    for the same cached method.

    Does not work for methods with arguments.
    """

    def __init__(self, ttl: int):
        self.ttl = ttl
        self.cache: dict[type, Any] = {}

    def __call__(self, fn):
        def wrapped(this):
            now = time.time()
            last_updated = None
            cached_value = None
            if this.__class__ in self.cache:
                last_updated, cached_value = self.cache[this.__class__]

            # ignoring this type issue is safe; if cached_value is returned, last_updated
            # is also set, but the type checker doesn't know it.
            if not cached_value or not last_updated or now - last_updated > self.ttl:
                try:
                    cached_value = fn(this)
                    self.cache[this.__class__] = (now, cached_value)
                except Exception:
                    # Use previously cached value when call fails, if available
                    if not cached_value:
                        raise
            return cached_value

        wrapped.invalidate = self._invalidate  # type: ignore[attr-defined]
        return wrapped

    def _invalidate(self):
        self.cache.clear()
