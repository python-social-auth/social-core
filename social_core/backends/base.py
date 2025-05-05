from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Literal, cast

import requests
from requests import Response

from ..exceptions import AuthConnectionError, AuthUnknownError
from ..utils import module_member, parse_qs, user_agent

if TYPE_CHECKING:
    from collections.abc import Mapping

    from requests.auth import AuthBase


class BaseAuth:
    """A authentication backend that authenticates the user based on
    the provider response"""

    name = ""  # provider name, it's stored in database
    supports_inactive_user = False  # Django auth
    ID_KEY: str = ""
    EXTRA_DATA: list[str | tuple[str, str] | tuple[str, str, bool]] | None = None
    GET_ALL_EXTRA_DATA = False
    REQUIRES_EMAIL_VALIDATION = False
    SEND_USER_AGENT = False

    def __init__(self, strategy, redirect_uri=None):
        self.strategy = strategy
        self.redirect_uri = redirect_uri
        self.data = self.strategy.request_data()
        self.redirect_uri = self.strategy.absolute_uri(self.redirect_uri)

    def setting(self, name, default=None):
        """Return setting value from strategy"""
        return self.strategy.setting(name, default=default, backend=self)

    def start(self):
        if self.uses_redirect():
            return self.strategy.redirect(self.auth_url())
        return self.strategy.html(self.auth_html())

    def complete(self, *args, **kwargs):
        return self.auth_complete(*args, **kwargs)

    def auth_url(self):
        """Must return redirect URL to auth provider"""
        raise NotImplementedError("Implement in subclass")

    def auth_html(self):
        """Must return login HTML content returned by provider"""
        raise NotImplementedError("Implement in subclass")

    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        raise NotImplementedError("Implement in subclass")

    def process_error(self, data):
        """Process data for errors, raise exception if needed.
        Call this method on any override of auth_complete."""

    def authenticate(self, *args, **kwargs):
        """Authenticate user using social credentials

        Authentication is made if this is the correct backend, backend
        verification is made by kwargs inspection for current backend
        name presence.
        """
        # Validate backend and arguments. Require that the Social Auth
        # response be passed in as a keyword argument, to make sure we
        # don't match the username/password calling conventions of
        # authenticate.
        if (
            "backend" not in kwargs
            or kwargs["backend"].name != self.name
            or "strategy" not in kwargs
            or "response" not in kwargs
        ):
            return None

        self.strategy = kwargs.get("strategy") or self.strategy
        self.redirect_uri = kwargs.get("redirect_uri") or self.redirect_uri
        self.data = self.strategy.request_data()
        kwargs.setdefault("is_new", False)
        pipeline = self.strategy.get_pipeline(self)
        args, kwargs = self.strategy.clean_authenticate_args(*args, **kwargs)
        return self.pipeline(pipeline, *args, **kwargs)

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        out = self.run_pipeline(pipeline, pipeline_index, *args, **kwargs)
        if not isinstance(out, dict):
            return out
        user = out.get("user")
        if user:
            user.social_user = out.get("social")
            user.is_new = out.get("is_new")
        return user

    def disconnect(self, *args, **kwargs):
        pipeline = self.strategy.get_disconnect_pipeline(self)
        kwargs["name"] = self.name
        kwargs["user_storage"] = self.strategy.storage.user
        return self.run_pipeline(pipeline, *args, **kwargs)

    def run_pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        out = kwargs.copy()
        out.setdefault("strategy", self.strategy)
        out.setdefault("backend", out.pop(self.name, None) or self)
        out.setdefault("request", self.strategy.request_data())
        out.setdefault("details", {})

        if (
            not isinstance(pipeline_index, int)
            or pipeline_index < 0
            or pipeline_index >= len(pipeline)
        ):
            pipeline_index = 0

        for idx, name in enumerate(pipeline[pipeline_index:]):
            out["pipeline_index"] = pipeline_index + idx
            func = module_member(name)
            result = func(*args, **out) or {}
            if not isinstance(result, dict):
                return result
            out.update(result)
        return out

    def extra_data(
        self,
        user,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        *args,
        **kwargs,
    ) -> dict[str, Any]:
        """Return default extra data to store in extra_data field"""
        data: dict[str, Any] = {
            # store the last time authentication took place
            "auth_time": int(time.time())
        }
        extra_data_entries: list[str | tuple[str, str] | tuple[str, str, bool]] = []
        if self.GET_ALL_EXTRA_DATA or self.setting("GET_ALL_EXTRA_DATA", False):
            extra_data_entries = list(response.keys())
        else:
            extra_data_entries = (self.EXTRA_DATA or []) + cast(
                "list[str | tuple[str, str] | tuple[str, str, bool]]",
                self.setting("EXTRA_DATA", []),
            )
        for entry in extra_data_entries:
            if isinstance(entry, list):
                entry = tuple(cast("list[str]", entry))
            discard = False
            if isinstance(entry, str):
                name = alias = entry
            elif len(entry) == 3:
                name, alias, discard = entry
            elif len(entry) == 2:
                name, alias = entry
            elif len(entry) == 1:
                name = alias = entry[0]
            else:
                raise AuthUnknownError(self, f"Invalid EXTRA_DATA item: {entry!r}")
            value = response.get(name, details.get(name, details.get(alias)))
            if discard and not value:
                continue
            data[alias] = value
        return data

    def auth_allowed(self, response, details):
        """Return True if the user should be allowed to authenticate, by
        default check if email is whitelisted (if there's a whitelist)"""
        emails = [email.lower() for email in self.setting("WHITELISTED_EMAILS", [])]
        domains = [domain.lower() for domain in self.setting("WHITELISTED_DOMAINS", [])]
        email = details.get("email")
        allowed = True
        if email and (emails or domains):
            email = email.lower()
            domain = email.split("@", 1)[1]
            allowed = email in emails or domain in domains
        return allowed

    def get_user_id(self, details, response):
        """Return a unique ID for the current user, by default from server
        response."""
        return response.get(self.ID_KEY)

    def get_user_details(self, response):
        """Must return user details in a know internal struct:
        {'username': <username if any>,
         'email': <user email if any>,
         'fullname': <user full name if any>,
         'first_name': <user first name if any>,
         'last_name': <user last name if any>}
        """
        raise NotImplementedError("Implement in subclass")

    def get_user_names(self, fullname="", first_name="", last_name=""):
        # Avoid None values
        fullname = fullname or ""
        first_name = first_name or ""
        last_name = last_name or ""
        if fullname and not (first_name or last_name):
            try:
                first_name, last_name = fullname.split(" ", 1)
            except ValueError:
                first_name = first_name or fullname or ""
                last_name = last_name or ""
        fullname = fullname or f"{first_name} {last_name}"
        return fullname.strip(), first_name.strip(), last_name.strip()

    def get_user(self, user_id):
        """
        Return user with given ID from the User model used by this backend.
        This is called by django.contrib.auth.middleware.
        """
        return self.strategy.get_user(user_id)

    def continue_pipeline(self, partial):
        """Continue previous halted pipeline"""
        return self.strategy.authenticate(
            self, pipeline_index=partial.next_step, *partial.args, **partial.kwargs
        )

    def auth_extra_arguments(self):
        """Return extra arguments needed on auth process. The defaults can be
        overridden by GET parameters."""
        extra_arguments = self.setting("AUTH_EXTRA_ARGUMENTS", {}).copy()
        extra_arguments.update(
            (key, self.data[key]) for key in extra_arguments if key in self.data
        )
        return extra_arguments

    def uses_redirect(self) -> bool:
        """Return True if this provider uses redirect url method,
        otherwise return false."""
        return True

    def request(
        self,
        url: str,
        *,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | bytes | str | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
    ) -> Response:
        headers = {} if headers is None else dict(headers)
        proxies = self.setting("PROXIES")
        verify = self.setting("VERIFY_SSL", True)
        #        if timeout is None:
        timeout = self.setting("REQUESTS_TIMEOUT") or self.setting("URLOPEN_TIMEOUT")

        if self.SEND_USER_AGENT and "User-Agent" not in headers:
            headers["User-Agent"] = self.setting("USER_AGENT") or user_agent()

        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                data=data,
                auth=auth,
                params=params,
                timeout=timeout,
                proxies=proxies,
                verify=verify,
            )
        except requests.ConnectionError as err:
            raise AuthConnectionError(self, str(err)) from err
        response.raise_for_status()
        return response

    def get_json(
        self,
        url: str,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | bytes | str | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
    ) -> dict[Any, Any]:
        return self.request(
            url, method=method, headers=headers, data=data, auth=auth, params=params
        ).json()

    def get_querystring(self, url, *args, **kwargs) -> dict[str, str]:
        return parse_qs(self.request(url, *args, **kwargs).text)

    def get_key_and_secret(self) -> tuple[str, str]:
        """Return tuple with Consumer Key and Consumer Secret for current
        service provider. Must return (key, secret), order *must* be respected.
        """
        return self.setting("KEY"), self.setting("SECRET")
