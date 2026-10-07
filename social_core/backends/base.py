from __future__ import annotations

import base64
import inspect
import time
import warnings
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Literal, cast

import requests

from social_core.exceptions import (
    AuthConfigurationError,
    AuthInputError,
    AuthPolicyError,
    AuthProviderError,
    AuthResponseError,
    AuthSessionError,
    ErrorStage,
    SocialAuthBaseException,
)
from social_core.registry import REGISTRY
from social_core.utils import (
    constant_time_compare,
    http_error,
    module_member,
    normalize_user_names,
    parse_qs,
    social_logger,
    user_agent,
    user_is_authenticated,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping

    from requests import Response
    from requests.auth import AuthBase

    from social_core.storage import PartialMixin, PipelineUserProtocol, UserProtocol
    from social_core.strategy import BaseStrategy, HttpResponseProtocol


class BaseAuth:
    """A authentication backend that authenticates the user based on
    the provider response.

    Set ``ASSOCIATION_ONLY`` to connect provider access to an authenticated local
    user without updating their profile. Browser flows must start through
    ``do_auth(user=...)`` and validate callbacks with
    ``validate_association_state()`` before processing provider credentials.
    Authentication and disconnect partials remain bound to that local user.
    """

    name = ""  # provider name, it's stored in database
    title: str | None = None  # human-readable sign-in label
    icon: str | None = None  # filename in static/social_auth/icons
    supports_inactive_user = False  # Django auth
    ID_KEY: str = ""
    LEGACY_ID_KEYS: tuple[str, ...] = ()
    MUTABLE_ID_KEYS: tuple[str, ...] = ()
    EXTRA_DATA: list[str | tuple[str, str] | tuple[str, str, bool]] | None = None
    GET_ALL_EXTRA_DATA = False
    REQUIRES_EMAIL_VALIDATION = False
    REQUIRES_USER_ID: bool = False
    SEND_USER_AGENT = True
    ASSOCIATION_ONLY = False

    def __init__(
        self, strategy: BaseStrategy | None = None, redirect_uri: str | None = None
    ) -> None:
        self.strategy: BaseStrategy = (
            strategy if strategy is not None else REGISTRY.default_strategy
        )
        self.redirect_uri = redirect_uri
        self._pipeline_type: ContextVar[str] = ContextVar(
            "pipeline_type", default="authentication"
        )
        self._mutable_id_key_warned = False
        self.data = self.strategy.request_data()
        self.redirect_uri = self.strategy.absolute_uri(self.redirect_uri)

    def log_debug(self, message, *args) -> None:
        social_logger.debug(f"{self.name}: {message}", *args)

    def log_warning(self, message, *args) -> None:
        social_logger.warning(f"{self.name}: {message}", *args)

    def setting(self, name: str, default=None):
        """Return setting value from strategy"""
        return self.strategy.setting(name, default=default, backend=self)

    def prepare_auth(self, user: UserProtocol | None = None) -> None:
        """Bind association-only authorization to an authenticated local user."""
        if self.ASSOCIATION_ONLY:
            user = self.require_association_user(user, stage="begin")
            self.strategy.session_set(
                f"{self.name}_state",
                {"state": self.strategy.random_string(32), "user_id": str(user.id)},
            )

    def require_association_user(
        self, user: UserProtocol | None, *, stage: ErrorStage = "user_info"
    ) -> UserProtocol:
        """Require an authenticated local user for an association-only flow."""
        if user is None or not user_is_authenticated(user):
            raise AuthSessionError(
                self,
                "Association requires an authenticated user",
                code="session_context_missing",
                stage=stage,
            )
        return user

    def get_association_state(self) -> str:
        """Return the token from a prepared, user-bound authorization context."""
        context = self.strategy.session_get(f"{self.name}_state")
        if not isinstance(context, dict):
            raise AuthSessionError(
                self, "state", code="session_context_missing", stage="callback"
            )
        state = context.get("state")
        if not isinstance(state, str) or not state:
            raise AuthSessionError(
                self, "state", code="session_context_missing", stage="callback"
            )
        return state

    def validate_association_state(
        self, request_state: Any, user: UserProtocol | None = None
    ) -> str:
        """Validate and consume authorization state bound to the current user."""
        if not request_state:
            raise AuthInputError(
                self, parameter="state", code="missing_parameter", stage="callback"
            )
        state = self.get_association_state()
        if not isinstance(request_state, (str, bytes)) or not constant_time_compare(
            request_state, state
        ):
            raise AuthSessionError(self, code="state_mismatch", stage="callback")
        user = self.require_association_user(user, stage="callback")
        context = self.strategy.session_get(f"{self.name}_state")
        if context.get("user_id") != str(user.id):
            raise AuthSessionError(
                self,
                "Association user mismatch",
                code="user_mismatch",
                stage="callback",
            )
        self.strategy.session_pop(f"{self.name}_state")
        return state

    def association_user_id_key(self, pipeline_type: str = "authentication") -> str:
        """Name of the initiator binding saved in pipeline arguments."""
        operation = "disconnect" if pipeline_type == "disconnect" else "association"
        return f"{self.name}_{operation}_user_id"

    def _bind_association_user(
        self, kwargs: dict[str, Any], pipeline_type: str = "authentication"
    ) -> None:
        stage: ErrorStage = (
            "disconnect" if pipeline_type == "disconnect" else "user_info"
        )
        user = self.require_association_user(kwargs.get("user"), stage=stage)
        key = self.association_user_id_key(pipeline_type)
        if key in kwargs and kwargs[key] != str(user.id):
            raise AuthSessionError(
                self,
                "Association user mismatch",
                code="user_mismatch",
                stage=stage,
            )
        kwargs[key] = str(user.id)

    def start(self) -> HttpResponseProtocol:
        if self.ASSOCIATION_ONLY:
            self.get_association_state()
        if self.uses_redirect():
            return self.strategy.redirect(self.auth_url())
        return self.strategy.html(self.auth_html())

    def complete(self, *args, **kwargs) -> HttpResponseProtocol | UserProtocol | None:
        return self.auth_complete(*args, **kwargs)

    def auth_url(self) -> str:
        """Must return redirect URL to auth provider"""
        raise NotImplementedError("Implement in subclass")

    def auth_html(self) -> str:
        """Must return login HTML content returned by provider"""
        return "Implement in subclass"

    def auth_complete(
        self, *args, **kwargs
    ) -> HttpResponseProtocol | UserProtocol | None:
        """Completes login process, must return user instance"""
        raise NotImplementedError("Implement in subclass")

    def process_error(self, data, *, stage: ErrorStage = "callback") -> None:
        """Hook to process provider response errors.

        Default implementation is a no-op. Backends that can detect
        provider-specific error payloads should override this method and
        raise an appropriate exception when needed.
        """

    def _process_error(self, data, *, stage: ErrorStage) -> None:
        """Call the error hook, including overrides predating the stage keyword."""
        kwargs: dict[str, ErrorStage]
        try:
            inspect.signature(self.process_error).bind(data, stage=stage)
        except TypeError:
            # Check the signature before calling so a TypeError inside the hook
            # is propagated without invoking it twice.
            kwargs = {}
        else:
            kwargs = {"stage": stage}
        try:
            self.process_error(data, **kwargs)
        except SocialAuthBaseException as error:
            error.stage = stage
            raise

    def authenticate(
        self, *args, **kwargs
    ) -> UserProtocol | HttpResponseProtocol | None:
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
        if self.ASSOCIATION_ONLY:
            self._bind_association_user(kwargs)
        kwargs.setdefault("is_new", False)
        pipeline = self.strategy.get_pipeline(self)
        args, kwargs = self.strategy.clean_authenticate_args(*args, **kwargs)
        return self.pipeline(pipeline, *args, **kwargs)

    def pipeline(
        self, pipeline: list[str], pipeline_index: int = 0, *args, **kwargs
    ) -> UserProtocol | HttpResponseProtocol | None:
        token = self._pipeline_type.set("authentication")
        try:
            out = self.run_pipeline(pipeline, pipeline_index, *args, **kwargs)
        finally:
            self._pipeline_type.reset(token)
        if not isinstance(out, dict):
            return out
        user = cast("UserProtocol | None", out.get("user"))
        if user:
            pipeline_user = cast("PipelineUserProtocol", user)
            pipeline_user.social_user = cast("Any", out.get("social"))
            pipeline_user.is_new = bool(out.get("is_new"))
        return user

    def disconnect(self, *args, **kwargs) -> dict[str, Any] | HttpResponseProtocol:
        if self.ASSOCIATION_ONLY:
            self._bind_association_user(kwargs, "disconnect")
        pipeline = self.strategy.get_disconnect_pipeline(self)
        kwargs["name"] = self.name
        kwargs["user_storage"] = self.strategy.storage.user
        token = self._pipeline_type.set("disconnect")
        try:
            return self.run_pipeline(pipeline, *args, **kwargs)
        finally:
            self._pipeline_type.reset(token)

    @property
    def pipeline_type(self) -> str:
        """Type of the currently executing pipeline, saved with its partials."""
        return self._pipeline_type.get()

    def run_pipeline(
        self, pipeline: list[str], pipeline_index: int = 0, *args, **kwargs
    ) -> dict[str, Any] | HttpResponseProtocol:
        """Merge step dictionaries into context and return it on completion.

        Falsy step results continue execution. Truthy non-dictionary results,
        such as HTTP responses, stop execution and are returned unchanged.
        """
        out = kwargs.copy()
        out.setdefault("strategy", self.strategy)
        out.setdefault("backend", out.pop(self.name, None) or self)
        out.pop("request", None)
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
        user: UserProtocol | None,
        uid: str,
        response: dict[str, Any],
        details: dict[str, Any],
        pipeline_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Return default extra data to store in extra_data field"""
        data: dict[str, Any] = {
            # store the last time authentication took place
            "auth_time": int(time.time())
        }
        extra_data_entries: (
            list[str] | list[str | tuple[str, str] | tuple[str, str, bool]]
        ) = []
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
                raise AuthConfigurationError(
                    self,
                    f"Invalid EXTRA_DATA item: {entry!r}",
                    code="invalid_setting",
                    parameter="EXTRA_DATA",
                    stage="pipeline",
                )
            value = response.get(name, details.get(name, details.get(alias)))
            if discard and not value:
                continue
            data[alias] = value
        return data

    def auth_allowed(self, response, details):
        """Return True if the user should be allowed to authenticate, by
        default check if email is whitelisted (if there's a whitelist)"""
        emails = [
            email.lower()
            for email in cast("list[str]", self.setting("WHITELISTED_EMAILS", []))
        ]
        domains = [
            domain.lower()
            for domain in cast("list[str]", self.setting("WHITELISTED_DOMAINS", []))
        ]
        email = details.get("email")
        allowed = True
        if email and (emails or domains):
            email = email.lower()
            parts = email.split("@", 1)
            if len(parts) != 2:
                allowed = False
            else:
                domain = parts[1]
                allowed = email in emails or domain in domains
        allow_groups = self.get_group_setting("ALLOW_GROUPS", response, [])
        if not isinstance(allow_groups, (list, tuple, set)) or any(
            not isinstance(group, str) or not group for group in allow_groups
        ):
            raise AuthConfigurationError(
                self, code="invalid_setting", parameter="ALLOW_GROUPS", stage="pipeline"
            )
        if allow_groups:
            # Backends override the default no-extraction implementation.
            # pylint: disable-next=assignment-from-none
            groups = self.get_user_groups(response)
            if groups is None:
                raise AuthConfigurationError(
                    self,
                    code="missing_setting",
                    parameter="group extraction",
                    stage="pipeline",
                )
            allowed = allowed and bool(set(groups).intersection(allow_groups))
        return allowed

    def get_user_groups(self, response) -> list[str] | None:
        """Return normalized external memberships, or None when disabled."""
        return None

    def get_group_setting(self, name: str, response, default=None):
        """Resolve group configuration for this provider (or a SAML IdP)."""
        return self.setting(name, default)

    def get_group_mappings(self):
        """Enumerate independently managed membership sources."""
        return [("", self.setting("GROUPS_MAP", {}))]

    def get_group_source(self, response) -> str:
        """Identify the provider's active membership source."""
        return ""

    def id_key(self) -> str:
        """Return the ID_KEY to use for this backend, checking settings first."""
        configured = self.setting("ID_KEY")
        id_key = configured or self.ID_KEY
        if (
            configured
            and id_key in self.MUTABLE_ID_KEYS
            and not self._mutable_id_key_warned
        ):
            self.log_warning(
                "configured ID_KEY %r is mutable and is unsafe as an account identifier",
                id_key,
            )
            self._mutable_id_key_warned = True
        return id_key

    def get_user_id_for_key(self, details, response, id_key: str):
        """Return a user identifier selected by an explicit response key."""
        return self.get_user_id_from_sources(details, response, id_key=id_key)

    def get_legacy_user_ids(self, details, response) -> list[str]:
        """Return current values of identifiers used by older releases."""
        if self.setting("ID_KEY"):
            return []
        identifiers = []
        for id_key in self.LEGACY_ID_KEYS:
            try:
                identifier = self.get_user_id_for_key(details, response, id_key)
            except AuthResponseError as error:
                if error.code != "missing_claim":
                    raise
                continue
            value = str(identifier)
            if value not in identifiers:
                identifiers.append(value)
        return identifiers

    def get_user_id(self, details, response):
        """Return a unique ID for the current user, by default from server
        response or details."""
        id_key = self.id_key()
        if self.REQUIRES_USER_ID or self.setting("ID_KEY"):
            return self.get_user_id_for_key(details, response, id_key)
        if details:
            user_id = details.get(id_key)
            if user_id:
                return user_id
        return response.get(id_key)

    def get_user_id_from_sources(
        self,
        *sources: Mapping[str, Any] | None,
        id_key: str | None = None,
    ):
        """Return the selected user ID from mappings or fail clearly.

        Sources are searched in order for the configured or explicitly passed
        ID key. Missing, ``None``, and empty-string values are rejected.
        """
        if id_key is None:
            id_key = self.id_key()
        for source in sources:
            if source is not None:
                user_id = source.get(id_key)
                if user_id is not None and user_id != "":
                    return user_id
        raise AuthResponseError(
            self, claim=id_key, code="missing_claim", stage="user_info"
        )

    def get_user_details(self, response) -> dict[str, Any]:
        """Return provider-supplied user details in a known internal structure.

        Leave name conversion to the social_names pipeline step.

        Omit unavailable names or return None for them. An empty string is a
        supplied value and can clear an existing user field. The social_names
        step can fill missing or blank fields when another name is available.

        The returned dictionary can contain:

        ``username``
            Username, if any.
        ``email``
            User email, if any.
        ``fullname``
            User full name, if any.
        ``first_name``
            User first name, if any.
        ``last_name``
            User last name, if any.
        """
        raise NotImplementedError("Implement in subclass")

    def get_refresh_token(self, extra_data: dict[str, Any]) -> str | None:
        """Select a stored renewal credential, or None when renewal is unavailable.

        Backends that exchange an access token should override this method.
        """
        token = extra_data.get("refresh_token")
        return token if isinstance(token, str) and token else None

    def get_refresh_token_kwargs(self, extra_data: dict[str, Any]) -> dict[str, Any]:
        """Return default refresh arguments from stored account credentials."""
        return {}

    def get_user_names(self, fullname="", first_name="", last_name=""):
        warnings.warn(
            "BaseAuth.get_user_names() is deprecated. Return provider-supplied "
            "names from get_user_details() and use the "
            "social_core.pipeline.social_auth.social_names pipeline step.",
            DeprecationWarning,
            stacklevel=2,
        )
        return normalize_user_names(fullname, first_name, last_name)

    def get_user(self, user_id):
        """
        Return user with given ID from the User model used by this backend.
        This is called by django.contrib.auth.middleware.
        """
        return self.strategy.get_user(user_id)

    def continue_pipeline(
        self, partial: PartialMixin
    ) -> UserProtocol | HttpResponseProtocol | None:
        """Continue previous halted pipeline"""
        with self._partial_pipeline_context(partial):
            return self.strategy.authenticate(
                self, *partial.args, pipeline_index=partial.next_step, **partial.kwargs
            )

    def continue_disconnect_pipeline(
        self, partial: PartialMixin
    ) -> dict[str, Any] | HttpResponseProtocol:
        """Continue a halted disconnect with its effective request data."""
        with self._partial_pipeline_context(partial, pipeline_type="disconnect"):
            return self.disconnect(
                *partial.args, pipeline_index=partial.next_step, **partial.kwargs
            )

    @contextmanager
    def _partial_pipeline_context(
        self, partial: PartialMixin, pipeline_type: str = "authentication"
    ) -> Generator[None, None, None]:
        if partial.pipeline_type != pipeline_type:
            raise AuthPolicyError(
                self, code="authentication_disallowed", stage="callback"
            )
        previous_data = self.data
        with self.strategy.pipeline_request_data(partial.request_data):
            self.data = self.strategy.request_data()
            try:
                yield
            finally:
                self.data = previous_data

    def validate_partial_pipeline(
        self, partial: PartialMixin, user: UserProtocol | None = None
    ) -> None:
        """Validate backend-specific requirements before resuming a pipeline."""
        if self.ASSOCIATION_ONLY:
            user = self.require_association_user(user, stage="callback")
            key = self.association_user_id_key(partial.pipeline_type)
            if partial.kwargs.get(key) != str(user.id):
                raise AuthSessionError(
                    self,
                    "Association user mismatch",
                    code="user_mismatch",
                    stage="callback",
                )

    def auth_extra_arguments(self) -> dict[str, str]:
        """Return extra arguments needed on auth process.

        Configured AUTH_EXTRA_ARGUMENTS are not overridden by request data by
        default. Set AUTH_EXTRA_ARGUMENTS_OVERRIDE_ALLOWLIST to an iterable of
        configured extra-argument keys that may be replaced by matching request
        data values.
        """
        extra_arguments = self.setting("AUTH_EXTRA_ARGUMENTS", {}).copy()
        override_allowlist = (
            self.setting("AUTH_EXTRA_ARGUMENTS_OVERRIDE_ALLOWLIST", ()) or ()
        )
        if isinstance(override_allowlist, str):
            override_allowlist = (override_allowlist,)

        extra_arguments.update(
            (key, self.data[key])
            for key in override_allowlist
            if key in extra_arguments and key in self.data
        )
        return extra_arguments

    def uses_redirect(self) -> bool:
        """Return True if this provider uses redirect url method,
        otherwise return false."""
        return True

    def request(  # noqa: PLR0913
        self,
        url: str,
        *,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | None = None,
        json: dict | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
        timeout: float | None = None,
        stage: ErrorStage = "user_info",
    ) -> Response:
        headers = {} if headers is None else dict(headers)
        proxies = self.setting("PROXIES")
        verify = self.setting("VERIFY_SSL", True)

        if timeout is None:
            timeout = (
                self.setting("REQUESTS_TIMEOUT")
                or self.setting("URLOPEN_TIMEOUT")
                or 5.0
            )

        if self.SEND_USER_AGENT and "User-Agent" not in headers:
            headers["User-Agent"] = self.setting("USER_AGENT") or user_agent()

        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                data=data,
                json=json,
                auth=auth,
                params=params,
                timeout=timeout,
                proxies=proxies,
                verify=verify,
            )
        except requests.exceptions.SSLError as error:
            raise AuthProviderError(self, code="tls_error", stage=stage) from error
        except requests.Timeout as error:
            raise AuthProviderError(self, code="timeout", stage=stage) from error
        except (
            requests.exceptions.InvalidURL,
            requests.exceptions.InvalidSchema,
            requests.exceptions.MissingSchema,
        ) as error:
            raise AuthConfigurationError(
                self, code="invalid_setting", parameter="url", stage=stage
            ) from error
        except requests.ConnectionError as error:
            raise AuthProviderError(
                self, code="connection_failed", stage=stage
            ) from error
        except requests.HTTPError as error:
            raise http_error(self, error, stage=stage) from error
        except requests.RequestException as error:
            raise AuthProviderError(self, stage=stage) from error
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            raise http_error(self, error, stage=stage) from error
        return response

    def get_json(  # noqa: PLR0913, PLR0917
        self,
        url: str,
        method: Literal["GET", "POST", "DELETE"] = "GET",
        headers: Mapping[str, str | bytes] | None = None,
        data: dict | None = None,
        json: dict | None = None,
        auth: tuple[str, str] | AuthBase | None = None,
        params: dict | None = None,
        timeout: float | None = None,
        stage: ErrorStage = "user_info",
    ) -> dict[Any, Any]:
        response = self.request(
            url,
            method=method,
            headers=headers,
            data=data,
            json=json,
            auth=auth,
            params=params,
            timeout=timeout,
            stage=stage,
        )
        try:
            return response.json()
        except ValueError as error:
            raise AuthResponseError(
                self, code="malformed_response", stage=stage
            ) from error

    def get_querystring(self, url, *args, **kwargs) -> dict[str, str]:
        return parse_qs(self.request(url, *args, **kwargs).text)

    def get_key_and_secret(self) -> tuple[str, str]:
        """Return tuple with Consumer Key and Consumer Secret for current
        service provider. Must return (key, secret), order *must* be respected.
        """
        return cast("str", self.setting("KEY")), cast("str", self.setting("SECRET"))

    def get_key_and_secret_basic_auth(self) -> bytes:
        """Generate HTTP Basic Authentication header value from KEY and SECRET.

        Returns:
            Basic authentication value in the format b"Basic <base64-encoded-credentials>"
        """
        key, secret = self.get_key_and_secret()
        credentials = f"{key}:{secret}".encode()
        encoded = base64.b64encode(credentials)
        return b"Basic " + encoded
