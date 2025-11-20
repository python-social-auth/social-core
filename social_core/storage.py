"""Models mixins for Social Auth"""

from __future__ import annotations

import base64
import re
import uuid
from abc import abstractmethod
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Protocol

from openid.association import Association as OpenIdAssociation

from .exceptions import InvalidExpiryValue, MissingBackend

if TYPE_CHECKING:
    from collections.abc import Callable

    from social_core.backends.base import BaseAuth
    from social_core.strategy import BaseStrategy

NO_ASCII_REGEX = re.compile(r"[^\x00-\x7F]+")
NO_SPECIAL_REGEX = re.compile(r"[^\w.@+_-]+", re.UNICODE)


class UserProtocol(Protocol):
    id: int
    username: str
    is_active: bool | Callable[[], bool]
    is_authenticated: bool | Callable[[], bool]

    # Set in BaseAuth.pipeline
    # social_user: UserMixin
    # is_new: bool


class UserMixin:
    # Consider tokens that expire in 5 seconds as already expired
    ACCESS_TOKEN_EXPIRED_THRESHOLD = 5

    provider = ""
    uid: str
    user: UserProtocol
    extra_data: dict[str, Any]

    @abstractmethod
    def save(self): ...

    def get_backend(self, strategy: BaseStrategy) -> type[BaseAuth]:
        return strategy.get_backend_class(self.provider)

    def get_backend_instance(self, strategy: BaseStrategy) -> BaseAuth | None:
        try:
            return strategy.get_backend(self.provider)
        except MissingBackend:
            return None

    @property
    def access_token(self) -> str | None:
        """Return access_token stored in extra_data or None"""
        return self.extra_data.get("access_token")

    def refresh_token(self, strategy: BaseStrategy, *args, **kwargs) -> None:
        token = self.extra_data.get("refresh_token") or self.extra_data.get(
            "access_token"
        )
        backend = self.get_backend_instance(strategy)
        if token and backend and hasattr(backend, "refresh_token"):
            response = backend.refresh_token(token, *args, **kwargs)  # type: ignore[attr-defined]
            extra_data = backend.extra_data(
                self.user, self.uid, response, self.extra_data or {}, {}
            )
            if self.set_extra_data(extra_data):
                self.save()

    def _compute_expiration_from_timestamp(
        self, value: int | str, field_name: str = "expires"
    ) -> timedelta:
        """Compute expiration timedelta from an absolute timestamp."""
        try:
            timestamp = int(value)
        except (ValueError, TypeError) as e:
            raise InvalidExpiryValue(field_name, value) from e

        try:
            now = datetime.now(timezone.utc)
            expiry_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return expiry_time - now
        except (OSError, ValueError) as e:
            raise InvalidExpiryValue(field_name, value) from e

    def _compute_expiration_from_relative(
        self, value: int | str, field_name: str = "expires"
    ) -> timedelta:
        """Compute expiration timedelta from relative seconds."""
        try:
            seconds = int(value)
        except (ValueError, TypeError) as e:
            raise InvalidExpiryValue(field_name, value) from e

        auth_time = self.extra_data.get("auth_time")
        if auth_time:
            try:
                auth_timestamp = int(auth_time)
            except (ValueError, TypeError):
                # Invalid auth_time value, fall back to treating as seconds from now
                pass
            else:
                try:
                    now = datetime.now(timezone.utc)
                    reference = datetime.fromtimestamp(auth_timestamp, tz=timezone.utc)
                    return (reference + timedelta(seconds=seconds)) - now
                except (OSError, ValueError):
                    # auth_time timestamp out of range, fall back to treating as seconds from now
                    pass
        # If no auth_time or invalid auth_time, treat as seconds from now
        return timedelta(seconds=seconds)

    def expiration_timedelta(self) -> timedelta | None:
        """Return provider session live seconds.

        Returns a timedelta ready to use with session.set_expiry().
        If provider returns a timestamp instead of session seconds to live, the
        timedelta is inferred from current time (using UTC timezone).

        Handles three types of expiration data:
        - expires_on: Always treated as absolute timestamp
        - expires_in: Always treated as relative seconds from auth_time
        - expires: Uses heuristic (>63072000 = 2 years) to distinguish timestamp vs relative
        """
        if not self.extra_data:
            return None

        # Check for expires_on (absolute timestamp)
        expires_on = self.extra_data.get("expires_on")
        if expires_on is not None:
            return self._compute_expiration_from_timestamp(expires_on, "expires_on")

        # Check for expires_in (relative seconds from auth_time)
        expires_in = self.extra_data.get("expires_in")
        if expires_in is not None:
            return self._compute_expiration_from_relative(expires_in, "expires_in")

        # Check for expires (use heuristic to determine type)
        return self._handle_expires_field()

    def _handle_expires_field(self) -> timedelta | None:
        """Handle the generic expires field using heuristic."""
        expires = self.extra_data.get("expires")
        if expires is None:
            return None

        try:
            expires_int = int(expires)
        except (ValueError, TypeError) as e:
            raise InvalidExpiryValue("expires", expires) from e

        # Use 2 years (63072000 seconds) as threshold to distinguish
        # absolute timestamps from relative seconds
        # Most tokens expire in hours/days/months, timestamps are much larger
        TIMESTAMP_THRESHOLD = 63072000

        if expires_int > TIMESTAMP_THRESHOLD:
            # Likely an absolute timestamp, try treating as expires_on
            return self._compute_expiration_from_timestamp(expires_int, "expires")

        # Treat as relative seconds (like expires_in)
        return self._compute_expiration_from_relative(expires_int, "expires")

    def expiration_datetime(self):
        # backward compatible alias
        return self.expiration_timedelta()

    def access_token_expired(self):
        """Return true / false if access token is already expired"""
        expiration = self.expiration_timedelta()
        return (
            expiration
            and expiration.total_seconds() <= self.ACCESS_TOKEN_EXPIRED_THRESHOLD
        )

    def get_access_token(self, strategy: BaseStrategy) -> str | None:
        """Returns a valid access token."""
        if self.access_token_expired():
            self.refresh_token(strategy)
        return self.access_token

    def set_extra_data(self, extra_data: dict[str, Any] | None = None) -> bool:
        if extra_data and self.extra_data != extra_data:
            if self.extra_data and not isinstance(self.extra_data, str):
                self.extra_data.update(extra_data)
            else:
                self.extra_data = extra_data
            return True
        return False

    @classmethod
    def clean_username(cls, value: str) -> str:
        """Clean username removing any unsupported character"""
        value = NO_ASCII_REGEX.sub("", value)
        return NO_SPECIAL_REGEX.sub("", value)

    @classmethod
    def changed(cls, user: UserProtocol) -> None:
        """The given user instance is ready to be saved"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_username(cls, user: UserProtocol) -> str:
        """Return the username for given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def user_model(cls) -> type[UserProtocol]:
        """Return the user model"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def username_max_length(cls) -> int:
        """Return the max length for username"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def allowed_to_disconnect(
        cls, user: UserProtocol, backend_name: str, association_id=None
    ) -> bool:
        """Return if it's safe to disconnect the social account for the
        given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def disconnect(cls, entry):
        """Disconnect the social account for the given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def user_exists(cls, *args, **kwargs) -> bool:
        """
        Return True/False if a User instance exists with the given arguments.
        Arguments are directly passed to filter() manager method.
        """
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def create_user(cls, *args, **kwargs):
        """Create a user instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_user(cls, pk):
        """Return user instance for given id"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_users_by_email(cls, email: str):
        """Return users instances for given email address"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_social_auth(cls, provider: str, uid: int):
        """Return UserSocialAuth for given provider and uid"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get_social_auth_for_user(
        cls,
        user: UserProtocol,
        provider: str | None = None,
        id: int | None = None,  # noqa: A002
    ):
        """Return all the UserSocialAuth instances for given user"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def create_social_auth(cls, user: UserProtocol, uid: int, provider: str):
        """Create a UserSocialAuth instance for given user"""
        raise NotImplementedError("Implement in subclass")


class NonceMixin:
    """One use numbers"""

    server_url = ""
    timestamp = 0
    salt = ""

    @classmethod
    def use(cls, server_url, timestamp, salt):
        """Create a Nonce instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get(cls, server_url, salt):
        """Retrieve a Nonce instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def delete(cls, nonce):
        """Delete a Nonce instance"""
        raise NotImplementedError("Implement in subclass")


class AssociationMixin:
    """OpenId account association"""

    server_url = ""
    handle = ""
    secret = ""
    issued = 0
    lifetime = 0
    assoc_type = ""

    @classmethod
    def oids(cls, server_url, handle=None):
        kwargs = {"server_url": server_url}
        if handle is not None:
            kwargs["handle"] = handle
        return sorted(
            ((assoc.id, cls.openid_association(assoc)) for assoc in cls.get(**kwargs)),
            key=lambda x: x[1].issued,
            reverse=True,
        )

    @classmethod
    def openid_association(cls, assoc):
        secret = assoc.secret
        if not isinstance(secret, bytes):
            secret = secret.encode()
        return OpenIdAssociation(
            assoc.handle,
            base64.decodebytes(secret),
            assoc.issued,
            assoc.lifetime,
            assoc.assoc_type,
        )

    @classmethod
    def store(cls, server_url, association):
        """Create an Association instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def get(cls, server_url: str | None = None, handle: str | None = None):
        """Get an Association instance"""
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def remove(cls, ids_to_delete):
        """Remove an Association instance"""
        raise NotImplementedError("Implement in subclass")


class CodeMixin:
    email = ""
    code = ""
    verified = False

    @abstractmethod
    def save(self): ...

    def verify(self) -> None:
        self.verified = True
        self.save()

    @classmethod
    def generate_code(cls):
        return uuid.uuid4().hex

    @classmethod
    def make_code(cls, email: str) -> CodeMixin:
        code = cls()
        code.email = email
        code.code = cls.generate_code()
        code.verified = False
        code.save()
        return code

    @classmethod
    def get_code(cls, code):
        raise NotImplementedError("Implement in subclass")


class PartialMixin:
    token = ""
    data: dict[str, Any] = {}
    next_step: int
    backend = ""

    @property
    def args(self):
        return self.data.get("args", [])

    @args.setter
    def args(self, value) -> None:
        self.data["args"] = value

    @abstractmethod
    def save(self): ...

    @property
    def kwargs(self):
        return self.data.get("kwargs", {})

    @kwargs.setter
    def kwargs(self, value) -> None:
        self.data["kwargs"] = value

    def extend_kwargs(self, values) -> None:
        self.data["kwargs"].update(values)

    @classmethod
    def generate_token(cls) -> str:
        return uuid.uuid4().hex

    @classmethod
    def load(cls, token: str) -> PartialMixin | None:
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def destroy(cls, token: str):
        raise NotImplementedError("Implement in subclass")

    @classmethod
    def prepare(
        cls, backend: str, next_step: int, data: dict[str, Any]
    ) -> PartialMixin:
        partial = cls()
        partial.backend = backend
        partial.next_step = next_step
        partial.data = data
        partial.token = cls.generate_token()
        return partial

    @classmethod
    def store(cls, partial: PartialMixin) -> PartialMixin:
        partial.save()
        return partial


class BaseStorage:
    user = UserMixin
    nonce = NonceMixin
    association = AssociationMixin
    code = CodeMixin
    partial = PartialMixin

    @classmethod
    def is_integrity_error(cls, exception) -> bool:
        """Check if given exception flags an integrity error in the DB"""
        raise NotImplementedError("Implement in subclass")
