"""Authentication failures with stable, framework-independent recovery metadata."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import Mapping

    from social_core.backends.base import BaseAuth

ErrorSource = Literal[
    "configuration",
    "request",
    "session",
    "provider_response",
    "local_policy",
    "storage",
    "unknown",
]
ErrorStage = Literal[
    "begin",
    "callback",
    "token_exchange",
    "token_validation",
    "user_info",
    "pipeline",
    "refresh",
    "disconnect",
    "unknown",
]
RecoveryAction = Literal[
    "none",
    "correct_input",
    "restart_login",
    "reauthenticate",
    "retry_later",
    "check_provider_profile",
    "use_existing_account",
    "contact_administrator",
]

# Safe defaults only: provider descriptions and identifiers belong in detail/context.
REASONS: dict[str, tuple[str, ErrorSource, RecoveryAction]] = {
    "missing_setting": (
        "Authentication configuration is incomplete.",
        "configuration",
        "contact_administrator",
    ),
    "invalid_setting": (
        "Authentication configuration is invalid.",
        "configuration",
        "contact_administrator",
    ),
    "unsupported_feature": (
        "The authentication integration does not support this feature.",
        "configuration",
        "contact_administrator",
    ),
    "backend_missing": (
        "The authentication backend is unavailable.",
        "configuration",
        "contact_administrator",
    ),
    "missing_parameter": (
        "A required authentication parameter is missing.",
        "request",
        "correct_input",
    ),
    "invalid_parameter": (
        "An authentication parameter is invalid.",
        "request",
        "correct_input",
    ),
    "session_context_missing": (
        "The authentication session is unavailable. Please restart login.",
        "session",
        "restart_login",
    ),
    "state_mismatch": (
        "The authentication response does not match the session.",
        "session",
        "restart_login",
    ),
    "user_mismatch": (
        "The authentication session belongs to a different user.",
        "session",
        "restart_login",
    ),
    "malformed_response": (
        "The authentication provider returned an invalid response.",
        "provider_response",
        "contact_administrator",
    ),
    "missing_claim": (
        "The authentication response is missing a required field.",
        "provider_response",
        "contact_administrator",
    ),
    "invalid_claim": (
        "An authentication response field could not be verified.",
        "provider_response",
        "contact_administrator",
    ),
    "invalid_signature": (
        "The authentication response signature could not be verified.",
        "provider_response",
        "contact_administrator",
    ),
    "nonce_mismatch": (
        "The authentication response could not be matched to the request.",
        "provider_response",
        "restart_login",
    ),
    "response_expired": (
        "The authentication response has expired.",
        "provider_response",
        "restart_login",
    ),
    "response_not_yet_valid": (
        "The authentication response is not yet valid.",
        "provider_response",
        "contact_administrator",
    ),
    "invalid_expiry": (
        "Stored authentication expiry data is invalid.",
        "storage",
        "contact_administrator",
    ),
    "profile_email_missing": (
        "The provider did not supply an email address.",
        "provider_response",
        "check_provider_profile",
    ),
    "authorization_code_rejected": (
        "The authorization code was rejected. Please restart login.",
        "provider_response",
        "restart_login",
    ),
    "credential_rejected": (
        "The authentication credentials were rejected.",
        "provider_response",
        "reauthenticate",
    ),
    "token_revoked": (
        "The authentication token has been revoked.",
        "provider_response",
        "reauthenticate",
    ),
    "reauthentication_required": (
        "Please authenticate with the provider again.",
        "storage",
        "reauthenticate",
    ),
    "email_verification_rejected": (
        "The email confirmation could not be verified.",
        "request",
        "restart_login",
    ),
    "authentication_disallowed": (
        "Authentication is not allowed by the application policy.",
        "local_policy",
        "contact_administrator",
    ),
    "membership_required": (
        "The account does not have the required membership.",
        "local_policy",
        "contact_administrator",
    ),
    "disconnect_disallowed": (
        "This account cannot be disconnected without another authentication method.",
        "local_policy",
        "none",
    ),
    "identity_in_use": (
        "This identity is already associated with another account.",
        "storage",
        "use_existing_account",
    ),
    "email_in_use": (
        "This email address is already in use.",
        "storage",
        "use_existing_account",
    ),
    "username_in_use": (
        "This username is already in use.",
        "storage",
        "use_existing_account",
    ),
    "identifier_migration_conflict": (
        "The stored authentication identity could not be migrated safely.",
        "storage",
        "contact_administrator",
    ),
    "connection_failed": (
        "The authentication provider could not be reached.",
        "provider_response",
        "retry_later",
    ),
    "timeout": (
        "The authentication provider did not respond in time.",
        "provider_response",
        "retry_later",
    ),
    "tls_error": (
        "A secure connection to the authentication provider could not be established.",
        "provider_response",
        "contact_administrator",
    ),
    "rate_limited": (
        "The authentication provider is temporarily limiting requests.",
        "provider_response",
        "retry_later",
    ),
    "unavailable": (
        "The authentication provider is temporarily unavailable.",
        "provider_response",
        "retry_later",
    ),
    "http_error": (
        "The authentication provider rejected the request.",
        "provider_response",
        "contact_administrator",
    ),
    "authorization_declined": (
        "Authentication process canceled",
        "provider_response",
        "none",
    ),
    "unknown_error": (
        "Authentication could not be completed.",
        "unknown",
        "contact_administrator",
    ),
}


class SocialAuthBaseException(ValueError):
    """Broad catch boundary for social-auth failures, including configuration."""

    default_code = "unknown_error"

    def __init__(  # noqa: PLR0913
        self,
        backend: BaseAuth | None = None,
        *details: object,
        code: str | None = None,
        source: ErrorSource | None = None,
        stage: ErrorStage = "unknown",
        recovery: RecoveryAction | None = None,
        parameter: str | None = None,
        claim: str | None = None,
        provider_code: str | int | None = None,
        status_code: int | None = None,
        retry_after: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        self.backend = backend
        self.code = code or self.default_code
        message, default_source, default_recovery = REASONS.get(
            self.code, REASONS[self.default_code]
        )
        self.source: ErrorSource = source or default_source
        self.stage: ErrorStage = stage
        self.recovery = recovery or default_recovery
        self.parameter = parameter
        self.claim = claim
        self.provider_code = provider_code
        self.status_code = status_code
        self.retry_after = retry_after
        self.detail = " ".join(str(detail) for detail in details)
        self.context = dict(context or {})
        super().__init__(message)

    def public_metadata(self) -> dict[str, str]:
        """Return non-identifying fields for client transports."""
        return {
            "error_code": self.code,
            "error_source": self.source,
            "error_stage": self.stage,
            "error_recovery": self.recovery,
        }


class AuthConfigurationError(SocialAuthBaseException):
    """The integration needs configuration or implementation changes."""

    default_code = "invalid_setting"


class AuthException(SocialAuthBaseException):
    """Broad catch boundary for authentication-flow failures."""


class AuthInputError(AuthException):
    """The application or browser supplied missing or invalid input."""

    default_code = "invalid_parameter"


class AuthSessionError(AuthException):
    """Authentication cannot be bound to its initiating session or user."""

    default_code = "session_context_missing"


class AuthResponseError(AuthException):
    """A provider response cannot be parsed or validated."""

    default_code = "malformed_response"


class AuthCredentialError(AuthException):
    """Credentials were rejected or another provider login is required."""

    default_code = "credential_rejected"


class AuthPolicyError(AuthException):
    """A local authentication or disconnect policy rejected the operation."""

    default_code = "authentication_disallowed"


class AuthAssociationError(AuthException):
    """A local account or stored authentication identity conflicts."""

    default_code = "identity_in_use"


class AuthProviderError(AuthException):
    """A provider request failed at the transport or HTTP boundary."""

    default_code = "http_error"


class AuthCanceled(AuthException):
    """Authorization was explicitly declined or canceled."""

    default_code = "authorization_declined"


class AuthUnknownError(AuthException):
    """The authentication failure has no known structured classification."""
