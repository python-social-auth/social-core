from __future__ import annotations

from hashlib import sha256
from typing import TYPE_CHECKING, TypeVar, cast

from social_core.exceptions import AuthConfigurationError, AuthCredentialError
from social_core.utils import constant_time_compare

from .partial import partial_step

if TYPE_CHECKING:
    from social_core.backends.base import BaseAuth

ResponseT = TypeVar("ResponseT")
_CODE_HASH_KEY = "email_validation_code_hash"


@partial_step(save_to_session=True, allow_external_resume=True)
def mail_validation(
    backend: BaseAuth[ResponseT], details, is_new=False, *args, **kwargs
) -> ResponseT | None:
    requires_validation = backend.REQUIRES_EMAIL_VALIDATION or backend.setting(
        "FORCE_EMAIL_VALIDATION", False
    )
    send_validation = details.get("email") and (
        is_new or backend.setting("PASSWORDLESS", False)
    )
    if requires_validation and send_validation:
        # External partial resumes may replay the original validation-link data
        # after a local confirmation request.
        data = backend.strategy.request_data()
        if "verification_code" in data:
            backend.strategy.session_pop("email_validation_address")
            # A code is honoured only while the partial it was mailed for is
            # resumed, which is when the session ownership and external resume
            # confirmation checks have run. A request that starts a new
            # pipeline must not consume it.
            submitted = data["verification_code"]
            saved_hash = kwargs.get(_CODE_HASH_KEY)
            if not (
                backend.strategy.is_partial_pipeline_resume()
                and isinstance(submitted, str)
                and isinstance(saved_hash, str)
                and constant_time_compare(
                    sha256(submitted.encode()).hexdigest(), saved_hash
                )
                and backend.strategy.validate_email(details["email"], submitted)
            ):
                raise AuthCredentialError(
                    backend, code="email_verification_rejected", stage="pipeline"
                )
            return None
        current_partial = kwargs["current_partial"]
        issued = backend.strategy.send_email_validation(
            backend, details["email"], current_partial.token
        )
        code = getattr(issued, "code", None)
        if not isinstance(code, str) or not code:
            raise AuthConfigurationError(
                backend,
                code="invalid_setting",
                stage="pipeline",
                parameter="EMAIL_VALIDATION_FUNCTION",
            )
        current_partial.kwargs[_CODE_HASH_KEY] = sha256(code.encode()).hexdigest()
        backend.strategy.session_set("email_validation_address", details["email"])
        return backend.strategy.redirect(
            cast("str", backend.strategy.setting("EMAIL_VALIDATION_URL"))
        )
    return None
