from __future__ import annotations

import unittest
from unittest.mock import Mock

from social_core import exceptions
from social_core.backends.base import BaseAuth
from social_core.exceptions import (
    AuthAssociationError,
    AuthCanceled,
    AuthConfigurationError,
    AuthCredentialError,
    AuthException,
    AuthInputError,
    AuthPolicyError,
    AuthProviderError,
    AuthResponseError,
    AuthSessionError,
    AuthUnknownError,
    SocialAuthBaseException,
)


class ExceptionContractTest(unittest.TestCase):
    def test_broad_catch_boundaries(self):
        for family in (
            AuthAssociationError,
            AuthCanceled,
            AuthCredentialError,
            AuthInputError,
            AuthPolicyError,
            AuthProviderError,
            AuthResponseError,
            AuthSessionError,
            AuthUnknownError,
        ):
            with self.subTest(family=family):
                error = family(None)
                self.assertIsInstance(error, AuthException)
                self.assertIsInstance(error, SocialAuthBaseException)
                self.assertIsInstance(error, ValueError)
        self.assertIsInstance(AuthConfigurationError(), SocialAuthBaseException)
        self.assertNotIsInstance(AuthConfigurationError(), AuthException)

    def test_diagnostics_are_not_public(self):
        backend = Mock(spec=BaseAuth)
        error = AuthResponseError(
            backend,
            "token=secret email=private@example.com",
            code="response_expired",
            claim="exp",
            stage="token_validation",
            context={"user_id": 42},
        )
        self.assertEqual(str(error), "The authentication response has expired.")
        self.assertEqual(error.args, (str(error),))
        self.assertIn("token=secret", error.detail)
        self.assertEqual(error.context, {"user_id": 42})
        self.assertIs(error.backend, backend)
        self.assertEqual(error.claim, "exp")
        self.assertEqual(
            error.public_metadata(),
            {
                "error_code": "response_expired",
                "error_source": "provider_response",
                "error_stage": "token_validation",
                "error_recovery": "restart_login",
            },
        )

    def test_message_is_not_a_classification(self):
        error = AuthUnknownError(None, "access_denied Signature has expired")
        self.assertEqual(error.code, "unknown_error")
        self.assertEqual(error.recovery, "contact_administrator")

    def test_application_codes_have_explicit_metadata(self):
        error = AuthPolicyError(
            code="app.registration_closed",
            source="local_policy",
            recovery="none",
            stage="pipeline",
        )
        self.assertEqual(error.code, "app.registration_closed")
        self.assertEqual(error.recovery, "none")
        self.assertEqual(str(error), str(AuthPolicyError()))

    def test_removed_names_are_not_aliases(self):
        for name in (
            "AuthFailed",
            "AuthTokenError",
            "AuthMissingParameter",
            "AuthForbidden",
            "AuthStateMissing",
            "AuthStateForbidden",
            "AuthAlreadyAssociated",
            "InvalidEmail",
            "MissingBackend",
            "AuthReauthenticationRequired",
            "InvalidExpiryValue",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(exceptions, name))
