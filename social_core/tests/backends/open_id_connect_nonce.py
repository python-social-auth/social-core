"""Nonce lifecycle assertions shared by the generic OIDC tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from unittest.mock import patch

from social_core.exceptions import AuthConfigurationError, AuthResponseError
from social_core.tests.exception_helpers import assert_auth_error
from social_core.tests.models import TestAssociation

if TYPE_CHECKING:
    from contextlib import AbstractContextManager
    from unittest.case import _AssertRaisesContext

    from social_core.backends.open_id_connect import OpenIdConnectAuth
    from social_core.tests.strategy import TestStrategy


class OpenIdConnectNonceAssertionsCapable(Protocol):
    backend: OpenIdConnectAuth
    strategy: TestStrategy

    def do_login(self): ...

    def pre_complete_callback(self, start_url) -> None: ...

    def test_invalid_signature(self) -> None: ...

    def subTest(self, **params) -> AbstractContextManager: ...

    def assertEqual(self, first, second) -> None: ...

    def assertFalse(self, expr) -> None: ...

    def assertGreater(self, first, second) -> None: ...

    def assertIs(self, first, second) -> None: ...

    def assertIsNone(self, obj) -> None: ...

    def assertRaises(
        self, expected_exception: type[AuthConfigurationError]
    ) -> _AssertRaisesContext[AuthConfigurationError]: ...


class OpenIdConnectNonceAssertionsMixin:
    def test_everything_works(self: OpenIdConnectNonceAssertionsCapable) -> None:
        self.do_login()
        self.assertFalse(TestAssociation.cache)

    def test_nonce_lifetime(self: OpenIdConnectNonceAssertionsCapable) -> None:
        for configured_lifetime in (None, 60):
            with self.subTest(lifetime=configured_lifetime):
                if configured_lifetime is not None:
                    self.strategy.set_settings(
                        {"SOCIAL_AUTH_OIDC_NONCE_LIFETIME": configured_lifetime}
                    )
                lifetime = configured_lifetime or 1800
                with patch(
                    "social_core.backends.open_id_connect.time.time", return_value=1000
                ):
                    nonce = self.backend.get_and_store_nonce(
                        self.backend.authorization_url(), "state"
                    )
                association = TestAssociation.get(handle=nonce)[0]
                self.assertEqual(association.issued, 1000)
                self.assertEqual(association.lifetime, lifetime)
                self.assertEqual(association.assoc_type, "state")
                with patch(
                    "social_core.storage.time.time", return_value=1000 + lifetime - 1
                ):
                    self.assertIs(self.backend.get_nonce(nonce), association)
                with patch(
                    "social_core.storage.time.time", return_value=1000 + lifetime
                ):
                    self.assertIsNone(self.backend.get_nonce(nonce))
                self.assertFalse(TestAssociation.get(handle=nonce))

    def test_invalid_nonce_lifetime(self: OpenIdConnectNonceAssertionsCapable) -> None:
        for lifetime in (0, -1, True, False, "1800", 1.5, None):
            with self.subTest(lifetime=lifetime):
                self.strategy.set_settings(
                    {"SOCIAL_AUTH_OIDC_NONCE_LIFETIME": lifetime}
                )
                with self.assertRaises(AuthConfigurationError) as caught:
                    self.backend.auth_url()
                self.assertEqual(caught.exception.code, "invalid_setting")
                self.assertEqual(caught.exception.stage, "begin")
                self.assertEqual(caught.exception.parameter, "NONCE_LIFETIME")
                self.assertFalse(TestAssociation.cache)

    def test_expired_nonce_rejects_login(
        self: OpenIdConnectNonceAssertionsCapable,
    ) -> None:
        def expire_nonce(start_url):
            for association in TestAssociation.cache.values():
                association.issued -= association.lifetime
            pre_complete_callback(start_url)

        pre_complete_callback = self.pre_complete_callback
        with (
            patch.object(self, "pre_complete_callback", side_effect=expire_nonce),
            assert_auth_error(self, AuthResponseError, "nonce_mismatch"),
        ):
            self.do_login()
        self.assertFalse(TestAssociation.cache)

    def test_nonce_cannot_be_reused(self: OpenIdConnectNonceAssertionsCapable) -> None:
        self.do_login()
        with assert_auth_error(self, AuthResponseError, "nonce_mismatch"):
            self.backend.validate_claims(self.backend.id_token)

    def test_abandoned_and_failed_login_nonces_have_lifetimes(
        self: OpenIdConnectNonceAssertionsCapable,
    ) -> None:
        self.backend.auth_url()
        self.backend.auth_url()
        self.test_invalid_signature()
        self.assertEqual(len(TestAssociation.cache), 3)
        for association in TestAssociation.cache.values():
            self.assertGreater(association.issued, 0)
            self.assertEqual(association.lifetime, 1800)
