"""Discovery and signing-key caches isolate backend configurations by URL."""

import json
import unittest
from unittest.mock import Mock, patch

from social_core.backends.okta import OktaOAuth2
from social_core.backends.okta_openidconnect import OktaOpenIdConnect
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy


def configured_strategy(url: str, client: str = "client") -> TestStrategy:
    strategy = TestStrategy(TestStorage)
    strategy.set_settings(
        {
            "SOCIAL_AUTH_OIDC_ENDPOINT": url,
            "SOCIAL_AUTH_API_URL": url,
            "SOCIAL_AUTH_KEY": client,
            "SOCIAL_AUTH_JWKS_URI": f"{url}/keys",
        }
    )
    return strategy


class OIDCUrlCacheTest(unittest.TestCase):
    def test_discovery_isolated_by_url_and_shared_for_matching_configuration(
        self,
    ) -> None:
        for backend_class in (OpenIdConnectAuth, OktaOAuth2, OktaOpenIdConnect):
            with self.subTest(backend=backend_class.name):
                first = backend_class(configured_strategy("https://cache-one.example"))
                second = backend_class(configured_strategy("https://cache-two.example"))
                matching = backend_class(
                    configured_strategy("https://cache-one.example")
                )
                first.get_openid_configuration.invalidate()
                self.addCleanup(first.get_openid_configuration.invalidate)
                one = {"issuer": "one"}
                two = {"issuer": "two"}
                with (
                    patch.object(first, "get_json", return_value=one) as first_fetch,
                    patch.object(second, "get_json", return_value=two) as second_fetch,
                    patch.object(matching, "get_json") as matching_fetch,
                ):
                    self.assertIs(first.oidc_config(), one)
                    self.assertIs(second.oidc_config(), two)
                    self.assertIs(matching.oidc_config(), one)
                    matching_fetch.assert_not_called()
                    first_fetch.assert_called_once_with(
                        first.oidc_config_url(), stage="begin"
                    )
                    second_fetch.assert_called_once_with(
                        second.oidc_config_url(), stage="begin"
                    )

                    first.get_openid_configuration.invalidate(
                        first, first.oidc_config_url()
                    )
                    self.assertIs(first.oidc_config(), one)
                    self.assertIs(second.oidc_config(), two)
                    self.assertEqual(first_fetch.call_count, 2)
                    self.assertEqual(second_fetch.call_count, 1)

    def test_okta_discovery_isolated_by_client_key(self) -> None:
        for backend_class in (OktaOAuth2, OktaOpenIdConnect):
            with self.subTest(backend=backend_class.name):
                first = backend_class(
                    configured_strategy("https://cache-client.example/oauth2", "one")
                )
                second = backend_class(
                    configured_strategy("https://cache-client.example/oauth2", "two")
                )
                first.get_openid_configuration.invalidate()
                self.addCleanup(first.get_openid_configuration.invalidate)
                one = {"issuer": "one"}
                two = {"issuer": "two"}
                with (
                    patch.object(first, "get_json", return_value=one) as first_fetch,
                    patch.object(second, "get_json", return_value=two) as second_fetch,
                ):
                    self.assertIs(first.oidc_config(), one)
                    self.assertIs(second.oidc_config(), two)
                    self.assertIs(first.oidc_config(), one)
                    first_fetch.assert_called_once_with(
                        first.oidc_config_url(), stage="begin"
                    )
                    second_fetch.assert_called_once_with(
                        second.oidc_config_url(), stage="begin"
                    )
                    self.assertNotEqual(
                        first.oidc_config_url(), second.oidc_config_url()
                    )

    def test_signing_keys_isolated_by_url_and_shared_for_matching_configuration(
        self,
    ) -> None:
        for backend_class in (OpenIdConnectAuth, OktaOpenIdConnect):
            with self.subTest(backend=backend_class.name):
                first = backend_class(configured_strategy("https://cache-one.example"))
                second = backend_class(configured_strategy("https://cache-two.example"))
                matching = backend_class(
                    configured_strategy("https://cache-one.example")
                )
                first.get_jwks_keys_for_uri.invalidate()
                self.addCleanup(first.get_jwks_keys_for_uri.invalidate)
                with (
                    patch.object(
                        first,
                        "request",
                        return_value=Mock(text=json.dumps({"keys": [{"kid": "one"}]})),
                    ) as first_fetch,
                    patch.object(
                        second,
                        "request",
                        return_value=Mock(text=json.dumps({"keys": [{"kid": "two"}]})),
                    ) as second_fetch,
                    patch.object(matching, "request") as matching_fetch,
                ):
                    one = first.get_jwks_keys()
                    two = second.get_jwks_keys()
                    self.assertEqual(one, [{"kid": "one"}])
                    self.assertEqual(two, [{"kid": "two"}])
                    self.assertIs(matching.get_jwks_keys(), one)
                    matching_fetch.assert_not_called()
                    first_fetch.assert_called_once_with(
                        first.jwks_uri(), stage="token_validation"
                    )
                    second_fetch.assert_called_once_with(
                        second.jwks_uri(), stage="token_validation"
                    )

                    first.get_jwks_keys_for_uri.invalidate(first, first.jwks_uri())
                    self.assertIsNot(first.get_jwks_keys(), one)
                    self.assertIs(second.get_jwks_keys(), two)
                    self.assertEqual(first_fetch.call_count, 2)
                    self.assertEqual(second_fetch.call_count, 1)

    def test_signing_key_rotation_invalidates_only_current_url(self) -> None:
        first = OpenIdConnectAuth(
            configured_strategy("https://cache-rotation-one.example")
        )
        second = OpenIdConnectAuth(
            configured_strategy("https://cache-rotation-two.example")
        )
        first.get_jwks_keys_for_uri.invalidate()
        self.addCleanup(first.get_jwks_keys_for_uri.invalidate)
        with (
            patch.object(
                first,
                "request",
                return_value=Mock(text=json.dumps({"keys": [{"kid": "old"}]})),
            ) as first_fetch,
            patch.object(
                second,
                "request",
                return_value=Mock(text=json.dumps({"keys": [{"kid": "other"}]})),
            ) as second_fetch,
            patch(
                "social_core.backends.open_id_connect.jwt.get_unverified_header",
                return_value={"kid": "new"},
            ),
        ):
            first.get_jwks_keys()
            other_keys = second.get_jwks_keys()
            first_fetch.return_value = Mock(text=json.dumps({"keys": []}))
            self.assertIsNone(first.find_valid_key("unused"))
            self.assertIs(second.get_jwks_keys(), other_keys)
            self.assertEqual(first_fetch.call_count, 2)
            self.assertEqual(second_fetch.call_count, 1)
