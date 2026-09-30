import json
from typing import cast
from unittest.mock import patch

from social_core.backends.facebook import API_VERSION
from social_core.exceptions import (
    AuthCanceled,
    AuthException,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
    AuthUnknownError,
)
from social_core.utils import get_querystring

from .base import BaseBackendTest
from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .open_id_connect import OpenIdConnectTest


class FacebookOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.facebook.FacebookOAuth2"
    user_data_url = f"https://graph.facebook.com/v{API_VERSION}/me"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "username": "foobar",
            "first_name": "Foo",
            "last_name": "Bar",
            "verified": True,
            "name": "Foo Bar",
            "gender": "male",
            "updated_time": "2013-02-13T14:59:42+0000",
            "link": "http://www.facebook.com/foobar",
            "id": "110011001100010",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class FacebookOAuth2WrongUserDataTest(FacebookOAuth2Test):
    user_data_body = "null"

    def test_login(self) -> None:
        with self.assertRaises(AuthUnknownError):
            self.do_login()

    def test_partial_pipeline(self) -> None:
        with self.assertRaises(AuthUnknownError):
            self.do_partial_pipeline()


class FacebookOAuth2AuthCancelTest(FacebookOAuth2Test):
    access_token_status = 400
    access_token_body = json.dumps(
        {
            "error": {
                "message": "redirect_uri isn't an absolute URI. Check RFC 3986.",
                "code": 191,
                "type": "OAuthException",
                "fbtrace_id": "123Abc",
            }
        }
    )

    def test_login(self) -> None:
        with self.assertRaises(AuthCanceled) as cm:
            self.do_login()
        self.assertIn("error", cm.exception.response.json())

    def test_partial_pipeline(self) -> None:
        with self.assertRaises(AuthCanceled) as cm:
            self.do_partial_pipeline()
        self.assertIn("error", cm.exception.response.json())


class FacebookAppOAuth2Test(BaseBackendTest):
    backend_path = "social_core.backends.facebook.FacebookAppOAuth2"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_FACEBOOK_APP_KEY": "a-key",
            "SOCIAL_AUTH_FACEBOOK_APP_SECRET": "a-secret-key",
        }

    def render_context(self) -> dict[str, object]:
        rendered_context: dict[str, object] = {}

        def render_html(tpl=None, html=None, context=None):
            rendered_context.update(context or {})
            return tpl or html or ""

        with patch.object(self.strategy, "render_html", side_effect=render_html):
            self.assertEqual(self.backend.auth_html(), "facebook.html")

        return rendered_context

    def callback_state(self) -> str:
        context = self.render_context()
        state = self.strategy.session_get("facebook-app_state")
        self.assertIsNotNone(state)
        self.assertEqual(
            get_querystring(str(context["FACEBOOK_COMPLETE_URI"]))["redirect_state"],
            state,
        )
        return cast("str", state)

    def test_auth_html_creates_redirect_state(self) -> None:
        context = self.render_context()
        state = self.strategy.session_get("facebook-app_state")

        self.assertIsNotNone(state)
        self.assertEqual(context["FACEBOOK_APP_NAMESPACE"], "a-key")
        self.assertEqual(context["FACEBOOK_KEY"], "a-key")
        self.assertEqual(
            get_querystring(str(context["FACEBOOK_COMPLETE_URI"]))["redirect_state"],
            state,
        )

    def test_complete_accepts_access_token_with_matching_state(self) -> None:
        state = self.callback_state()
        self.strategy.set_request_data(
            {"access_token": "access-token", "redirect_state": state}, self.backend
        )

        with patch.object(self.backend, "do_auth", return_value="user") as do_auth:
            self.assertEqual(self.backend.complete(), "user")

        do_auth.assert_called_once_with("access-token", {})

    def test_complete_accepts_signed_request_with_matching_state(self) -> None:
        state = self.callback_state()
        self.strategy.set_request_data(
            {"signed_request": "signed-request", "redirect_state": state},
            self.backend,
        )
        signed_response = {"user_id": "user-id", "oauth_token": "access-token"}

        with (
            patch.object(
                self.backend, "load_signed_request", return_value=signed_response
            ),
            patch.object(self.backend, "do_auth", return_value="user") as do_auth,
        ):
            self.assertEqual(self.backend.complete(), "user")

        do_auth.assert_called_once_with("access-token", signed_response)

    def test_complete_rejects_missing_redirect_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data({"access_token": "access-token"}, self.backend)

        with (
            patch.object(self.backend, "do_auth") as do_auth,
            self.assertRaises(AuthMissingParameter),
        ):
            self.backend.complete()

        do_auth.assert_not_called()

    def test_complete_rejects_signed_request_without_redirect_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(
            {"signed_request": "signed-request"}, self.backend
        )
        signed_response = {"user_id": "user-id", "oauth_token": "access-token"}

        with (
            patch.object(
                self.backend, "load_signed_request", return_value=signed_response
            ),
            patch.object(self.backend, "do_auth") as do_auth,
            self.assertRaises(AuthMissingParameter),
        ):
            self.backend.complete()

        do_auth.assert_not_called()

    def test_complete_rejects_mismatched_redirect_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(
            {"access_token": "access-token", "redirect_state": "invalid-state"},
            self.backend,
        )

        with (
            patch.object(self.backend, "do_auth") as do_auth,
            self.assertRaises(AuthStateForbidden),
        ):
            self.backend.complete()

        do_auth.assert_not_called()

    def test_complete_rejects_orphaned_redirect_state(self) -> None:
        self.strategy.set_request_data(
            {"access_token": "access-token", "redirect_state": "orphan-state"},
            self.backend,
        )

        with (
            patch.object(self.backend, "do_auth") as do_auth,
            self.assertRaises(AuthStateMissing),
        ):
            self.backend.complete()

        do_auth.assert_not_called()

    def test_complete_preserves_access_denied_error(self) -> None:
        self.strategy.set_request_data({"error": "access_denied"}, self.backend)

        with self.assertRaises(AuthCanceled):
            self.backend.complete()

    def test_complete_preserves_missing_credentials_error(self) -> None:
        state = self.callback_state()
        self.strategy.set_request_data({"redirect_state": state}, self.backend)

        with self.assertRaises(AuthException):
            self.backend.complete()


class FacebookLimitedLoginTest(OpenIdConnectTest):
    backend_path = "social_core.backends.facebook_limited.FacebookLimitedLogin"
    issuer = "https://facebook.com"
    openid_config_body = """
    {
      "issuer": "https://facebook.com",
      "authorization_endpoint": "https://facebook.com/dialog/oauth/",
      "jwks_uri": "https://facebook.com/.well-known/oauth/openid/jwks/",
      "response_types_supported": [
        "id_token",
        "token id_token"
      ],
      "subject_types_supported": "pairwise",
      "id_token_signing_alg_values_supported": [
        "RS256"
      ],
      "claims_supported": [
        "iss",
        "aud",
        "sub",
        "iat",
        "exp",
        "jti",
        "nonce",
        "at_hash",
        "name",
        "email",
        "picture",
        "user_friends",
        "user_birthday",
        "user_age_range"
      ]
    }
    """

    def test_invalid_nonce(self) -> None:
        # The nonce isn't generated server-side so the test isn't relevant here.
        pass
