import datetime
import json
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

from social_core.backends.facebook import API_VERSION
from social_core.backends.facebook_limited import FacebookLimitedLogin
from social_core.exceptions import (
    AuthCanceled,
    AuthException,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
    AuthTokenError,
    AuthUnknownError,
)
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME, get_querystring

from .base import BaseBackendTest
from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .open_id_connect import PARTIAL_ID_TOKEN_KEY, OpenIdConnectTest

if TYPE_CHECKING:
    from social_core.storage import PartialMixin
    from social_core.strategy import HttpResponseProtocol
    from social_core.tests.models import User


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


class FacebookLimitedLoginTest(OpenIdConnectTest[FacebookLimitedLogin]):
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

    def get_id_token(self, *args, **kwargs):
        return {
            **super().get_id_token(*args, **kwargs),
            "name": "Cartman",
            "email": "cartman@example.com",
            "picture": "https://example.com/cartman.png",
        }

    def limited_login_token(self, **kwargs) -> str:
        return json.loads(self.prepare_access_token_body(access_token=None, **kwargs))[
            "id_token"
        ]

    def test_token_login(self) -> None:
        user = cast("User", self.backend.do_auth(self.limited_login_token()))

        self.assertTrue(user.username)
        self.assertEqual(user.email, "cartman@example.com")
        self.assertEqual(user.social[0].uid, "1234")
        self.assertIsNotNone(self.backend.id_token)

    def test_partial_pipeline_after_token_expires(self) -> None:
        self.pipeline_settings()
        pipeline = list(self.strategy.get_pipeline(self.backend))
        pipeline.remove("social_core.tests.pipeline.ask_for_password")
        pipeline.insert(0, "social_core.tests.pipeline.ask_for_password")
        self.strategy.set_settings({"SOCIAL_AUTH_PIPELINE": pipeline})
        result = self.backend.do_auth(self.limited_login_token())

        for step, value in (("password", "foobar"), ("slug", "foo-bar")):
            with self.subTest(step=step):
                self.assertEqual(
                    cast("HttpResponseProtocol", result).url,
                    self.strategy.build_absolute_uri(f"/{step}"),
                )
                token = self.strategy.session_pop(PARTIAL_TOKEN_SESSION_NAME)
                partial = self.strategy.partial_load(token)
                self.assertIsNotNone(partial)
                partial = cast("PartialMixin", partial)
                claims = partial.kwargs[PARTIAL_ID_TOKEN_KEY]
                self.assertEqual(partial.kwargs["response"], claims)
                self.assertNotIn("access_token", partial.kwargs["response"])
                self.strategy.session_set(step, value)
                self.backend = FacebookLimitedLogin(self.strategy)
                expired_time = datetime.datetime.fromtimestamp(
                    claims["exp"] + self.backend.ID_TOKEN_MAX_AGE + 1,
                    datetime.timezone.utc,
                )
                with (
                    patch("jwt.api_jwt.datetime") as jwt_datetime,
                    patch(
                        "social_core.backends.open_id_connect.datetime"
                    ) as oidc_datetime,
                    patch.object(
                        self.backend,
                        "validate_and_return_id_token",
                        side_effect=AssertionError("JWT must not be revalidated"),
                    ) as validate,
                ):
                    jwt_datetime.now.return_value = expired_time
                    oidc_datetime.datetime.now.return_value = expired_time
                    result = self.backend.continue_pipeline(partial)
                    validate.assert_not_called()

        user = cast("User", result)
        self.assertTrue(user.username)
        self.assertEqual(user.email, "cartman@example.com")
        self.assertEqual(user.social[0].uid, "1234")
        self.assertEqual(user.password, "foobar")
        self.assertEqual(user.slug, "foo-bar")

        with self.assertRaisesRegex(AuthTokenError, "Missing access_token"):
            self.strategy.authenticate(self.backend, pipeline_index=0, response={})

    def test_invalid_token_login(self) -> None:
        # A reused backend must validate every fresh login.
        self.backend.do_auth(self.limited_login_token())
        expired_time = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(seconds=30)
        for kwargs, message in (
            ({"expiration_datetime": expired_time}, "Signature has expired"),
            ({"tamper_message": True}, "Signature verification failed"),
        ):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(AuthTokenError, message),
            ):
                self.backend.do_auth(self.limited_login_token(**kwargs))

    def test_pipeline_index_does_not_trust_caller_supplied_claims(self) -> None:
        for reused in (False, True):
            if reused:
                self.backend.do_auth(self.limited_login_token())
            with (
                self.subTest(reused=reused),
                self.assertRaisesRegex(AuthTokenError, "Signature verification failed"),
            ):
                self.strategy.authenticate(
                    self.backend,
                    pipeline_index=0,
                    response={
                        "access_token": self.limited_login_token(tamper_message=True)
                    },
                    **{PARTIAL_ID_TOKEN_KEY: {"sub": "forged-subject"}},
                )

    def test_pipeline_index_without_token_rejects_reused_claims(self) -> None:
        self.backend.do_auth(self.limited_login_token())
        claims = cast("dict", self.backend.id_token).copy()

        for response in ({}, claims):
            with (
                self.subTest(response=response),
                self.assertRaisesRegex(AuthTokenError, "Missing access_token"),
            ):
                self.strategy.authenticate(
                    self.backend,
                    pipeline_index=0,
                    response=response,
                    **{PARTIAL_ID_TOKEN_KEY: claims},
                )

    def test_failed_partial_resume_does_not_allow_claim_reuse(self) -> None:
        self.pipeline_settings()
        self.backend.do_auth(self.limited_login_token())
        token = self.strategy.session_pop(PARTIAL_TOKEN_SESSION_NAME)
        partial = cast("PartialMixin", self.strategy.partial_load(token))
        self.backend = FacebookLimitedLogin(self.strategy)

        with (
            patch.object(
                self.backend, "authenticate", side_effect=RuntimeError("Resume failed")
            ),
            self.assertRaisesRegex(RuntimeError, "Resume failed"),
        ):
            self.backend.continue_pipeline(partial)

        with self.assertRaisesRegex(AuthTokenError, "Missing access_token"):
            self.strategy.authenticate(self.backend, pipeline_index=0, response={})

    def test_invalid_nonce(self) -> None:
        # The nonce isn't generated server-side so the test isn't relevant here.
        pass
