from typing import TYPE_CHECKING, cast
from unittest.mock import patch

from social_core.actions import do_complete
from social_core.backends.base import BaseAuth
from social_core.backends.oauth import BaseOAuth2
from social_core.tests.models import TestPartial, TestUserSocialAuth, User
from social_core.utils import (
    PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME,
    PARTIAL_TOKEN_PENDING_SESSION_NAME,
    PARTIAL_TOKEN_SESSION_NAME,
)

from .actions import BaseActionTest

if TYPE_CHECKING:
    from social_core.tests.models import TestStorage


class BackendThatControlsRedirect(BaseOAuth2):
    """
    A fake backend that sets the URL to redirect to after login.

    It is not always possible to set the redirect URL in the session state prior to auth and then retrieve it when
    auth is complete, because the session cookie might not be available post-auth. For example, for SAML, a POST request
    redirects the user from the IdP (Identity Provider) back to the SP (Service Provider) to complete the auth process,
    but the session cookie will not be present if the session cookie's `SameSite` attribute is not set to "None".
    To mitigate this, SAML provides a `RelayState` parameter to pass data like a redirect URL from the SP to the IdP
    and back again. In that case, the redirect URL is only known in `auth_complete`, and must be communicated back to
    the `do_complete` action via session state so that it can issue the intended redirect.
    """

    ACCESS_TOKEN_URL = "https://example.com/oauth/access_token"

    def auth_url(self) -> str:
        return "https://example.com/oauth/auth?state=foo"

    def auth_complete(self, *args, **kwargs):
        # Put the redirect URL in the session state, as this is where the `do_complete` action looks for it.
        self.strategy.session_set(kwargs["redirect_name"], "/after-login")
        return kwargs["user"]


class PartialTokenBackend(BaseAuth):
    name = "partial-token"

    def auth_url(self) -> str:
        return "/auth"

    def auth_complete(self, *args, **kwargs):
        raise AssertionError("Unexpected backend completion")


class LoginActionTest(BaseActionTest):
    def test_login(self) -> None:
        self.do_login()

    def test_login_with_partial_pipeline(self) -> None:
        self.do_login_with_partial_pipeline()

    def test_fields_stored_in_session(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_FIELDS_STORED_IN_SESSION": ["foo", "bar"]}
        )
        self.strategy.set_request_data({"foo": "1", "bar": "2"}, self.backend)
        self.do_login()
        self.assertEqual(self.strategy.session_get("foo"), "1")
        self.assertEqual(self.strategy.session_get("bar"), "2")

        self._logout(self.backend)
        # The _logout helper function doesn't clear the session.
        self.assertEqual(self.strategy.session_get("foo"), "1")
        self.assertEqual(self.strategy.session_get("bar"), "2")

        # Login again - without the 'bar' request param and make
        # sure its value didn't persist in the session.
        self.strategy.remove_from_request_data("bar")
        self.strategy.set_request_data({"foo": "3"}, self.backend)
        self.do_login()
        self.assertEqual(self.strategy.session_get("foo"), "3")
        self.assertEqual(self.strategy.session_get("bar"), None)

    def test_redirect_value(self) -> None:
        self.strategy.set_request_data({"next": "/after-login"}, self.backend)
        redirect = self.do_login(after_complete_checks=False)
        self.assertEqual(redirect.url, "/after-login")

    def test_backslash_redirect_value_falls_back(self) -> None:
        self.strategy.set_request_data({"next": "/\\evil.com"}, self.backend)
        redirect = self.do_login(after_complete_checks=False)
        self.assertEqual(redirect.url, self.login_redirect_url)

    def test_redirect_value_set_by_backend(self) -> None:
        self.backend = BackendThatControlsRedirect(self.strategy)
        self.user = TestUserSocialAuth.create_user("test-user")
        redirect = self.do_login(after_complete_checks=False)
        self.assertEqual(redirect.url, "/after-login")

    def test_login_with_invalid_partial_pipeline(self) -> None:
        def before_complete() -> None:
            partial_token = cast(
                "str", self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME)
            )
            partial = cast("TestStorage", self.strategy.storage).partial.load(
                partial_token
            )
            assert partial is not None
            partial.data["backend"] = "foobar"

        self.do_login_with_partial_pipeline(before_complete)

    def test_complete_rejects_cross_session_partial_token(self) -> None:
        def unexpected_login(*args, **kwargs) -> None:
            raise AssertionError("Unexpected login")

        TestPartial.reset_cache()
        self.addCleanup(TestPartial.reset_cache)
        backend = PartialTokenBackend(self.strategy)
        self.strategy.set_settings({"SOCIAL_AUTH_LOGIN_ERROR_URL": "/error"})
        partial = TestPartial.prepare(backend.name, 0, {"args": [], "kwargs": {}})
        partial.token = "attacker-token"
        partial.save()
        self.strategy.set_request_data({"partial_token": partial.token}, backend)

        redirect = do_complete(backend, login=unexpected_login)

        self.assertEqual(redirect.url, "/error")
        self.assertIsNone(self.strategy.session_get("username"))
        self.assertIsNotNone(TestPartial.load(partial.token))

    def test_complete_external_partial_requires_confirmation(self) -> None:
        def unexpected_login(*args, **kwargs) -> None:
            raise AssertionError("Unexpected login")

        TestPartial.reset_cache()
        self.addCleanup(TestPartial.reset_cache)
        backend = PartialTokenBackend(self.strategy)
        partial = TestPartial.prepare(backend.name, 0, {"args": [], "kwargs": {}})
        partial.token = "external-token"
        partial.data[PARTIAL_PIPELINE_ALLOW_EXTERNAL_RESUME] = True
        partial.save()
        self.strategy.set_request_data({"partial_token": partial.token}, backend)

        with patch.object(
            self.strategy,
            "partial_pipeline_external_resume_confirmation",
            return_value=self.strategy.redirect("/confirm"),
        ):
            redirect = do_complete(backend, login=unexpected_login)

        self.assertEqual(redirect.url, "/confirm")
        self.assertEqual(
            self.strategy.session_get(PARTIAL_TOKEN_PENDING_SESSION_NAME),
            partial.token,
        )

    def test_new_user(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_NEW_USER_REDIRECT_URL": "/new-user"})
        redirect = self.do_login(after_complete_checks=False)
        self.assertEqual(redirect.url, "/new-user")

    def test_inactive_user(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_INACTIVE_USER_URL": "/inactive"})
        User.set_active(False)
        redirect = self.do_login(after_complete_checks=False)
        self.assertEqual(redirect.url, "/inactive")

    def test_inactive_user_allowed(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_ALLOW_INACTIVE_USERS_LOGIN": True})
        User.set_active(False)
        redirect = self.do_login(after_complete_checks=False)
        self.assertEqual(redirect.url, "/success")

    def test_invalid_user(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_LOGIN_ERROR_URL": "/error",
                "SOCIAL_AUTH_PIPELINE": (
                    "social_core.pipeline.social_auth.social_details",
                    "social_core.pipeline.social_auth.social_uid",
                    "social_core.pipeline.social_auth.auth_allowed",
                    "social_core.pipeline.social_auth.social_user",
                    "social_core.pipeline.user.get_username",
                    "social_core.pipeline.user.create_user",
                    "social_core.pipeline.social_auth.associate_user",
                    "social_core.pipeline.social_auth.load_extra_data",
                    "social_core.pipeline.user.user_details",
                    "social_core.tests.pipeline.remove_user",
                ),
            }
        )
        redirect = self.do_login(after_complete_checks=False)
        self.assertEqual(redirect.url, "/error")
