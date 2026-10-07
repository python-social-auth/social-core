from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from unittest.mock import Mock
from uuid import uuid4

from social_core.actions import do_auth, do_complete, do_disconnect
from social_core.exceptions import (
    AuthAssociationError,
    AuthInputError,
    AuthResponseError,
    AuthSessionError,
)
from social_core.tests.exception_helpers import assert_auth_error
from social_core.tests.models import TestPartial, TestUserSocialAuth, User
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME, get_querystring

from .base import BaseBackendTest

if TYPE_CHECKING:
    from social_core.storage import PartialMixin

ACCOUNT_SID = "ACc65ea16c9ebd4d4684edf814995b27e"
OTHER_ACCOUNT_SID = "AC11111111111111111111111111111111"
APP_SID = "AP11111111111111111111111111111111"


class TwilioAuthTest(BaseBackendTest):
    backend_path = "social_core.backends.twilio.TwilioAuth"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_TWILIO_KEY": APP_SID,
            "SOCIAL_AUTH_TWILIO_SECRET": "twilio-auth-token",
            "SOCIAL_AUTH_LOGIN_REDIRECT_URL": "/done",
        }

    def start_for_user(self, user: User) -> str:
        start_url = do_auth(self.backend, user=user).url
        callback = get_querystring(start_url)["cb"]
        return get_querystring(callback)["redirect_state"]

    def complete_for_user(self, user: User, account_sid: str = ACCOUNT_SID) -> User:
        state = self.start_for_user(user)
        self.strategy.set_request_data(
            {"AccountSid": account_sid, "redirect_state": state}, self.backend
        )
        result = self.backend.complete(user=user)
        self.assertIsInstance(result, User)
        return cast("User", result)

    def pause_for_user(self, user: User) -> PartialMixin:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": (
                    "social_core.pipeline.social_auth.social_details",
                    "social_core.pipeline.social_auth.social_uid",
                    "social_core.pipeline.social_auth.auth_allowed",
                    "social_core.tests.pipeline.ask_for_password",
                    "social_core.pipeline.social_auth.social_user",
                    "social_core.pipeline.user.get_username",
                    "social_core.pipeline.user.create_user",
                    "social_core.pipeline.social_auth.associate_user",
                    "social_core.pipeline.social_auth.load_extra_data",
                    "social_core.pipeline.user.user_details",
                )
            }
        )
        state = self.start_for_user(user)
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": state}, self.backend
        )

        response = do_complete(self.backend, login=Mock(), user=user)

        self.assertEqual(response.url, self.strategy.build_absolute_uri("/password"))
        token = cast("str", self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME))
        partial = TestPartial.load(token)
        self.assertIsNotNone(partial)
        return cast("PartialMixin", partial)

    def test_auth_url_preserves_https_callback(self) -> None:
        user = User("existing")
        self.backend.redirect_uri = "https://myapp.com/complete/twilio"

        callback = get_querystring(do_auth(self.backend, user=user).url)["cb"]
        query = get_querystring(callback)

        self.assertEqual(
            callback,
            "https://myapp.com/complete/twilio?"
            f"redirect_state={query['redirect_state']}",
        )
        self.assertEqual(
            self.strategy.session_get("twilio_state"),
            {"state": query["redirect_state"], "user_id": str(user.id)},
        )

    def test_start_serializes_user_id(self) -> None:
        user = User("existing")
        untyped_user = cast(Any, user)
        untyped_user.id = uuid4()

        state = self.start_for_user(user)

        self.assertEqual(
            self.strategy.session_get("twilio_state"),
            {"state": state, "user_id": str(user.id)},
        )

    def test_start_requires_authenticated_user(self) -> None:
        with self.assertRaises(AuthSessionError):
            do_auth(self.backend)

    def test_direct_start_without_prepared_context_fails(self) -> None:
        with self.assertRaises(AuthSessionError):
            self.backend.start()

    def test_missing_account_sid_fails_and_consumes_state(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        self.strategy.set_request_data({"redirect_state": state}, self.backend)

        with assert_auth_error(self, AuthResponseError, "missing_claim"):
            self.backend.complete(user=user)

        self.assertIsNone(self.strategy.session_get("twilio_state"))

    def test_complete_rejects_missing_redirect_state(self) -> None:
        user = User("existing")
        self.start_for_user(user)
        self.strategy.set_request_data({"AccountSid": ACCOUNT_SID}, self.backend)

        with self.assertRaises(AuthInputError):
            self.backend.complete(user=user)

    def test_complete_rejects_mismatched_redirect_state(self) -> None:
        user = User("existing")
        self.start_for_user(user)
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": "invalid-state"},
            self.backend,
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)

    def test_complete_rejects_orphan_redirect_state(self) -> None:
        user = User("existing")
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": "orphan-state"},
            self.backend,
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)

    def test_complete_rejects_legacy_string_state(self) -> None:
        user = User("existing")
        self.strategy.session_set("twilio_state", "legacy-state")
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": "legacy-state"},
            self.backend,
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)

    def test_complete_requires_authenticated_user(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": state}, self.backend
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete()

    def test_complete_rejects_different_user(self) -> None:
        initiating_user = User("initiator")
        other_user = User("other")
        state = self.start_for_user(initiating_user)
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": state}, self.backend
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=other_user)

    def test_complete_associates_twilio_with_current_user(self) -> None:
        user = User("existing")

        result = self.complete_for_user(user)

        self.assertIs(result, user)
        social = TestUserSocialAuth.get_social_auth("twilio", ACCOUNT_SID)
        self.assertIsNotNone(social)
        self.assertIs(social.user, user)

    def test_complete_preserves_local_profile_fields(self) -> None:
        user = User("existing", email="person@example.com")
        untyped_user = cast(Any, user)
        untyped_user.fullname = "Existing Person"
        untyped_user.first_name = "Existing"
        untyped_user.last_name = "Person"

        self.complete_for_user(user)

        self.assertEqual(user.email, "person@example.com")
        self.assertEqual(untyped_user.fullname, "Existing Person")
        self.assertEqual(untyped_user.first_name, "Existing")
        self.assertEqual(untyped_user.last_name, "Person")

    def test_partial_pipeline_resumes_for_initiating_user(self) -> None:
        user = User("existing")
        self.pause_for_user(user)
        self.strategy.session_set("password", "secret")

        response = do_complete(self.backend, login=Mock(), user=user)

        self.assertEqual(response.url, "/done")
        social = TestUserSocialAuth.get_social_auth("twilio", ACCOUNT_SID)
        self.assertIsNotNone(social)
        self.assertIs(social.user, user)

    def test_partial_pipeline_resumes_for_uuid_user(self) -> None:
        user = User("existing")
        untyped_user = cast(Any, user)
        untyped_user.id = uuid4()
        partial = self.pause_for_user(user)
        self.assertNotIn("user", partial.kwargs)
        self.strategy.session_set("password", "secret")

        response = do_complete(self.backend, login=Mock(), user=user)

        self.assertEqual(response.url, "/done")
        social = TestUserSocialAuth.get_social_auth("twilio", ACCOUNT_SID)
        self.assertIsNotNone(social)
        self.assertIs(social.user, user)

    def test_disconnect_partial_pipeline_resumes_for_initiating_user(self) -> None:
        user = User("existing")
        TestUserSocialAuth.create_social_auth(user, ACCOUNT_SID, "twilio")
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_DISCONNECT_PIPELINE": (
                    "social_core.tests.pipeline.ask_for_password",
                    "social_core.tests.pipeline.set_password",
                    "social_core.pipeline.disconnect.allowed_to_disconnect",
                    "social_core.pipeline.disconnect.get_entries",
                    "social_core.pipeline.disconnect.revoke_tokens",
                    "social_core.pipeline.disconnect.disconnect",
                )
            }
        )

        response = do_disconnect(self.backend, user)
        self.assertEqual(response.url, self.strategy.build_absolute_uri("/password"))
        self.strategy.session_set("password", "secret")
        response = do_disconnect(self.backend, user)

        self.assertEqual(response.url, self.strategy.build_absolute_uri("/done"))
        self.assertEqual(user.social, [])

    def test_disconnect_partial_pipeline_rejects_different_user(self) -> None:
        initiating_user = User("initiator")
        other_user = User("other")
        TestUserSocialAuth.create_social_auth(initiating_user, ACCOUNT_SID, "twilio")
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_DISCONNECT_PIPELINE": (
                    "social_core.tests.pipeline.ask_for_password",
                    "social_core.pipeline.disconnect.disconnect",
                )
            }
        )
        do_disconnect(self.backend, initiating_user)

        with self.assertRaises(AuthSessionError):
            do_disconnect(self.backend, other_user)

        self.assertIsNotNone(TestUserSocialAuth.get_social_auth("twilio", ACCOUNT_SID))

    def test_partial_pipeline_rejects_logged_out_user(self) -> None:
        user = User("existing")
        self.pause_for_user(user)

        with self.assertRaises(AuthSessionError):
            do_complete(self.backend, login=Mock())

    def test_partial_pipeline_rejects_different_user(self) -> None:
        initiating_user = User("initiator")
        other_user = User("other")
        self.pause_for_user(initiating_user)

        with self.assertRaises(AuthSessionError):
            do_complete(self.backend, login=Mock(), user=other_user)

    def test_partial_pipeline_rejects_legacy_unbound_partial(self) -> None:
        user = User("existing")
        partial = self.pause_for_user(user)
        partial.kwargs.pop(self.backend.association_user_id_key())
        partial.save()

        with self.assertRaises(AuthSessionError):
            do_complete(self.backend, login=Mock(), user=user)

    def test_complete_does_not_log_current_user_in_again(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": state}, self.backend
        )
        login = Mock()

        response = do_complete(self.backend, login=login, user=user)

        login.assert_not_called()
        self.assertEqual(response.url, "/done")

    def test_existing_association_is_idempotent(self) -> None:
        user = User("existing")
        self.complete_for_user(user)

        result = self.complete_for_user(user)

        self.assertIs(result, user)
        social = TestUserSocialAuth.get_social_auth("twilio", ACCOUNT_SID)
        self.assertIsNotNone(social)
        self.assertIs(social.user, user)

    def test_state_cannot_be_replayed(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        data = {"AccountSid": ACCOUNT_SID, "redirect_state": state}
        self.strategy.set_request_data(data, self.backend)
        self.backend.complete(user=user)

        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)

    def test_associated_sid_cannot_authenticate_another_user(self) -> None:
        victim = User("victim")
        attacker = User("attacker")
        TestUserSocialAuth.create_social_auth(victim, ACCOUNT_SID, "twilio")
        state = self.start_for_user(attacker)
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": state}, self.backend
        )

        with self.assertRaises(AuthAssociationError):
            self.backend.complete(user=attacker)

        social = TestUserSocialAuth.get_social_auth("twilio", ACCOUNT_SID)
        self.assertIsNotNone(social)
        self.assertIs(social.user, victim)

    def test_new_start_replaces_previous_association_state(self) -> None:
        user = User("existing")
        first_state = self.start_for_user(user)
        second_state = self.start_for_user(user)

        self.assertNotEqual(first_state, second_state)
        self.strategy.set_request_data(
            {"AccountSid": OTHER_ACCOUNT_SID, "redirect_state": first_state},
            self.backend,
        )
        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)
