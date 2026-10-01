from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import Mock
from uuid import uuid4

import responses

from social_core.actions import do_auth, do_complete, do_disconnect
from social_core.backends.drip import DripOAuth
from social_core.exceptions import (
    AuthAlreadyAssociated,
    AuthCanceled,
    AuthForbidden,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
)
from social_core.tests.models import TestPartial, TestUserSocialAuth, User
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME, get_querystring, parse_qs

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

if TYPE_CHECKING:
    from social_core.storage import PartialMixin


class DripOAuthTest(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.drip.DripOAuth"
    user_data_url = "https://api.getdrip.com/v2/user"
    access_token_body = json.dumps(
        {"access_token": "822bbf7cd12243df", "token_type": "bearer", "scope": "public"}
    )

    user_data_body = json.dumps(
        {"users": [{"email": "other@example.com", "name": None}]}
    )

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {**super().extra_settings(), "SOCIAL_AUTH_LOGIN_REDIRECT_URL": "/done"}

    def start_for_user(self, user: User) -> str:
        return get_querystring(do_auth(self.backend, user=user).url)["state"]

    def prepare_callback(self, user: User) -> str:
        start_url = do_auth(self.backend, user=user).url
        self.auth_handlers(start_url)
        self.pre_complete_callback(start_url)
        state = get_querystring(start_url)["state"]
        self.strategy.set_request_data({"code": "foobar", "state": state}, self.backend)
        return state

    def complete_for_user(self, user: User) -> User:
        self.prepare_callback(user)
        result = self.backend.complete(user=user)
        self.assertIs(result, user)
        return cast("User", result)

    def pause_for_user(self, user: User) -> PartialMixin:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": (
                    "social_core.pipeline.social_auth.social_details",
                    "social_core.pipeline.social_auth.social_uid",
                    "social_core.tests.pipeline.ask_for_password",
                    "social_core.pipeline.social_auth.social_user",
                    "social_core.pipeline.user.create_user",
                    "social_core.pipeline.social_auth.associate_user",
                    "social_core.pipeline.social_auth.load_extra_data",
                    "social_core.pipeline.user.user_details",
                )
            }
        )
        self.prepare_callback(user)
        response = do_complete(self.backend, login=Mock(), user=user)
        self.assertEqual(response.url, self.strategy.build_absolute_uri("/password"))
        token = cast("str", self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME))
        partial = TestPartial.load(token)
        self.assertIsNotNone(partial)
        return cast("PartialMixin", partial)

    def test_association(self) -> None:
        user = User("existing")
        state = self.prepare_callback(user)
        login = Mock()

        result = do_complete(self.backend, login=login, user=user)

        self.assertEqual(result.url, "/done")
        login.assert_not_called()
        self.assertEqual(len(User.cache), 1)
        social = TestUserSocialAuth.get_social_auth("drip", "other@example.com")
        self.assertIs(social.user, user)
        self.assertEqual(social.extra_data["access_token"], "822bbf7cd12243df")
        self.assertEqual(social.extra_data["token_type"], "bearer")
        token_request = next(
            call.request
            for call in responses.calls
            if call.request.url == self.backend.access_token_url()
        )
        redirect_uri = parse_qs(token_request.body)["redirect_uri"]
        self.assertEqual(get_querystring(redirect_uri)["redirect_state"], state)
        self.assertIsNone(self.strategy.session_get("drip_state"))

    def test_association_preserves_profile(self) -> None:
        user = User("existing", email="local@example.com")
        untyped_user = cast(Any, user)  # noqa: TC006
        untyped_user.fullname = "Local Name"
        self.user_data_body = json.dumps(
            {"users": [{"email": "other@example.com", "name": "Drip Name"}]}
        )
        self.strategy.set_settings(
            {"SOCIAL_AUTH_NO_DEFAULT_PROTECTED_USER_FIELDS": True}
        )

        self.complete_for_user(user)

        self.assertEqual(user.username, "existing")
        self.assertEqual(user.email, "local@example.com")
        self.assertEqual(untyped_user.fullname, "Local Name")

    def test_start_requires_authenticated_user(self) -> None:
        with self.assertRaises(AuthForbidden):
            do_auth(self.backend)
        user = User("anonymous")
        cast(Any, user).is_authenticated = False  # noqa: TC006
        with self.assertRaises(AuthForbidden):
            do_auth(self.backend, user=user)
        self.assertIsNone(self.strategy.session_get("drip_state"))

    def test_direct_start_requires_prepared_context(self) -> None:
        with self.assertRaises(AuthStateMissing):
            self.backend.start()

    def test_auth_url_parameters(self) -> None:
        self.start_for_user(User("existing"))
        self.check_parameters_in_authorization_url()

    def test_invalid_callback_rejected_before_provider_requests(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        context = {"state": state, "user_id": str(user.id)}
        cases: tuple[tuple[dict[str, Any], Any, User | None, type[Exception]], ...] = (
            ({}, context, user, AuthMissingParameter),
            ({"state": "wrong"}, context, user, AuthStateForbidden),
            ({"state": {"invalid": "state"}}, context, user, AuthStateForbidden),
            ({"state": state}, None, user, AuthStateMissing),
            ({"state": state}, "legacy-state", user, AuthStateMissing),
            ({"state": state}, {"state": []}, user, AuthStateMissing),
            ({"state": state}, {"state": state}, user, AuthForbidden),
            ({"state": state}, context, None, AuthForbidden),
            ({"state": state}, context, User("other"), AuthForbidden),
        )
        for data, stored, current_user, exception in cases:
            with self.subTest(data=data, stored=stored, user=current_user):
                self.strategy.session_set("drip_state", stored)
                self.strategy.set_request_data({"code": "foobar", **data}, self.backend)
                with self.assertRaises(exception):
                    self.backend.complete(user=current_user)
                self.assertEqual(len(responses.calls), 0)

    def test_state_cannot_be_replayed(self) -> None:
        user = User("existing")
        self.complete_for_user(user)
        calls = len(responses.calls)
        with self.assertRaises(AuthStateMissing):
            self.backend.complete(user=user)
        self.assertEqual(len(responses.calls), calls)

    def test_new_start_replaces_previous_state(self) -> None:
        user = User("existing")
        first = self.start_for_user(user)
        second = self.start_for_user(user)
        self.assertNotEqual(first, second)
        self.strategy.set_request_data({"state": first}, self.backend)
        with self.assertRaises(AuthStateForbidden):
            self.backend.complete(user=user)
        self.assertEqual(len(responses.calls), 0)

    def test_denied_callback_consumes_state(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        self.strategy.set_request_data(
            {"state": state, "error": "access_denied"}, self.backend
        )
        with self.assertRaises(AuthCanceled):
            self.backend.complete(user=user)
        self.assertIsNone(self.strategy.session_get("drip_state"))
        self.assertEqual(len(responses.calls), 0)

    def test_existing_association_is_idempotent(self) -> None:
        user = User("existing")
        self.complete_for_user(user)
        self.complete_for_user(user)
        self.assertEqual(len(user.social), 1)

    def test_association_cannot_authenticate_another_user(self) -> None:
        victim = User("victim")
        attacker = User("attacker")
        social = TestUserSocialAuth.create_social_auth(
            victim, "other@example.com", "drip"
        )
        self.prepare_callback(attacker)
        with self.assertRaises(AuthAlreadyAssociated):
            self.backend.complete(user=attacker)
        self.assertIs(social.user, victim)
        self.assertEqual(attacker.social, [])

    def test_changed_email_creates_association_for_current_user(self) -> None:
        user = User("existing")
        self.complete_for_user(user)
        self.user_data_body = json.dumps(
            {"users": [{"email": "changed@example.com", "name": None}]}
        )
        self.complete_for_user(user)
        self.assertEqual(
            {social.uid for social in user.social},
            {"other@example.com", "changed@example.com"},
        )

    def test_direct_token_requires_authenticated_user(self) -> None:
        for user in (None, User("anonymous")):
            if user is not None:
                cast(Any, user).is_authenticated = False  # noqa: TC006
            with self.subTest(user=user), self.assertRaises(AuthForbidden):
                self.backend.do_auth("token", user=user)
        self.assertEqual(len(responses.calls), 0)

    def test_direct_token_associates_current_user(self) -> None:
        user = User("existing")
        responses.add(
            responses.GET,
            self.user_data_url,
            body=self.user_data_body,
            content_type="application/json",
        )
        self.assertIs(self.backend.do_auth("token", user=user), user)
        self.assertEqual(user.social[0].extra_data["access_token"], "token")

    def test_authenticate_requires_authenticated_user(self) -> None:
        with self.assertRaises(AuthForbidden):
            self.strategy.authenticate(backend=self.backend, response={"users": []})
        self.assertEqual(len(User.cache), 0)

    def test_pipeline_rejects_mismatched_initiator(self) -> None:
        user = User("existing")
        other = User("other")
        with self.assertRaises(AuthForbidden):
            self.strategy.authenticate(
                backend=self.backend,
                response={},
                user=other,
                drip_association_user_id=str(user.id),
            )
        self.assertEqual(other.social, [])

    def test_association_with_configured_provider_field_id(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_DRIP_ID_KEY": "name"})
        self.user_data_body = json.dumps(
            {"users": [{"email": "other@example.com", "name": "Drip User"}]}
        )

        user = self.complete_for_user(User("existing"))

        self.assertEqual(user.social[0].uid, "Drip User")

    def test_configured_id_uses_normalized_details_fallback(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_DRIP_ID_KEY": "fullname"})

        self.assertEqual(
            self.backend.get_user_id(
                {"fullname": "Drip User"},
                {"users": [{"name": "Drip User"}]},
            ),
            "Drip User",
        )

    def test_missing_configured_id_raises_missing_parameter(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_DRIP_ID_KEY": "missing_id"})

        with self.assertRaisesRegex(AuthMissingParameter, "missing_id"):
            self.backend.get_user_id({}, {"users": [{}]})

    def test_partial_resumes_for_initiator_with_new_backend(self) -> None:
        for use_uuid in (False, True):
            with self.subTest(use_uuid=use_uuid):
                user = User(f"existing-{use_uuid}")
                if use_uuid:
                    cast(Any, user).id = uuid4()  # noqa: TC006
                partial = self.pause_for_user(user)
                self.assertEqual(
                    partial.kwargs["drip_association_user_id"], str(user.id)
                )
                # Round-trip stored data before the framework deserializes it.
                partial.data = json.loads(json.dumps(partial.data))
                self.backend = DripOAuth(self.strategy, redirect_uri=self.complete_url)
                self.strategy.session_set("password", "secret")
                calls = len(responses.calls)
                response = do_complete(self.backend, login=Mock(), user=user)
                self.assertEqual(response.url, "/done")
                self.assertEqual(len(responses.calls), calls)
                self.assertIs(user.social[0].user, user)
                # Use a different remote identifier for the next subtest.
                self.user_data_body = json.dumps(
                    {"users": [{"email": "uuid@example.com", "name": None}]}
                )
                self.strategy.session_pop("password")

    def test_partial_rejects_logged_out_or_different_user(self) -> None:
        user = User("existing")
        self.pause_for_user(user)
        for current_user in (None, User("other")):
            with self.subTest(user=current_user), self.assertRaises(AuthForbidden):
                do_complete(self.backend, login=Mock(), user=current_user)
        self.assertEqual(user.social, [])

    def test_partial_rejects_legacy_unbound_context(self) -> None:
        user = User("existing")
        partial = self.pause_for_user(user)
        partial.kwargs.pop("drip_association_user_id")
        partial.save()
        with self.assertRaises(AuthForbidden):
            do_complete(self.backend, login=Mock(), user=user)

    def test_disconnect_partial_binding(self) -> None:
        user = User("existing")
        social = TestUserSocialAuth.create_social_auth(
            user, "other@example.com", "drip"
        )
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_DISCONNECT_PIPELINE": (
                    "social_core.tests.pipeline.ask_for_password",
                    "social_core.pipeline.disconnect.get_entries",
                    "social_core.pipeline.disconnect.disconnect",
                )
            }
        )
        do_disconnect(self.backend, user)
        for current_user in (None, User("other")):
            with self.subTest(user=current_user), self.assertRaises(AuthForbidden):
                do_disconnect(self.backend, cast("User", current_user))
        self.assertIn(social, user.social)
        self.strategy.session_set("password", "secret")
        self.backend = DripOAuth(self.strategy, redirect_uri=self.complete_url)
        do_disconnect(self.backend, user)
        self.assertEqual(user.social, [])
