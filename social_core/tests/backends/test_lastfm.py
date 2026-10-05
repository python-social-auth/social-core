import json
from typing import Any, cast

import responses

from social_core.actions import do_auth
from social_core.exceptions import (
    AuthAssociationError,
    AuthInputError,
    AuthSessionError,
)
from social_core.tests.models import TestUserSocialAuth, User
from social_core.utils import get_querystring, parse_qs

from .base import BaseBackendTest


class LastFmAuthTest(BaseBackendTest):
    backend_path = "social_core.backends.lastfm.LastFmAuth"
    expected_username = "foobar"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_LASTFM_KEY": "a-key",
            "SOCIAL_AUTH_LASTFM_SECRET": "a-secret-key",
        }

    def start_for_user(self, user: User) -> str:
        start_url = do_auth(self.backend, user=user).url
        query = get_querystring(start_url)
        state = get_querystring(query["cb"])["redirect_state"]
        self.assertEqual(query["api_key"], "a-key")
        context = self.strategy.session_get("lastfm_state")
        self.assertEqual(context["state"], state)
        self.assertEqual(context["user_id"], str(user.id))
        return state

    def prepare_callback(self, user: User) -> str:
        state = self.start_for_user(user)
        self.strategy.set_request_data(
            {"token": "foobar", "redirect_state": state}, self.backend
        )
        responses.add(
            responses.POST,
            "https://ws.audioscrobbler.com/2.0/",
            body=json.dumps({"session": {"name": "foobar", "key": "session-key"}}),
            content_type="application/json",
        )
        return state

    def complete_for_user(self, user: User) -> User:
        self.prepare_callback(user)
        result = self.backend.complete(user=user)
        self.assertIs(result, user)
        return cast("User", result)

    def test_auth_url_contains_session_bound_callback(self) -> None:
        self.backend.redirect_uri = "https://myapp.com/complete/lastfm?next=/profile"

        user = User("existing")
        start_url = do_auth(self.backend, user=user).url
        query = get_querystring(start_url)
        callback_query = get_querystring(query["cb"])

        self.assertEqual(query["api_key"], "a-key")
        self.assertTrue(query["cb"].startswith("https://myapp.com/complete/lastfm?"))
        self.assertEqual(callback_query["next"], "/profile")
        context = self.strategy.session_get("lastfm_state")
        self.assertEqual(callback_query["redirect_state"], context["state"])
        self.assertEqual(context["user_id"], str(user.id))

    def test_new_start_replaces_previous_state(self) -> None:
        user = User("existing")
        first_state = self.start_for_user(user)
        second_state = self.start_for_user(user)
        self.assertNotEqual(first_state, second_state)

    def test_complete_rejects_missing_state(self) -> None:
        user = User("existing")
        self.start_for_user(user)
        self.strategy.set_request_data({"token": "foobar"}, self.backend)

        with self.assertRaises(AuthInputError):
            self.backend.complete(user=user)

        self.assertEqual(len(responses.calls), 0)

    def test_complete_rejects_mismatched_state(self) -> None:
        user = User("existing")
        self.start_for_user(user)
        self.strategy.set_request_data(
            {"token": "foobar", "redirect_state": "invalid-state"},
            self.backend,
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)

        self.assertEqual(len(responses.calls), 0)

    def test_complete_rejects_orphan_state(self) -> None:
        user = User("existing")
        self.strategy.set_request_data(
            {"token": "foobar", "redirect_state": "orphan-state"},
            self.backend,
        )

        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)

        self.assertEqual(len(responses.calls), 0)

    def test_complete_rejects_missing_token(self) -> None:
        user = User("existing")
        state = self.start_for_user(user)
        self.strategy.set_request_data({"redirect_state": state}, self.backend)

        with self.assertRaises(AuthInputError):
            self.backend.complete(user=user)

        self.assertEqual(len(responses.calls), 0)

    def test_session_request_is_signed(self) -> None:
        self.complete_for_user(User("existing"))

        request_data = parse_qs(responses.calls[-1].request.body)
        self.assertEqual(request_data["method"], "auth.getSession")
        self.assertEqual(request_data["api_key"], "a-key")
        self.assertEqual(request_data["token"], "foobar")
        self.assertEqual(request_data["format"], "json")
        self.assertEqual(request_data["api_sig"], "a17701f3803e1ec60da5947b7bb5f793")

    def test_association(self) -> None:
        user = self.complete_for_user(User("existing"))
        self.assertEqual(len(User.cache), 1)
        social = TestUserSocialAuth.get_social_auth("lastfm", "foobar")
        self.assertIs(social.user, user)
        self.assertEqual(social.extra_data["session_key"], "session-key")

    def test_start_requires_authenticated_user(self) -> None:
        with self.assertRaises(AuthSessionError):
            do_auth(self.backend)
        anonymous = User("anonymous")
        cast(Any, anonymous).is_authenticated = False  # noqa: TC006
        with self.assertRaises(AuthSessionError):
            do_auth(self.backend, user=anonymous)

    def test_direct_start_requires_prepared_context(self) -> None:
        with self.assertRaises(AuthSessionError):
            self.backend.start()

    def test_state_cannot_be_replayed(self) -> None:
        user = User("existing")
        self.complete_for_user(user)
        calls = len(responses.calls)
        with self.assertRaises(AuthSessionError):
            self.backend.complete(user=user)
        self.assertEqual(len(responses.calls), calls)

    def test_association_cannot_authenticate_another_user(self) -> None:
        victim = User("victim")
        attacker = User("attacker")
        social = TestUserSocialAuth.create_social_auth(victim, "foobar", "lastfm")
        self.prepare_callback(attacker)
        with self.assertRaises(AuthAssociationError):
            self.backend.complete(user=attacker)
        self.assertIs(social.user, victim)
        self.assertEqual(attacker.social, [])
