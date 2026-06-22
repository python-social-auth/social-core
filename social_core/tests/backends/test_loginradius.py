import json
from typing import cast
from unittest.mock import patch

import responses

from social_core.exceptions import AuthMissingParameter, AuthStateForbidden
from social_core.utils import get_querystring

from .base import BaseBackendTest


class LoginRadiusAuthTest(BaseBackendTest):
    backend_path = "social_core.backends.loginradius.LoginRadiusAuth"
    expected_username = "foobar"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_LOGINRADIUS_KEY": "a-key",
            "SOCIAL_AUTH_LOGINRADIUS_SECRET": "a-secret-key",
        }

    def render_context(self) -> dict[str, object]:
        rendered_context: dict[str, object] = {}

        def render_html(tpl=None, html=None, context=None):
            rendered_context.update(context or {})
            return tpl or html or ""

        with patch.object(self.strategy, "render_html", side_effect=render_html):
            self.assertEqual(self.backend.auth_html(), "loginradius.html")

        return rendered_context

    def mock_loginradius_responses(self) -> None:
        responses.add(
            responses.POST,
            self.backend.access_token_url(),
            body=json.dumps({"access_token": "access-token"}),
            content_type="application/json",
        )
        responses.add(
            responses.GET,
            self.backend.PROFILE_URL,
            body=json.dumps(
                {
                    "ID": "user-id",
                    "Provider": "loginradius",
                    "NickName": "foobar",
                    "Email": [{"Value": "foobar@example.com"}],
                    "FullName": "Foo Bar",
                    "FirstName": "Foo",
                    "LastName": "Bar",
                }
            ),
            content_type="application/json",
        )

    def do_start(self):
        context = self.render_context()
        state = self.strategy.session_get("loginradius_state")
        self.strategy.set_request_data(
            {"token": "loginradius-token", "redirect_state": state}, self.backend
        )
        self.mock_loginradius_responses()
        user = self.backend.complete()

        token_request = responses.calls[0].request
        token_query = get_querystring(cast("str", token_request.url))
        self.assertEqual(token_query["token"], "loginradius-token")
        self.assertEqual(token_query["secret"], "a-secret-key")
        self.assertEqual(context["LOGINRADIUS_REDIRECT_STATE"], state)
        return user

    def test_auth_html_creates_redirect_state(self) -> None:
        context = self.render_context()
        state = self.strategy.session_get("loginradius_state")

        self.assertIsNotNone(state)
        self.assertEqual(context["LOGINRADIUS_KEY"], "a-key")
        self.assertEqual(context["LOGINRADIUS_REDIRECT_STATE"], state)
        self.assertEqual(
            get_querystring(cast("str", context["LOGINRADIUS_REDIRECT_URL"]))[
                "redirect_state"
            ],
            state,
        )

    def test_complete_rejects_missing_redirect_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data({"token": "loginradius-token"}, self.backend)

        with self.assertRaises(AuthMissingParameter):
            self.backend.complete()

    def test_complete_rejects_mismatched_redirect_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(
            {"token": "loginradius-token", "redirect_state": "invalid-state"},
            self.backend,
        )

        with self.assertRaises(AuthStateForbidden):
            self.backend.complete()

    def test_login(self) -> None:
        self.do_login()
