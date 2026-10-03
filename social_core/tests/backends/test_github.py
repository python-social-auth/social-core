import json
from typing import Any, cast
from unittest import TestCase

import responses

from social_core.exceptions import (
    AuthCanceled,
    AuthFailed,
    AuthMissingParameter,
    AuthStateForbidden,
)
from social_core.utils import get_querystring, parse_qs

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test

CAPTURE_GITHUB_EMAILS_PIPELINE = (
    "social_core.tests.backends.test_github.capture_github_emails"
)


def capture_github_emails(strategy, response, *args, **kwargs) -> None:
    strategy.session_set("github_emails", response.get("emails"))


class TestCaptureGithubEmails(TestCase):
    class DummyStrategy:
        def __init__(self) -> None:
            self.data: dict[str, Any] = {}

        def session_set(self, key, value) -> None:
            self.data[key] = value

    def test_capture_github_emails_missing_emails_key(self) -> None:
        strategy = self.DummyStrategy()

        capture_github_emails(strategy, {})

        assert "github_emails" in strategy.data
        assert strategy.data["github_emails"] is None

    def test_capture_github_emails_response_none_raises_attribute_error(self) -> None:
        strategy = self.DummyStrategy()

        with self.assertRaises(AttributeError):
            capture_github_emails(strategy, None)


class GithubOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.github.GithubOAuth2"
    user_data_url = "https://api.github.com/user"
    expected_username = "foobar"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
            "expires_in": 28800,
            "refresh_token": "foobar-refresh-token",
        }
    )
    refresh_token_body = json.dumps(
        {
            "access_token": "foobar-new-token",
            "token_type": "bearer",
            "expires_in": 28800,
            "refresh_token": "foobar-new-refresh-token",
            "refresh_token_expires_in": 15897600,
            "scope": "",
        }
    )
    user_data_body = json.dumps(
        {
            "login": "foobar",
            "id": 1,
            "avatar_url": "https://github.com/images/error/foobar_happy.gif",
            "gravatar_id": "somehexcode",
            "url": "https://api.github.com/users/foobar",
            "name": "monalisa foobar",
            "company": "GitHub",
            "blog": "https://github.com/blog",
            "location": "San Francisco",
            "email": "foo@bar.com",
            "hireable": False,
            "bio": "There once was...",
            "public_repos": 2,
            "public_gists": 1,
            "followers": 20,
            "following": 0,
            "html_url": "https://github.com/foobar",
            "created_at": "2008-01-14T04:33:35Z",
            "type": "User",
            "total_private_repos": 100,
            "owned_private_repos": 100,
            "private_gists": 81,
            "disk_usage": 10000,
            "collaborators": 8,
            "plan": {
                "name": "Medium",
                "space": 400,
                "collaborators": 10,
                "private_repos": 20,
            },
        }
    )

    def do_login(self):
        user = super().do_login()
        self.assertTrue(user.social)
        social = user.social[0]

        self.assertIsNotNone(social.extra_data["expires_in"])
        self.assertIsNotNone(social.extra_data["refresh_token"])

        return user

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        _user, social = self.do_refresh_token()
        self.assertEqual(social.extra_data["access_token"], "foobar-new-token")


class GithubAppAuthTest(GithubOAuth2Test, OAuth2StateTestMixin):
    backend_path = "social_core.backends.github.GithubAppAuth"

    @staticmethod
    def installation_callback_data(
        state: str | None = None, code: str = "installation-code"
    ) -> dict[str, str]:
        data = {
            "code": code,
            "installation_id": "12345",
            "setup_action": "install",
        }
        if state is not None:
            data["state"] = state
        return data

    def test_installation_callback_without_state_restarts_oauth(self) -> None:
        self.strategy.set_request_data(self.installation_callback_data(), self.backend)

        redirect = self.backend.complete()

        self.assertTrue(redirect.url.startswith(self.backend.authorization_url()))
        state = get_querystring(redirect.url).get("state")
        self.assertIsNotNone(state)
        self.assertEqual(state, self.backend.get_session_state())
        self.assertEqual(len(responses.calls), 0)

    def test_restarted_oauth_exchanges_only_fresh_code(self) -> None:
        self.strategy.set_request_data(
            self.installation_callback_data(code="untrusted-installation-code"),
            self.backend,
        )
        redirect = self.backend.complete()
        state = get_querystring(redirect.url)["state"]

        self.strategy.set_request_data(
            {"code": "state-bound-code", "state": state}, self.backend
        )
        self.pre_complete_callback(redirect.url)
        responses.add(
            responses.GET,
            self.user_data_url,
            body=self.user_data_body,
            content_type="application/json",
        )

        user = self.backend.complete()

        token_request = next(
            call.request
            for call in responses.calls
            if cast("str", call.request.url).startswith(self.backend.access_token_url())
        )
        self.assertEqual(parse_qs(token_request.body)["code"], "state-bound-code")
        self.assertEqual(user.username, self.expected_username)

    def test_incomplete_installation_callback_rejects_missing_state(self) -> None:
        for missing_name in ("code", "installation_id", "setup_action"):
            with self.subTest(missing_name=missing_name):
                data = self.installation_callback_data()
                data.pop(missing_name)
                self.strategy.request_data().clear()
                self.strategy.set_request_data(data, self.backend)

                with self.assertRaises(AuthMissingParameter):
                    self.backend.complete()

        self.assertEqual(len(responses.calls), 0)

    def test_installation_callback_preserves_provider_errors(self) -> None:
        data = self.installation_callback_data()
        data["error"] = "access_denied"
        self.strategy.set_request_data(data, self.backend)

        with self.assertRaises(AuthCanceled):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)

    def test_installation_callback_rejects_mismatched_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(
            self.installation_callback_data("attacker-state"), self.backend
        )

        with self.assertRaises(AuthStateForbidden):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)

    def test_installation_callback_accepts_matching_state(self) -> None:
        start_url = self.backend.start().url
        state = self.backend.get_session_state()
        self.strategy.set_request_data(
            self.installation_callback_data(state), self.backend
        )
        self.pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            self.user_data_url,
            body=self.user_data_body,
            content_type="application/json",
        )

        user = self.backend.complete()

        self.assertEqual(user.username, self.expected_username)


class GithubOAuth2NoEmailTest(GithubOAuth2Test):
    emails_url = "https://api.github.com/user/emails"
    user_data_body = json.dumps(
        {
            "login": "foobar",
            "id": 1,
            "avatar_url": "https://github.com/images/error/foobar_happy.gif",
            "gravatar_id": "somehexcode",
            "url": "https://api.github.com/users/foobar",
            "name": "monalisa foobar",
            "company": "GitHub",
            "blog": "https://github.com/blog",
            "location": "San Francisco",
            "email": "",
            "hireable": False,
            "bio": "There once was...",
            "public_repos": 2,
            "public_gists": 1,
            "followers": 20,
            "following": 0,
            "html_url": "https://github.com/foobar",
            "created_at": "2008-01-14T04:33:35Z",
            "type": "User",
            "total_private_repos": 100,
            "owned_private_repos": 100,
            "private_gists": 81,
            "disk_usage": 10000,
            "collaborators": 8,
            "plan": {
                "name": "Medium",
                "space": 400,
                "collaborators": 10,
                "private_repos": 20,
            },
        }
    )

    def add_emails_response(
        self, emails: list[dict[str, str | bool]], status: int = 200
    ) -> None:
        responses.add(
            responses.GET,
            self.emails_url,
            status=status,
            body=json.dumps(emails),
            content_type="application/json",
        )

    def capture_emails_in_pipeline(self) -> None:
        pipeline = self.strategy.get_pipeline(self.backend)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": (
                    pipeline[0],
                    CAPTURE_GITHUB_EMAILS_PIPELINE,
                    *pipeline[1:],
                )
            }
        )

    def test_login_email_denied(self) -> None:
        self.add_emails_response([], status=403)
        self.do_login()

    def test_login_with_empty_email_list(self) -> None:
        self.add_emails_response([])
        user = self.do_login()
        self.assertNotIn("emails", user.social[0].extra_data)

    def test_login_next_format(self) -> None:
        self.add_emails_response([{"email": "foo@bar.com"}])
        user = self.do_login()
        self.assertEqual(user.email, "foo@bar.com")

    def test_login(self) -> None:
        emails: list[dict[str, str | bool]] = [
            {"email": "secondary@example.com", "primary": False},
            {"email": "foo@bar.com", "primary": True},
        ]
        self.add_emails_response(emails)
        self.capture_emails_in_pipeline()

        user = self.do_login()

        self.assertEqual(self.strategy.session_get("github_emails"), emails)
        self.assertEqual(user.email, "foo@bar.com")
        self.assertNotIn("emails", user.social[0].extra_data)

    def test_partial_pipeline(self) -> None:
        self.add_emails_response([{"email": "foo@bar.com"}])
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        self.add_emails_response([{"email": "foo@bar.com"}])
        self.do_refresh_token()


class GithubOrganizationOAuth2Test(GithubOAuth2Test):
    backend_path = "social_core.backends.github.GithubOrganizationOAuth2"

    def auth_handlers(self, start_url):
        url = "https://api.github.com/orgs/foobar/members/foobar"
        responses.add(responses.GET, url, status=204, body="")
        return super().auth_handlers(start_url)

    def test_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_ORG_NAME": "foobar"})
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_ORG_NAME": "foobar"})
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_ORG_NAME": "foobar"})
        self.do_refresh_token()


class GithubOrganizationOAuth2FailTest(GithubOAuth2Test):
    backend_path = "social_core.backends.github.GithubOrganizationOAuth2"

    def auth_handlers(self, start_url):
        url = "https://api.github.com/orgs/foobar/members/foobar"
        responses.add(
            responses.GET,
            url,
            status=404,
            body='{"message": "Not Found"}',
            content_type="application/json",
        )
        return super().auth_handlers(start_url)

    def test_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_ORG_NAME": "foobar"})
        with self.assertRaises(AuthFailed):
            self.do_login()

    def test_partial_pipeline(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_ORG_NAME": "foobar"})
        with self.assertRaises(AuthFailed):
            self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_ORG_NAME": "foobar"})
        with self.assertRaises(AuthFailed):
            self.do_refresh_token()


class GithubTeamOAuth2Test(GithubOAuth2Test):
    backend_path = "social_core.backends.github.GithubTeamOAuth2"

    def auth_handlers(self, start_url):
        url = "https://api.github.com/teams/123/members/foobar"
        responses.add(responses.GET, url, status=204, body="")
        return super().auth_handlers(start_url)

    def test_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_TEAM_ID": "123"})
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_TEAM_ID": "123"})
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_TEAM_ID": "123"})
        self.do_refresh_token()


class GithubTeamOAuth2FailTest(GithubOAuth2Test):
    backend_path = "social_core.backends.github.GithubTeamOAuth2"

    def auth_handlers(self, start_url):
        url = "https://api.github.com/teams/123/members/foobar"
        responses.add(
            responses.GET,
            url,
            status=404,
            body='{"message": "Not Found"}',
            content_type="application/json",
        )
        return super().auth_handlers(start_url)

    def test_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_TEAM_ID": "123"})
        with self.assertRaises(AuthFailed):
            self.do_login()

    def test_partial_pipeline(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_TEAM_ID": "123"})
        with self.assertRaises(AuthFailed):
            self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITHUB_TEAM_ID": "123"})
        with self.assertRaises(AuthFailed):
            self.do_refresh_token()
