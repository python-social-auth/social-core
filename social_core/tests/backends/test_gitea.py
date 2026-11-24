from __future__ import annotations

import json
from typing import Any
from unittest import TestCase

import responses

from social_core.exceptions import AuthPolicyError

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

ACCESS_TOKEN_BODY = json.dumps(
    {
        "access_token": "foobar",
        "token_type": "bearer",
        "expires_in": 7200,
        "refresh_token": "barfoo",
    }
)

USER_DATA = {
    "id": 123456,
    "login": "foobar",
    "full_name": "Foo Bar",
    "email": "foobar@example.com",
    "language": "en-US",
    "is_admin": False,
    "last_login": "2016-12-28T12:26:19+01:00",
    "created": "2016-12-28T12:26:19+01:00",
    "restricted": False,
    "username": "foobar",
}


def capture_gitea_emails(strategy, response, *args, **kwargs) -> None:
    strategy.session_set("gitea_emails", response.get("emails"))


class TestCaptureGiteaEmails(TestCase):
    class DummyStrategy:
        def __init__(self) -> None:
            self.data: dict[str, Any] = {}

        def session_set(self, key, value) -> None:
            self.data[key] = value

    def test_capture_gitea_emails_missing_emails_key(self) -> None:
        strategy = self.DummyStrategy()

        capture_gitea_emails(strategy, {})

        assert "gitea_emails" in strategy.data
        assert strategy.data["gitea_emails"] is None


class GiteaOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.gitea.GiteaOAuth2"
    user_data_url = "https://gitea.com/api/v1/user"
    emails_url = "https://gitea.com/api/v1/user/emails"
    expected_username = "foobar"
    access_token_body = ACCESS_TOKEN_BODY
    user_data_body = json.dumps(
        {
            **USER_DATA,
            "avatar_url": "https://gitea.com/user/avatar/foobar/-1",
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

    def auth_handlers(self, start_url: str) -> str:
        target_url = super().auth_handlers(start_url)
        self.add_emails_response(
            [
                {
                    "email": "foobar@example.com",
                    "primary": True,
                    "verified": True,
                }
            ]
        )
        return target_url

    def capture_emails_in_pipeline(self) -> None:
        pipeline = self.strategy.get_pipeline(self.backend)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": (
                    pipeline[0],
                    "social_core.tests.backends.test_gitea.capture_gitea_emails",
                    *pipeline[1:],
                )
            }
        )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class GiteaOAuth2EmailsTest(GiteaOAuth2Test):
    def test_login_email_denied(self) -> None:
        self.add_emails_response([], status=403)
        user = self.do_login()
        self.assertEqual(user.email, "foobar@example.com")
        self.assertNotIn("emails", user.social[0].extra_data)

    def test_login_with_empty_email_list(self) -> None:
        self.add_emails_response([])
        user = self.do_login()
        self.assertEqual(user.email, "foobar@example.com")
        self.assertNotIn("emails", user.social[0].extra_data)

    def test_login_prefers_primary_email(self) -> None:
        emails: list[dict[str, str | bool]] = [
            {"email": "secondary@example.com", "primary": False, "verified": True},
            {"email": "foo@bar.com", "primary": True, "verified": True},
        ]
        self.add_emails_response(emails)
        self.capture_emails_in_pipeline()

        user = self.do_login()

        self.assertEqual(self.strategy.session_get("gitea_emails"), emails)
        self.assertEqual(user.email, "foo@bar.com")
        self.assertNotIn("emails", user.social[0].extra_data)

    def test_login_next_format(self) -> None:
        self.add_emails_response(
            [{"email": "foo@bar.com", "primary": True, "verified": True}]
        )
        user = self.do_login()
        self.assertEqual(user.email, "foo@bar.com")

    def test_partial_pipeline(self) -> None:
        self.add_emails_response(
            [{"email": "foo@bar.com", "primary": True, "verified": True}]
        )
        self.do_partial_pipeline()


class GiteaOAuth2EmailDeniedWhitelistTest(GiteaOAuth2Test):
    user_data_body = json.dumps(
        {
            **USER_DATA,
            "email": "other@notallowed.com",
            "avatar_url": "https://gitea.com/user/avatar/foobar/-1",
        }
    )

    def test_login_email_denied_with_domain_whitelist(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GITEA_WHITELISTED_DOMAINS": ["example.com"]}
        )
        self.add_emails_response([], status=403)

        with self.assertRaises(AuthPolicyError):
            self.do_login()


class GiteaCustomDomainOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.gitea.GiteaOAuth2"
    user_data_url = "https://example.com/api/v1/user"
    emails_url = "https://example.com/api/v1/user/emails"
    expected_username = "foobar"
    access_token_body = ACCESS_TOKEN_BODY
    user_data_body = json.dumps(
        {
            **USER_DATA,
            "avatar_url": "https://example.com/user/avatar/foobar/-1",
        }
    )

    def extra_settings(self) -> dict[str, str | list[str]]:
        settings = super().extra_settings()
        settings["SOCIAL_AUTH_GITEA_API_URL"] = "https://example.com"
        return settings

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

    def auth_handlers(self, start_url: str) -> str:
        target_url = super().auth_handlers(start_url)
        self.add_emails_response(
            [
                {
                    "email": "foobar@example.com",
                    "primary": True,
                    "verified": True,
                }
            ]
        )
        return target_url

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_login_includes_secondary_emails(self) -> None:
        emails: list[dict[str, str | bool]] = [
            {"email": "git@example.com", "primary": False, "verified": True},
            {"email": "foobar@example.com", "primary": True, "verified": True},
        ]
        self.add_emails_response(emails)
        pipeline = self.strategy.get_pipeline(self.backend)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_PIPELINE": (
                    pipeline[0],
                    "social_core.tests.backends.test_gitea.capture_gitea_emails",
                    *pipeline[1:],
                )
            }
        )

        user = self.do_login()

        self.assertEqual(self.strategy.session_get("gitea_emails"), emails)
        self.assertEqual(user.email, "foobar@example.com")
        self.assertNotIn("emails", user.social[0].extra_data)
