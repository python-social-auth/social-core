from __future__ import annotations

import json

from social_core.exceptions import AuthException, AuthPolicyError, AuthResponseError
from social_core.pipeline import DEFAULT_AUTH_PIPELINE
from social_core.tests.models import User

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class SlackOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.slack.SlackOAuth2"
    user_data_url = "https://slack.com/api/users.identity"
    access_token_body = json.dumps({"access_token": "foobar", "token_type": "bearer"})
    user_data_body = json.dumps(
        {
            "ok": True,
            "user": {"email": "foobar@example.com", "name": "Foo Bar", "id": "123456"},
            "team": {"id": "456789"},
            "scope": "identity.basic,identity.email",
        }
    )
    expected_username = "foobar"

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()


class SlackOAuth2TestTeamName(SlackOAuth2Test):
    expected_username = "foobar@Square"
    user_data_body = json.dumps(
        {
            "ok": True,
            "user": {"email": "foobar@example.com", "name": "Foo Bar", "id": "123456"},
            "team": {
                "id": "456789",
                "name": "Square",
            },
            "scope": "identity.basic,identity.email,identity.team",
        }
    )


class SlackOAuth2TestUnicodeTeamName(SlackOAuth2Test):
    user_data_body = json.dumps(
        {
            "ok": True,
            "user": {"email": "foobar@example.com", "name": "Foo Bar", "id": "123456"},
            "team": {
                "id": "456789",
                "name": "Square \u221a team",
            },
            "scope": "identity.basic,identity.email,identity.team",
        }
    )

    def test_login(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_SLACK_USERNAME_WITH_TEAM": False})
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_SLACK_USERNAME_WITH_TEAM": False})
        self.do_partial_pipeline()


class SlackOAuth2TeamRestrictionTest(SlackOAuth2Test):
    def setUp(self) -> None:
        super().setUp()
        self.strategy.set_settings({"SOCIAL_AUTH_SLACK_TEAM": "456789"})

    def assert_rejected(self, exception: type[AuthException]) -> AuthException:
        with self.assertRaises(exception) as caught:
            self.do_start()
        self.assertEqual(caught.exception.stage, "user_info")
        self.assertFalse(User.cache)
        return caught.exception

    def test_other_team(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_SLACK_TEAM": "T0ALLOWED"})
        error = self.assert_rejected(AuthPolicyError)
        self.assertEqual(error.code, "membership_required")

    def test_other_team_with_partial_pipeline(self) -> None:
        self.pipeline_settings()
        self.strategy.set_settings({"SOCIAL_AUTH_SLACK_TEAM": "T0ALLOWED"})
        self.assert_rejected(AuthPolicyError)

    def test_other_team_without_auth_allowed_pipeline_step(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_SLACK_TEAM": "T0ALLOWED",
                "SOCIAL_AUTH_PIPELINE": tuple(
                    step
                    for step in DEFAULT_AUTH_PIPELINE
                    if step != "social_core.pipeline.social_auth.auth_allowed"
                ),
            }
        )
        self.assert_rejected(AuthPolicyError)

    def test_missing_team(self) -> None:
        assert self.user_data_body is not None
        data = json.loads(self.user_data_body)
        del data["team"]
        self.user_data_body = json.dumps(data)
        error = self.assert_rejected(AuthResponseError)
        self.assertEqual(error.code, "missing_claim")

    def test_malformed_team(self) -> None:
        assert self.user_data_body is not None
        data = json.loads(self.user_data_body)
        data["team"] = "456789"
        self.user_data_body = json.dumps(data)
        self.assert_rejected(AuthResponseError)

    def test_failed_identity_response(self) -> None:
        self.user_data_body = json.dumps({"ok": False, "error": "invalid_auth"})
        error = self.assert_rejected(AuthResponseError)
        self.assertEqual(error.code, "malformed_response")
