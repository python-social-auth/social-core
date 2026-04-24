import json

import responses

from social_core.exceptions import AuthFailed

from .oauth import BaseAuthUrlTestMixin, OAuth2Test

CAPTURE_GITHUB_EMAILS_PIPELINE = (
    "social_core.tests.backends.test_github.capture_github_emails"
)


def capture_github_emails(strategy, response, *args, **kwargs) -> None:
    strategy.session_set("github_emails", response.get("emails"))


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

    def add_emails_response(self, emails) -> None:
        responses.add(
            responses.GET,
            self.emails_url,
            status=200,
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

    def test_login(self) -> None:
        self.add_emails_response(["foo@bar.com"])
        self.do_login()

    def test_login_next_format(self) -> None:
        self.add_emails_response([{"email": "foo@bar.com"}])
        self.do_login()

    def test_pipeline_receives_legacy_email_response(self) -> None:
        emails = ["foo@bar.com"]
        self.add_emails_response(emails)
        self.capture_emails_in_pipeline()

        user = self.do_login()

        self.assertEqual(self.strategy.session_get("github_emails"), emails)
        self.assertEqual(user.email, "foo@bar.com")
        self.assertNotIn("emails", user.social[0].extra_data)

    def test_pipeline_receives_dict_email_response(self) -> None:
        emails = [
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
