import json
from urllib.parse import parse_qs, urlparse

import responses

from social_core.exceptions import (
    AuthConfigurationError,
    AuthProviderError,
    AuthResponseError,
)

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class GitLabOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.gitlab.GitLabOAuth2"
    user_data_url = "https://gitlab.com/api/v4/user"
    expected_username = "foobar"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
            "expires_in": 7200,
            "refresh_token": "barfoo",
        }
    )
    user_data_body = json.dumps(
        {
            "two_factor_enabled": False,
            "can_create_project": True,
            "confirmed_at": "2016-12-28T12:26:19.256Z",
            "twitter": "",
            "linkedin": "",
            "color_scheme_id": 1,
            "web_url": "https://gitlab.com/foobar",
            "skype": "",
            "identities": [],
            "id": 123456,
            "projects_limit": 100000,
            "current_sign_in_at": "2016-12-28T12:26:19.795Z",
            "state": "active",
            "location": None,
            "email": "foobar@example.com",
            "website_url": "",
            "username": "foobar",
            "bio": None,
            "last_sign_in_at": "2016-12-28T12:26:19.795Z",
            "is_admin": False,
            "external": False,
            "organization": None,
            "name": "Foo Bar",
            "can_create_group": True,
            "created_at": "2016-12-28T12:26:19.638Z",
            "avatar_url": "https://secure.gravatar.com/avatar/94d093eda664addd6e450d7e9881bcae?s=32&d=identicon",
            "theme_id": 2,
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_group_extraction_requests_api_scope(self) -> None:
        query = parse_qs(urlparse(self.backend.auth_url()).query)
        self.assertEqual(query["scope"], ["read_user"])
        self.strategy.set_settings({"SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True})
        query = parse_qs(urlparse(self.backend.auth_url()).query)
        self.assertEqual(query["scope"], ["read_user read_api"])

    def test_group_scope_preserves_configured_api_permissions(self) -> None:
        for scope, expected in (
            (["read_api"], ["read_api"]),
            (["api"], ["api"]),
            (["read_repository"], ["read_repository", "read_api"]),
        ):
            with self.subTest(scope=scope):
                self.strategy.set_settings(
                    {
                        "SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True,
                        "SOCIAL_AUTH_GITLAB_IGNORE_DEFAULT_SCOPE": True,
                        "SOCIAL_AUTH_GITLAB_SCOPE": scope,
                    }
                )
                query = parse_qs(urlparse(self.backend.auth_url()).query)
                self.assertEqual(query["scope"], [" ".join(expected)])
                self.assertEqual(self.backend.get_scope(), expected)
                self.assertEqual(self.backend.setting("SCOPE"), scope)

    def test_group_paths_are_paginated_and_filtered(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True})
        responses.add(responses.GET, self.user_data_url, json={"id": 123456})
        url = "https://gitlab.com/api/v4/groups"
        responses.add(
            responses.GET,
            url,
            json=[{"id": 1, "full_path": "org/translators"}],
            headers={"X-Next-Page": "2"},
        )
        responses.add(
            responses.GET,
            url,
            json=[{"id": 2, "full_path": "org/reviewers"}],
            headers={"X-Next-Page": ""},
        )
        data = self.backend.user_data("token")
        self.assertEqual(
            self.backend.get_user_groups(data), ["org/translators", "org/reviewers"]
        )
        for page, call in enumerate(responses.calls[1:], 1):
            query = parse_qs(urlparse(str(call.request.url)).query)
            self.assertEqual(query["all_available"], ["false"])
            self.assertEqual(query["min_access_level"], ["5"])
            self.assertEqual(query["page"], [str(page)])
            self.assertEqual(call.request.headers["Authorization"], "Bearer token")

    def test_group_ids_and_self_hosted_instance(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True,
                "SOCIAL_AUTH_GITLAB_GROUPS_IDENTIFIER": "id",
                "SOCIAL_AUTH_GITLAB_API_URL": "https://gitlab.example.com",
            }
        )
        responses.add(
            responses.GET, "https://gitlab.example.com/api/v4/user", json={"id": 123456}
        )
        responses.add(
            responses.GET,
            "https://gitlab.example.com/api/v4/groups",
            json=[{"id": 123, "full_path": "org/team"}],
        )
        self.assertEqual(
            self.backend.get_user_groups(self.backend.user_data("token")), ["123"]
        )

    def test_group_pagination_without_next_page_header(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True})
        responses.add(responses.GET, self.user_data_url, json={"id": 123456})
        url = "https://gitlab.com/api/v4/groups"
        expected = [f"org/team-{number}" for number in range(101)]
        responses.add(
            responses.GET, url, json=[{"full_path": name} for name in expected[:100]]
        )
        responses.add(responses.GET, url, json=[{"full_path": expected[100]}])

        self.assertEqual(
            self.backend.get_user_groups(self.backend.user_data("token")), expected
        )
        self.assertEqual(len(responses.calls), 3)
        self.assertEqual(
            parse_qs(urlparse(str(responses.calls[2].request.url)).query)["page"], ["2"]
        )

    def test_invalid_group_json_is_wrapped(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True})
        responses.add(responses.GET, self.user_data_url, json={"id": 123456})
        responses.add(
            responses.GET,
            "https://gitlab.com/api/v4/groups",
            body="not JSON",
            content_type="application/json",
        )

        with self.assertRaises(AuthResponseError) as caught:
            self.backend.user_data("token")
        self.assertEqual(caught.exception.code, "malformed_response")
        self.assertEqual(caught.exception.stage, "user_info")
        self.assertIsInstance(caught.exception.__cause__, ValueError)

    def test_group_retrieval_failure_does_not_return_partial_list(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True})
        responses.add(responses.GET, self.user_data_url, json={"id": 123456})
        url = "https://gitlab.com/api/v4/groups"
        responses.add(
            responses.GET,
            url,
            json=[{"full_path": "org/team"}],
            headers={"X-Next-Page": "2"},
        )
        responses.add(responses.GET, url, status=403)
        with self.assertRaises(AuthProviderError):
            self.backend.user_data("token")

    def test_malformed_group_responses_and_pagination(self) -> None:
        for payload, headers in (
            ({}, {}),
            ([{}], {}),
            ([{"full_path": "team"}], {"X-Next-Page": "1"}),
        ):
            responses.reset()
            responses.add(responses.GET, self.user_data_url, json={"id": 123456})
            responses.add(
                responses.GET,
                "https://gitlab.com/api/v4/groups",
                json=payload,
                headers=headers,
            )
            self.strategy.set_settings({"SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True})
            with (
                self.subTest(payload=payload, headers=headers),
                self.assertRaises(AuthResponseError),
            ):
                self.backend.user_data("token")

    def test_invalid_group_identifier(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_GITLAB_GROUPS_ENABLED": True,
                "SOCIAL_AUTH_GITLAB_GROUPS_IDENTIFIER": "name",
            }
        )
        responses.add(responses.GET, self.user_data_url, json={"id": 123456})
        with self.assertRaises(AuthConfigurationError):
            self.backend.user_data("token")


class GitLabCustomDomainOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.gitlab.GitLabOAuth2"
    user_data_url = "https://example.com/api/v4/user"
    expected_username = "foobar"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
            "expires_in": 7200,
            "refresh_token": "barfoo",
        }
    )
    user_data_body = json.dumps(
        {
            "two_factor_enabled": False,
            "can_create_project": True,
            "confirmed_at": "2016-12-28T12:26:19.256Z",
            "twitter": "",
            "linkedin": "",
            "color_scheme_id": 1,
            "web_url": "https://example.com/foobar",
            "skype": "",
            "identities": [],
            "id": 123456,
            "projects_limit": 100000,
            "current_sign_in_at": "2016-12-28T12:26:19.795Z",
            "state": "active",
            "location": None,
            "email": "foobar@example.com",
            "website_url": "",
            "username": "foobar",
            "bio": None,
            "last_sign_in_at": "2016-12-28T12:26:19.795Z",
            "is_admin": False,
            "external": False,
            "organization": None,
            "name": "Foo Bar",
            "can_create_group": True,
            "created_at": "2016-12-28T12:26:19.638Z",
            "avatar_url": "https://secure.gravatar.com/avatar/94d093eda664addd6e450d7e9881bcae?s=32&d=identicon",
            "theme_id": 2,
        }
    )

    def test_login(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GITLAB_API_URL": "https://example.com"}
        )
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GITLAB_API_URL": "https://example.com"}
        )
        self.do_partial_pipeline()
