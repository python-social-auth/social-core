import json

import responses

from social_core.exceptions import (
    AuthConfigurationError,
    AuthCredentialError,
    AuthProviderError,
    AuthResponseError,
)
from social_core.tests.models import User

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class BitbucketOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.bitbucket.BitbucketOAuth2"

    access_token_body = json.dumps(
        {
            "access_token": "foobar_access",
            "scopes": "foo_scope",
            "expires_in": 3600,
            "refresh_token": "foobar_refresh",
            "token_type": "bearer",
        }
    )
    user_data_url = "https://api.bitbucket.org/2.0/user"
    expected_username = "foobar"
    bb_api_user_emails = "https://api.bitbucket.org/2.0/user/emails"

    user_data_body = json.dumps(
        {
            "created_on": "2012-03-29T18:07:38+00:00",
            "display_name": "Foo Bar",
            "links": {
                "avatar": {"href": "https://bitbucket.org/account/foobar/avatar/32/"},
                "followers": {
                    "href": "https://api.bitbucket.org/2.0/users/foobar/followers"
                },
                "following": {
                    "href": "https://api.bitbucket.org/2.0/users/foobar/following"
                },
                "hooks": {"href": "https://api.bitbucket.org/2.0/users/foobar/hooks"},
                "html": {"href": "https://bitbucket.org/foobar"},
                "repositories": {
                    "href": "https://api.bitbucket.org/2.0/repositories/foobar"
                },
                "self": {"href": "https://api.bitbucket.org/2.0/users/foobar"},
            },
            "location": "Fooville, Bar",
            "type": "user",
            "username": "foobar",
            "uuid": "{397621dc-0f78-329f-8d6d-727396248e3f}",
            "website": "http://foobar.com",
        }
    )

    emails_body = json.dumps(
        {
            "page": 1,
            "pagelen": 10,
            "size": 2,
            "values": [
                {
                    "email": "foo@bar.com",
                    "is_confirmed": True,
                    "is_primary": True,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/user/emails/foo@bar.com"
                        }
                    },
                    "type": "email",
                },
                {
                    "email": "not@confirme.com",
                    "is_confirmed": False,
                    "is_primary": False,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/user/emails/not@confirmed.com"
                        }
                    },
                    "type": "email",
                },
            ],
        }
    )

    def test_login(self) -> None:
        responses.add(
            responses.GET, self.bb_api_user_emails, status=200, body=self.emails_body
        )
        self.do_login()

    def test_partial_pipeline(self) -> None:
        responses.add(
            responses.GET, self.bb_api_user_emails, status=200, body=self.emails_body
        )
        self.do_partial_pipeline()

    def refresh_with_response(self, status: int, body: str) -> None:
        responses.add(
            responses.GET, self.bb_api_user_emails, status=200, body=self.emails_body
        )
        self.do_login()
        responses.add(
            responses.POST, self.backend.refresh_token_url(), status=status, body=body
        )
        user = next(iter(User.cache.values()))
        user.social[0].refresh_token(strategy=self.strategy)

    def assert_requires_reauthentication(
        self, status: int, provider_code: str, description: str
    ) -> None:
        body = json.dumps({"error": provider_code, "error_description": description})
        with self.assertRaises(AuthCredentialError) as context:
            self.refresh_with_response(status, body)
        self.assertEqual(context.exception.code, "reauthentication_required")
        self.assertEqual(context.exception.stage, "refresh")
        self.assertEqual(context.exception.status_code, status)
        self.assertEqual(context.exception.provider_code, provider_code)

    def test_expired_refresh_token_requires_reauthentication(self) -> None:
        self.assert_requires_reauthentication(
            400, "invalid_request", "Invalid refresh_token"
        )

    def test_inactive_user_refresh_requires_reauthentication(self) -> None:
        self.assert_requires_reauthentication(401, "access_denied", "User is inactive")

    def test_unauthorized_refresh_without_error_code_is_unchanged(self) -> None:
        with self.assertRaises(AuthProviderError) as context:
            self.refresh_with_response(401, "Unauthorized")
        self.assertEqual(context.exception.code, "http_error")

    def test_other_refresh_errors_are_unchanged(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            self.refresh_with_response(400, json.dumps({"error": "invalid_client"}))

    def test_refresh_outage_is_unchanged(self) -> None:
        with self.assertRaises(AuthProviderError) as context:
            self.refresh_with_response(503, "")
        self.assertEqual(context.exception.code, "unavailable")


class BitbucketOAuth2FailTest(BitbucketOAuth2Test):
    emails_body = json.dumps(
        {
            "page": 1,
            "pagelen": 10,
            "size": 1,
            "values": [
                {
                    "email": "foo@bar.com",
                    "is_confirmed": False,
                    "is_primary": True,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/user/emails/foo@bar.com"
                        }
                    },
                    "type": "email",
                }
            ],
        }
    )

    def test_login(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_BITBUCKET_OAUTH2_VERIFIED_EMAILS_ONLY": True}
        )
        with self.assertRaises(AuthResponseError):
            super().test_login()

    def test_partial_pipeline(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_BITBUCKET_OAUTH2_VERIFIED_EMAILS_ONLY": True}
        )
        with self.assertRaises(AuthResponseError):
            super().test_partial_pipeline()
