import json
import time

import responses

from social_core.utils import parse_qs

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class MicrosoftOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.microsoft.MicrosoftOAuth2"
    user_data_url = "https://graph.microsoft.com/v1.0/me"
    expected_username = "foobar"
    user_data_body = json.dumps(
        {
            "displayName": "foo bar",
            "givenName": "foobar",
            "jobTitle": "Auditor",
            "mail": "foobar@foobar.com",
            "mobilePhone": None,
            "officeLocation": "12/1110",
            "preferredLanguage": "en-US",
            "surname": "Bowen",
            "userPrincipalName": "foobar",
            "id": "48d31887-5fad-4d73-a9f5-3c356e68a038",
        }
    )
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
            "id_token": "",
            "expires_in": 3600,
            "expires_on": 1423650396,
            "not_before": 1423646496,
            "refresh_token": "foobar-refresh-token",
        }
    )
    refresh_token_body = json.dumps(
        {
            "access_token": "foobar-new-token",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "foobar-new-refresh-token",
            "scope": "identity",
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        social = user.social[0]
        self.assertEqual(social.extra_data["refresh_token"], "foobar-refresh-token")
        self.assertEqual(social.extra_data["expires_in"], 3600)

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        _user, social = self.do_refresh_token()
        self.assertEqual(social.extra_data["access_token"], "foobar-new-token")
        self.assertEqual(social.extra_data["refresh_token"], "foobar-new-refresh-token")
        self.assertEqual(
            parse_qs(responses.calls[-1].request.body)["refresh_token"],
            "foobar-refresh-token",
        )

    def test_get_access_token_refreshes_expired_token(self) -> None:
        user = self.do_login()
        responses.add(
            self._method(self.backend.REFRESH_TOKEN_METHOD),
            self.backend.refresh_token_url(),
            status=200,
            body=self.refresh_token_body,
        )
        social = user.social[0]
        social.extra_data["auth_time"] = int(time.time()) - 7200
        self.assertEqual(social.get_access_token(self.strategy), "foobar-new-token")
        self.assertEqual(social.extra_data["refresh_token"], "foobar-new-refresh-token")

    def test_get_auth_token_refreshes_expired_token(self) -> None:
        user = self.do_login()
        responses.add(
            self._method(self.backend.REFRESH_TOKEN_METHOD),
            self.backend.refresh_token_url(),
            status=200,
            body=self.refresh_token_body,
        )
        user.social_user.extra_data["auth_time"] = int(time.time()) - 7200
        self.assertEqual(self.backend.get_auth_token(user.id), "foobar-new-token")
