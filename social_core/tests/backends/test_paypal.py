import json
from typing import cast
from urllib.parse import parse_qs

import responses

from social_core.backends.paypal import PayPalOAuth2, PayPalOAuth2Sandbox

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class PayPalOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.paypal.PayPalOAuth2"
    user_data_url = (
        "https://api.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1"
    )
    expected_username = "mWq6_1sU85v5EG9yHdPxJRrhGHrnMJ-1PQKtX6pcsmA"
    access_token_body = json.dumps(
        {
            "token_type": "Bearer",
            "expires_in": 28800,
            "refresh_token": "foobar-refresh-token",
            "access_token": "foobar-token",
        }
    )
    user_data_body = json.dumps(
        {
            "user_id": "https://www.paypal.com/webapps/auth/identity/user/mWq6_1sU85v5EG9yHdPxJRrhGHrnMJ-1PQKtX6pcsmA",
            "name": "identity test",
            "given_name": "identity",
            "family_name": "test",
            "payer_id": "WDJJHEBZ4X2LY",
            "address": {
                "street_address": "1 Main St",
                "locality": "San Jose",
                "region": "CA",
                "postal_code": "95131",
                "country": "US",
            },
            "verified_account": True,
            "emails": [{"value": "user1@example.com", "primary": True}],
        }
    )
    refresh_token_body = json.dumps(
        {
            "access_token": "foobar-new-token",
            "token_type": "Bearer",
            "refresh_token": "foobar-new-refresh-token",
            "expires_in": 28800,
        }
    )

    def test_login(self) -> None:
        user = self.do_login()
        self.assertEqual(
            user.social_user.extra_data["refresh_token"], "foobar-refresh-token"
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_refresh_token(self) -> None:
        user, social = self.do_refresh_token()
        self.assertEqual(user.username, self.expected_username)
        self.assertEqual(social.extra_data["access_token"], "foobar-new-token")
        body = parse_qs(cast("str", responses.calls[-1].request.body))
        self.assertEqual(body["grant_type"], ["refresh_token"])
        self.assertEqual(body["refresh_token"], ["foobar-refresh-token"])
        self.assertEqual(social.extra_data["refresh_token"], "foobar-new-refresh-token")
        responses.replace(
            responses.POST,
            self.backend.refresh_token_url(),
            json={"access_token": "second-access-token"},
        )
        social.refresh_token(self.strategy)
        body = parse_qs(cast("str", responses.calls[-1].request.body))
        self.assertEqual(body["refresh_token"], ["foobar-new-refresh-token"])
        self.assertEqual(social.access_token, "second-access-token")
        self.assertEqual(social.extra_data["refresh_token"], "foobar-new-refresh-token")

    def test_get_email_no_emails(self) -> None:
        emails: list[dict[str, str | bool]] = []
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, "")

    def test_sandbox_stores_refresh_token(self) -> None:
        backend = PayPalOAuth2Sandbox(self.strategy)
        assert self.access_token_body is not None
        extra_data = backend.extra_data(
            None, "user-id", json.loads(self.access_token_body), {}, {}
        )
        self.assertEqual(extra_data["refresh_token"], "foobar-refresh-token")

    def test_get_email_multiple_emails(self) -> None:
        expected_email = "mail2@example.com"
        emails: list[dict[str, str | bool]] = [
            {"value": "mail1@example.com", "primary": False},
            {"value": expected_email, "primary": True},
        ]
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, expected_email)

    def test_get_email_multiple_emails_no_primary(self) -> None:
        expected_email = "mail1@example.com"
        emails: list[dict[str, str | bool]] = [
            {"value": expected_email, "primary": False},
            {"value": "mail2@example.com", "primary": False},
        ]
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, expected_email)
