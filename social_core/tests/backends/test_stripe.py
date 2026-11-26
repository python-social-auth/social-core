import json
from unittest.mock import Mock

import requests
import responses

from social_core.actions import do_auth, do_complete
from social_core.exceptions import AuthSessionError
from social_core.tests.models import TestUserSocialAuth, User
from social_core.utils import get_querystring

from .base import BaseBackendTest


class StripeOAuth2Test(BaseBackendTest):
    backend_path = "social_core.backends.stripe.StripeOAuth2"
    account_data_url = "https://api.stripe.com/v1/account"
    access_token_body = json.dumps(
        {
            "stripe_publishable_key": "pk_test_foobar",
            "access_token": "foobar",
            "livemode": False,
            "token_type": "bearer",
            "scope": "read_only",
            "refresh_token": "rt_foobar",
            "stripe_user_id": "acct_foobar",
        }
    )
    expected_username = "acct_foobar"
    user_data_body = json.dumps(
        {
            "id": "acct_1LUYJiECsxMRIeT8",
            "object": "account",
            "country": "FR",
            "created": 1659974194,
            "default_currency": "eur",
            "details_submitted": True,
            "email": "foobar@yahoo.com",
            "type": "express",
        }
    )

    def setUp(self) -> None:
        super().setUp()
        self.strategy.set_settings(self.extra_settings())
        responses.add(
            responses.GET, self.account_data_url, status=200, body=self.user_data_body
        )

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_STRIPE_KEY": "a-key",
            "SOCIAL_AUTH_STRIPE_SECRET": "a-secret-key",
            "SOCIAL_AUTH_LOGIN_REDIRECT_URL": "/done",
        }

    def test_login(self) -> None:
        with self.assertRaises(AuthSessionError):
            do_auth(self.backend)

    def test_association_requires_initiating_user(self) -> None:
        user = User("owner")
        state = get_querystring(do_auth(self.backend, user=user).url)["state"]
        self.strategy.set_request_data({"code": "foobar", "state": state}, self.backend)
        with self.assertRaises(AuthSessionError):
            do_complete(self.backend, login=Mock(), user=User("other"))
        self.assertIsNone(TestUserSocialAuth.get_social_auth("stripe", "acct_foobar"))

    def test_association_for_initiating_user(self) -> None:
        user = User("owner")
        state = get_querystring(do_auth(self.backend, user=user).url)["state"]
        self.strategy.set_request_data({"code": "foobar", "state": state}, self.backend)
        responses.add(
            responses.POST,
            self.backend.access_token_url(),
            status=200,
            body=self.access_token_body,
            content_type="application/json",
        )
        self.assertEqual(
            do_complete(self.backend, login=Mock(), user=user).url, "/done"
        )
        social = TestUserSocialAuth.get_social_auth("stripe", "acct_foobar")
        self.assertIsNotNone(social)
        self.assertIs(social.user, user)

    def test_get_user_details(self) -> None:
        response = requests.get(self.account_data_url, timeout=1)
        user_details = self.backend.get_user_details(response.json())
        self.assertEqual(user_details["email"], "foobar@yahoo.com")
