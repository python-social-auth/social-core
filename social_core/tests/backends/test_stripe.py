# pyright: reportAttributeAccessIssue=false
import json

import requests
import responses

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class StripeOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
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

    def setUp(self):
        super().setUp()
        responses.add(
            responses.GET, self.account_data_url, status=200, body=self.user_data_body
        )

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()

    def test_get_user_details(self):
        response = requests.get(self.account_data_url, timeout=1)
        user_details = self.backend.get_user_details(response.json())
        self.assertEqual(user_details["email"], "foobar@yahoo.com")
