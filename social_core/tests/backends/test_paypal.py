import json

from .oauth import OAuth2Test
<<<<<<< HEAD
<<<<<<< HEAD
from social_core.backends.paypal import PayPalOAuth2
=======
>>>>>>> 832a896 (Implement PayPal backend)
=======
from social_core.backends.paypal import PayPalOAuth2
>>>>>>> 8306f4e (Fix email selection and add tests for it)


class PayPalOAuth2Test(OAuth2Test):
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

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()

    def test_refresh_token(self):
        user, social = self.do_refresh_token()
        self.assertEqual(user.username, self.expected_username)
        self.assertEqual(social.extra_data["access_token"], "foobar-new-token")
<<<<<<< HEAD
<<<<<<< HEAD

    def test_get_email_no_emails(self):
        emails = []
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, "")
=======

    def test_get_email_no_emails(self):
        emails = []
<<<<<<< HEAD
        primary_email = PayPalOAuth2.get_email(emails)
        self.assertEqual(primary_email, "")
>>>>>>> 8306f4e (Fix email selection and add tests for it)
=======
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, "")
>>>>>>> 2b13af7 (Variable renaming)

    def test_get_email_multiple_emails(self):
        expected_email = "mail2@example.com"
        emails = [
            {"value": "mail1@example.com", "primary": False},
            {"value": expected_email, "primary": True},
        ]
<<<<<<< HEAD
<<<<<<< HEAD
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, expected_email)
=======
        primary_email = PayPalOAuth2.get_email(emails)
        self.assertEqual(primary_email, expected_email)
>>>>>>> 8306f4e (Fix email selection and add tests for it)
=======
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, expected_email)
>>>>>>> 2b13af7 (Variable renaming)

    def test_get_email_multiple_emails_no_primary(self):
        expected_email = "mail1@example.com"
        emails = [
            {"value": expected_email, "primary": False},
            {"value": "mail2@example.com", "primary": False},
        ]
<<<<<<< HEAD
<<<<<<< HEAD
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, expected_email)
=======
>>>>>>> 832a896 (Implement PayPal backend)
=======
        primary_email = PayPalOAuth2.get_email(emails)
        self.assertEqual(primary_email, expected_email)
>>>>>>> 8306f4e (Fix email selection and add tests for it)
=======
        email = PayPalOAuth2.get_email(emails)
        self.assertEqual(email, expected_email)
>>>>>>> 2b13af7 (Variable renaming)
