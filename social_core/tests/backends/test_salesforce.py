import json

from social_core.exceptions import AuthPolicyError
from social_core.tests.models import User

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class SalesforceOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.salesforce.SalesforceOAuth2"
    user_data_url = "https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P"
    expected_username = "foobar@example.com"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "Bearer",
            "id": user_data_url,
            "instance_url": "https://yourInstance.salesforce.com",
            "issued_at": "1278448832702",
            "signature": "0CmxinZir53Yex7nE0TD+zMpvIWYGb/bdJh6XfOH6EQ=",
        }
    )
    user_data = {
        "id": user_data_url,
        "user_id": "005x00000012Q9P",
        "organization_id": "00Dx0000000BV7z",
        "username": "foobar@example.com",
        "display_name": "Foo Bar",
        "email": "foobar@example.com",
        "email_verified": True,
        "first_name": "Foo",
        "last_name": "Bar",
    }
    user_data_body = json.dumps(user_data)

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_login_with_verified_email_and_whitelist(self) -> None:
        self.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{self.name}_WHITELISTED_DOMAINS": ["example.com"],
                f"SOCIAL_AUTH_{self.name}_WHITELISTED_EMAILS": ["foobar@example.com"],
            }
        )
        self.do_login()

    def test_login_with_unverified_email_without_whitelist(self) -> None:
        self.user_data_body = json.dumps({**self.user_data, "email_verified": False})
        self.do_login()

    def test_unverified_email_denied_with_whitelist(self) -> None:
        whitelists: tuple[tuple[str, str], ...] = (
            (f"SOCIAL_AUTH_{self.name}_WHITELISTED_DOMAINS", "example.com"),
            (f"SOCIAL_AUTH_{self.name}_WHITELISTED_EMAILS", "foobar@example.com"),
        )
        unverified: tuple[object, ...] = (False, None, "true", 1)
        for setting, value in whitelists:
            self.strategy.set_settings({setting: [value]})
            for email_verified in unverified:
                with self.subTest(setting=setting, email_verified=email_verified):
                    response = {**self.user_data, "email_verified": email_verified}
                    details = self.backend.get_user_details(response)
                    self.assertFalse(self.backend.auth_allowed(response, details))
            self.strategy.set_settings({setting: []})

    def test_login_with_unverified_email_denied_with_whitelist(self) -> None:
        self.strategy.set_settings(
            {f"SOCIAL_AUTH_{self.name}_WHITELISTED_DOMAINS": ["example.com"]}
        )
        self.user_data_body = json.dumps({**self.user_data, "email_verified": False})

        with self.assertRaises(AuthPolicyError) as caught:
            self.do_login()

        self.assertEqual(caught.exception.code, "authentication_disallowed")
        self.assertEqual(caught.exception.stage, "pipeline")
        self.assertFalse(User.cache)

    def test_login_without_email_verified_denied_with_whitelist(self) -> None:
        self.strategy.set_settings(
            {f"SOCIAL_AUTH_{self.name}_WHITELISTED_DOMAINS": ["example.com"]}
        )
        user_data = self.user_data.copy()
        del user_data["email_verified"]
        self.user_data_body = json.dumps(user_data)

        with self.assertRaises(AuthPolicyError):
            self.do_login()

        self.assertFalse(User.cache)


class SalesforceOAuth2SandboxTest(SalesforceOAuth2Test):
    backend_path = "social_core.backends.salesforce.SalesforceOAuth2Sandbox"
