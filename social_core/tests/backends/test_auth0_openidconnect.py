import json

import responses

from social_core.tests.backends.oauth import BaseAuthUrlTestMixin
from social_core.tests.backends.open_id_connect import OpenIdConnectTest


class Auth0OpenIdConnectTest(OpenIdConnectTest, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.auth0_openidconnect.Auth0OpenIdConnectAuth"
    domain = "example.auth0.com"
    issuer = f"https://{domain}/"

    openid_config_body = json.dumps(
        {
            "issuer": issuer,
            "authorization_endpoint": f"https://{domain}/authorize",
            "token_endpoint": f"https://{domain}/oauth/token",
            "userinfo_endpoint": f"https://{domain}/userinfo",
            "revocation_endpoint": f"https://{domain}/oauth/revoke",
            "jwks_uri": f"https://{domain}/.well-known/jwks.json",
        }
    )

    expected_username = "testuser"

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {
                "SOCIAL_AUTH_AUTH0_OPENIDCONNECT_DOMAIN": self.domain,
                "SOCIAL_AUTH_AUTH0_OPENIDCONNECT_USERNAME_KEY": "nickname",
            }
        )
        return settings

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)

        # Mock userinfo response with Auth0-specific fields
        responses.add(
            "GET",
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps(
                {
                    "nickname": self.expected_username,
                    "email": "test@example.com",
                    "email_verified": True,
                    "picture": "https://example.com/avatar.jpg",
                    "locale": "en-US",
                    "sub": "auth0|123456789",
                    "name": "Test User",
                    "given_name": "Test",
                    "family_name": "User",
                }
            ),
            content_type="application/json",
        )

    def test_domain_configuration(self):
        """Test that domain-based URLs are constructed correctly"""
        self.assertEqual(
            self.backend.authorization_url(), f"https://{self.domain}/authorize"
        )
        self.assertEqual(
            self.backend.access_token_url(), f"https://{self.domain}/oauth/token"
        )

    def test_auth0_user_details(self):
        """Test Auth0-specific user detail extraction"""
        response = {
            "nickname": "testuser",
            "email": "test@example.com",
            "email_verified": True,
            "picture": "https://example.com/avatar.jpg",
            "locale": "en-US",
            "sub": "auth0|123456789",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
        }

        details = self.backend.get_user_details(response)

        self.assertEqual(details["username"], "testuser")
        self.assertEqual(details["email"], "test@example.com")
        self.assertTrue(details["email_verified"])
        self.assertEqual(details["picture"], "https://example.com/avatar.jpg")
        self.assertEqual(details["user_id"], "auth0|123456789")

    def test_everything_works(self) -> None:
        self.do_login()
