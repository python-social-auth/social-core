# pyright: reportAttributeAccessIssue=false

import json

import responses

from .oauth import OAuth2PkcePlainTest, OAuth2PkceS256Test


class BitbucketDataCenterOAuth2Mixin:
    backend_path = "social_core.backends.bitbucket_datacenter.BitbucketDataCenterOAuth2"
    application_properties_url = (
        "https://bachmanity.atlassian.net/rest/api/latest/application-properties"
    )
    application_properties_headers = {"x-ausername": "erlich-bachman"}
    application_properties_body = json.dumps(
        {
            "version": "8.15.0",
            "buildNumber": "8015000",
            "buildDate": "1697764661289",
            "displayName": "Bitbucket",
        }
    )
    user_data_url = (
        "https://bachmanity.atlassian.net/rest/api/latest/users/erlich-bachman"
    )
    user_data_body = json.dumps(
        {
            "name": "erlich-bachman",
            "emailAddress": "erlich@bachmanity.com",
            "active": True,
            "displayName": "Erlich Bachman",
            "id": 1,
            "slug": "erlich-bachman",
            "type": "NORMAL",
            "links": {
                "self": [
                    {"href": "https://bachmanity.atlassian.net/users/erlich-bachman"}
                ]
            },
            "avatarUrl": "http://www.gravatar.com/avatar/af7d968fe79ea45271e3100391824b79.jpg?s=48&d=mm",
        }
    )
    access_token_body = json.dumps(
        {
            "scope": "PUBLIC_REPOS",
            "access_token": "dummy_access_token",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "dummy_refresh_token",
        }
    )
    refresh_token_body = json.dumps(
        {
            "scope": "PUBLIC_REPOS",
            "access_token": "dummy_access_token_refreshed",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "dummy_refresh_token_refreshed",
        }
    )
    expected_username = "erlich-bachman"

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {f"SOCIAL_AUTH_{self.name}_URL": "https://bachmanity.atlassian.net"}
        )
        return settings

    def auth_handlers(self, start_url):
        target_url = super().auth_handlers(start_url)
        responses.add(
            responses.GET,
            self.application_properties_url,
            body=self.application_properties_body,
            adding_headers=self.application_properties_headers,
            content_type="text/json",
        )
        return target_url

    def test_login(self):
        user = self.do_login()

        self.assertEqual(len(user.social), 1)

        social = user.social[0]
        self.assertEqual(social.uid, "1")
        self.assertEqual(social.extra_data["first_name"], "Erlich")
        self.assertEqual(social.extra_data["last_name"], "Bachman")
        self.assertEqual(social.extra_data["email"], "erlich@bachmanity.com")
        self.assertEqual(social.extra_data["name"], "erlich-bachman")
        self.assertEqual(social.extra_data["username"], "erlich-bachman")
        self.assertEqual(social.extra_data["display_name"], "Erlich Bachman")
        self.assertEqual(social.extra_data["type"], "NORMAL")
        self.assertEqual(social.extra_data["active"], True)
        self.assertEqual(
            social.extra_data["url"],
            "https://bachmanity.atlassian.net/users/erlich-bachman",
        )
        self.assertEqual(
            social.extra_data["avatar_url"],
            "http://www.gravatar.com/avatar/af7d968fe79ea45271e3100391824b79.jpg?s=48&d=mm",
        )
        self.assertEqual(social.extra_data["scope"], "PUBLIC_REPOS")
        self.assertEqual(social.extra_data["access_token"], "dummy_access_token")
        self.assertEqual(social.extra_data["token_type"], "bearer")
        self.assertEqual(social.extra_data["expires"], 3600)
        self.assertEqual(social.extra_data["refresh_token"], "dummy_refresh_token")

    def test_refresh_token(self):
        _, social = self.do_refresh_token()

        self.assertEqual(social.uid, "1")
        self.assertEqual(social.extra_data["first_name"], "Erlich")
        self.assertEqual(social.extra_data["last_name"], "Bachman")
        self.assertEqual(social.extra_data["email"], "erlich@bachmanity.com")
        self.assertEqual(social.extra_data["name"], "erlich-bachman")
        self.assertEqual(social.extra_data["username"], "erlich-bachman")
        self.assertEqual(social.extra_data["display_name"], "Erlich Bachman")
        self.assertEqual(social.extra_data["type"], "NORMAL")
        self.assertEqual(social.extra_data["active"], True)
        self.assertEqual(
            social.extra_data["url"],
            "https://bachmanity.atlassian.net/users/erlich-bachman",
        )
        self.assertEqual(
            social.extra_data["avatar_url"],
            "http://www.gravatar.com/avatar/af7d968fe79ea45271e3100391824b79.jpg?s=48&d=mm",
        )
        self.assertEqual(social.extra_data["scope"], "PUBLIC_REPOS")
        self.assertEqual(
            social.extra_data["access_token"], "dummy_access_token_refreshed"
        )
        self.assertEqual(social.extra_data["token_type"], "bearer")
        self.assertEqual(social.extra_data["expires"], 3600)
        self.assertEqual(
            social.extra_data["refresh_token"], "dummy_refresh_token_refreshed"
        )


class BitbucketDataCenterOAuth2TestPkcePlain(
    BitbucketDataCenterOAuth2Mixin,
    OAuth2PkcePlainTest,
):
    pass


class BitbucketDataCenterOAuth2TestPkceS256(
    BitbucketDataCenterOAuth2Mixin,
    OAuth2PkceS256Test,
):
    pass
