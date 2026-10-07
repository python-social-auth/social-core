import json

from social_core.exceptions import AuthResponseError

from .oauth import BaseAuthUrlTestMixin, OAuth2Test
from .open_id_connect import OpenIdConnectTest


class TwitchOpenIdConnectTest(OpenIdConnectTest):
    backend_path = "social_core.backends.twitch.TwitchOpenIdConnect"
    user_data_url = "https://id.twitch.tv/oauth2/userinfo"
    user_data_body = json.dumps({"sub": "1234"})
    issuer = "https://id.twitch.tv/oauth2"
    expected_username = "test_user1"
    openid_config_body = json.dumps(
        {
            "authorization_endpoint": "https://id.twitch.tv/oauth2/authorize",
            "claims_parameter_supported": True,
            "claims_supported": [
                "iss",
                "azp",
                "preferred_username",
                "updated_at",
                "aud",
                "exp",
                "iat",
                "picture",
                "sub",
                "email",
                "email_verified",
            ],
            "id_token_signing_alg_values_supported": [
                "RS256",
            ],
            "issuer": "https://id.twitch.tv/oauth2",
            "jwks_uri": "https://id.twitch.tv/oauth2/keys",
            "response_types_supported": [
                "id_token",
                "code",
                "token",
                "code id_token",
                "token id_token",
            ],
            "scopes_supported": [
                "openid",
            ],
            "subject_types_supported": [
                "public",
            ],
            "token_endpoint": "https://id.twitch.tv/oauth2/token",
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
            ],
            "userinfo_endpoint": "https://id.twitch.tv/oauth2/userinfo",
        }
    )

    def get_id_token(self, *args, **kwargs):
        return {
            **super().get_id_token(*args, **kwargs),
            "preferred_username": self.expected_username,
            "email": "example@reply.com",
        }

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_missing_validated_id_token(self) -> None:
        missing_claims: tuple[dict[str, str] | None, ...] = (None, {})
        for claims in missing_claims:
            self.backend.id_token = claims
            with (
                self.subTest(claims=claims),
                self.assertRaises(AuthResponseError) as caught,
            ):
                self.backend.get_user_details({})
            self.assertEqual(caught.exception.code, "missing_claim")
            self.assertEqual(caught.exception.claim, "id_token")
            self.assertEqual(caught.exception.stage, "user_info")


class TwitchOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.twitch.TwitchOAuth2"
    user_data_url = "https://api.twitch.tv/helix/users"
    expected_username = "test_user1"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
        }
    )
    user_data_body = json.dumps(
        {
            "data": [
                {
                    "id": "689563726",
                    "login": "test_user1",
                    "display_name": "test_user1",
                    "type": "",
                    "broadcaster_type": "",
                    "description": "",
                    "profile_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/foo.png",
                    "offline_image_url": "",
                    "view_count": 0,
                    "email": "example@reply.com",
                    "created_at": "2021-05-21T18:59:25Z",
                    "access_token": "hmkgz15x7j54jm63rpwfwhcnue6t4fxwv",
                }
            ]
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
