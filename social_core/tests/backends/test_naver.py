import json

from social_core.exceptions import AuthMissingParameter

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class NaverOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.naver.NaverOAuth2"
    user_data_url = "https://openapi.naver.com/v1/nid/me"
    expected_username = "foobar"
    access_token_body = json.dumps(
        {
            "access_token": "foobar",
            "token_type": "bearer",
        }
    )

    user_data_content_type = "text/json"
    user_data_body = json.dumps(
        {
            "resultcode": "00",
            "message": "success",
            "response": {
                "email": "openapi@naver.com",
                "nickname": "foobar",
                "profile_image": "https://ssl.pstatic.net/static/pwe/address/nodata_33x33.gif",
                "age": "40-49",
                "gender": "F",
                "id": "32742776",
                "name": "foobar",
                "birthday": "10-01",
            },
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_login_with_configured_provider_field_id(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_NAVER_ID_KEY": "mobile"})
        self.user_data_body = json.dumps(
            {
                "response": {
                    "id": "32742776",
                    "email": "openapi@naver.com",
                    "name": "foobar",
                    "mobile": "010-1234-5678",
                }
            }
        )

        user = self.do_login()

        self.assertEqual(user.social[0].uid, "010-1234-5678")

    def test_missing_configured_provider_field_id(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_NAVER_ID_KEY": "mobile"})

        with self.assertRaisesRegex(AuthMissingParameter, "mobile"):
            self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
