import json
from typing import Any

from .oauth import BaseAuthUrlTestMixin, OAuth2Test, VerifiedEmailWhitelistTestMixin


class KakaoOAuth2Test(
    OAuth2Test, BaseAuthUrlTestMixin, VerifiedEmailWhitelistTestMixin
):
    backend_path = "social_core.backends.kakao.KakaoOAuth2"
    user_data_url = "https://kapi.kakao.com/v2/user/me"
    expected_username = "foobar"
    access_token_body = json.dumps({"access_token": "foobar"})
    user_data_body = json.dumps(
        {
            "id": "101010101",
            "properties": {
                "nickname": "foobar",
                "thumbnail_image": "http://mud-kage.kakao.co.kr/14/dn/btqbh1AKmRf/"
                "ujlHpQhxtMSbhKrBisrxe1/o.jpg",
                "profile_image": "http://mud-kage.kakao.co.kr/14/dn/btqbjCnl06Q/"
                "wbMJSVAUZB7lzSImgGdsoK/o.jpg",
            },
            "kakao_account": {"email": "a"},
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def user_data_with_email(self, *, verified: bool) -> dict[str, Any]:
        assert self.user_data_body is not None
        return {
            **json.loads(self.user_data_body),
            "kakao_account": {
                "email": self.whitelisted_email,
                "is_email_valid": True,
                "is_email_verified": verified,
            },
        }

    def test_invalid_email_denied_with_whitelist(self) -> None:
        self.strategy.set_settings(
            {"SOCIAL_AUTH_KAKAO_WHITELISTED_EMAILS": [self.whitelisted_email]}
        )
        response = self.user_data_with_email(verified=True)
        response["kakao_account"]["is_email_valid"] = False
        details = self.backend.get_user_details(response)
        self.assertFalse(self.backend.auth_allowed(response, details))
