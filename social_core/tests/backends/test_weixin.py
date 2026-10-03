import json
from typing import cast

import responses

from social_core.utils import parse_qs

from .oauth import OAuth2StateTestMixin, OAuth2Test


class WeixinOAuth2APPTest(OAuth2Test, OAuth2StateTestMixin):
    backend_path = "social_core.backends.weixin.WeixinOAuth2APP"
    user_data_url = "https://api.weixin.qq.com/sns/userinfo"
    expected_username = "wechat-user"
    access_token_body = json.dumps(
        {
            "access_token": "access-token",
            "openid": "wechat-openid",
        }
    )
    user_data_body = json.dumps(
        {
            "openid": "wechat-openid",
            "nickname": "wechat-user",
        }
    )

    def auth_handlers(self, start_url: str) -> str:
        target_url = super().auth_handlers(start_url)
        # requests preserves the authorization URL fragment across the mocked
        # redirect when the Location header does not provide its own fragment.
        return f"{target_url}#wechat_redirect"

    def test_login(self) -> None:
        self.do_login()

    def test_authorization_url_uses_wechat_redirect_fragment(self) -> None:
        self.assertTrue(self.backend.start().url.endswith("#wechat_redirect"))

    def test_access_token_request_parameters(self) -> None:
        self.do_login()

        token_request = next(
            call.request
            for call in responses.calls
            if cast("str", call.request.url).startswith(self.backend.access_token_url())
        )

        self.assertEqual(
            parse_qs(token_request.body),
            {
                "appid": "a-key",
                "code": "foobar",
                "grant_type": "authorization_code",
                "secret": "a-secret-key",
            },
        )

    def test_complete_rejects_missing_state_parameter(self) -> None:
        super().test_complete_rejects_missing_state_parameter()
        self.assertEqual(len(responses.calls), 0)

    def test_complete_rejects_mismatched_state_parameter(self) -> None:
        super().test_complete_rejects_mismatched_state_parameter()
        self.assertEqual(len(responses.calls), 0)
