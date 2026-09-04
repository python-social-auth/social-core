import json

from social_core.exceptions import AuthMissingParameter

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class DripOAuthTest(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.drip.DripOAuth"
    user_data_url = "https://api.getdrip.com/v2/user"
    expected_username = "other@example.com"
    access_token_body = json.dumps(
        {"access_token": "822bbf7cd12243df", "token_type": "bearer", "scope": "public"}
    )

    user_data_body = json.dumps(
        {"users": [{"email": "other@example.com", "name": None}]}
    )

    def test_login(self) -> None:
        self.do_login()

    def test_login_with_configured_provider_field_id(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_DRIP_ID_KEY": "name"})
        self.user_data_body = json.dumps(
            {"users": [{"email": "other@example.com", "name": "Drip User"}]}
        )

        user = self.do_login()

        self.assertEqual(user.social[0].uid, "Drip User")

    def test_configured_id_uses_normalized_details_fallback(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_DRIP_ID_KEY": "fullname"})

        self.assertEqual(
            self.backend.get_user_id(
                {"fullname": "Drip User"},
                {"users": [{"name": "Drip User"}]},
            ),
            "Drip User",
        )

    def test_missing_configured_id_raises_missing_parameter(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_DRIP_ID_KEY": "missing_id"})

        with self.assertRaisesRegex(AuthMissingParameter, "missing_id"):
            self.backend.get_user_id({}, {"users": [{}]})

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
