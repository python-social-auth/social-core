import json
from unittest.mock import patch

from social_core.exceptions import AuthResponseError

from .oauth import BaseAuthUrlTestMixin, OAuth2StateTestMixin, OAuth2Test


class UntappdOAuth2Test(OAuth2Test, OAuth2StateTestMixin, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.untappd.UntappdOAuth2"
    user_data_url = "https://api.untappd.com/v4/user/info/"
    expected_username = "ada"
    access_token_body = json.dumps(
        {"meta": {"http_code": 200}, "response": {"access_token": "foobar"}}
    )
    user_data_body = json.dumps(
        {
            "meta": {"http_code": 200},
            "response": {
                "user": {
                    "id": "123",
                    "user_name": "ada",
                    "first_name": "Ada",
                    "last_name": "Lovelace",
                    "settings": {"email_address": "ada@example.com"},
                }
            },
        }
    )

    def test_auth_params_include_redirect_url_and_state(self) -> None:
        params = self.backend.auth_params("test-state")

        self.assertEqual(params["redirect_url"], self.backend.get_redirect_uri())
        self.assertEqual(params["state"], "test-state")

    def test_login(self) -> None:
        self.do_login()

    def test_token_response_requires_nested_object_and_usable_token(self) -> None:
        for nested, code in (
            (None, "malformed_response"),
            ([], "malformed_response"),
            ("token", "malformed_response"),
            ({}, "missing_claim"),
            ({"access_token": None}, "missing_claim"),
            ({"access_token": ""}, "missing_claim"),
        ):
            response: dict[str, object] = {
                "meta": {"http_code": 200},
                "response": nested,
            }
            if nested is None:
                del response["response"]
            with (
                self.subTest(response=response),
                patch.object(self.backend, "validate_state", return_value="state"),
                patch.object(self.backend, "get_json", return_value=response),
                patch.object(self.backend, "user_data") as user_data,
                patch.object(self.strategy, "authenticate") as authenticate,
                self.assertRaises(AuthResponseError) as caught,
            ):
                self.backend.auth_complete()
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.stage, "token_exchange")
            user_data.assert_not_called()
            authenticate.assert_not_called()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_malformed_metadata_is_rejected_before_token_or_profile_use(self) -> None:
        invalid_values: tuple[object, ...] = (None, "500", [], {}, False, 500.0)
        payloads: list[object] = [
            None,
            [],
            {"meta": None},
            {"meta": []},
            {"meta": "invalid"},
        ]
        payloads.extend({"meta": {"http_code": value}} for value in invalid_values)
        for payload in payloads:
            for stage in ("token_exchange", "user_info"):
                with (
                    self.subTest(payload=payload, stage=stage),
                    patch.object(self.backend, "get_json", return_value=payload),
                    self.assertRaises(AuthResponseError) as caught,
                ):
                    if stage == "token_exchange":
                        self.backend.request_access_token(self.backend.ACCESS_TOKEN_URL)
                    else:
                        self.backend.user_data("token")
                self.assertEqual(caught.exception.code, "malformed_response")
                self.assertEqual(caught.exception.stage, stage)
