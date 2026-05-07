import json

import responses

from social_core.backends.odnoklassniki import odnoklassniki_sig
from social_core.exceptions import AuthFailed
from social_core.utils import get_querystring

from .base import BaseBackendTest

SECRET = "a-secret-key"


class OdnoklassnikiAppTest(BaseBackendTest):
    backend_path = "social_core.backends.odnoklassniki.OdnoklassnikiApp"
    expected_username = "12345"
    user_data_url = "https://api.ok.ru/fb.do"

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            f"SOCIAL_AUTH_{self.name}_KEY": "a-key",
            f"SOCIAL_AUTH_{self.name}_SECRET": SECRET,
            f"SOCIAL_AUTH_{self.name}_PUBLIC_NAME": "public-key",
        }

    def auth_sig(self, logged_user_id: str = "12345") -> str:
        return odnoklassniki_sig(f"{logged_user_id}session-key{SECRET}")

    def request_data(
        self, logged_user_id: str = "12345", auth_sig: str | None = None
    ) -> dict[str, str]:
        return {
            "logged_user_id": logged_user_id,
            "api_server": "https://attacker.example/",
            "application_key": "public-key",
            "session_key": "session-key",
            "session_secret_key": "session-secret-key",
            "authorized": "1",
            "apiconnection": "1",
            "auth_sig": auth_sig or self.auth_sig(logged_user_id),
        }

    def add_user_response(self, uid: str = "12345", body: object | None = None) -> None:
        if body is None:
            body = [
                {
                    "uid": uid,
                    "first_name": "Foo",
                    "last_name": "Bar",
                    "name": "Foo Bar",
                }
            ]
        responses.add(
            responses.GET,
            self.user_data_url,
            body=json.dumps(body),
            content_type="application/json",
        )

    def do_start(self):
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response()
        return self.backend.complete()

    def test_login(self) -> None:
        self.do_login()

        request_url = responses.calls[0].request.url
        assert request_url is not None
        self.assertTrue(request_url.startswith(self.user_data_url))
        query = get_querystring(request_url)
        self.assertEqual(query["method"], "users.getInfo")
        self.assertEqual(query["uids"], "12345")

    def test_rejects_mismatched_user_details_uid(self) -> None:
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response(uid="67890")

        with self.assertRaises(AuthFailed):
            self.backend.complete()

    def test_rejects_malformed_user_details_response(self) -> None:
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response(body={"uid": "12345"})

        with self.assertRaises(AuthFailed):
            self.backend.complete()

    def test_rejects_invalid_auth_sig_before_api_request(self) -> None:
        self.strategy.set_request_data(
            self.request_data(auth_sig=self.auth_sig("67890")), self.backend
        )

        with self.assertRaises(AuthFailed):
            self.backend.complete()

        self.assertEqual(len(responses.calls), 0)
