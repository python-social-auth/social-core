import json
from unittest.mock import patch

import responses

from social_core.backends.odnoklassniki import odnoklassniki_sig
from social_core.exceptions import AuthInputError, AuthResponseError, AuthSessionError
from social_core.tests.models import TestUserSocialAuth, User
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

    def test_missing_signature_fields_fail_before_provider_request(self) -> None:
        for parameter in ("logged_user_id", "session_key", "auth_sig"):
            data = self.request_data()
            del data[parameter]
            self.strategy.set_request_data(data, self.backend)
            self.strategy.remove_from_request_data(parameter)
            with (
                self.subTest(parameter=parameter),
                self.assertRaises(AuthInputError) as caught,
            ):
                self.backend.complete()
            self.assertEqual(caught.exception.code, "missing_parameter")
            self.assertEqual(caught.exception.parameter, parameter)
            self.assertEqual(caught.exception.stage, "callback")
            self.assertEqual(caught.exception.source, "request")
        self.assertEqual(len(responses.calls), 0)

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

    def test_authenticated_user_accepts_existing_association(self) -> None:
        user = User("existing")
        social = TestUserSocialAuth(
            user, self.backend.name, "12345", id_key=self.backend.id_key()
        )
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response()

        result = self.backend.complete(user=user)

        self.assertIs(result, user)
        self.assertEqual(user.social, [social])
        self.assertEqual(len(User.cache), 1)

    def test_authenticated_user_accepts_unkeyed_existing_association(self) -> None:
        user = User("existing")
        social = TestUserSocialAuth(
            user, self.backend.name, "12345", extra_data={"uid": "12345"}
        )
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response()

        result = self.backend.complete(user=user)

        self.assertIs(result, user)
        self.assertEqual(user.social, [social])
        self.assertEqual(social.id_key, self.backend.id_key())
        self.assertEqual(len(User.cache), 1)

    def test_authenticated_user_rejects_new_association(self) -> None:
        user = User("existing")
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response()

        with (
            patch.object(self.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthSessionError) as caught,
        ):
            self.backend.complete(user=user)

        authenticate.assert_not_called()
        self.assertEqual(caught.exception.code, "user_mismatch")
        self.assertEqual(caught.exception.stage, "callback")
        self.assertEqual(caught.exception.source, "session")
        self.assertEqual(user.social, [])
        self.assertEqual(list(User.cache.values()), [user])
        self.assertEqual(TestUserSocialAuth.cache_by_uid, {})

    def test_authenticated_user_rejects_different_association(self) -> None:
        owner = User("owner")
        user = User("existing")
        social = TestUserSocialAuth(
            owner, self.backend.name, "12345", id_key=self.backend.id_key()
        )
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response()

        with self.assertRaises(AuthSessionError) as caught:
            self.backend.complete(user=user)

        self.assertEqual(caught.exception.code, "user_mismatch")
        self.assertEqual(caught.exception.stage, "callback")
        self.assertEqual(owner.social, [social])
        self.assertEqual(user.social, [])
        self.assertEqual(len(User.cache), 2)

    def test_rejects_mismatched_user_details_uid(self) -> None:
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response(uid="67890")

        with self.assertRaises(AuthResponseError):
            self.backend.complete()

    def test_rejects_malformed_user_details_response(self) -> None:
        self.strategy.set_request_data(self.request_data(), self.backend)
        self.add_user_response(body={"uid": "12345"})

        with self.assertRaises(AuthResponseError):
            self.backend.complete()

    def test_rejects_invalid_auth_sig_before_api_request(self) -> None:
        for signature in (self.auth_sig("67890"), "é"):
            self.strategy.set_request_data(
                self.request_data(auth_sig=signature), self.backend
            )
            with (
                self.subTest(signature=signature),
                self.assertRaises(AuthResponseError) as caught,
            ):
                self.backend.complete()
            self.assertEqual(caught.exception.code, "invalid_signature")
            self.assertEqual(caught.exception.stage, "callback")

        self.assertEqual(len(responses.calls), 0)

    def test_accepts_uppercase_auth_sig(self) -> None:
        self.strategy.set_request_data(
            self.request_data(auth_sig=self.auth_sig().upper()), self.backend
        )
        self.backend.verify_auth_sig()

    def test_rejects_non_string_auth_sig(self) -> None:
        for signature in (["sig"], {"sig": "value"}, True, 123, b"sig"):
            data: dict[str, object] = dict(self.request_data())
            data["auth_sig"] = signature
            self.strategy.set_request_data(data, self.backend)
            with (
                self.subTest(signature=signature),
                self.assertRaises(AuthInputError) as caught,
            ):
                self.backend.complete()
            self.assertEqual(caught.exception.parameter, "auth_sig")
            self.assertEqual(caught.exception.code, "invalid_parameter")
            self.assertEqual(caught.exception.stage, "callback")
        self.assertEqual(len(responses.calls), 0)
