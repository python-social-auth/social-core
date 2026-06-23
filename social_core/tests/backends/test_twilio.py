from social_core.exceptions import (
    AuthFailed,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
)
from social_core.utils import get_querystring

from .base import BaseBackendTest

ACCOUNT_SID = "ACc65ea16c9ebd4d4684edf814995b27e"
APP_SID = "AP11111111111111111111111111111111"


class TwilioAuthTest(BaseBackendTest):
    backend_path = "social_core.backends.twilio.TwilioAuth"
    expected_username = ACCOUNT_SID

    def extra_settings(self) -> dict[str, str | list[str]]:
        return {
            "SOCIAL_AUTH_TWILIO_KEY": APP_SID,
            "SOCIAL_AUTH_TWILIO_SECRET": "twilio-auth-token",
        }

    def do_start(self):
        start_url = self.backend.start().url
        callback = get_querystring(start_url)["cb"]
        state = get_querystring(callback)["redirect_state"]
        data = {"AccountSid": ACCOUNT_SID, "redirect_state": state}
        self.strategy.set_request_data(data, self.backend)
        return self.backend.complete()

    def test_auth_url_preserves_https_callback(self) -> None:
        self.backend.redirect_uri = "https://myapp.com/complete/twilio"

        callback = get_querystring(self.backend.auth_url())["cb"]
        query = get_querystring(callback)

        self.assertEqual(
            callback,
            "https://myapp.com/complete/twilio?"
            f"redirect_state={query['redirect_state']}",
        )
        self.assertEqual(
            query["redirect_state"], self.strategy.session_get("twilio_state")
        )

    def test_missing_account_sid_fails(self) -> None:
        self.strategy.set_request_data({}, self.backend)

        with self.assertRaisesRegex(AuthFailed, "Missing AccountSid"):
            self.backend.complete()

    def test_complete_rejects_missing_redirect_state(self) -> None:
        self.backend.start()
        data = {"AccountSid": ACCOUNT_SID}
        self.strategy.set_request_data(data, self.backend)

        with self.assertRaises(AuthMissingParameter):
            self.backend.complete()

    def test_complete_rejects_mismatched_redirect_state(self) -> None:
        self.backend.start()
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": "invalid-state"},
            self.backend,
        )

        with self.assertRaises(AuthStateForbidden):
            self.backend.complete()

    def test_complete_rejects_orphan_redirect_state(self) -> None:
        self.strategy.set_request_data(
            {"AccountSid": ACCOUNT_SID, "redirect_state": "orphan-state"},
            self.backend,
        )

        with self.assertRaises(AuthStateMissing):
            self.backend.complete()

    def test_login(self) -> None:
        self.do_login()

    def test_complete_accepts_connect_redirect(self) -> None:
        state = self.backend.get_or_create_state()
        data = {"AccountSid": ACCOUNT_SID, "redirect_state": state}
        self.strategy.set_request_data(data, self.backend)

        user = self.backend.complete()

        self.assertEqual(user.username, ACCOUNT_SID)
        self.assertEqual(self.strategy.session_get("username"), ACCOUNT_SID)
