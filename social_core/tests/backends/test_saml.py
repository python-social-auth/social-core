import json
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
import responses

try:
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    SAML_MODULE_ENABLED = True
except ImportError:
    SAML_MODULE_ENABLED = False

from social_core.exceptions import AuthFailed, AuthMissingParameter
from social_core.tests.models import User

from .base import BaseBackendTest

DATA_DIR = Path(__file__).parent / "data"


@unittest.skipIf(
    "__pypy__" in sys.builtin_module_names, "dm.xmlsec not compatible with pypy"
)
@unittest.skipUnless(SAML_MODULE_ENABLED, "Only run if onelogin.saml2 is installed")
class SAMLTest(BaseBackendTest):
    backend_path = "social_core.backends.saml.SAMLAuth"
    expected_username = "myself"
    response_fixture = "saml_response.txt"

    def authn_request_id_session_key(self, idp_name: str) -> str:
        return f"{self.backend.name}_{idp_name}_authn_request_id"

    def extra_settings(self):
        file = DATA_DIR / "saml_config.json"
        config_str = file.read_text()
        return json.loads(config_str)

    def setUp(self) -> None:
        """Patch the time so that we can replay canned
        request/response pairs"""
        super().setUp()

        def fixed_time():
            return OneLogin_Saml2_Utils.parse_SAML_to_time("2015-05-09T03:57:22Z")

        now_patch = patch.object(OneLogin_Saml2_Utils, "now", fixed_time)
        now_patch.start()
        self.addCleanup(now_patch.stop)

    def install_http_intercepts(self, start_url, return_url) -> None:
        # When we request start_url
        # (https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO...)
        # we will eventually get a redirect back, with SAML assertion
        # data in the query string.  A pre-recorded correct response
        # is kept in this .txt file:
        file = DATA_DIR / self.response_fixture
        response_url = file.read_text()
        responses.add(
            responses.GET,
            start_url,
            status=301,
            headers={"Location": response_url},
        )
        responses.add(responses.GET, return_url, status=200, body="foobar")

    def do_start(self):
        start_url = self.backend.start().url
        # Modify the start URL to make the SAML request consistent
        # from test to test:
        start_url = self.modify_start_url(start_url)
        # If the SAML Identity Provider recognizes the user, we will
        # be redirected back to:
        return_url = self.backend.redirect_uri
        self.install_http_intercepts(start_url, return_url)
        response = requests.get(start_url, timeout=1)
        self.assertTrue(response.url.startswith(return_url))
        self.assertEqual(response.text, "foobar")
        query_values = {
            k: v[0] for k, v in parse_qs(urlparse(response.url).query).items()
        }
        self.assertNotIn(" ", query_values["SAMLResponse"])
        self.strategy.set_request_data(query_values, self.backend)
        return self.backend.complete()

    def test_metadata_generation(self) -> None:
        """Test that we can generate the metadata without error"""
        xml, errors = self.backend.generate_metadata_xml()
        self.assertEqual(len(errors), 0)
        self.assertEqual(xml.decode()[0], "<")

    def test_login_with_next_url(self) -> None:
        """
        Test that we login and then redirect to the "next" URL.
        """
        # pretend we've started with a URL like /login/saml/?idp=testshib&next=/foo/bar
        self.strategy.set_request_data(
            {"idp": "testshib", "next": "/foo/bar"}, self.backend
        )
        self.do_login()
        # The core `do_complete` action assumes the "next" URL is stored in session state or the request data.
        self.assertEqual(self.strategy.session_get("next"), "/foo/bar")

    def test_login_no_next_url(self) -> None:
        """
        Test that we handle "next" being omitted from the request data and RelayState.
        """
        self.response_fixture = "saml_response_no_next_url.txt"

        # pretend we've started with a URL like /login/saml/?idp=testshib
        self.strategy.set_request_data({"idp": "testshib"}, self.backend)
        self.do_login()
        self.assertEqual(self.strategy.session_get("next"), None)

    def test_login_with_legacy_relay_state(self) -> None:
        """
        Test that we handle legacy RelayState (i.e. just the IDP name, not a JSON object).

        This is the form that RelayState had in prior versions of this library. It should be supported for backwards
        compatibility. It is also sent by some identity providers (like Okta) on IdP-initiated login.
        """
        self.response_fixture = "saml_response_legacy.txt"

        self.strategy.set_request_data({"idp": "testshib"}, self.backend)
        self.do_login()

    def test_login_no_idp_in_initial_request(self) -> None:
        """
        Logging in without an idp param should raise AuthMissingParameter
        """
        with self.assertRaises(AuthMissingParameter):
            self.do_start()

    def test_login_no_idp_in_saml_response(self) -> None:
        """
        The RelayState should always contain a JSON object with an "idp" key, or be just the IDP name as a string.
        This tests that an exception is raised if it is a JSON object, but is missing the "idp" key.
        """
        self.response_fixture = "saml_response_no_idp_name.txt"

        with self.assertRaises(AuthMissingParameter):
            self.do_start()

    def test_relay_state_session_restored_after_saml_response_validation(
        self,
    ) -> None:
        """
        Session restore uses RelayState data, so it must wait until the SAML response is valid.
        """
        events = []

        class ValidAuth:
            def process_response(self, request_id=None):
                if request_id is not None:
                    raise AssertionError("request_id should be None")
                events.append("process_response")

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_attributes(self):
                return {}

            def get_nameid(self):
                return "name-id"

            def get_session_index(self):
                return "session-index"

        def restore_session(session_id, kwargs) -> None:
            events.append("restore_session")
            self.assertEqual(session_id, "restored-session")

        def authenticate(*args, **kwargs):
            events.append("authenticate")
            return "user"

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps(
                    {
                        "idp": "testshib",
                        self.strategy.SESSION_SAVE_KEY: "restored-session",
                    }
                ),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "restore_session", restore_session),
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
        ):
            self.assertEqual(self.backend.complete(), "user")

        self.assertEqual(
            events,
            ["process_response", "restore_session", "authenticate"],
        )

    def test_relay_state_restored_session_request_id_validates_in_response_to(
        self,
    ) -> None:
        events: list[str | tuple[str, None] | tuple[str, User]] = []
        victim = User("victim")
        key = self.authn_request_id_session_key("testshib")
        self.strategy.session_set(key, "STALE_ID")

        class ValidAuth:
            def process_response(self, request_id=None):
                events.append(("process_response", request_id))

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_last_response_in_response_to(self):
                return "TEST_ID"

            def get_attributes(self):
                return {}

            def get_nameid(self):
                return "name-id"

            def get_session_index(self):
                return "session-index"

        def restore_session(session_id, kwargs) -> None:
            events.append("restore_session")
            self.assertEqual(session_id, "restored-session")
            self.strategy.session_set(key, "TEST_ID")
            kwargs["user"] = victim

        def authenticate(*args, **kwargs):
            events.append(("authenticate", kwargs["user"]))
            return "user"

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps(
                    {
                        "idp": "testshib",
                        self.strategy.SESSION_SAVE_KEY: "restored-session",
                    }
                ),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "restore_session", restore_session),
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
        ):
            self.assertEqual(self.backend.complete(), "user")

        self.assertEqual(
            events,
            [
                ("process_response", None),
                "restore_session",
                ("authenticate", victim),
            ],
        )
        self.assertIsNone(self.strategy.session_get(key))

    def test_relay_state_restored_session_skips_no_id_validation_for_in_response_to(
        self,
    ) -> None:
        events: list[str | tuple[str, str | None] | tuple[str, User]] = []
        victim = User("victim")
        key = self.authn_request_id_session_key("testshib")

        class ValidAuth:
            def process_response(self, request_id=None):
                if request_id is None:
                    raise AssertionError(
                        "request_id should be restored before validation"
                    )
                events.append(("process_response", request_id))

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_last_response_in_response_to(self):
                return "TEST_ID"

            def get_attributes(self):
                return {}

            def get_nameid(self):
                return "name-id"

            def get_session_index(self):
                return "session-index"

        def restore_session(session_id, kwargs) -> None:
            events.append("restore_session")
            self.assertEqual(session_id, "restored-session")
            self.strategy.session_set(key, "TEST_ID")
            kwargs["user"] = victim

        def authenticate(*args, **kwargs):
            events.append(("authenticate", kwargs["user"]))
            return "user"

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps(
                    {
                        "idp": "testshib",
                        self.strategy.SESSION_SAVE_KEY: "restored-session",
                    }
                ),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "restore_session", restore_session),
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(
                self.backend,
                "_response_in_response_to",
                return_value="TEST_ID",
            ),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
        ):
            self.assertEqual(self.backend.complete(), "user")

        self.assertEqual(
            events,
            [
                ("process_response", "TEST_ID"),
                "restore_session",
                ("authenticate", victim),
            ],
        )
        self.assertIsNone(self.strategy.session_get(key))

    def test_relay_state_restored_session_rejects_mismatched_in_response_to(
        self,
    ) -> None:
        events: list[str | tuple[str, None]] = []
        victim = User("victim")
        key = self.authn_request_id_session_key("testshib")

        class ValidAuth:
            def process_response(self, request_id=None):
                events.append(("process_response", request_id))

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_last_response_in_response_to(self):
                return "OTHER_ID"

        def restore_session(session_id, kwargs) -> None:
            events.append("restore_session")
            self.assertEqual(session_id, "restored-session")
            self.strategy.session_set(key, "TEST_ID")
            kwargs["user"] = victim

        def authenticate(*args, **kwargs):
            self.fail("authenticate should not be called")

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps(
                    {
                        "idp": "testshib",
                        self.strategy.SESSION_SAVE_KEY: "restored-session",
                    }
                ),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "restore_session", restore_session),
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
            self.assertRaisesRegex(AuthFailed, "invalid InResponseTo"),
        ):
            self.backend.complete()

        self.assertEqual(
            events,
            [
                ("process_response", None),
                "restore_session",
            ],
        )
        self.assertEqual(self.strategy.session_get(key), "TEST_ID")

    def test_relay_state_restored_session_ignores_transient_request_id(self) -> None:
        events: list[str | tuple[str, str | None]] = []
        victim = User("victim")
        key = self.authn_request_id_session_key("testshib")
        self.strategy.session_set(key, "STALE_ID")

        class ValidAuth:
            def process_response(self, request_id=None):
                if request_id is None:
                    raise AssertionError(
                        "request_id should be restored before validation"
                    )
                events.append(("process_response", request_id))

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_last_response_in_response_to(self):
                return "STALE_ID"

        def restore_session(session_id, kwargs) -> None:
            events.append("restore_session")
            self.assertEqual(session_id, "restored-session")
            self.strategy.session_set(key, "TEST_ID")
            kwargs["user"] = victim

        def authenticate(*args, **kwargs):
            self.fail("authenticate should not be called")

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps(
                    {
                        "idp": "testshib",
                        self.strategy.SESSION_SAVE_KEY: "restored-session",
                    }
                ),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "restore_session", restore_session),
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(
                self.backend,
                "_response_in_response_to",
                return_value="STALE_ID",
            ),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
            self.assertRaisesRegex(AuthFailed, "invalid InResponseTo"),
        ):
            self.backend.complete()

        self.assertEqual(
            events,
            [
                ("process_response", "STALE_ID"),
                "restore_session",
            ],
        )
        self.assertEqual(self.strategy.session_get(key), "TEST_ID")

    def test_relay_state_session_not_restored_for_invalid_saml_response(self) -> None:
        """
        Invalid SAML responses must not trigger RelayState-derived session changes.
        """

        class InvalidAuth:
            def process_response(self, request_id=None):
                if request_id is not None:
                    raise AssertionError("request_id should be None")

            def get_errors(self):
                return ["invalid"]

            def is_authenticated(self):
                return False

            def get_last_error_reason(self):
                return "invalid response"

        def restore_session(session_id, kwargs) -> None:
            self.fail("restore_session should not be called")

        def authenticate(*args, **kwargs):
            self.fail("authenticate should not be called")

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps(
                    {
                        "idp": "testshib",
                        self.strategy.SESSION_SAVE_KEY: "restored-session",
                        "next": "/after-login",
                    }
                ),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "restore_session", restore_session),
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(self.backend, "_create_saml_auth", return_value=InvalidAuth()),
            self.assertRaises(AuthFailed),
        ):
            self.backend.complete()

        self.assertIsNone(self.strategy.session_get("next"))

    def test_relay_state_session_not_restored_for_invalid_in_response_to_response(
        self,
    ) -> None:
        """
        A parseable InResponseTo alone is not enough to trust RelayState session data.
        """
        events: list[tuple[str, str]] = []

        class InvalidAuth:
            def process_response(self, request_id: str | None = None) -> None:
                if request_id is None:
                    raise AssertionError("request_id should be TEST_ID")
                events.append(("process_response", request_id))

            def get_errors(self):
                return ["invalid"]

            def is_authenticated(self):
                return False

            def get_last_error_reason(self):
                return "invalid response"

        def restore_session(session_id, kwargs) -> None:
            self.fail("restore_session should not be called")

        def authenticate(*args, **kwargs):
            self.fail("authenticate should not be called")

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps(
                    {
                        "idp": "testshib",
                        self.strategy.SESSION_SAVE_KEY: "restored-session",
                        "next": "/after-login",
                    }
                ),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "restore_session", restore_session),
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(
                self.backend,
                "_response_in_response_to",
                return_value="TEST_ID",
            ),
            patch.object(self.backend, "_create_saml_auth", return_value=InvalidAuth()),
            self.assertRaises(AuthFailed),
        ):
            self.backend.complete()

        self.assertEqual(events, [("process_response", "TEST_ID")])
        self.assertIsNone(self.strategy.session_get("next"))

    def test_authenticated_user_requires_stored_authn_request_id(self) -> None:
        self.strategy.set_request_data(
            {
                "RelayState": json.dumps({"idp": "testshib"}),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.backend, "_create_saml_auth") as create_saml_auth,
            self.assertRaisesRegex(AuthFailed, "missing AuthnRequest ID"),
        ):
            self.backend.complete(user=User("victim"))

        create_saml_auth.assert_not_called()

    def test_authenticated_user_requires_matching_in_response_to(self) -> None:
        request_ids = []

        class ValidAuth:
            def __init__(self, in_response_to):
                self.in_response_to = in_response_to

            def process_response(self, request_id=None):
                request_ids.append(request_id)

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_last_response_in_response_to(self):
                return self.in_response_to

        for in_response_to in (None, "OTHER_ID"):
            with self.subTest(in_response_to=in_response_to):
                key = self.authn_request_id_session_key("testshib")
                self.strategy.session_set(key, "TEST_ID")
                self.strategy.set_request_data(
                    {
                        "RelayState": json.dumps({"idp": "testshib"}),
                        "SAMLResponse": "irrelevant",
                    },
                    self.backend,
                )

                with (
                    patch.object(
                        self.backend,
                        "_response_in_response_to",
                        return_value=in_response_to,
                    ),
                    patch.object(
                        self.backend,
                        "_create_saml_auth",
                        return_value=ValidAuth(in_response_to),
                    ),
                    self.assertRaisesRegex(AuthFailed, "invalid InResponseTo"),
                ):
                    self.backend.complete(user=User("victim"))

                self.assertEqual(self.strategy.session_get(key), "TEST_ID")

        self.assertEqual(request_ids, [None, "TEST_ID"])

    def test_authenticated_user_accepts_matching_in_response_to(self) -> None:
        events = []
        victim = User("victim")
        key = self.authn_request_id_session_key("testshib")
        self.strategy.session_set(key, "TEST_ID")

        class ValidAuth:
            def process_response(self, request_id=None):
                events.append(("process_response", request_id))

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_last_response_in_response_to(self):
                return "TEST_ID"

            def get_attributes(self):
                return {}

            def get_nameid(self):
                return "name-id"

            def get_session_index(self):
                return "session-index"

        def authenticate(*args, **kwargs):
            events.append(("authenticate", kwargs["user"]))
            return "user"

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps({"idp": "testshib"}),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(
                self.backend,
                "_response_in_response_to",
                return_value="TEST_ID",
            ),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
        ):
            self.assertEqual(self.backend.complete(user=victim), "user")

        self.assertEqual(
            events,
            [("process_response", "TEST_ID"), ("authenticate", victim)],
        )
        self.assertIsNone(self.strategy.session_get(key))

    def test_anonymous_user_allows_unsolicited_saml_response(self) -> None:
        events = []

        class ValidAuth:
            def process_response(self, request_id=None):
                events.append(("process_response", request_id))

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_attributes(self):
                return {}

            def get_nameid(self):
                return "name-id"

            def get_session_index(self):
                return "session-index"

        def authenticate(*args, **kwargs):
            events.append(("authenticate", kwargs.get("user")))
            return "user"

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps({"idp": "testshib"}),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
        ):
            self.assertEqual(self.backend.complete(), "user")

        self.assertEqual(
            events,
            [("process_response", None), ("authenticate", None)],
        )

    def test_anonymous_user_allows_unsolicited_response_with_stale_request_id(
        self,
    ) -> None:
        events = []
        key = self.authn_request_id_session_key("testshib")
        self.strategy.session_set(key, "STALE_ID")

        class ValidAuth:
            def process_response(self, request_id=None):
                events.append(("process_response", request_id))

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_last_response_in_response_to(self):
                return None

            def get_attributes(self):
                return {}

            def get_nameid(self):
                return "name-id"

            def get_session_index(self):
                return "session-index"

        def authenticate(*args, **kwargs):
            events.append(("authenticate", kwargs.get("user")))
            return "user"

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps({"idp": "testshib"}),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(self.strategy, "authenticate", authenticate),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
        ):
            self.assertEqual(self.backend.complete(), "user")

        self.assertEqual(
            events,
            [("process_response", None), ("authenticate", None)],
        )
        self.assertEqual(self.strategy.session_get(key), "STALE_ID")

    def test_anonymous_user_with_stored_request_requires_matching_in_response_to(
        self,
    ) -> None:
        class ValidAuth:
            def process_response(self, request_id=None):
                if request_id != "TEST_ID":
                    raise AssertionError("request_id should be TEST_ID")

            def get_errors(self):
                return []

            def is_authenticated(self):
                return True

            def get_last_response_in_response_to(self):
                return "OTHER_ID"

        key = self.authn_request_id_session_key("testshib")
        self.strategy.session_set(key, "TEST_ID")
        self.strategy.set_request_data(
            {
                "RelayState": json.dumps({"idp": "testshib"}),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(
                self.backend,
                "_response_in_response_to",
                return_value="OTHER_ID",
            ),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
            self.assertRaisesRegex(AuthFailed, "invalid InResponseTo"),
        ):
            self.backend.complete()

        self.assertEqual(self.strategy.session_get(key), "TEST_ID")

    def test_anonymous_user_rejects_untracked_in_response_to(self) -> None:
        class ValidAuth:
            def process_response(self, request_id=None):
                raise AssertionError("SAML response should not be processed")

        self.strategy.set_request_data(
            {
                "RelayState": json.dumps({"idp": "testshib"}),
                "SAMLResponse": "irrelevant",
            },
            self.backend,
        )

        with (
            patch.object(
                self.backend,
                "_response_in_response_to",
                return_value="TEST_ID",
            ),
            patch.object(self.backend, "_create_saml_auth", return_value=ValidAuth()),
            self.assertRaisesRegex(AuthFailed, "missing AuthnRequest ID"),
        ):
            self.backend.complete()

    def modify_start_url(self, start_url):
        """
        Given a SAML redirect URL, parse it and change the ID to
        a consistent value, so the request is always identical.
        """
        # Parse the SAML Request URL to get the XML being sent to TestShib
        url_parts = urlparse(start_url)
        query = {k: v[0] for (k, v) in parse_qs(url_parts.query).items()}
        xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(query["SAMLRequest"])
        # Modify the XML:
        xml = xml.decode()
        xml, changed = re.subn(r'ID="[^"]+"', 'ID="TEST_ID"', xml)
        self.assertEqual(changed, 1)
        relay_state = self.backend.parse_relay_state(query["RelayState"])
        self.strategy.session_set(
            self.authn_request_id_session_key(relay_state["idp"]),
            "TEST_ID",
        )
        # Update the URL to use the modified query string:
        query["SAMLRequest"] = OneLogin_Saml2_Utils.deflate_and_base64_encode(xml)
        url_parts = list(url_parts)
        url_parts[4] = urlencode(query)
        return urlunparse(url_parts)
