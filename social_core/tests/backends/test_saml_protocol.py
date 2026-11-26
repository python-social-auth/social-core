# Keep this shared module cohesive for protocol regression review.
# SAML protocol regressions share one signed-response fixture.
# pylint: disable=too-many-lines
"""SAML wire-level compatibility tests for the social-core backend.

This is not a complete SAML toolkit conformance suite. In particular, the
backend has no shared replay cache for unsolicited assertions. We test replay
rejection for consumed SP request IDs, without claiming global replay protection.
"""

import json
import unittest
from base64 import b64encode
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from social_core.exceptions import (
    AuthAssociationError,
    AuthConfigurationError,
    AuthInputError,
    AuthPolicyError,
    AuthResponseError,
    AuthSessionError,
)
from social_core.strategy import BaseStrategy
from social_core.tests.models import TestUserSocialAuth, User

from .base import BaseBackendTest

LEGACY_SESSION_ID_FIELD = "psa_session_id"

try:
    from lxml import etree
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    # This backend import must remain optional when the SAML extra is absent.
    # pylint: disable-next=ungrouped-imports
    from social_core.backends.saml import SAMLIdentityProvider

    from . import saml_helpers as saml

    SAML_MODULE_ENABLED = True
except ImportError:
    SAML_MODULE_ENABLED = False


@unittest.skipUnless(SAML_MODULE_ENABLED, "Requires the SAML extra")
class SAMLProtocolTest(BaseBackendTest):
    backend_path = "social_core.backends.saml.SAMLAuth"

    def extra_settings(self):
        return {
            "SOCIAL_AUTH_SAML_SP_ENTITY_ID": saml.SP,
            "SOCIAL_AUTH_SAML_SP_PUBLIC_CERT": saml.keypair("sp")[1].decode(),
            "SOCIAL_AUTH_SAML_SP_PRIVATE_KEY": saml.keypair("sp")[0].decode(),
            "SOCIAL_AUTH_SAML_ORG_INFO": {
                "en-US": {
                    "name": "Example",
                    "displayname": "Example SP",
                    "url": "https://sp.example.com",
                }
            },
            "SOCIAL_AUTH_SAML_TECHNICAL_CONTACT": {
                "givenName": "Technical",
                "emailAddress": "tech@example.com",
            },
            "SOCIAL_AUTH_SAML_SUPPORT_CONTACT": {
                "givenName": "Support",
                "emailAddress": "support@example.com",
            },
            "SOCIAL_AUTH_SAML_ENABLED_IDPS": {
                name: {
                    "entity_id": saml.ENTITY,
                    "url": saml.SSO,
                    "slo_url": saml.SLO,
                    "x509cert": saml.keypair("idp")[1].decode(),
                    "attr_username": "username",
                }
                for name in ("idp", "other")
            },
        }

    def setUp(self):
        super().setUp()
        self.backend.redirect_uri = saml.ACS
        self.idps = self.strategy.get_setting("SOCIAL_AUTH_SAML_ENABLED_IDPS")
        self.clock = patch.object(OneLogin_Saml2_Utils, "now", return_value=1717243200)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        path = patch.object(
            self.strategy, "request_path", return_value="/complete/saml"
        )
        path.start()
        self.addCleanup(path.stop)
        self.key = "saml_idp_authn_request_id"
        self.strategy.session_set(self.key, "request-id")

    def security(self, **values):
        self.strategy.set_settings({"SOCIAL_AUTH_SAML_SECURITY_CONFIG": values})

    def post(self, node, relay_state: str | None = '{"idp":"idp"}'):
        self.strategy.request_data().clear()
        values = {
            "SAMLResponse": saml.encode(node) if not isinstance(node, str) else node,
            self.backend.BROWSER_RETURN_FIELD: "1",
        }
        if relay_state is not None:
            values["RelayState"] = relay_state
        self.strategy.set_request_data(values, self.backend)

    def complete(self, node, relay_state: str | None = '{"idp":"idp"}', **kwargs):
        self.post(node, relay_state)
        with patch.object(
            self.strategy, "authenticate", return_value="authenticated"
        ) as authenticate:
            self.assertEqual(self.backend.complete(**kwargs), "authenticated")
        return authenticate.call_args.kwargs["response"]

    def rejected(
        self,
        node,
        exception: type[Exception] = AuthResponseError,
        relay_state: str | None = '{"idp":"idp"}',
        **kwargs,
    ):
        self.post(node, relay_state)
        with (
            patch.object(self.strategy, "authenticate") as authenticate,
            patch.object(
                self.strategy, "session_set", wraps=self.strategy.session_set
            ) as session_set,
            patch.object(
                self.strategy, "session_pop", wraps=self.strategy.session_pop
            ) as session_pop,
            self.assertRaises(exception),
        ):
            self.backend.complete(**kwargs)
        authenticate.assert_not_called()
        session_set.assert_not_called()
        session_pop.assert_not_called()

    def test_signature_placements_and_raw_attributes(self):
        for signed in ("assertion", "response", "both"):
            with self.subTest(signed=signed):
                self.strategy.session_set(self.key, "request-id")
                result = self.complete(saml.signed_response(signed=signed))
                self.assertEqual(result["attributes"][saml.UID], ["stable-uid"])
                self.assertEqual(
                    result["attributes"]["custom:roles"], ["member", "admin"]
                )
                self.assertEqual(result["attributes"]["name_id"], "stable-name-id")
                self.assertEqual(result["session_index"], "session-index")
                self.assertEqual(result["idp_name"], "idp")
                self.assertIsNone(self.strategy.session_get(self.key))

    def test_unsigned_untrusted_and_tampered(self):
        tampered = saml.signed_response()
        saml.find(tampered, ".//saml:NameID").text = "attacker"
        for node in (
            saml.response(),
            saml.signed_response(identity="untrusted"),
            tampered,
        ):
            with self.subTest(xml=etree.QName(node).localname):
                self.rejected(node)

    def test_invalid_signature_on_either_signed_element(self):
        for path in ("ds:Signature", "saml:Assertion/ds:Signature"):
            with self.subTest(path=path):
                node = saml.signed_response(signed="both")
                saml.find(node, f"{path}/ds:SignatureValue").text = "AAAA"
                self.rejected(node)

    def test_invalid_response_does_not_set_next_url(self):
        self.rejected(
            saml.signed_response(identity="untrusted"),
            relay_state='{"idp":"idp","next":"/after"}',
        )
        self.assertIsNone(self.strategy.session_get("next"))

    def test_signature_requirements(self):
        for setting, accepted, rejected in (
            ("wantAssertionsSigned", "assertion", "response"),
            ("wantMessagesSigned", "response", "assertion"),
        ):
            with self.subTest(setting=setting):
                self.security(**{setting: True})
                self.strategy.session_set(self.key, "request-id")
                self.rejected(saml.signed_response(signed=rejected))
                self.complete(saml.signed_response(signed=accepted))
        self.security(wantAssertionsSigned=True, wantMessagesSigned=True)
        self.strategy.session_set(self.key, "request-id")
        self.complete(saml.signed_response(signed="both"))

    def test_invalid_semantics_with_valid_signatures(self):
        cases = (
            (".", "Destination", "https://wrong.example.com/acs"),
            (".", "Destination", ""),
            (".", "Version", "1.0"),
            ("saml:Issuer", None, "https://wrong.example.com/idp"),
            ("saml:Assertion/saml:Issuer", None, "https://wrong.example.com/idp"),
            (".//saml:Audience", None, "https://wrong.example.com/sp"),
            (
                ".//saml:SubjectConfirmationData",
                "Recipient",
                "https://wrong.example.com/acs",
            ),
            (".//saml:SubjectConfirmationData", "InResponseTo", "other-request"),
            (".//saml:SubjectConfirmationData", "NotOnOrAfter", saml.NOW),
            (".//saml:SubjectConfirmationData", "NotBefore", saml.AFTER),
            (".//saml:Conditions", "NotOnOrAfter", saml.BEFORE),
            (".//saml:Conditions", "NotBefore", saml.AFTER),
            (".//saml:AuthnStatement", "SessionNotOnOrAfter", saml.NOW),
            (
                ".//samlp:StatusCode",
                "Value",
                "urn:oasis:names:tc:SAML:2.0:status:Responder",
            ),
        )
        for path, attr, value in cases:
            with self.subTest(path=path, attr=attr, value=value):
                node = saml.response()
                target = node if path == "." else saml.find(node, path)
                if attr:
                    target.set(attr, value)
                else:
                    target.text = value
                self.rejected(saml.signed_response(node, signed="both"))

    def test_missing_required_elements(self):
        for path in (
            ".//saml:Conditions",
            ".//saml:AuthnStatement",
            ".//saml:SubjectConfirmation",
            ".//saml:NameID",
            ".//saml:AttributeStatement",
        ):
            with self.subTest(path=path):
                node = saml.response()
                target = saml.find(node, path)
                target.getparent().remove(target)
                self.rejected(saml.signed_response(node))

    def test_multiple_assertions_and_duplicate_ids(self):
        node = saml.response()
        node.append(deepcopy(saml.find(node, "saml:Assertion")))
        self.rejected(saml.signed_response(node, signed="response"))
        # Signing a duplicate ID is itself forbidden by xmlsec. Introduce it
        # after signing to exercise the consumer's rejection of wrapping input.
        node = saml.signed_response()
        node.set("ID", saml.find(node, "saml:Assertion").attrib["ID"])
        self.rejected(node)

    def test_malformed_responses(self):
        for value in ("", "!not-base64!", "a", "bm90IHhtbA==", "PHNhbWw+"):
            with self.subTest(value=value):
                self.rejected(value)

    def test_dtd_is_rejected(self):
        xml = b'<!DOCTYPE Response [<!ENTITY example "expanded">]><Response>&example;</Response>'
        self.rejected(b64encode(xml).decode())

    def test_missing_response(self):
        self.strategy.set_request_data({"RelayState": "idp"}, self.backend)
        with (
            patch.object(self.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthInputError) as caught,
        ):
            self.backend.complete()
        self.assertEqual(caught.exception.code, "missing_parameter")
        self.assertEqual(caught.exception.parameter, "SAMLResponse")
        authenticate.assert_not_called()

    def test_optional_nameid_and_attribute_statement(self):
        self.security(wantNameId=False, wantAttributeStatement=False)
        node = saml.response()
        nameid = saml.find(node, ".//saml:NameID")
        nameid.getparent().remove(nameid)
        self.assertIsNone(
            self.complete(saml.signed_response(node))["attributes"]["name_id"]
        )
        self.strategy.session_set(self.key, "request-id")
        node = saml.response()
        attrs = saml.find(node, ".//saml:AttributeStatement")
        attrs.getparent().remove(attrs)
        result = self.complete(saml.signed_response(node))
        self.assertEqual(
            self.backend.get_user_id({}, result), "idp:persistent:c3RhYmxlLW5hbWUtaWQ"
        )

    def test_attribute_values_and_duplicate_names(self):
        node = saml.response(
            attributes={"username": ["alice"], "empty": [], "multi": ["one", "two"]}
        )
        result = self.complete(saml.signed_response(node))
        self.assertEqual(result["attributes"]["empty"], [])
        self.assertEqual(result["attributes"]["multi"], ["one", "two"])
        self.strategy.session_set(self.key, "request-id")
        node = saml.response()
        attrs = saml.find(node, ".//saml:AttributeStatement")
        attrs.append(deepcopy(attrs[0]))
        self.rejected(saml.signed_response(node))

    def test_certificate_rollover(self):
        conf = self.idps["idp"]
        del conf["x509cert"]
        conf["x509certMulti"] = {
            "signing": [saml.keypair(name)[1].decode() for name in ("idp", "rollover")]
        }
        for identity in ("idp", "rollover"):
            with self.subTest(identity=identity):
                self.strategy.session_set(self.key, "request-id")
                self.complete(saml.signed_response(identity=identity))
        self.strategy.session_set(self.key, "request-id")
        self.rejected(saml.signed_response(identity="untrusted"))
        conf["x509certMulti"] = {"signing": [saml.keypair("rollover")[1].decode()]}
        self.rejected(saml.signed_response(identity="idp"))

    def test_encrypted_assertion(self):
        self.security(wantAssertionsEncrypted=True)
        self.rejected(saml.signed_response())
        node = saml.signed_response()
        saml.encrypt(saml.find(node, "saml:Assertion"))
        self.assertEqual(self.complete(node)["attributes"][saml.UID], ["stable-uid"])

    def test_encrypted_nameid(self):
        self.security(wantNameIdEncrypted=True)
        self.rejected(saml.signed_response())
        node = saml.response()
        saml.encrypt(saml.find(node, ".//saml:NameID"))
        result = self.complete(saml.signed_response(node))
        self.assertEqual(result["attributes"]["name_id"], "stable-name-id")

    def name_id_response(self, name_id_format: str | None, *, encrypted=False):
        self.strategy.session_set(self.key, "request-id")
        node = saml.response(attributes={"username": ["alice"]})
        name_id = saml.find(node, ".//saml:NameID")
        if name_id_format is None:
            del name_id.attrib["Format"]
        else:
            name_id.set("Format", name_id_format)
        if encrypted:
            saml.encrypt(name_id)
        return saml.signed_response(node)

    def test_name_id_format_matches_requested(self):
        # The default unspecified request leaves the choice to the IdP
        for name_id_format in (saml.PERSISTENT, saml.TRANSIENT, None):
            self.complete(self.name_id_response(name_id_format))
        self.strategy.set_settings(
            {"SOCIAL_AUTH_SAML_SP_EXTRA": {"NameIDFormat": saml.PERSISTENT}}
        )
        result = self.complete(self.name_id_response(saml.PERSISTENT))
        self.assertEqual(
            self.backend.get_user_id({}, result), "idp:persistent:c3RhYmxlLW5hbWUtaWQ"
        )
        # NameIDPolicy in an unsigned AuthnRequest can be changed by the browser
        for name_id_format in (saml.TRANSIENT, saml.UNSPECIFIED, None):
            with self.subTest(name_id_format=name_id_format):
                self.rejected(self.name_id_response(name_id_format))
        with self.assertRaises(AuthResponseError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "invalid_claim")
        self.assertEqual(caught.exception.claim, "NameID")
        self.assertEqual(self.strategy.session_get(self.key), "request-id")

    def test_name_id_format_idp_override(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_SAML_SP_EXTRA": {"NameIDFormat": saml.PERSISTENT}}
        )
        conf = self.idps["idp"]
        conf["name_id_format"] = saml.UNSPECIFIED
        self.complete(self.name_id_response(saml.UNSPECIFIED))
        self.complete(self.name_id_response(None))
        self.rejected(self.name_id_response(saml.PERSISTENT))
        conf["name_id_format"] = None
        for name_id_format in (saml.PERSISTENT, saml.TRANSIENT, None):
            self.complete(self.name_id_response(name_id_format))

    def test_name_id_format_without_requested_format(self):
        self.strategy.set_settings(
            {"SOCIAL_AUTH_SAML_SP_EXTRA": {"NameIDFormat": saml.PERSISTENT}}
        )
        # The encrypted format is requested instead of the configured one
        self.security(wantNameIdEncrypted=True)
        self.complete(self.name_id_response(saml.TRANSIENT, encrypted=True))
        conf = self.idps["idp"]
        conf["name_id_format"] = saml.PERSISTENT
        self.complete(self.name_id_response(saml.PERSISTENT, encrypted=True))
        self.rejected(self.name_id_response(saml.TRANSIENT, encrypted=True))
        del conf["name_id_format"]
        # There is no format to check without NameID
        self.security(wantNameId=False)
        self.strategy.session_set(self.key, "request-id")
        node = saml.response()
        name_id = saml.find(node, ".//saml:NameID")
        name_id.getparent().remove(name_id)
        result = self.complete(saml.signed_response(node))
        self.assertIsNone(result["attributes"]["name_id"])

    def test_wrong_key_and_corrupt_ciphertext(self):
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt):
                node = saml.signed_response()
                saml.encrypt(
                    saml.find(node, "saml:Assertion"),
                    identity="sp" if corrupt else "untrusted",
                )
                if corrupt:
                    saml.find(
                        node, ".//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue"
                    ).text = "AAAA"
                self.rejected(node)

    def test_request_correlation_and_replay(self):
        self.rejected(
            saml.signed_response(saml.response("wrong-request")),
            exception=AuthResponseError,
        )
        node = saml.signed_response()
        self.complete(node)
        self.rejected(node, exception=AuthSessionError)

    def test_stripped_unsigned_in_response_to_is_still_correlated(self):
        # With an assertion-only signature the envelope attribute is not
        # covered; the signed SubjectConfirmationData copy must still be used.
        node = saml.response()
        del node.attrib["InResponseTo"]
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                stripped = saml.signed_response(deepcopy(node))
                if encrypted:
                    saml.encrypt(saml.find(stripped, "saml:Assertion"))
                self.strategy.session_set(self.key, "wrong-request")
                self.rejected(stripped, exception=AuthSessionError)
                self.strategy.session_pop(self.key)
                self.rejected(stripped, exception=AuthSessionError)
                self.strategy.session_set(self.key, "request-id")
                self.complete(stripped)
                self.assertIsNone(self.strategy.session_get(self.key))
                self.rejected(stripped, exception=AuthSessionError)

    def test_added_unsigned_in_response_to_is_not_correlated(self):
        # Adding the envelope attribute to an unsolicited response whose
        # assertion alone is signed must not satisfy request correlation.
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                node = saml.signed_response(saml.response(None))
                if encrypted:
                    saml.encrypt(saml.find(node, "saml:Assertion"))
                node.set("InResponseTo", "request-id")
                self.rejected(node, exception=AuthSessionError)
                self.rejected(node, user=User("existing"), exception=AuthSessionError)
                self.assertEqual(self.strategy.session_get(self.key), "request-id")

    def test_signed_envelope_in_response_to_is_correlated(self):
        # A signed response covers the envelope attribute, so it is trusted
        # even when SubjectConfirmationData carries no copy of it.
        node = saml.response()
        data = saml.find(node, ".//saml:SubjectConfirmationData")
        del data.attrib["InResponseTo"]
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                signed = deepcopy(node)
                if encrypted:
                    saml.encrypt(saml.find(signed, "saml:Assertion"))
                self.strategy.session_set(self.key, "request-id")
                self.complete(saml.signed_response(signed, signed="response"))
                self.assertIsNone(self.strategy.session_get(self.key))

    def test_stripped_in_response_to_checks_all_bearer_confirmations(self):
        for invalid_confirmation in ("non-bearer", "missing-data", "expired"):
            with self.subTest(invalid_confirmation=invalid_confirmation):
                self.strategy.session_set(self.key, "request-id")
                node = saml.response()
                del node.attrib["InResponseTo"]
                subject = saml.find(node, ".//saml:Subject")
                confirmation = deepcopy(saml.find(subject, "saml:SubjectConfirmation"))
                data = saml.find(confirmation, "saml:SubjectConfirmationData")
                data.set("InResponseTo", "wrong-request")
                if invalid_confirmation == "non-bearer":
                    confirmation.set(
                        "Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
                    )
                elif invalid_confirmation == "missing-data":
                    confirmation.remove(data)
                else:
                    data.set("NotOnOrAfter", saml.NOW)
                subject.insert(1, confirmation)
                self.complete(saml.signed_response(node))

    def test_stripped_in_response_to_ignores_unusable_matching_confirmation(self):
        for invalid_confirmation in ("expired", "not-yet-valid", "wrong-recipient"):
            with self.subTest(invalid_confirmation=invalid_confirmation):
                self.strategy.session_set(self.key, "request-id")
                node = saml.response("wrong-request")
                del node.attrib["InResponseTo"]
                subject = saml.find(node, ".//saml:Subject")
                confirmation = deepcopy(saml.find(subject, "saml:SubjectConfirmation"))
                data = saml.find(confirmation, "saml:SubjectConfirmationData")
                data.set("InResponseTo", "request-id")
                if invalid_confirmation == "expired":
                    data.set("NotOnOrAfter", saml.NOW)
                elif invalid_confirmation == "not-yet-valid":
                    data.set("NotBefore", "2024-06-01T12:00:01Z")
                else:
                    data.set("Recipient", "https://wrong.example.com/acs")
                subject.insert(1, confirmation)
                self.rejected(saml.signed_response(node), exception=AuthSessionError)

    def test_unsolicited_login_requires_explicit_opt_in(self):
        node = saml.signed_response(saml.response(None))
        self.rejected(node, user=User("existing"), exception=AuthSessionError)
        self.rejected(node, exception=AuthSessionError)
        self.strategy.set_settings({"SOCIAL_AUTH_SAML_ALLOW_IDP_INITIATED": True})
        self.complete(node)
        self.assertEqual(self.strategy.session_get(self.key), "request-id")
        self.strategy.session_pop(self.key)
        self.rejected(node, user=User("existing"), exception=AuthSessionError)
        self.complete(node)

    def test_matching_request_allows_account_linking(self):
        self.complete(saml.signed_response(), user=User("existing"))

    def test_other_idp_cannot_use_request(self):
        self.rejected(
            saml.signed_response(),
            relay_state='{"idp":"other"}',
            exception=AuthSessionError,
        )
        self.strategy.session_set("saml_other_authn_request_id", "request-id")
        self.idps["other"]["entity_id"] = "https://other.example.com/metadata"
        self.rejected(
            saml.signed_response(),
            relay_state='{"idp":"other"}',
            exception=AuthResponseError,
        )

    def test_relay_state_session_id_cannot_replace_browser_request(self):
        relay = json.dumps({"idp": "idp", LEGACY_SESSION_ID_FIELD: "saved-session"})
        for browser_request in (None, "victim-request"):
            with self.subTest(browser_request=browser_request):
                self.strategy.session_set(self.key, browser_request)
                self.rejected(
                    saml.signed_response(),
                    relay_state=relay,
                    exception=AuthSessionError
                    if browser_request is None
                    else AuthResponseError,
                )
                self.assertEqual(self.strategy.session_get(self.key), browser_request)
        self.strategy.session_set(self.key, "request-id")
        self.complete(saml.signed_response(), relay_state=relay)
        self.assertIsNone(self.strategy.session_get(self.key))

    def test_browser_return_preserves_response_and_requires_browser_request(self):
        relay = json.dumps({"idp": "idp", LEGACY_SESSION_ID_FIELD: "attacker-session"})
        saml_response = saml.encode(saml.signed_response())
        self.strategy.set_request_data(
            {"SAMLResponse": saml_response, "RelayState": relay}, self.backend
        )
        with patch.object(self.strategy, "authenticate") as authenticate:
            page = self.backend.complete()
        authenticate.assert_not_called()
        self.assertEqual(self.strategy.session_get(self.key), "request-id")
        self.assertIn('name="SAMLResponse"', page.content)
        self.assertIn(saml_response, page.content)
        self.assertIn('name="psa_saml_browser_return"', page.content)
        self.assertIn("no-store", page.headers["Cache-Control"])
        self.assertEqual(page.headers["X-Frame-Options"], "DENY")
        self.assertEqual(page.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("form-action 'self'", page.headers["Content-Security-Policy"])

        self.complete(
            saml_response,
            relay_state=relay,
        )
        self.assertIsNone(self.strategy.session_get(self.key))
        self.rejected(
            saml_response,
            relay_state=relay,
            exception=AuthSessionError,
        )

    def test_browser_return_escapes_untrusted_values(self):
        self.strategy.set_request_data(
            {
                "SAMLResponse": '"><script>alert(1)</script>',
                "RelayState": '"><img src=x onerror=alert(1)>',
            },
            self.backend,
        )
        page = self.backend.complete()
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page.content)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", page.content)
        self.assertNotIn("<script>alert(1)</script>", page.content)

    def test_browser_return_rejects_non_string_fields(self):
        for values, parameter in (
            ({"SAMLResponse": 123}, "SAMLResponse"),
            ({"SAMLResponse": "response", "RelayState": ["idp"]}, "RelayState"),
        ):
            with self.subTest(parameter=parameter):
                self.strategy.set_request_data(values, self.backend)
                with (
                    patch.object(self.strategy, "html_with_headers") as html,
                    self.assertRaises(AuthInputError) as caught,
                ):
                    self.backend.complete()
                self.assertEqual(caught.exception.code, "invalid_parameter")
                self.assertEqual(caught.exception.parameter, parameter)
                self.assertEqual(caught.exception.stage, "callback")
                html.assert_not_called()

    def test_browser_return_without_relay_state_uses_current_path(self):
        self.backend.redirect_uri = None
        self.strategy.set_request_data({"SAMLResponse": "response"}, self.backend)
        page = self.backend.complete()
        self.assertIn('action=""', page.content)
        self.assertNotIn('name="RelayState"', page.content)
        self.assertEqual(self.strategy.session_get(self.key), "request-id")

    def test_browser_return_requires_response_headers(self):
        self.strategy.set_request_data({"SAMLResponse": "irrelevant"}, self.backend)
        with (
            patch.object(
                type(self.strategy), "html_with_headers", BaseStrategy.html_with_headers
            ),
            self.assertRaises(AuthConfigurationError) as caught,
        ):
            self.backend.complete()
        self.assertEqual(caught.exception.code, "unsupported_feature")
        self.assertEqual(caught.exception.stage, "callback")

    def test_relay_state_variants_and_single_idp(self):
        self.strategy.set_settings({"SOCIAL_AUTH_SAML_ALLOW_IDP_INITIATED": True})
        for relay in ("idp", '{"idp":"idp","next":"/after"}'):
            with self.subTest(relay=relay):
                self.complete(saml.signed_response(saml.response(None)), relay)
        self.assertEqual(self.strategy.session_get("next"), "/after")
        self.rejected(
            saml.signed_response(), exception=AuthInputError, relay_state=None
        )
        del self.idps["other"]
        result = self.complete(saml.signed_response(), relay_state=None)
        self.assertEqual(result["idp_name"], "idp")
        self.assertEqual(
            self.backend.get_user_id({}, result), "idp:persistent:c3RhYmxlLW5hbWUtaWQ"
        )

    def test_invalid_relay_state(self):
        for relay in (
            "[]",
            "null",
            "42",
            '"idp"',
            "{}",
            '{"idp":[]}',
            '{"idp":{"x":1}}',
            "unknown",
            "{broken",
        ):
            with self.subTest(relay=relay):
                self.rejected(
                    saml.signed_response(),
                    exception=AuthInputError,
                    relay_state=relay,
                )

    def test_pipeline_preserves_existing_identity_and_logout_data(self):
        self.post(saml.signed_response())
        user = self.backend.complete()
        association = TestUserSocialAuth.get_social_auth(
            "saml", "idp:persistent:c3RhYmxlLW5hbWUtaWQ"
        )
        self.assertEqual(association.uid, "idp:persistent:c3RhYmxlLW5hbWUtaWQ")
        self.assertEqual(association.extra_data["name_id"], "stable-name-id")
        self.assertEqual(association.extra_data["session_index"], "session-index")
        self.strategy.session_set(self.key, "request-id")
        self.post(saml.signed_response())
        self.assertEqual(self.backend.complete().id, user.id)

    def test_non_persistent_name_id_uses_fallback_namespace(self):
        for name_id_format in (saml.TRANSIENT, saml.UNSPECIFIED, None):
            with self.subTest(name_id_format=name_id_format):
                node = saml.response()
                name_id = saml.find(node, ".//saml:NameID")
                if name_id_format is None:
                    del name_id.attrib["Format"]
                else:
                    name_id.set("Format", name_id_format)
                self.strategy.session_set(self.key, "request-id")
                result = self.complete(saml.signed_response(node))
                self.assertEqual(result["attributes"]["name_id_format"], name_id_format)
                self.assertEqual(
                    self.backend.get_user_id({}, result),
                    "idp:fallback:c3RhYmxlLXVpZA",
                )

    def test_fallback_does_not_select_persistent_association(self):
        owner = User("previous")
        TestUserSocialAuth(
            owner,
            "saml",
            "idp:stable-uid",
            extra_data={"name_id": "previous", "name_id_format": saml.PERSISTENT},
        )
        node = saml.response()
        saml.find(node, ".//saml:NameID").set("Format", saml.TRANSIENT)
        self.strategy.session_set(self.key, "request-id")
        result = self.complete(saml.signed_response(node))
        with self.assertRaises(AuthAssociationError):
            self.backend.get_user_id({}, result)

    def test_fallback_value_matching_persistent_key_suffix_is_separate(self):
        node = saml.response()
        saml.find(node, ".//saml:NameID").set("Format", saml.TRANSIENT)
        saml.find(
            node, f".//saml:Attribute[@Name='{saml.UID}']/saml:AttributeValue"
        ).text = "persistent:c3RhYmxlLXVpZA"
        self.strategy.session_set(self.key, "request-id")
        result = self.complete(saml.signed_response(node))
        self.assertNotEqual(
            self.backend.get_user_id({}, result), "idp:persistent:c3RhYmxlLXVpZA"
        )

    def test_reserved_legacy_fallback_key_requires_recovery(self):
        owner = User("previous")
        TestUserSocialAuth(
            owner,
            "saml",
            "idp:persistent:c3RhYmxlLXVpZA",
            extra_data={"name_id": "stable-uid", "name_id_format": saml.PERSISTENT},
        )
        node = saml.response()
        saml.find(node, ".//saml:NameID").set("Format", saml.TRANSIENT)
        saml.find(
            node, f".//saml:Attribute[@Name='{saml.UID}']/saml:AttributeValue"
        ).text = "persistent:c3RhYmxlLXVpZA"
        self.strategy.session_set(self.key, "request-id")
        result = self.complete(saml.signed_response(node))
        with self.assertRaises(AuthAssociationError):
            self.backend.get_user_id({}, result)

    def test_matching_legacy_fallback_keeps_original_key(self):
        owner = User("previous")
        TestUserSocialAuth(owner, "saml", "idp:stable-uid", extra_data={})
        node = saml.response()
        saml.find(node, ".//saml:NameID").set("Format", saml.TRANSIENT)
        self.strategy.session_set(self.key, "request-id")
        result = self.complete(saml.signed_response(node))
        self.assertEqual(self.backend.get_user_id({}, result), "idp:stable-uid")

    def test_configured_identifier_cannot_select_persistent_association(self):
        self.idps["idp"]["attr_user_permanent_id"] = saml.UID
        owner = User("previous")
        TestUserSocialAuth(
            owner,
            "saml",
            "idp:stable-uid",
            extra_data={"saml_identifier_kind": "persistent"},
        )
        result = self.complete(saml.signed_response())
        with self.assertRaises(AuthAssociationError):
            self.backend.get_user_id({}, result)

    def test_configured_permanent_id_wins_over_persistent_name_id(self):
        self.idps["idp"]["attr_user_permanent_id"] = saml.UID
        result = self.complete(saml.signed_response())
        self.assertEqual(self.backend.get_user_id({}, result), "idp:stable-uid")
        self.assertIsNone(
            self.backend.get_legacy_social_auth("idp:stable-name-id", "", result)
        )

    def test_login_name_association_migrates_to_matching_name_id(self):
        owner = User("alice", email="previous@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "saml",
            "idp:stable-uid",
            extra_data={"name_id": "stable-name-id", "session_index": "old"},
        )
        self.post(saml.signed_response())
        self.assertIs(self.backend.complete(), owner)
        self.assertEqual(legacy.uid, "idp:persistent:c3RhYmxlLW5hbWUtaWQ")
        self.assertEqual(legacy.extra_data["session_index"], "session-index")
        self.assertEqual(len(User.cache), 1)

    def test_reassigned_login_name_gets_separate_user(self):
        owner = User("alice", email="previous@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "saml",
            "idp:stable-uid",
            extra_data={"name_id": "previous-holder", "session_index": "old"},
        )
        self.post(saml.signed_response())
        user = self.backend.complete()
        self.assertIsNot(user, owner)
        self.assertEqual(legacy.uid, "idp:stable-uid")
        self.assertEqual(legacy.extra_data["name_id"], "previous-holder")
        self.assertEqual(user.social[0].uid, "idp:persistent:c3RhYmxlLW5hbWUtaWQ")

    def test_persistent_name_id_does_not_select_legacy_login_name(self):
        owner = User("previous", email="previous@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "saml",
            "idp:stable-name-id",
            extra_data={"name_id": "previous-holder"},
        )
        self.post(saml.signed_response())
        user = self.backend.complete()
        self.assertIsNot(user, owner)
        self.assertEqual(legacy.uid, "idp:stable-name-id")
        self.assertEqual(user.social[0].uid, "idp:persistent:c3RhYmxlLW5hbWUtaWQ")

    def test_namespaced_association_requires_matching_name_id_evidence(self):
        owner = User("previous", email="previous@example.com")
        existing = TestUserSocialAuth(
            owner,
            "saml",
            "idp:persistent:c3RhYmxlLW5hbWUtaWQ",
            extra_data={
                "name_id": "previous-holder",
                "name_id_format": saml.PERSISTENT,
            },
        )
        self.post(saml.signed_response())
        with self.assertRaises(AuthAssociationError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "identifier_migration_conflict")
        self.assertIs(existing.user, owner)

    def test_login_name_association_without_name_id_requires_recovery(self):
        owner = User("alice", email="previous@example.com")
        legacy = TestUserSocialAuth(
            owner, "saml", "idp:stable-uid", extra_data={"session_index": "old"}
        )
        self.post(saml.signed_response())
        with self.assertRaises(AuthAssociationError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "identifier_migration_conflict")
        self.assertEqual(legacy.uid, "idp:stable-uid")
        self.assertEqual(len(User.cache), 1)
        # Even an authenticated owner needs matching saved NameID evidence.
        self.strategy.session_set(self.key, "request-id")
        self.post(saml.signed_response())
        with self.assertRaises(AuthAssociationError):
            self.backend.complete(user=owner)
        self.assertEqual(legacy.uid, "idp:stable-uid")

    def test_nonpersistent_legacy_name_id_cannot_migrate(self):
        owner = User("alice", email="previous@example.com")
        legacy = TestUserSocialAuth(
            owner,
            "saml",
            "idp:stable-uid",
            extra_data={
                "name_id": "stable-name-id",
                "name_id_format": saml.TRANSIENT,
            },
        )
        self.post(saml.signed_response())
        with self.assertRaises(AuthAssociationError) as caught:
            self.backend.complete()
        self.assertEqual(caught.exception.code, "identifier_migration_conflict")
        self.assertEqual(legacy.uid, "idp:stable-uid")

    def test_legacy_lookup_rejects_another_identity_context(self):
        owner = User("alice", email="previous@example.com")
        legacy = TestUserSocialAuth(
            owner, "saml", "idp:stable-uid", extra_data={"name_id": "stable-name-id"}
        )
        result = self.complete(saml.signed_response())
        for uid in ("idp:stable-uid", "other:stable-name-id", "idp:other"):
            with self.subTest(uid=uid):
                self.assertIsNone(self.backend.get_legacy_social_auth(uid, "", result))
                self.assertEqual(legacy.uid, "idp:stable-uid")

    def test_attribute_mapping(self):
        provider = self.backend.get_idp("idp")
        attrs: dict[str, str | list[str] | None] = {
            saml.UID: ["first", "second"],
            "name_id": "fallback",
            saml.MAIL: ["a@example.com"],
            "username": ["alice"],
            "given_name": ["Alice"],
            "surname": ["Example"],
            "fullname": ["Alice Example"],
        }
        self.assertEqual(provider.get_user_permanent_id(attrs), "first")
        self.assertEqual(
            provider.get_user_details(attrs),
            {
                "username": "alice",
                "email": "a@example.com",
                "first_name": "Alice",
                "last_name": "Example",
                "fullname": "Alice Example",
            },
        )
        del attrs[saml.UID]
        self.assertEqual(provider.get_user_permanent_id(attrs), "fallback")
        provider.conf.update(attr_user_permanent_id="custom:id", attr_email=None)
        attrs["custom:id"] = ["custom-uid", "ignored"]
        self.assertEqual(provider.get_user_permanent_id(attrs), "custom-uid")
        self.assertIsNone(provider.get_user_details(attrs)["email"])
        del attrs["custom:id"]
        with self.assertRaises(AuthResponseError):
            provider.get_user_permanent_id(attrs)
        for value in ([], [""], None):
            with self.subTest(value=value):
                attrs["custom:id"] = value
                with self.assertRaises(AuthResponseError):
                    provider.get_user_permanent_id(attrs)
        provider.conf["attr_username"] = "missing"
        with self.assertRaises(AuthResponseError):
            provider.get_user_details(attrs)
        del provider.conf["attr_username"]
        self.assertIsNone(provider.get_user_details({})["username"])

    def test_idp_names_keep_identical_subjects_distinct(self):
        result = self.complete(saml.signed_response())
        self.assertEqual(
            self.backend.get_user_id({}, result), "idp:persistent:c3RhYmxlLW5hbWUtaWQ"
        )
        self.strategy.session_set("saml_other_authn_request_id", "request-id")
        result = self.complete(saml.signed_response(), relay_state="other")
        self.assertEqual(
            self.backend.get_user_id({}, result), "other:persistent:c3RhYmxlLW5hbWUtaWQ"
        )

    def test_entitlement_hook_blocks_authentication(self):
        self.post(saml.signed_response())

        def check(idp, attributes):
            self.assertEqual(idp.name, "idp")
            self.assertEqual(attributes["custom:roles"], ["member", "admin"])
            raise AuthPolicyError(
                self.backend, code="authentication_disallowed", stage="callback"
            )

        with (
            patch.object(self.backend, "_check_entitlements", check),
            patch.object(self.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthPolicyError),
        ):
            self.backend.complete()
        authenticate.assert_not_called()

    def test_authn_request_and_dynamic_idp(self):
        self.security(authnRequestsSigned=True)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_SAML_SP_EXTRA": {"NameIDFormat": saml.PERSISTENT}}
        )
        self.strategy.set_request_data(
            {"idp": "dynamic", "next": "/after"}, self.backend
        )
        dynamic = SAMLIdentityProvider(self.backend, "dynamic", **self.idps["idp"])
        with patch.object(self.backend, "get_idp", return_value=dynamic):
            url = self.backend.auth_url()
        node, query = saml.decode_redirect(url)
        saml.verify_redirect(query)
        self.assertEqual(node.get("Destination"), saml.SSO)
        self.assertEqual(node.get("AssertionConsumerServiceURL"), saml.ACS)
        self.assertEqual(node.get("ProtocolBinding"), saml.POST)
        self.assertEqual(saml.find(node, "saml:Issuer").text, saml.SP)
        self.assertEqual(
            saml.find(node, "samlp:NameIDPolicy").get("Format"), saml.PERSISTENT
        )
        self.assertEqual(
            self.strategy.session_get("saml_dynamic_authn_request_id"), node.get("ID")
        )
        self.assertEqual(
            json.loads(query["RelayState"]), {"idp": "dynamic", "next": "/after"}
        )
        self.assertEqual(query["SigAlg"], saml.SHA256)

    def test_configured_signature_algorithm_without_session_relay(self):
        self.security(authnRequestsSigned=True, signatureAlgorithm=saml.SHA512)
        self.strategy.set_request_data({"idp": "idp"}, self.backend)
        node, query = saml.decode_redirect(self.backend.auth_url())
        saml.verify_redirect(query)
        self.assertEqual(query["SigAlg"], saml.SHA512)
        self.assertEqual(self.strategy.session_get(self.key), node.get("ID"))
        self.assertNotIn(LEGACY_SESSION_ID_FIELD, json.loads(query["RelayState"]))

    def test_signed_metadata(self):
        self.security(signMetadata=True, signatureAlgorithm=saml.SHA512)
        xml, errors = self.backend.generate_metadata_xml()
        self.assertEqual(errors, [])
        node = etree.fromstring(xml)
        saml.verify_xml(node)
        self.assertEqual(
            saml.find(node, "ds:Signature/ds:SignedInfo/ds:SignatureMethod").get(
                "Algorithm"
            ),
            saml.SHA512,
        )

    def test_metadata_contents(self):
        self.security(authnRequestsSigned=True, wantAssertionsSigned=True)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_SAML_SP_EXTRA": {
                    "NameIDFormat": saml.PERSISTENT,
                    "singleLogoutService": {"url": saml.ACS, "binding": saml.BINDING},
                }
            }
        )
        xml, errors = self.backend.generate_metadata_xml()
        self.assertEqual(errors, [])
        node = etree.fromstring(xml)
        self.assertEqual(node.get("entityID"), saml.SP)
        descriptor = saml.find(node, "md:SPSSODescriptor")
        self.assertEqual(descriptor.get("AuthnRequestsSigned"), "true")
        self.assertEqual(descriptor.get("WantAssertionsSigned"), "true")
        self.assertEqual(saml.find(descriptor, "md:NameIDFormat").text, saml.PERSISTENT)
        self.assertEqual(
            saml.find(descriptor, "md:AssertionConsumerService").get("Location"),
            saml.ACS,
        )
        self.assertEqual(
            saml.find(descriptor, "md:AssertionConsumerService").get("Binding"),
            saml.POST,
        )
        self.assertEqual(
            saml.find(descriptor, "md:SingleLogoutService").get("Location"), saml.ACS
        )
        certificate = saml.find(descriptor, ".//ds:X509Certificate").text
        expected = "".join(saml.keypair("sp")[1].decode().splitlines()[1:-1])
        self.assertEqual("".join(certificate.split()), expected)
        self.assertEqual(
            saml.find(node, "md:Organization/md:OrganizationName").text, "Example"
        )
        self.assertEqual(len(node.findall("md:ContactPerson", saml.NS)), 2)

    def test_logout_request(self):
        self.security(logoutRequestSigned=True)
        social = SimpleNamespace(
            extra_data={"name_id": "stable-name-id", "session_index": "session-index"}
        )
        url = self.backend.request_logout("idp", social, return_to="/logged-out")
        node, query = saml.decode_redirect(url)
        saml.verify_redirect(query)
        self.assertEqual(node.get("Destination"), saml.SLO)
        self.assertEqual(saml.find(node, "saml:Issuer").text, saml.SP)
        self.assertEqual(saml.find(node, "saml:NameID").text, "stable-name-id")
        self.assertEqual(saml.find(node, "samlp:SessionIndex").text, "session-index")
        self.assertEqual(query["RelayState"], "/logged-out")

    def test_incoming_logout(self):
        self.security(wantMessagesSigned=True, logoutResponseSigned=True)
        for kind in ("LogoutRequest", "LogoutResponse"):
            for variant in (
                "valid",
                "unsigned",
                "untrusted",
                "tampered",
                "issuer",
                "destination",
                "status",
            ):
                if kind == "LogoutRequest" and variant == "status":
                    continue
                with self.subTest(kind=kind, variant=variant):
                    node = saml.logout(kind)
                    if variant == "issuer":
                        saml.find(
                            node, "saml:Issuer"
                        ).text = "https://wrong.example.com"
                    if variant == "destination":
                        node.set("Destination", "https://wrong.example.com")
                    if variant == "status":
                        saml.find(node, ".//samlp:StatusCode").set(
                            "Value", "urn:oasis:names:tc:SAML:2.0:status:Responder"
                        )
                    query = saml.redirect_query(
                        node,
                        kind="SAMLRequest"
                        if kind == "LogoutRequest"
                        else "SAMLResponse",
                        identity="untrusted" if variant == "untrusted" else "idp",
                        relay_state="/after",
                    )
                    if variant == "unsigned":
                        del query["Signature"]
                        del query["SigAlg"]
                    if variant == "tampered":
                        query["RelayState"] = "/changed"
                    self.strategy.request_data().clear()
                    self.strategy.set_request_data(query, self.backend)
                    delete = Mock()
                    url, errors = self.backend.process_logout("idp", delete)
                    if variant == "valid":
                        self.assertEqual(errors, [])
                        delete.assert_called_once_with()
                        if kind == "LogoutRequest":
                            reply, query = saml.decode_redirect(url, "SAMLResponse")
                            saml.verify_redirect(query, "SAMLResponse")
                            self.assertEqual(reply.get("InResponseTo"), node.get("ID"))
                    else:
                        self.assertTrue(errors)
                        delete.assert_not_called()

    def test_incoming_logout_request_relay_state_redirect(self):
        # python3-saml redirects to RelayState when the IdP has no SLO endpoint.
        del self.idps["idp"]["slo_url"]
        for relay_state, settings, host in (
            ("/after", {}, "myapp.com"),
            ("http://myapp.com/after", {}, "myapp.com"),
            ("//attacker.example/after", {}, "myapp.com"),
            ("https://attacker.example/after", {}, None),
            (
                "https://partner.example/after",
                {"SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS": ["partner.example"]},
                "partner.example",
            ),
            (
                "https://attacker.example/after",
                {"SOCIAL_AUTH_SANITIZE_REDIRECTS": False},
                "attacker.example",
            ),
        ):
            for idp_name in ("idp", "other"):
                with self.subTest(relay_state=relay_state, idp=idp_name, **settings):
                    self.strategy.set_settings(
                        {
                            "SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS": [],
                            "SOCIAL_AUTH_SANITIZE_REDIRECTS": True,
                            **settings,
                        }
                    )
                    query = saml.redirect_query(
                        saml.logout("LogoutRequest"),
                        kind="SAMLRequest",
                        relay_state=relay_state,
                    )
                    self.strategy.request_data().clear()
                    self.strategy.set_request_data(query, self.backend)
                    delete = Mock()
                    url, errors = self.backend.process_logout(idp_name, delete)
                    self.assertEqual(errors, [])
                    delete.assert_called_once_with()
                    if idp_name == "other":
                        # The reply goes to the configured SLO endpoint.
                        self.assertTrue(url.startswith(f"{saml.SLO}?"))
                    elif host is None:
                        self.assertIsNone(url)
                    else:
                        self.assertEqual(urlsplit(url).netloc, host)
