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

from social_core.exceptions import (
    AuthFailed,
    AuthForbidden,
    AuthInvalidParameter,
    AuthMissingParameter,
)
from social_core.tests.models import TestUserSocialAuth, User

from .base import BaseBackendTest

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
            "SAMLResponse": saml.encode(node) if not isinstance(node, str) else node
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
        exception: type[Exception] = AuthFailed,
        relay_state: str | None = '{"idp":"idp"}',
        **kwargs,
    ):
        self.post(node, relay_state)
        with (
            patch.object(self.strategy, "authenticate") as authenticate,
            patch.object(self.strategy, "restore_session") as restore,
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
        restore.assert_not_called()
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
            self.assertRaises(AuthFailed),
        ):
            self.backend.complete()
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
        self.assertEqual(self.backend.get_user_id({}, result), "idp:stable-name-id")

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
        self.rejected(saml.signed_response(saml.response("wrong-request")))
        node = saml.signed_response()
        self.complete(node)
        self.rejected(node)

    def test_unsolicited_login_and_account_linking(self):
        node = saml.signed_response(saml.response(None))
        self.rejected(node, user=User("existing"))
        self.complete(node)
        self.assertEqual(self.strategy.session_get(self.key), "request-id")
        self.strategy.session_pop(self.key)
        self.rejected(node, user=User("existing"))
        self.complete(node)

    def test_matching_request_allows_account_linking(self):
        self.complete(saml.signed_response(), user=User("existing"))

    def test_other_idp_cannot_use_request(self):
        self.rejected(saml.signed_response(), relay_state='{"idp":"other"}')
        self.strategy.session_set("saml_other_authn_request_id", "request-id")
        self.idps["other"]["entity_id"] = "https://other.example.com/metadata"
        self.rejected(saml.signed_response(), relay_state='{"idp":"other"}')

    def test_restored_session_is_checked_after_signature(self):
        relay = json.dumps(
            {"idp": "idp", self.strategy.SESSION_SAVE_KEY: "saved-session"}
        )
        self.rejected(saml.signed_response(identity="untrusted"), relay_state=relay)
        self.strategy.session_pop(self.key)
        events = []

        def restore(session_id, kwargs):
            self.assertEqual(session_id, "saved-session")
            events.append("restore")
            self.strategy.session_set(self.key, "request-id")

        with patch.object(self.strategy, "restore_session", restore):
            self.complete(saml.signed_response(), relay_state=relay)
        self.assertEqual(events, ["restore"])
        self.assertIsNone(self.strategy.session_get(self.key))

    def test_restored_session_mismatched_request(self):
        relay = json.dumps(
            {"idp": "idp", self.strategy.SESSION_SAVE_KEY: "saved-session"}
        )
        self.post(saml.signed_response(), relay)
        for restored_id in (None, "wrong-request"):
            with self.subTest(restored_id=restored_id):

                def restore(session_id, kwargs, restored_id=restored_id):
                    self.strategy.session_set(self.key, restored_id)

                with (
                    patch.object(self.strategy, "restore_session", restore),
                    patch.object(self.strategy, "authenticate") as authenticate,
                    self.assertRaises(AuthFailed),
                ):
                    self.backend.complete()
                authenticate.assert_not_called()
                self.assertEqual(self.strategy.session_get(self.key), restored_id)

    def test_relay_state_variants_and_single_idp(self):
        for relay in ("idp", '{"idp":"idp","next":"/after"}'):
            with self.subTest(relay=relay):
                self.complete(saml.signed_response(saml.response(None)), relay)
        self.assertEqual(self.strategy.session_get("next"), "/after")
        self.rejected(
            saml.signed_response(), exception=AuthMissingParameter, relay_state=None
        )
        del self.idps["other"]
        result = self.complete(saml.signed_response(), relay_state=None)
        self.assertEqual(result["idp_name"], "idp")
        self.assertEqual(self.backend.get_user_id({}, result), "idp:stable-uid")

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
                    exception=AuthInvalidParameter,
                    relay_state=relay,
                )

    def test_pipeline_preserves_existing_identity_and_logout_data(self):
        self.post(saml.signed_response())
        user = self.backend.complete()
        association = TestUserSocialAuth.get_social_auth("saml", "idp:stable-uid")
        self.assertEqual(association.uid, "idp:stable-uid")
        self.assertEqual(association.extra_data["name_id"], "stable-name-id")
        self.assertEqual(association.extra_data["session_index"], "session-index")
        self.strategy.session_set(self.key, "request-id")
        self.post(saml.signed_response())
        self.assertEqual(self.backend.complete().id, user.id)

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
        with self.assertRaises(AuthMissingParameter):
            provider.get_user_permanent_id(attrs)
        for value in ([], [""], None):
            with self.subTest(value=value):
                attrs["custom:id"] = value
                with self.assertRaises(AuthInvalidParameter):
                    provider.get_user_permanent_id(attrs)
        provider.conf["attr_username"] = "missing"
        with self.assertRaises(AuthMissingParameter):
            provider.get_user_details(attrs)
        del provider.conf["attr_username"]
        self.assertIsNone(provider.get_user_details({})["username"])

    def test_idp_names_keep_identical_subjects_distinct(self):
        result = self.complete(saml.signed_response())
        self.assertEqual(self.backend.get_user_id({}, result), "idp:stable-uid")
        self.strategy.session_set("saml_other_authn_request_id", "request-id")
        result = self.complete(saml.signed_response(), relay_state="other")
        self.assertEqual(self.backend.get_user_id({}, result), "other:stable-uid")

    def test_entitlement_hook_blocks_authentication(self):
        self.post(saml.signed_response())

        def check(idp, attributes):
            self.assertEqual(idp.name, "idp")
            self.assertEqual(attributes["custom:roles"], ["member", "admin"])
            raise AuthForbidden(self.backend)

        with (
            patch.object(self.backend, "_check_entitlements", check),
            patch.object(self.strategy, "authenticate") as authenticate,
            self.assertRaises(AuthForbidden),
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

    def test_configured_signature_algorithm_and_session_relay(self):
        self.security(authnRequestsSigned=True, signatureAlgorithm=saml.SHA512)
        self.strategy.set_request_data({"idp": "idp"}, self.backend)
        with patch.object(self.strategy, "get_session_id", return_value="saved"):
            node, query = saml.decode_redirect(self.backend.auth_url())
        saml.verify_redirect(query)
        self.assertEqual(query["SigAlg"], saml.SHA512)
        self.assertEqual(self.strategy.session_get(self.key), node.get("ID"))
        self.assertEqual(
            json.loads(query["RelayState"])[self.strategy.SESSION_SAVE_KEY], "saved"
        )

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
