"""Local SAML IdP fixtures; no upstream response/authentication classes are used.

Keys are ephemeral test-only RSA keys. All protocol times are fixed; tests patch
only the toolkit clock. Semantic mutations must happen before signing, while
signature-tampering tests deliberately mutate the signed result.
"""

from base64 import b64decode, b64encode
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import parse_qs, urlencode, urlsplit
from zlib import compress, decompress

import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from lxml import etree

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
}
NOW = "2024-06-01T12:00:00Z"
BEFORE = "2024-06-01T11:00:00Z"
AFTER = "2024-06-01T13:00:00Z"
ENTITY = "https://idp.example.com/metadata"
SP = "https://sp.example.com/metadata"
ACS = "http://myapp.com/complete/saml"
SSO = "https://idp.example.com/sso"
SLO = "https://idp.example.com/slo"
BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
UID = "urn:oid:0.9.2342.19200300.100.1.1"
MAIL = "urn:oid:0.9.2342.19200300.100.1.3"
SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"


@lru_cache
def keypair(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        cert.public_bytes(serialization.Encoding.PEM),
    )


def element(name, parent=None, text=None, **attrs):
    prefix, local = name.split(":")
    tag = f"{{{NS[prefix]}}}{local}"
    node = (
        etree.Element(tag, nsmap=NS, **attrs)
        if parent is None
        else etree.SubElement(parent, tag, **attrs)
    )
    node.text = text
    return node


def find(node, path):
    result = node.find(path, NS)
    assert result is not None, f"Missing fixture element: {path}"
    return result


def response(request_id: str | None = "request-id", attributes=None):
    node = element(
        "samlp:Response",
        ID="response-id",
        Version="2.0",
        IssueInstant=NOW,
        Destination=ACS,
    )
    if request_id is not None:
        node.set("InResponseTo", request_id)
    element("saml:Issuer", node, ENTITY)
    element("samlp:StatusCode", element("samlp:Status", node), Value=SUCCESS)
    assertion = element(
        "saml:Assertion", node, ID="assertion-id", Version="2.0", IssueInstant=NOW
    )
    element("saml:Issuer", assertion, ENTITY)
    subject = element("saml:Subject", assertion)
    element("saml:NameID", subject, "stable-name-id", Format=PERSISTENT)
    confirmation = element(
        "saml:SubjectConfirmation",
        subject,
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
    )
    data = element(
        "saml:SubjectConfirmationData", confirmation, Recipient=ACS, NotOnOrAfter=AFTER
    )
    if request_id is not None:
        data.set("InResponseTo", request_id)
    conditions = element(
        "saml:Conditions", assertion, NotBefore=BEFORE, NotOnOrAfter=AFTER
    )
    element("saml:Audience", element("saml:AudienceRestriction", conditions), SP)
    statement = element(
        "saml:AuthnStatement",
        assertion,
        AuthnInstant=NOW,
        SessionIndex="session-index",
        SessionNotOnOrAfter=AFTER,
    )
    element(
        "saml:AuthnContextClassRef",
        element("saml:AuthnContext", statement),
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    )
    attrs = element("saml:AttributeStatement", assertion)
    if attributes is None:
        attributes = {
            UID: ["stable-uid"],
            "username": ["alice"],
            MAIL: ["alice@example.com"],
            "custom:roles": ["member", "admin"],
        }
    for name, values in attributes.items():
        attr = element("saml:Attribute", attrs, Name=name)
        for value in values:
            element("saml:AttributeValue", attr, value)
    return node


def sign(node, identity="idp"):
    key, cert = keypair(identity)
    signature = xmlsec.template.create(
        node,
        xmlsec.constants.TransformExclC14N,
        xmlsec.constants.TransformRsaSha256,
        ns="ds",
    )
    node.insert(1, signature)
    reference = xmlsec.template.add_reference(
        signature, xmlsec.constants.TransformSha256, uri=f"#{node.get('ID')}"
    )
    xmlsec.template.add_transform(reference, xmlsec.constants.TransformEnveloped)
    xmlsec.template.add_transform(reference, xmlsec.constants.TransformExclC14N)
    xmlsec.template.x509_data_add_certificate(
        xmlsec.template.add_x509_data(xmlsec.template.ensure_key_info(signature))
    )
    xmlsec.tree.add_ids(node, ["ID"])
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_memory(key, xmlsec.constants.KeyDataFormatPem, None)
    ctx.key.load_cert_from_memory(cert, xmlsec.constants.KeyDataFormatPem)
    ctx.sign(signature)
    return node


def signed_response(node=None, signed="assertion", identity="idp"):
    if node is None:
        node = response()
    if signed in {"assertion", "both"}:
        sign(find(node, "saml:Assertion"), identity)
    if signed in {"response", "both"}:
        sign(node, identity)
    return node


def encode(node):
    return b64encode(etree.tostring(node)).decode()


def encrypt(node, identity="sp"):
    """Replace an Assertion or NameID by its encrypted SAML wrapper."""
    parent = node.getparent()
    index = parent.index(node)
    wrapper_name = (
        "EncryptedAssertion"
        if etree.QName(node).localname == "Assertion"
        else "EncryptedID"
    )
    template = xmlsec.template.encrypted_data_create(
        node,
        xmlsec.constants.TransformAes128Cbc,
        type=xmlsec.constants.TypeEncElement,
        ns="xenc",
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(template)
    info = xmlsec.template.encrypted_data_ensure_key_info(template, ns="ds")
    encrypted_key = xmlsec.template.add_encrypted_key(
        info, xmlsec.constants.TransformRsaOaep
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(encrypted_key)
    manager = xmlsec.KeysManager()
    manager.add_key(
        xmlsec.Key.from_memory(
            keypair(identity)[1], xmlsec.constants.KeyDataFormatCertPem, None
        )
    )
    ctx = xmlsec.EncryptionContext(manager)
    ctx.key = xmlsec.Key.generate(
        xmlsec.constants.KeyDataAes, 128, xmlsec.constants.KeyDataTypeSession
    )
    encrypted = ctx.encrypt_xml(template, node)
    parent.remove(encrypted)
    wrapper = element(f"saml:{wrapper_name}")
    wrapper.append(encrypted)
    parent.insert(index, wrapper)


def redirect_query(node, kind="SAMLResponse", identity="idp", relay_state=None):
    values = {kind: b64encode(compress(etree.tostring(node))[2:-4]).decode()}
    if relay_state is not None:
        values["RelayState"] = relay_state
    values["SigAlg"] = SHA256
    key = serialization.load_pem_private_key(keypair(identity)[0], password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    values["Signature"] = b64encode(
        key.sign(urlencode(values).encode(), padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    return values


def decode_redirect(url, kind="SAMLRequest"):
    query = {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}
    return etree.fromstring(decompress(b64decode(query[kind]), -15)), query


def verify_redirect(query, kind="SAMLRequest", identity="sp"):
    values = {kind: query[kind]}
    if "RelayState" in query:
        values["RelayState"] = query["RelayState"]
    values["SigAlg"] = query["SigAlg"]
    cert = x509.load_pem_x509_certificate(keypair(identity)[1])
    public_key = cert.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    public_key.verify(
        b64decode(query["Signature"]),
        urlencode(values).encode(),
        padding.PKCS1v15(),
        {SHA256: hashes.SHA256, SHA512: hashes.SHA512}[query["SigAlg"]](),
    )


def verify_xml(node, identity="sp"):
    xmlsec.tree.add_ids(node, ["ID"])
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_memory(
        keypair(identity)[1], xmlsec.constants.KeyDataFormatCertPem, None
    )
    ctx.verify(find(node, "ds:Signature"))


def logout(kind="LogoutResponse", request_id="logout-id"):
    node = element(
        f"samlp:{kind}",
        ID="idp-logout-id",
        Version="2.0",
        IssueInstant=NOW,
        Destination=ACS,
    )
    element("saml:Issuer", node, ENTITY)
    if kind == "LogoutResponse":
        node.set("InResponseTo", request_id)
        element("samlp:StatusCode", element("samlp:Status", node), Value=SUCCESS)
    else:
        node.set("NotOnOrAfter", AFTER)
        element("saml:NameID", node, "stable-name-id", Format=PERSISTENT)
        element("samlp:SessionIndex", node, "session-index")
    return node
