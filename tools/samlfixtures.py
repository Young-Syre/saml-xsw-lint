"""Build the benign signed SAML fixtures.

Everything here is fabricated: ``idp.example`` and ``sp.example`` are reserved
example domains, the NameID is an invented opaque identifier, and the signing
keys are derived from published seeds (see ``tools/keys.py``). No real identity
provider's metadata, certificate or response is used anywhere in this
repository.

The signatures are real in the sense that matters for the fixtures: the digest
is computed over the canonicalised referenced element and the signature value is
a PKCS#1 v1.5 signature over the canonicalised SignedInfo, both verifiable with
this repository's own code. They are not claimed to be accepted by xmlsec1 or
any other library - see the limits documented in ``tools/c14n.py``.
"""

from __future__ import annotations

import base64
import datetime as dt
from dataclasses import dataclass
from xml.etree import ElementTree as ET

from saml_xsw_lint.emit import serialise
from saml_xsw_lint.model import NS_ASSERTION, NS_DSIG, NS_PROTOCOL

from . import keys
from .c14n import canonicalise, enveloped_digest_input

IDP_ENTITY = "https://idp.example/metadata"
SP_ENTITY = "https://sp.example/metadata"
ACS_URL = "https://sp.example/saml/acs"
REQUEST_ID = "_req-9c1f4a7b2e"
NAMEID = "e7c1a0d4-3f2b-4c88-9a1e-fabricated0001"

ISSUE_INSTANT = "2026-01-15T12:00:00Z"
NOT_BEFORE = "2026-01-15T11:59:30Z"
NOT_ON_OR_AFTER = "2026-01-15T12:04:30Z"
SESSION_NOT_ON_OR_AFTER = "2026-01-15T20:00:00Z"

EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"


@dataclass(frozen=True)
class CertificateSpec:
    seed: str
    bits: int
    name: tuple[tuple[str, str], ...]
    not_before: dt.datetime
    not_after: dt.datetime
    serial: int


def _utc(year: int, month: int = 1, day: int = 1) -> dt.datetime:
    return dt.datetime(year, month, day, tzinfo=dt.timezone.utc)


CERTIFICATES: dict[str, CertificateSpec] = {
    "idp": CertificateSpec(
        seed="saml-xsw-lint fixture key: idp.example signing, 2048 bit",
        bits=2048,
        name=(("2.5.4.6", "GB"), ("2.5.4.10", "Example Identity Provider"), ("2.5.4.3", "idp.example")),
        not_before=_utc(2026),
        not_after=_utc(2046),
        serial=0x5A17C0DE0001,
    ),
    "other-idp": CertificateSpec(
        seed="saml-xsw-lint fixture key: other-idp.example signing, 2048 bit",
        bits=2048,
        name=(("2.5.4.6", "GB"), ("2.5.4.10", "Another Example Identity Provider"),
              ("2.5.4.3", "other-idp.example")),
        not_before=_utc(2026),
        not_after=_utc(2051),  # notAfter past 2049 forces GeneralizedTime
        serial=0x5A17C0DE0002,
    ),
    "expired-idp": CertificateSpec(
        seed="saml-xsw-lint fixture key: expired-idp.example signing, 2048 bit",
        bits=2048,
        name=(("2.5.4.6", "GB"), ("2.5.4.10", "Expired Example Identity Provider"),
              ("2.5.4.3", "expired-idp.example")),
        not_before=_utc(2008),
        not_after=_utc(2010),
        serial=0x5A17C0DE0003,
    ),
    "weak-idp": CertificateSpec(
        seed="saml-xsw-lint fixture key: weak-idp.example signing, 1024 bit",
        bits=1024,
        name=(("2.5.4.6", "GB"), ("2.5.4.10", "Weak Example Identity Provider"),
              ("2.5.4.3", "weak-idp.example")),
        not_before=_utc(2026),
        not_after=_utc(2046),
        serial=0x5A17C0DE0004,
    ),
}


def certificate_der(name: str) -> bytes:
    spec = CERTIFICATES[name]
    key = keys.derive_key(spec.seed, spec.bits)
    return keys.self_signed_certificate(key, list(spec.name), spec.not_before,
                                        spec.not_after, spec.serial)


def certificate_pem(name: str) -> str:
    return keys.to_pem(certificate_der(name))


def certificate_b64(name: str) -> str:
    return base64.b64encode(certificate_der(name)).decode("ascii")


def signing_key(name: str) -> keys.RSAKey:
    spec = CERTIFICATES[name]
    return keys.derive_key(spec.seed, spec.bits)


# ------------------------------------------------------------------- tree build
def element(tag: str, attributes: dict[str, str] | None = None, text: str | None = None,
            children: list[ET.Element] | None = None) -> ET.Element:
    node = ET.Element(tag, attributes or {})
    if text is not None:
        node.text = text
    for child in children or []:
        node.append(child)
    return node


def saml(name: str, **kwargs) -> ET.Element:
    return element(f"{{{NS_ASSERTION}}}{name}", **kwargs)


def samlp(name: str, **kwargs) -> ET.Element:
    return element(f"{{{NS_PROTOCOL}}}{name}", **kwargs)


def ds(name: str, **kwargs) -> ET.Element:
    return element(f"{{{NS_DSIG}}}{name}", **kwargs)


def signature_template(reference_uri: str, certificate: str) -> ET.Element:
    """An unsigned ds:Signature skeleton; digest and value are filled in later."""
    return ds("Signature", children=[
        ds("SignedInfo", children=[
            ds("CanonicalizationMethod", attributes={"Algorithm": EXC_C14N}),
            ds("SignatureMethod", attributes={"Algorithm": RSA_SHA256}),
            ds("Reference", attributes={"URI": reference_uri}, children=[
                ds("Transforms", children=[
                    ds("Transform", attributes={"Algorithm": ENVELOPED}),
                    ds("Transform", attributes={"Algorithm": EXC_C14N}),
                ]),
                ds("DigestMethod", attributes={"Algorithm": SHA256}),
                ds("DigestValue", text=""),
            ]),
        ]),
        ds("SignatureValue", text=""),
        ds("KeyInfo", children=[
            ds("X509Data", children=[ds("X509Certificate", text=certificate)]),
        ]),
    ])


def assertion(assertion_id: str, *, signature: ET.Element | None = None) -> ET.Element:
    children = [saml("Issuer", text=IDP_ENTITY)]
    if signature is not None:
        children.append(signature)
    children += [
        saml("Subject", children=[
            saml("NameID", attributes={
                "Format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            }, text=NAMEID),
            saml("SubjectConfirmation", attributes={
                "Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            }, children=[
                saml("SubjectConfirmationData", attributes={
                    "NotOnOrAfter": NOT_ON_OR_AFTER,
                    "Recipient": ACS_URL,
                    "InResponseTo": REQUEST_ID,
                }),
            ]),
        ]),
        saml("Conditions", attributes={
            "NotBefore": NOT_BEFORE,
            "NotOnOrAfter": NOT_ON_OR_AFTER,
        }, children=[
            saml("AudienceRestriction", children=[saml("Audience", text=SP_ENTITY)]),
            saml("OneTimeUse"),
        ]),
        saml("AuthnStatement", attributes={
            "AuthnInstant": ISSUE_INSTANT,
            "SessionIndex": "_sess-4b1d9e07",
            "SessionNotOnOrAfter": SESSION_NOT_ON_OR_AFTER,
        }, children=[
            saml("AuthnContext", children=[
                saml("AuthnContextClassRef",
                     text="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
            ]),
        ]),
        saml("AttributeStatement", children=[
            saml("Attribute", attributes={
                "Name": "https://idp.example/claims/groups",
                "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            }, children=[saml("AttributeValue", text="staff")]),
        ]),
    ]
    return saml("Assertion", attributes={
        "ID": assertion_id,
        "Version": "2.0",
        "IssueInstant": ISSUE_INSTANT,
    }, children=children)


def response(response_id: str, assertion_element: ET.Element,
             signature: ET.Element | None = None) -> ET.Element:
    children = [saml("Issuer", text=IDP_ENTITY)]
    if signature is not None:
        children.append(signature)
    children += [
        samlp("Status", children=[
            samlp("StatusCode", attributes={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"}),
        ]),
        assertion_element,
    ]
    return samlp("Response", attributes={
        "ID": response_id,
        "Version": "2.0",
        "IssueInstant": ISSUE_INSTANT,
        "Destination": ACS_URL,
        "InResponseTo": REQUEST_ID,
    }, children=children)


# ----------------------------------------------------------------------- signing
def sign(target: ET.Element, signature: ET.Element, key: keys.RSAKey) -> None:
    """Fill in DigestValue and SignatureValue in place.

    The digest covers the referenced element after the enveloped-signature
    transform; the signature covers the canonicalised SignedInfo.
    """
    signed_info = signature.find(f"{{{NS_DSIG}}}SignedInfo")
    digest_value = signature.find(
        f"{{{NS_DSIG}}}SignedInfo/{{{NS_DSIG}}}Reference/{{{NS_DSIG}}}DigestValue"
    )
    import hashlib

    digest = hashlib.sha256(enveloped_digest_input(target)).digest()
    digest_value.text = base64.b64encode(digest).decode("ascii")
    value = signature.find(f"{{{NS_DSIG}}}SignatureValue")
    value.text = base64.b64encode(key.sign_pkcs1_sha256(canonicalise(signed_info))).decode("ascii")


def benign_assertion_signed(cert_name: str = "idp") -> ET.Element:
    assertion_id = "_a7f3c92d-5e18-4b6a-8c01-fixture000001"
    signature = signature_template(f"#{assertion_id}", certificate_b64(cert_name))
    assertion_element = assertion(assertion_id, signature=signature)
    root = response("_r41b8e2c7-90da-4f55-b3e6-fixture000001", assertion_element)
    sign(assertion_element, signature, signing_key(cert_name))
    return root


def benign_response_signed(cert_name: str = "idp") -> ET.Element:
    response_id = "_r52c9f3d8-a1eb-4c66-c4f7-fixture000002"
    signature = signature_template(f"#{response_id}", certificate_b64(cert_name))
    assertion_element = assertion("_a8g4d03e-6f29-4c7b-9d12-fixture000002".replace("g", "b"))
    root = response(response_id, assertion_element, signature=signature)
    sign(root, signature, signing_key(cert_name))
    return root


BENIGN_BANNER = """
  saml-xsw-lint benign fixture: {description}

  Entirely fabricated. idp.example and sp.example are reserved example domains,
  the NameID is an invented opaque identifier, and the signing key is derived
  from a published seed in tools/keys.py - it is not secret and must never be
  used for anything. Regenerate with: python -m tools.make_examples
"""


def benign_documents() -> dict[str, str]:
    """Filename -> serialised XML for the two benign fixtures."""
    return {
        "benign-response.xml": serialise(
            benign_assertion_signed(),
            banner=BENIGN_BANNER.format(description="signature over the Assertion"),
        ),
        "benign-response-signed.xml": serialise(
            benign_response_signed(),
            banner=BENIGN_BANNER.format(description="signature over the Response"),
        ),
    }
