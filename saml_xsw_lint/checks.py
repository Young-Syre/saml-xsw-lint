"""The checks.

Each function takes the :class:`~saml_xsw_lint.model.Document` and returns
findings. Nothing here verifies a signature: the questions asked are "could a
correct verifier and the application that follows it disagree about which bytes
were signed", and "is the trust model behind this document sound".
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import re
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

from . import der
from .findings import Finding
from .model import (
    NS_ASSERTION,
    NS_DSIG,
    OTHER_ID_ATTRS,
    SAML_ID_ATTR,
    Document,
    is_ncname,
    localname,
    qname,
)

C14N_EXCLUSIVE = {
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
}
C14N_INCLUSIVE = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
    "http://www.w3.org/2006/12/xml-c14n11",
    "http://www.w3.org/2006/12/xml-c14n11#WithComments",
}
TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
TRANSFORM_XSLT = "http://www.w3.org/TR/1999/REC-xslt-19991116"
TRANSFORM_XPATH = "http://www.w3.org/TR/1999/REC-xpath-19991116"
TRANSFORM_XPATH_FILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2"
TRANSFORM_BASE64 = "http://www.w3.org/2000/09/xmldsig#base64"

WEAK_DIGESTS = {
    "http://www.w3.org/2000/09/xmldsig#sha1": "SHA-1",
    "http://www.w3.org/2001/04/xmldsig-more#md5": "MD5",
    "http://www.w3.org/2001/04/xmldsig-more#sha1": "SHA-1",
}
WEAK_SIGNATURES = {
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "RSA-SHA1",
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1": "DSA-SHA1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-md5": "RSA-MD5",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": "ECDSA-SHA1",
}

WRAPPING_CONTAINERS = ("Object", "Extensions", "SignatureProperties", "SignatureProperty", "Manifest")

_URL = re.compile(r"\A[A-Za-z][A-Za-z0-9+.\-]*://")
_EMAIL = re.compile(r"\A[^@\s]+@[^@\s]+\.[^@\s]+\Z")

NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


@dataclass
class Options:
    """Everything a check may need from the command line."""

    cert_der: bytes | None = None
    acs_url: str | None = None
    audience: str | None = None
    max_window_seconds: int = 3600
    max_session_seconds: int = 86400
    now: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))


def _dsig(name: str) -> str:
    return f"{{{NS_DSIG}}}{name}"


def _parse_datetime(text: str | None) -> dt.datetime | None:
    if not text:
        return None
    value = text.strip()
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------- structure
def check_structure(doc: Document, options: Options) -> list[Finding]:
    out: list[Finding] = []
    assertions = doc.assertions
    signed = doc.signed_elements()
    covered = doc.covered_assertions()

    if not doc.signatures:
        out.append(Finding("STR010", doc.path(doc.root), "the document contains no ds:Signature element"))

    if len(assertions) > 1:
        described = ", ".join(
            f"{doc.path(a)} (ID={a.attrib.get(SAML_ID_ATTR, '-')}, "
            f"{'covered by a signature' if doc.is_covered(a) else 'NOT covered'})"
            for a in assertions
        )
        out.append(Finding("STR001", doc.path(doc.root),
                           f"{len(assertions)} Assertion elements: {described}"))

    for assertion in doc.unsigned_assertions():
        out.append(Finding("STR002", doc.path(assertion),
                           f"ID={assertion.attrib.get(SAML_ID_ATTR, '-')} is not inside any signed element"))

    if assertions and len(covered) != len(assertions):
        out.append(Finding("STR003", doc.path(doc.root),
                           f"{len(assertions)} assertion(s), {len(covered)} covered by a signature, "
                           f"{len(signed)} signed element(s) in total"))

    if assertions and covered and not doc.is_covered(assertions[0]):
        out.append(Finding("STR014", doc.path(assertions[0]),
                           "the application would normally read this assertion, but the signed "
                           f"assertion is at {doc.path(covered[0])}"))

    for value, holders in sorted(doc.id_index.items()):
        if len(holders) > 1:
            where = ", ".join(f"{doc.path(e)}/@{a}" for e, a in holders)
            out.append(Finding("STR006", doc.path(holders[0][0]),
                               f"id {value!r} appears {len(holders)} times: {where}"))
        for element, attr in holders:
            if not is_ncname(value):
                out.append(Finding("STR007", doc.path(element),
                                   f"@{attr}={value!r} is not a valid NCName"))
            if attr != SAML_ID_ATTR and attr in OTHER_ID_ATTRS:
                out.append(Finding("STR008", doc.path(element),
                                   f"@{attr} carries an id-like value; SAML 2.0 defines "
                                   f"@{SAML_ID_ATTR} as the xsd:ID attribute"))

    for assertion in assertions:
        container = doc.enclosed_by_localname(assertion, *WRAPPING_CONTAINERS)
        if container is not None:
            out.append(Finding("STR013", doc.path(assertion),
                               f"nested inside {qname(container.tag)} at {doc.path(container)}"))

    for signature in doc.signatures:
        if len(signature.references) > 1:
            out.append(Finding("STR012", doc.path(signature.element),
                               f"SignedInfo has {len(signature.references)} Reference elements: "
                               + ", ".join(repr(r.uri) for r in signature.references)))
        for ref in signature.references:
            out.extend(_check_reference(doc, signature.element, ref))
    return out


def _check_reference(doc: Document, signature: ET.Element, ref) -> list[Finding]:
    out: list[Finding] = []
    where = doc.path(ref.element)
    if ref.uri is None:
        out.append(Finding("STR009", where, "Reference has no URI attribute"))
        return out
    if ref.whole_document:
        if len(doc.assertions) > 1:
            out.append(Finding("STR005", where,
                               f'URI="" covers the whole document, which holds '
                               f"{len(doc.assertions)} assertions"))
        return out
    if not ref.uri.startswith("#"):
        out.append(Finding("STR011", where, f"URI={ref.uri!r} is not a same-document fragment"))
        return out
    if ref.target is None:
        out.append(Finding("STR009", where,
                           f"URI={ref.uri!r} matches no element in the document"))
        return out
    if ref.target_attr not in (None, SAML_ID_ATTR):
        out.append(Finding("STR015", where,
                           f"URI={ref.uri!r} resolved against @{ref.target_attr} on "
                           f"{doc.path(ref.target)}"))
    if not doc.is_ancestor_or_self(ref.target, signature):
        out.append(Finding("STR004", doc.path(signature),
                           f"references {doc.path(ref.target)} "
                           f"(ID={ref.target.attrib.get(SAML_ID_ATTR, '-')}) but sits outside it"))
    return out


# -------------------------------------------------------------------- transforms
def check_transforms(doc: Document, options: Options) -> list[Finding]:
    out: list[Finding] = []
    for signature in doc.signatures:
        where = doc.path(signature.element)
        if signature.c14n_method is None:
            out.append(Finding("TRN007", where, "SignedInfo has no CanonicalizationMethod"))
        elif signature.c14n_method in C14N_INCLUSIVE:
            out.append(Finding("TRN006", where,
                               f"SignedInfo canonicalisation is {signature.c14n_method}"))

        for ref in signature.references:
            ref_where = doc.path(ref.element)
            if not ref.has_transforms_element:
                out.append(Finding("TRN005", ref_where, "Reference has no Transforms element"))
            enveloped_needed = ref.target is not None and doc.is_ancestor_or_self(
                ref.target, signature.element
            )
            for algorithm in ref.transforms:
                if not algorithm:
                    out.append(Finding("TRN008", ref_where, "Transform has no Algorithm attribute"))
                elif "xslt" in algorithm.lower():
                    out.append(Finding("TRN001", ref_where, f"transform {algorithm}"))
                elif algorithm in (TRANSFORM_XPATH, TRANSFORM_XPATH_FILTER2):
                    expression = _xpath_text(ref.element)
                    detail = f"transform {algorithm}"
                    if expression:
                        detail += f"; expression: {expression}"
                    out.append(Finding("TRN002", ref_where, detail))
                elif algorithm in C14N_INCLUSIVE:
                    out.append(Finding("TRN006", ref_where, f"reference transform {algorithm}"))
                elif algorithm in C14N_EXCLUSIVE or algorithm == TRANSFORM_ENVELOPED:
                    continue
                else:
                    out.append(Finding("TRN004", ref_where, f"transform {algorithm}"))
            if enveloped_needed and TRANSFORM_ENVELOPED not in ref.transforms:
                out.append(Finding("TRN003", ref_where,
                                   "the signature is inside the element it references but no "
                                   "enveloped-signature transform is listed"))
    return out


def _xpath_text(reference: ET.Element) -> str:
    texts = [
        " ".join((node.text or "").split())
        for node in reference.iter()
        if localname(node.tag) in ("XPath", "XPath2") and node.text
    ]
    return "; ".join(t for t in texts if t)


# ------------------------------------------------------------------ crypto/trust
def check_crypto(doc: Document, options: Options) -> list[Finding]:
    out: list[Finding] = []
    fingerprints: dict[str, str] = {}
    matched_trusted = False
    embedded_any = False

    for signature in doc.signatures:
        where = doc.path(signature.element)
        algorithm = signature.signature_method or ""
        if "hmac" in algorithm.lower():
            out.append(Finding("CRY003", where, f"SignatureMethod is {algorithm}"))
        elif algorithm in WEAK_SIGNATURES:
            out.append(Finding("CRY002", where,
                               f"SignatureMethod is {WEAK_SIGNATURES[algorithm]} ({algorithm})"))
        for ref in signature.references:
            if ref.digest_method in WEAK_DIGESTS:
                out.append(Finding("CRY001", doc.path(ref.element),
                                   f"DigestMethod is {WEAK_DIGESTS[ref.digest_method]} "
                                   f"({ref.digest_method})"))

        key_info = signature.key_info
        if key_info is None:
            out.append(Finding("CRY013", where,
                               "no KeyInfo; the verifier must supply the key from metadata"))
            continue

        out.extend(_check_key_urls(doc, key_info))
        out.extend(_check_rsa_key_value(doc, key_info))

        for cert_element in key_info.iter(_dsig("X509Certificate")):
            embedded_any = True
            cert_where = doc.path(cert_element)
            text = "".join(cert_element.itertext())
            try:
                raw = der.der_from_base64(text)
                certificate = der.Certificate.from_der(raw)
            except (der.DERError, binascii.Error, ValueError) as exc:
                out.append(Finding("CRY014", cert_where, f"could not parse: {exc}"))
                continue
            fingerprints[certificate.sha256_fingerprint] = cert_where
            out.append(Finding(
                "CRY004", cert_where,
                f"subject {certificate.subject or '(empty)'}; issuer "
                f"{certificate.issuer or '(empty)'}; "
                f"{certificate.public_key.algorithm_name}-{certificate.public_key.bits}; "
                f"valid {certificate.not_before:%Y-%m-%d} to {certificate.not_after:%Y-%m-%d}; "
                f"sha256 {certificate.sha256_fingerprint[:32]}...",
                extra={"fingerprint_sha256": certificate.sha256_fingerprint},
            ))
            out.extend(_check_certificate(certificate, cert_where, options))
            if options.cert_der is not None and raw == options.cert_der:
                matched_trusted = True

    if len(fingerprints) > 1:
        out.append(Finding("CRY015", doc.path(doc.root),
                           f"{len(fingerprints)} distinct certificates: "
                           + ", ".join(f"{fp[:16]}... at {where}" for fp, where in fingerprints.items())))

    if options.cert_der is not None:
        trusted_fp = hashlib.sha256(options.cert_der).hexdigest()
        if not embedded_any:
            pass
        elif matched_trusted:
            out.append(Finding("CRY006", doc.path(doc.root),
                               f"an embedded certificate equals the supplied --cert "
                               f"(sha256 {trusted_fp[:32]}...); this is a byte comparison, not "
                               "signature verification"))
        else:
            out.append(Finding("CRY005", doc.path(doc.root),
                               f"no embedded certificate equals --cert (sha256 {trusted_fp[:32]}...); "
                               f"document carries: "
                               + (", ".join(f"{fp[:16]}..." for fp in fingerprints) or "none")))
    return out


def _check_certificate(certificate: der.Certificate, where: str, options: Options) -> list[Finding]:
    out: list[Finding] = []
    if certificate.is_self_issued:
        verified = certificate.verify_self_signature()
        state = {True: "self-signature verifies", False: "self-signature does NOT verify",
                 None: f"self-signature not checked ({certificate.signature_algorithm_name})"}[verified]
        out.append(Finding("CRY007", where, f"issuer equals subject; {state}"))
        if verified is False:
            out.append(Finding("CRY016", where,
                               "issuer equals subject but the signature does not verify against "
                               "the certificate's own public key"))
    if certificate.is_expired(options.now):
        out.append(Finding("CRY008", where,
                           f"notAfter {certificate.not_after.isoformat()} is in the past"))
    if certificate.is_not_yet_valid(options.now):
        out.append(Finding("CRY009", where,
                           f"notBefore {certificate.not_before.isoformat()} is in the future"))
    bits = certificate.public_key.bits
    if certificate.public_key.algorithm == der.OID_RSA and bits and bits < 2048:
        out.append(Finding("CRY010", where, f"RSA modulus is {bits} bits"))
    elif certificate.public_key.algorithm == der.OID_DSA and bits and bits < 2048:
        out.append(Finding("CRY010", where, f"DSA key is {bits} bits"))
    return out


def _check_key_urls(doc: Document, key_info: ET.Element) -> list[Finding]:
    out: list[Finding] = []
    for node in key_info.iter():
        name = localname(node.tag)
        for attribute in ("URI", "Location"):
            value = node.attrib.get(attribute)
            if value and (_URL.match(value) or value.startswith("//")):
                out.append(Finding("CRY011", doc.path(node),
                                   f"{qname(node.tag)}/@{attribute} = {value!r}; not fetched"))
        if name in ("KeyName", "X509SKI", "MgmtData") and node.text and _URL.match(node.text.strip()):
            out.append(Finding("CRY011", doc.path(node),
                               f"{qname(node.tag)} contains the URL {node.text.strip()!r}; not fetched"))
    return out


def _check_rsa_key_value(doc: Document, key_info: ET.Element) -> list[Finding]:
    out: list[Finding] = []
    for modulus in key_info.iter(_dsig("Modulus")):
        text = "".join(modulus.itertext()).strip()
        try:
            raw = base64.b64decode(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError):
            continue
        bits = int.from_bytes(raw, "big").bit_length()
        if bits and bits < 2048:
            out.append(Finding("CRY012", doc.path(modulus),
                               f"RSAKeyValue modulus is {bits} bits"))
    return out


# ------------------------------------------------------------------- semantics
def check_semantics(doc: Document, options: Options) -> list[Finding]:
    out: list[Finding] = []
    for response in doc.responses:
        where = doc.path(response)
        if not response.attrib.get("Destination"):
            out.append(Finding("SEM010", where, "Response has no Destination attribute"))
        if not response.attrib.get("InResponseTo"):
            out.append(Finding("SEM018", where,
                               "Response has no InResponseTo attribute (unsolicited response)"))

    for assertion in doc.assertions:
        out.extend(_check_assertion(doc, assertion, options))
    return out


def _check_assertion(doc: Document, assertion: ET.Element, options: Options) -> list[Finding]:
    out: list[Finding] = []
    saml = f"{{{NS_ASSERTION}}}"
    where = doc.path(assertion)

    conditions = assertion.find(f"{saml}Conditions")
    if conditions is None:
        out.append(Finding("SEM001", where, "no saml:Conditions element"))
    else:
        cond_where = doc.path(conditions)
        not_before = conditions.attrib.get("NotBefore")
        not_on_or_after = conditions.attrib.get("NotOnOrAfter")
        if not not_before:
            out.append(Finding("SEM002", cond_where, "Conditions has no NotBefore"))
        if not not_on_or_after:
            out.append(Finding("SEM003", cond_where, "Conditions has no NotOnOrAfter"))
        start, end = _parse_datetime(not_before), _parse_datetime(not_on_or_after)
        if start and end:
            window = int((end - start).total_seconds())
            if window > options.max_window_seconds:
                out.append(Finding("SEM004", cond_where,
                                   f"validity window is {window}s "
                                   f"({not_before} to {not_on_or_after}), limit is "
                                   f"{options.max_window_seconds}s"))
        restrictions = conditions.findall(f"{saml}AudienceRestriction")
        if not restrictions:
            out.append(Finding("SEM005", cond_where, "Conditions has no AudienceRestriction"))
        elif options.audience is not None:
            audiences = [
                (a.text or "").strip()
                for restriction in restrictions
                for a in restriction.findall(f"{saml}Audience")
            ]
            if options.audience not in audiences:
                out.append(Finding("SEM019", cond_where,
                                   f"audience(s) {audiences} do not include "
                                   f"{options.audience!r}"))
        if conditions.find(f"{saml}OneTimeUse") is None:
            out.append(Finding("SEM016", cond_where, "no saml:OneTimeUse condition"))

    subject = assertion.find(f"{saml}Subject")
    name_id = subject.find(f"{saml}NameID") if subject is not None else None
    if name_id is not None:
        nid_where = doc.path(name_id)
        fmt = name_id.attrib.get("Format")
        # itertext, not .text: `.text` is only the run before the first child
        # element, so `<NameID>admin<X/>@evil.test</NameID>` reported as
        # `'admin'` -- and SEM015 then did not recognise it as an email at all.
        # A comment cannot split it (expat drops comments during parsing, which
        # is why the comment-splitting XSW variant does not reach here) but a
        # child element can, and "two parsers read one document differently" is
        # this tool's whole subject.
        value = "".join(name_id.itertext()).strip()
        if not fmt:
            out.append(Finding("SEM013", nid_where, f"NameID {value!r} has no Format"))
        elif fmt == NAMEID_UNSPECIFIED:
            out.append(Finding("SEM014", nid_where, f"Format is {fmt}"))
        if _EMAIL.match(value) or fmt == NAMEID_EMAIL:
            out.append(Finding("SEM015", nid_where,
                               f"NameID {value!r} is an email address"
                               + (f" (Format {fmt})" if fmt else "")))

    confirmation_data = None
    if subject is not None:
        for confirmation in subject.findall(f"{saml}SubjectConfirmation"):
            found = confirmation.find(f"{saml}SubjectConfirmationData")
            if found is not None:
                confirmation_data = found
                break
    if confirmation_data is None:
        out.append(Finding("SEM006", where, "no saml:SubjectConfirmationData"))
    else:
        scd_where = doc.path(confirmation_data)
        recipient = confirmation_data.attrib.get("Recipient")
        if not recipient:
            out.append(Finding("SEM007", scd_where, "SubjectConfirmationData has no Recipient"))
        elif options.acs_url is not None and recipient != options.acs_url:
            out.append(Finding("SEM008", scd_where,
                               f"Recipient {recipient!r} does not match --acs-url "
                               f"{options.acs_url!r}"))
        if not confirmation_data.attrib.get("InResponseTo"):
            out.append(Finding("SEM009", scd_where, "SubjectConfirmationData has no InResponseTo"))
        if not confirmation_data.attrib.get("NotOnOrAfter"):
            out.append(Finding("SEM017", scd_where, "SubjectConfirmationData has no NotOnOrAfter"))

    statements = assertion.findall(f"{saml}AuthnStatement")
    if not statements:
        out.append(Finding("SEM011", where, "no saml:AuthnStatement"))
    for statement in statements:
        session_end = _parse_datetime(statement.attrib.get("SessionNotOnOrAfter"))
        instant = _parse_datetime(statement.attrib.get("AuthnInstant"))
        if session_end and instant:
            session = int((session_end - instant).total_seconds())
            if session > options.max_session_seconds:
                out.append(Finding("SEM012", doc.path(statement),
                                   f"SessionNotOnOrAfter is {session}s after AuthnInstant, "
                                   f"limit is {options.max_session_seconds}s"))

    for value in assertion.iter(f"{saml}AttributeValue"):
        if len(value):
            out.append(Finding("SEM020", doc.path(value),
                               "AttributeValue contains child elements: "
                               + ", ".join(qname(c.tag) for c in value)))
    return out
