"""Finding catalogue.

Every check in this package resolves to exactly one entry here. The catalogue is
the single source of truth for finding ids, names, severities and the mechanism
text printed by ``--list-checks`` and rendered in the README table.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Ordered severity. Comparisons are used for ``--fail-on`` thresholds."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls[text.strip().upper()]
        except KeyError:  # pragma: no cover - argparse validates first
            raise ValueError(f"unknown severity: {text!r}") from None


@dataclass(frozen=True)
class Spec:
    """Static description of one check."""

    id: str
    name: str
    severity: Severity
    mechanism: str
    group: str


@dataclass
class Finding:
    """One instance of a check firing against one document."""

    id: str
    where: str = "/"
    detail: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def spec(self) -> Spec:
        return CATALOGUE[self.id]

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def severity(self) -> Severity:
        return self.spec.severity

    def to_dict(self) -> dict:
        out = {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.label,
            "group": self.spec.group,
            "where": self.where,
            "detail": self.detail,
            "mechanism": self.spec.mechanism,
        }
        if self.extra:
            out["extra"] = self.extra
        return out


def _spec(group: str, ident: str, name: str, severity: Severity, mechanism: str) -> Spec:
    return Spec(id=ident, name=name, severity=severity, mechanism=mechanism, group=group)


_SPECS: list[Spec] = [
    # ---------------------------------------------------------------- XML safety
    _spec("xml-safety", "XML001", "DOCTYPE declaration present", Severity.CRITICAL,
          "A SAML response has no legitimate reason to carry a DOCTYPE. A DOCTYPE is the "
          "entry point for entity expansion and external entity resolution, so this tool "
          "refuses the document before handing any of it to an XML parser."),
    _spec("xml-safety", "XML002", "Entity declaration present", Severity.CRITICAL,
          "An <!ENTITY> declaration lets the document define its own substitution text. "
          "Nested declarations produce exponential expansion (billion laughs); an external "
          "declaration turns the verifier into a file and URL reader."),
    _spec("xml-safety", "XML003", "Parameter entity present", Severity.CRITICAL,
          "Parameter entities (%name;) are evaluated inside the DTD and are the usual "
          "vehicle for out-of-band XXE exfiltration, because the leaked value is smuggled "
          "into a URL the parser then fetches."),
    _spec("xml-safety", "XML004", "External entity reference (SYSTEM/PUBLIC)", Severity.CRITICAL,
          "SYSTEM or PUBLIC identifiers instruct the parser to dereference a file path or "
          "URL. In a SAML endpoint that read happens server side, pre-authentication."),
    _spec("xml-safety", "XML005", "Reference to an undeclared entity", Severity.HIGH,
          "Only the five predefined entities and numeric character references are legitimate "
          "here. Anything else implies a DTD this tool has refused, so the document cannot "
          "be interpreted the way its author intended."),
    _spec("xml-safety", "XML006", "Input larger than the configured limit", Severity.HIGH,
          "Refused before parsing. An unbounded parse of attacker-supplied XML is a denial "
          "of service primitive in its own right."),
    _spec("xml-safety", "XML007", "Document is not well-formed XML", Severity.HIGH,
          "The document could not be parsed. Note that SAML implementations have been broken "
          "by exactly this: two parsers disagreeing about a document one of them accepts."),
    _spec("xml-safety", "XML008", "Input is not XML and not valid base64", Severity.HIGH,
          "The file is neither XML nor a base64 blob that decodes to XML, so there is "
          "nothing to analyse."),

    # ---------------------------------------------------------------- structure
    _spec("structure", "STR001", "More than one Assertion in the document", Severity.HIGH,
          "XML Signature covers the element a Reference names, not the document. Once two "
          "assertions exist, 'the signature verified' and 'the assertion I read is signed' "
          "are different statements, and the application usually only checks the first."),
    _spec("structure", "STR002", "Assertion not covered by any Signature", Severity.HIGH,
          "An assertion whose id no Reference names is unsigned content sitting in a "
          "document that, as a whole, has a valid signature somewhere."),
    _spec("structure", "STR003", "Signed element count does not match assertion count", Severity.MEDIUM,
          "A document with more assertions than signed elements has content that arrived "
          "with no integrity protection at all."),
    _spec("structure", "STR004", "Signature is not enveloped by the element it references", Severity.HIGH,
          "In a normal SAML response the signature sits inside the element it protects. A "
          "signature elsewhere in the tree still verifies, which is what lets an attacker "
          "keep a valid signature over content the application never looks at."),
    _spec("structure", "STR005", "Whole-document Reference (URI=\"\") with several assertions", Severity.HIGH,
          "URI=\"\" means 'the document I am in'. With more than one assertion present, what "
          "the digest covered and what the application reads are no longer the same thing, "
          "and the enveloped-signature transform makes the covered subset non-obvious."),
    _spec("structure", "STR006", "Duplicate ID attribute value", Severity.CRITICAL,
          "Reference resolution is an id lookup. With two elements carrying the same id, "
          "which one is returned is parser-dependent, so the verifier and the application can "
          "resolve the same reference to different elements. This is the whole attack."),
    _spec("structure", "STR007", "ID value is not a valid xsd:ID (NCName)", Severity.MEDIUM,
          "xsd:ID values must be NCNames. A value that is not one is handled differently by "
          "different parsers - some reject it, some index it anyway, some index it after "
          "normalisation - which reintroduces the resolution ambiguity of STR006."),
    _spec("structure", "STR008", "Id-bearing attribute a verifier may not treat as an id", Severity.MEDIUM,
          "A signature verifier only indexes attributes it has been told are of type ID. "
          "SAML uses 'ID'; an element carrying 'id' or 'Id' may resolve for the application "
          "(or for a DOM API) and not for the verifier, or the reverse."),
    _spec("structure", "STR009", "Reference URI resolves to no element", Severity.HIGH,
          "A dangling same-document reference cannot be verified. Implementations have been "
          "seen to treat an unresolvable reference as vacuously satisfied."),
    _spec("structure", "STR010", "No Signature in the document", Severity.HIGH,
          "Nothing in this document is integrity protected. Reported so that an unsigned "
          "response is never mistaken for a clean result."),
    _spec("structure", "STR011", "Reference URI is not a same-document fragment", Severity.HIGH,
          "An absolute URI in a Reference asks the verifier to fetch the signed content. "
          "This tool never fetches anything; a verifier that does is both an SSRF primitive "
          "and signing something the application will not read."),
    _spec("structure", "STR012", "SignedInfo contains several References", Severity.MEDIUM,
          "Multiple references are legal but unusual in SAML. Each one has to be checked "
          "against what the application reads; a verifier that stops at the first satisfied "
          "reference covers less than it appears to."),
    _spec("structure", "STR013", "Assertion inside a wrapping container", Severity.HIGH,
          "An Assertion nested inside ds:Object, ds:SignatureProperties or samlp:Extensions "
          "is in a position no conforming IdP emits. These containers have permissive content "
          "models, which is exactly why wrapping attacks park signed content in them."),
    _spec("structure", "STR014", "First Assertion in document order is not the signed one", Severity.HIGH,
          "Applications read 'the assertion' - usually the first one a query returns. If that "
          "is not the element a Reference covers, signature verification is protecting "
          "something nobody consumes."),
    _spec("structure", "STR015", "Reference resolved only via a non-ID attribute", Severity.MEDIUM,
          "The reference could not be resolved against an 'ID' attribute and was matched "
          "against a differently-named id-like attribute instead. Verifier and application "
          "will not agree on this lookup."),

    # ---------------------------------------------------------------- XSW shapes
    _spec("xsw", "XSW001", "XSW1 - signed Response nested inside the Signature", Severity.CRITICAL,
          "The forged Response is the document root. The original, validly signed Response is "
          "moved inside the Signature element that references it. The reference still "
          "resolves, the digest still matches, and the attacker's Response is what any "
          "root-relative query returns."),
    _spec("xsw", "XSW002", "XSW2 - signed Response as a sibling of its detached Signature", Severity.CRITICAL,
          "As XSW1, but the Signature and the Response it covers are siblings inside the "
          "forged Response rather than nested. Verifiers that resolve references by id "
          "anywhere in the document accept it."),
    _spec("xsw", "XSW003", "XSW3 - forged Assertion precedes the signed Assertion", Severity.CRITICAL,
          "Two assertions share a parent. The first in document order is unsigned and "
          "attacker-controlled, the second carries the signature. Any code that takes "
          "'the first assertion' reads the forgery."),
    _spec("xsw", "XSW004", "XSW4 - signed Assertion nested inside a forged Assertion", Severity.CRITICAL,
          "The signed assertion becomes a child of the attacker's assertion. A descendant "
          "query such as //Assertion/Subject/NameID hits the outer forgery first."),
    _spec("xsw", "XSW005", "XSW5 - Signature detached from the Assertion it covers", Severity.CRITICAL,
          "The signature is lifted out of the assertion it references and parked elsewhere, "
          "with a forged assertion left in the position the application reads. The reference "
          "is still satisfied because id resolution ignores position."),
    _spec("xsw", "XSW006", "XSW6 - signed Assertion nested inside the Signature", Severity.CRITICAL,
          "The original assertion is moved inside the Signature element that references it, "
          "and the Signature is carried by the forged assertion. The forgery therefore "
          "'contains' its own proof."),
    _spec("xsw", "XSW007", "XSW7 - Assertion parked in samlp:Extensions", Severity.CRITICAL,
          "Extensions has a lax content model, so a signed assertion can be hidden there "
          "while a forged assertion occupies the normal position. A check that counts "
          "assertions only in the expected location does not see the one parked here."),
    _spec("xsw", "XSW008", "XSW8 - signed Assertion inside ds:Object", Severity.CRITICAL,
          "As XSW6, but the signed assertion is placed in the ds:Object child of the "
          "Signature. ds:Object exists to carry arbitrary signed payloads, which makes it a "
          "schema-valid hiding place."),

    # ---------------------------------------------------------------- transforms
    _spec("transforms", "TRN001", "XSLT transform in a Reference", Severity.CRITICAL,
          "An XSLT transform is a program the verifier runs on attacker-supplied input while "
          "computing the digest. It is code execution in the signature verification path, and "
          "it can also make the digest cover something other than the element referenced."),
    _spec("transforms", "TRN002", "XPath transform in a Reference", Severity.HIGH,
          "An XPath or XPath Filter 2.0 transform lets the document choose which nodes the "
          "digest covers. An attacker can exclude the parts they intend to forge and the "
          "signature will still verify over the remainder."),
    _spec("transforms", "TRN003", "Enveloped-signature transform missing", Severity.MEDIUM,
          "A signature nested inside the element it references must remove itself from the "
          "digest input. Without that transform the digest is self-referential and cannot be "
          "the one the IdP computed, so some other transform is doing the work."),
    _spec("transforms", "TRN004", "Unexpected transform algorithm", Severity.MEDIUM,
          "SAML needs exactly enveloped-signature followed by exclusive canonicalisation. "
          "Anything else changes what the digest covers and has to be justified."),
    _spec("transforms", "TRN005", "Reference has no Transforms element", Severity.HIGH,
          "With no transforms, the digest input is the raw referenced subtree including the "
          "signature itself, which cannot have been computed by the signer. Either the digest "
          "covers something unexpected or the verifier is being invited to improvise."),
    _spec("transforms", "TRN006", "Non-exclusive canonicalisation", Severity.MEDIUM,
          "Inclusive c14n serialises inherited namespace context. Moving a signed element "
          "into a different part of the tree can therefore change or preserve the digest in "
          "ways the signer never considered - the usual result is that wrapped content keeps "
          "verifying in its new position."),
    _spec("transforms", "TRN007", "CanonicalizationMethod missing from SignedInfo", Severity.MEDIUM,
          "SignedInfo itself must state how it was canonicalised. Without it, the verifier "
          "picks a default and may serialise SignedInfo differently from the signer."),
    _spec("transforms", "TRN008", "Transform algorithm attribute missing or empty", Severity.MEDIUM,
          "A Transform with no Algorithm cannot be interpreted; implementations variously "
          "skip it, fail, or fall back to a default."),

    # ---------------------------------------------------------------- crypto/trust
    _spec("crypto", "CRY001", "Weak DigestMethod", Severity.HIGH,
          "SHA-1 and MD5 digests are collision-prone. A collision between a benign and a "
          "forged assertion subtree makes one signature valid for both."),
    _spec("crypto", "CRY002", "Weak SignatureMethod", Severity.HIGH,
          "RSA-SHA1, RSA-MD5 and DSA-SHA1 inherit the collision weakness of their hash and "
          "are rejected by current guidance."),
    _spec("crypto", "CRY003", "HMAC SignatureMethod", Severity.CRITICAL,
          "HMAC means the signature is keyed by a shared secret rather than by the IdP's "
          "private key. Any party that can verify can also sign. Where a certificate was "
          "expected, an HMAC algorithm is an algorithm-substitution attack."),
    _spec("crypto", "CRY004", "KeyInfo carries its own X509Certificate", Severity.INFO,
          "The document is shipping the key it wants to be verified against. That is normal "
          "in SAML messages and harmless on its own - the bug is a verifier that trusts the "
          "embedded certificate instead of the one pinned in IdP metadata."),
    _spec("crypto", "CRY005", "Embedded certificate does not match --cert", Severity.CRITICAL,
          "The document is signed by a key other than the trusted one. If verification "
          "nevertheless succeeds, the deployment is trusting key material supplied by the "
          "message."),
    _spec("crypto", "CRY006", "Embedded certificate matches --cert", Severity.INFO,
          "The embedded certificate is byte-identical to the supplied trusted certificate. "
          "This says nothing about whether the signature itself is valid."),
    _spec("crypto", "CRY007", "Certificate is self-signed", Severity.INFO,
          "Self-signed certificates are the norm for SAML signing keys, which are pinned by "
          "metadata rather than validated by a chain. Reported as context: there is no chain "
          "to check, so pinning is the only control."),
    _spec("crypto", "CRY008", "Certificate has expired", Severity.MEDIUM,
          "Expiry of the signing certificate is a deployment problem rather than a bypass, "
          "but implementations differ on whether they enforce it, and some fail open."),
    _spec("crypto", "CRY009", "Certificate is not yet valid", Severity.MEDIUM,
          "A notBefore in the future means the certificate is not usable yet, and in "
          "practice usually means it was fabricated or generated with a wrong clock. Either "
          "way a verifier that accepts it is not checking the validity period."),
    _spec("crypto", "CRY010", "Certificate public key smaller than 2048 bits", Severity.HIGH,
          "An RSA key below 2048 bits is below current minimums; 512- and 768-bit moduli have "
          "been factored outright."),
    _spec("crypto", "CRY011", "KeyInfo points at a URL", Severity.HIGH,
          "A ds:RetrievalMethod, X509 CRL URI or URL-shaped KeyName asks the verifier to "
          "fetch key material at verification time. That is a server-side request driven by "
          "an unauthenticated message. This tool reports the URL and never fetches it."),
    _spec("crypto", "CRY012", "RSAKeyValue modulus smaller than 2048 bits", Severity.HIGH,
          "A bare RSAKeyValue is a raw public key with no certificate and no chain. A short "
          "modulus there is both weak and a sign the document chose its own key."),
    _spec("crypto", "CRY013", "Signature has no KeyInfo", Severity.LOW,
          "Without KeyInfo the verifier must already know which key to use, which is the "
          "correct design. Reported so that the trust source is explicit in the output."),
    _spec("crypto", "CRY014", "Certificate could not be parsed", Severity.MEDIUM,
          "The base64 in X509Certificate did not decode to a DER certificate this tool can "
          "read. Parser disagreement over malformed certificates is itself a finding."),
    _spec("crypto", "CRY015", "Several distinct certificates in one document", Severity.MEDIUM,
          "More than one signing certificate means more than one candidate key. Which one a "
          "verifier picks for which signature is implementation-defined."),
    _spec("crypto", "CRY016", "Self-signature does not verify", Severity.MEDIUM,
          "The certificate claims to be self-signed (issuer equals subject) but its signature "
          "does not verify against its own public key. The certificate has been edited or "
          "assembled by hand."),

    # ---------------------------------------------------------------- semantics
    _spec("semantics", "SEM001", "Assertion has no Conditions element", Severity.HIGH,
          "With no Conditions there is no validity window and no audience: the assertion is "
          "replayable forever and at any service provider that accepts the IdP."),
    _spec("semantics", "SEM002", "Conditions has no NotBefore", Severity.MEDIUM,
          "An open-ended lower bound means an assertion minted in the past, or pre-dated by "
          "an attacker with a signing oracle, is still inside its window. It also removes the "
          "clock-skew boundary that makes replay windows bounded at both ends."),
    _spec("semantics", "SEM003", "Conditions has no NotOnOrAfter", Severity.HIGH,
          "An assertion with no upper bound never expires, so one capture - from a log, a "
          "proxy, a browser history or a shared machine - is a permanent credential for that "
          "subject at that service provider."),
    _spec("semantics", "SEM004", "Validity window wider than the configured maximum", Severity.MEDIUM,
          "A wide window extends the replay opportunity for anything that can read the "
          "assertion in transit or at rest (logs, proxies, browser history)."),
    _spec("semantics", "SEM005", "No AudienceRestriction", Severity.HIGH,
          "Without an audience, an assertion minted for one service provider is accepted by "
          "another. Where several SPs share an IdP, this is cross-service impersonation."),
    _spec("semantics", "SEM006", "No SubjectConfirmationData", Severity.HIGH,
          "Bearer confirmation data is what binds the assertion to this delivery: recipient, "
          "request id and an expiry. Its absence removes all three bindings."),
    _spec("semantics", "SEM007", "SubjectConfirmationData has no Recipient", Severity.MEDIUM,
          "Recipient is the assertion saying which ACS endpoint it was minted for. Without "
          "it, an assertion can be forwarded to a different endpoint."),
    _spec("semantics", "SEM008", "Recipient does not match --acs-url", Severity.HIGH,
          "The assertion was minted for a different endpoint from the one being tested. An "
          "SP that accepts it is not checking Recipient."),
    _spec("semantics", "SEM009", "SubjectConfirmationData has no InResponseTo", Severity.MEDIUM,
          "InResponseTo ties the assertion to a specific AuthnRequest. Without it, an "
          "assertion can be injected into a login flow the user did not start, which is the "
          "shape of SAML login CSRF."),
    _spec("semantics", "SEM010", "Response has no Destination", Severity.MEDIUM,
          "Destination is the signed statement of where the response was meant to be "
          "delivered. Omitting it removes the only endpoint binding at the Response level."),
    _spec("semantics", "SEM011", "No AuthnStatement", Severity.MEDIUM,
          "Without an authentication statement the assertion carries no record of when or "
          "how the subject authenticated, so session lifetime and step-up decisions have "
          "nothing to rest on."),
    _spec("semantics", "SEM012", "SessionNotOnOrAfter far in the future", Severity.LOW,
          "A long IdP session bound into the assertion means revocation at the IdP does not "
          "reach the SP for that long."),
    _spec("semantics", "SEM013", "NameID has no Format", Severity.MEDIUM,
          "With no Format, the SP has to guess what kind of identifier it is holding. Two "
          "formats sharing a value space - an email and a persistent id, say - can then "
          "collide onto one account."),
    _spec("semantics", "SEM014", "NameID Format is unspecified", Severity.LOW,
          "nameid-format:unspecified pushes identifier interpretation onto the SP, with the "
          "same collision risk as SEM013."),
    _spec("semantics", "SEM015", "NameID looks like a mutable identifier", Severity.MEDIUM,
          "An email address is a mutable, often attacker-influenced identifier. Keying "
          "accounts on it means whoever controls the address at the IdP controls the account "
          "at the SP - the usual route to SAML account takeover by email change or by a "
          "second IdP that asserts the same address."),
    _spec("semantics", "SEM016", "No OneTimeUse condition", Severity.LOW,
          "OneTimeUse asks the SP to refuse the assertion a second time. Without it, replay "
          "protection depends entirely on the SP keeping its own set of seen ids."),
    _spec("semantics", "SEM017", "SubjectConfirmationData has no NotOnOrAfter", Severity.MEDIUM,
          "The bearer confirmation has no expiry of its own, so the only limit is the "
          "Conditions window, if any."),
    _spec("semantics", "SEM018", "Response has no InResponseTo", Severity.LOW,
          "An unsolicited response. Legitimate for IdP-initiated SSO, but it means the SP "
          "cannot correlate the response with a request it made."),
    _spec("semantics", "SEM019", "Audience does not match --audience", Severity.HIGH,
          "The assertion names a different audience from the entity id being tested. An SP "
          "that accepts it is not enforcing AudienceRestriction."),
    _spec("semantics", "SEM020", "Attribute value contains markup", Severity.LOW,
          "Attribute values flow into application state and often into HTML. Markup inside a "
          "signed attribute is both a parsing hazard and a sign the assertion was hand-built."),
]

CATALOGUE: dict[str, Spec] = {s.id: s for s in _SPECS}

GROUPS = ("xml-safety", "structure", "xsw", "transforms", "crypto", "semantics")


def specs_in_order() -> list[Spec]:
    """Catalogue entries grouped, then sorted by id - the README table order."""
    return sorted(_SPECS, key=lambda s: (GROUPS.index(s.group), s.id))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest severity first, then by id, then by location."""
    return sorted(findings, key=lambda f: (-int(f.severity), f.id, f.where))
