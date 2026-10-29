# saml-xsw-lint

[![tests](https://github.com/Young-Syre/saml-xsw-lint/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/saml-xsw-lint/actions/workflows/tests.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-green)](LICENSE)
[![dependencies: none](https://img.shields.io/badge/dependencies-none-lightgrey)](pyproject.toml)

An offline analyser for SAML responses and the XML signatures inside them. It reads a
local file and reports the ways in which a document is *shaped* so that a correct
signature verifier and the application behind it can disagree about what was signed.

It makes no network requests, and it is not a signature verifier. Both of those are
explained below, because they are the two things it would be easiest to overclaim.

## XML Signature signs a reference, not a document

XML Signature does not sign a document. It signs a *reference*.

```xml
<ds:Reference URI="#_a7f3c92d">
  <ds:DigestValue>Sk1FvLxG17bwisHQsec0+3izkeBqlgtfj2QXZ0TuJzc=</ds:DigestValue>
</ds:Reference>
```

That says: *the element whose id is `_a7f3c92d`, canonicalised, hashes to this value*. It
says nothing about where that element sits in the tree, nothing about whether the element
the application later reads is the element that was hashed, and nothing about whether the
key that signed it is a key you have any reason to trust.

Three properties of the standard turn that gap into a vulnerability class:

1. **Reference resolution is an id lookup, not a path.** `URI="#x"` means "whatever
   element in this document has the id `x`". Move that element anywhere and the reference
   still resolves.
2. **Exclusive canonicalisation is position-independent by design.** It serialises the
   referenced subtree with the namespace declarations that subtree actually uses, and
   deliberately ignores the context it is nested in - so that signed fragments can be
   relocated between documents without breaking. The digest of a signed assertion is
   therefore *identical* before and after an attacker moves it.
3. **Verification and consumption are different pieces of code.** A library verifies "a
   signature in this document is valid". The application then asks "what does the
   assertion say?", usually by taking the first `<Assertion>` a query returns. Nobody owns
   the join.

**Signature wrapping (XSW)** is the attack that follows: keep the validly signed assertion
somewhere in the document - inside the `<ds:Signature>` element itself, inside
`<ds:Object>`, inside `<samlp:Extensions>`, nested inside a forged assertion - and put the
forged assertion where the parser will find it. The signature verifies. The application
reads the forgery. This was set out systematically in Somorovsky et al., *On Breaking
SAML: Be Whoever You Want to Be* (USENIX Security 2012), which found the pattern across
most of the SAML frameworks and services it examined; the variant numbering most testers
use today comes from the Burp extension SAML Raider. It has kept recurring since, across libraries and languages,
because the gap is in how the pieces fit together rather than in any one of them.

This repository's own examples demonstrate point 2 directly. Every `examples/xsw-*.xml`
file is generated from a benign signed response by moving elements around, and in every
one of them the digest and the signature still check out - verified in
`tests/test_generate.py` by recomputing both:

```
test_every_variant_still_verifies ... ok
test_digest_is_identical_in_benign_and_wrapped_documents ... ok
```

The other half of the problem is not about signatures at all. An assertion with no
`AudienceRestriction` is accepted by a service provider it was never minted for; one with
no `NotOnOrAfter` never expires; one keyed on an email address hands the account to
whoever can change that address at the identity provider. Those checks live here too,
because a deployment that gets the signature right and the semantics wrong is still
broken.

## What this tool is not

- **It is not a signature verifier.** It does not canonicalise, it does not compute
  digests over your documents, and it does not check `SignatureValue`. Without the trusted
  key it could not tell you a signature is valid, and even with the key it would be a
  worse choice than a hardened library. It answers a different question: *given that a
  correct verifier will say "valid", can the application still be fooled, and is the trust
  model sound?*
- **It does not decide that a document is safe.** A clean run means none of the 75
  implemented checks fired. The attack surface is larger than the checks.
- **It does not replace testing the deployment.** A shape finding is a hypothesis about
  your identity provider and service provider pair; `--generate` exists so you can go and
  test it, against systems you are authorised to test.
- **It never makes a network request.** No metadata fetch, no key fetch, no CRL or OCSP.
  When a document asks the verifier to fetch something - `ds:RetrievalMethod`, a
  URL-shaped `KeyName`, an absolute `Reference URI` - the URL is reported and not
  dereferenced. `tests/test_no_network.py` walks the package's syntax tree and fails if
  any module imports anything outside a 15-name allowlist, so `urllib`, `socket`, `http`,
  `ssl` and `subprocess` cannot appear without the test being changed deliberately.

## Install

Python 3.11 or newer, standard library only.

```console
$ git clone https://github.com/Young-Syre/saml-xsw-lint
$ cd saml-xsw-lint
$ pip install .            # provides the saml-xsw-lint command
```

Or run it straight from a checkout, with no install at all:

```console
$ python -m saml_xsw_lint examples/benign-response.xml
```

## Usage

Input is a local file: raw XML, or the base64 blob from a `SAMLResponse` form field
(auto-detected), optionally DEFLATE-compressed as in the HTTP-Redirect binding. `-` reads
standard input.

```console
$ saml-xsw-lint response.xml
$ saml-xsw-lint --json --cert idp.crt --acs-url https://sp.example/saml/acs response.b64
$ saml-xsw-lint --generate examples/benign-response.xml --out xsw-variants
```

### A benign response

```console
$ python -m saml_xsw_lint examples/benign-response.xml
saml-xsw-lint 0.1.0 - examples/benign-response.xml

INFO     CRY004  KeyInfo carries its own X509Certificate
         at /samlp:Response/saml:Assertion/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate
         subject C=GB, O=Example Identity Provider, CN=idp.example; issuer C=GB, O=Example
         Identity Provider, CN=idp.example; RSA-2048; valid 2026-01-01 to 2046-01-01; sha256
         8159f42a9f3917f424be5295958fc6d7...

INFO     CRY007  Certificate is self-signed
         at /samlp:Response/saml:Assertion/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate
         issuer equals subject; self-signature verifies

summary: 2 finding(s) - 2 info
fail-on: medium
$ echo $?
0
```

Two informational findings, because the document carries its own certificate and that
certificate is self-signed. Neither is a flaw: SAML signing certificates are normally
self-signed and pinned through metadata rather than validated by a chain. They are
reported so that the trust source is visible in the output rather than assumed.

### A wrapped response

```console
$ python -m saml_xsw_lint examples/xsw-03-forged-assertion-first.xml
saml-xsw-lint 0.1.0 - examples/xsw-03-forged-assertion-first.xml

CRITICAL XSW003  XSW3 - forged Assertion precedes the signed Assertion
         at /samlp:Response/saml:Assertion[1]
         unsigned Assertion precedes the signed Assertion at
         /samlp:Response/saml:Assertion[2]

HIGH     STR001  More than one Assertion in the document
         at /samlp:Response
         2 Assertion elements: /samlp:Response/saml:Assertion[1]
         (ID=_a7f3c92d-5e18-4b6a-8c01-fixture000001-forged, NOT covered),
         /samlp:Response/saml:Assertion[2] (ID=_a7f3c92d-5e18-4b6a-8c01-fixture000001,
         covered by a signature)

HIGH     STR002  Assertion not covered by any Signature
         at /samlp:Response/saml:Assertion[1]
         ID=_a7f3c92d-5e18-4b6a-8c01-fixture000001-forged is not inside any signed element

HIGH     STR014  First Assertion in document order is not the signed one
         at /samlp:Response/saml:Assertion[1]
         the application would normally read this assertion, but the signed assertion is at
         /samlp:Response/saml:Assertion[2]

MEDIUM   STR003  Signed element count does not match assertion count
         at /samlp:Response
         2 assertion(s), 1 covered by a signature, 1 signed element(s) in total

INFO     CRY004  KeyInfo carries its own X509Certificate
         at /samlp:Response/saml:Assertion[2]/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate
         subject C=GB, O=Example Identity Provider, CN=idp.example; issuer C=GB, O=Example
         Identity Provider, CN=idp.example; RSA-2048; valid 2026-01-01 to 2046-01-01; sha256
         8159f42a9f3917f424be5295958fc6d7...

INFO     CRY007  Certificate is self-signed
         at /samlp:Response/saml:Assertion[2]/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate
         issuer equals subject; self-signature verifies

summary: 7 finding(s) - 1 critical, 3 high, 1 medium, 2 info
fail-on: medium
$ echo $?
1
```

The forged assertion is first in document order and unsigned; the signed one is second.
Any code that reads "the assertion" reads the forgery.

### An unsafe document, with `--explain`

```console
$ python -m saml_xsw_lint tests/data/unsafe-external-entity.xml --explain
saml-xsw-lint 0.1.0 - tests/data/unsafe-external-entity.xml
note: input refused before parsing; nothing was expanded

CRITICAL XML001  DOCTYPE declaration present
         at /
         a DOCTYPE declaration is present; refused before parsing
         why: A SAML response has no legitimate reason to carry a DOCTYPE. A DOCTYPE is
              the entry point for entity expansion and external entity resolution, so
              this tool refuses the document before handing any of it to an XML parser.

CRITICAL XML002  Entity declaration present
         at /
         1 <!ENTITY declaration(s) present; not expanded
         why: An <!ENTITY> declaration lets the document define its own substitution
              text. Nested declarations produce exponential expansion (billion laughs);
              an external declaration turns the verifier into a file and URL reader.

CRITICAL XML004  External entity reference (SYSTEM/PUBLIC)
         at /
         external identifier keyword(s): SYSTEM
         why: SYSTEM or PUBLIC identifiers instruct the parser to dereference a file
              path or URL. In a SAML endpoint that read happens server side, pre-
              authentication.

HIGH     XML005  Reference to an undeclared entity
         at /
         reference(s) to undeclared entities: &secret;
         why: Only the five predefined entities and numeric character references are
              legitimate here. Anything else implies a DTD this tool has refused, so the
              document cannot be interpreted the way its author intended.

summary: 4 finding(s) - 3 critical, 1 high
fail-on: medium
$ echo $?
2
```

### JSON output

```console
$ python -m saml_xsw_lint examples/xsw-07-assertion-in-extensions.xml --json | head -31
{
  "tool": "saml-xsw-lint",
  "version": "0.1.0",
  "input": "examples/xsw-07-assertion-in-extensions.xml",
  "notes": [],
  "refused": false,
  "fail_on": "medium",
  "summary": {
    "total": 7,
    "by_severity": {
      "critical": 1,
      "high": 3,
      "medium": 1,
      "info": 2
    }
  },
  "findings": [
    {
      "id": "XSW007",
      "name": "XSW7 - Assertion parked in samlp:Extensions",
      "severity": "critical",
      "group": "xsw",
      "where": "/samlp:Response/samlp:Extensions/saml:Assertion",
      "detail": "Assertion (ID=_a7f3c92d-5e18-4b6a-8c01-fixture000001, signed) is inside /samlp:Response/samlp:Extensions",
      "mechanism": "Extensions has a lax content model, so a signed assertion can be hidden there while a forged assertion occupies the normal position. A check that counts assertions only in the expected location does not see the one parked here."
    },
    {
      "id": "STR001",
      "name": "More than one Assertion in the document",
      "severity": "high",
      "group": "structure",
```

### Generating the variants

```console
$ python -m saml_xsw_lint --generate examples/benign-response.xml --out xsw-variants
wrote xsw-variants/xsw-03-forged-assertion-first.xml  (variant 3, expects XSW003)
wrote xsw-variants/xsw-04-signed-assertion-nested.xml  (variant 4, expects XSW004)
wrote xsw-variants/xsw-05-detached-signature.xml  (variant 5, expects XSW005)
wrote xsw-variants/xsw-06-signed-assertion-in-signature.xml  (variant 6, expects XSW006)
wrote xsw-variants/xsw-07-assertion-in-extensions.xml  (variant 7, expects XSW007)
wrote xsw-variants/xsw-08-signed-assertion-in-object.xml  (variant 8, expects XSW008)
```

Each generated document carries a banner naming the variant and stating that it is for
authorised testing only. Which variants apply depends on what the input signs: a response
signed at the `Response` level yields XSW1 and XSW2, one signed at the `Assertion` level
yields XSW3 to XSW8. Asking for an inapplicable variant is an error rather than a guess.

Generation is offline and local. These documents are attack payloads: send them only to an
identity provider or service provider you own or have written permission to test.

## The XSW variants

Published descriptions of the eight variants differ in small details, so this table states
the exact structural predicate each finding matches rather than relying on the number.
Documents often match more than one shape - XSW6 and XSW8 differ only by a `ds:Object`,
and a real-world payload may combine them - so every match is reported.

| Variant | Signs | Structural predicate this tool matches | Finding | Example |
| --- | --- | --- | --- | --- |
| XSW1 | response | the referenced element is a Response and it is a descendant of the Signature that references it; the forged Response is the document root | `XSW001` | `examples/xsw-01-signed-response-in-signature.xml` |
| XSW2 | response | the referenced element is a Response which is neither an ancestor nor a descendant of the Signature that references it; both sit inside the forged Response | `XSW002` | `examples/xsw-02-signed-response-beside-signature.xml` |
| XSW3 | assertion | the referenced Assertion has an unsigned Assertion sibling earlier in document order under the same parent | `XSW003` | `examples/xsw-03-forged-assertion-first.xml` |
| XSW4 | assertion | the referenced Assertion is a descendant of an unsigned Assertion | `XSW004` | `examples/xsw-04-signed-assertion-nested.xml` |
| XSW5 | assertion | the Signature is outside the Assertion it references and is not an ancestor of it, and the document contains an unsigned Assertion | `XSW005` | `examples/xsw-05-detached-signature.xml` |
| XSW6 | assertion | the referenced Assertion is a descendant of the Signature that references it, and not inside a ds:Object | `XSW006` | `examples/xsw-06-signed-assertion-in-signature.xml` |
| XSW7 | assertion | an Assertion is a descendant of samlp:Extensions | `XSW007` | `examples/xsw-07-assertion-in-extensions.xml` |
| XSW8 | assertion | the referenced Assertion is a descendant of a ds:Object inside the Signature that references it | `XSW008` | `examples/xsw-08-signed-assertion-in-object.xml` |

## Findings

Severity is advisory and reflects how far the finding is from a working bypass, not a CVSS
score. `--fail-on` sets which severities make the exit code non-zero.

**XML safety (these are refusals: the document is never parsed)**

| ID | Name | Severity | Mechanism (first sentence; `--list-checks --json` prints all of it) |
| --- | --- | --- | --- |
| `XML001` | DOCTYPE declaration present | critical | A SAML response has no legitimate reason to carry a DOCTYPE. |
| `XML002` | Entity declaration present | critical | An &lt;!ENTITY&gt; declaration lets the document define its own substitution text. |
| `XML003` | Parameter entity present | critical | Parameter entities (%name;) are evaluated inside the DTD and are the usual vehicle for out-of-band XXE exfiltration, because the leaked value is smuggled into a URL the parser then fetches. |
| `XML004` | External entity reference (SYSTEM/PUBLIC) | critical | SYSTEM or PUBLIC identifiers instruct the parser to dereference a file path or URL. |
| `XML005` | Reference to an undeclared entity | high | Only the five predefined entities and numeric character references are legitimate here. |
| `XML006` | Input larger than the configured limit | high | Refused before parsing. |
| `XML007` | Document is not well-formed XML | high | The document could not be parsed. |
| `XML008` | Input is not XML and not valid base64 | high | The file is neither XML nor a base64 blob that decodes to XML, so there is nothing to analyse. |

**Structure**

| ID | Name | Severity | Mechanism (first sentence; `--list-checks --json` prints all of it) |
| --- | --- | --- | --- |
| `STR001` | More than one Assertion in the document | high | XML Signature covers the element a Reference names, not the document. |
| `STR002` | Assertion not covered by any Signature | high | An assertion whose id no Reference names is unsigned content sitting in a document that, as a whole, has a valid signature somewhere. |
| `STR003` | Signed element count does not match assertion count | medium | A document with more assertions than signed elements has content that arrived with no integrity protection at all. |
| `STR004` | Signature is not enveloped by the element it references | high | In a normal SAML response the signature sits inside the element it protects. |
| `STR005` | Whole-document Reference (URI="") with several assertions | high | URI="" means 'the document I am in'. |
| `STR006` | Duplicate ID attribute value | critical | Reference resolution is an id lookup. |
| `STR007` | ID value is not a valid xsd:ID (NCName) | medium | xsd:ID values must be NCNames. |
| `STR008` | Id-bearing attribute a verifier may not treat as an id | medium | A signature verifier only indexes attributes it has been told are of type ID. |
| `STR009` | Reference URI resolves to no element | high | A dangling same-document reference cannot be verified. |
| `STR010` | No Signature in the document | high | Nothing in this document is integrity protected. |
| `STR011` | Reference URI is not a same-document fragment | high | An absolute URI in a Reference asks the verifier to fetch the signed content. |
| `STR012` | SignedInfo contains several References | medium | Multiple references are legal but unusual in SAML. |
| `STR013` | Assertion inside a wrapping container | high | An Assertion nested inside ds:Object, ds:SignatureProperties or samlp:Extensions is in a position no conforming IdP emits. |
| `STR014` | First Assertion in document order is not the signed one | high | Applications read 'the assertion' - usually the first one a query returns. |
| `STR015` | Reference resolved only via a non-ID attribute | medium | The reference could not be resolved against an 'ID' attribute and was matched against a differently-named id-like attribute instead. |

**Signature wrapping**

| ID | Name | Severity | Mechanism (first sentence; `--list-checks --json` prints all of it) |
| --- | --- | --- | --- |
| `XSW001` | XSW1 - signed Response nested inside the Signature | critical | The forged Response is the document root. |
| `XSW002` | XSW2 - signed Response as a sibling of its detached Signature | critical | As XSW1, but the Signature and the Response it covers are siblings inside the forged Response rather than nested. |
| `XSW003` | XSW3 - forged Assertion precedes the signed Assertion | critical | Two assertions share a parent. |
| `XSW004` | XSW4 - signed Assertion nested inside a forged Assertion | critical | The signed assertion becomes a child of the attacker's assertion. |
| `XSW005` | XSW5 - Signature detached from the Assertion it covers | critical | The signature is lifted out of the assertion it references and parked elsewhere, with a forged assertion left in the position the application reads. |
| `XSW006` | XSW6 - signed Assertion nested inside the Signature | critical | The original assertion is moved inside the Signature element that references it, and the Signature is carried by the forged assertion. |
| `XSW007` | XSW7 - Assertion parked in samlp:Extensions | critical | Extensions has a lax content model, so a signed assertion can be hidden there while a forged assertion occupies the normal position. |
| `XSW008` | XSW8 - signed Assertion inside ds:Object | critical | As XSW6, but the signed assertion is placed in the ds:Object child of the Signature. |

**Transforms and canonicalisation**

| ID | Name | Severity | Mechanism (first sentence; `--list-checks --json` prints all of it) |
| --- | --- | --- | --- |
| `TRN001` | XSLT transform in a Reference | critical | An XSLT transform is a program the verifier runs on attacker-supplied input while computing the digest. |
| `TRN002` | XPath transform in a Reference | high | An XPath or XPath Filter 2.0 transform lets the document choose which nodes the digest covers. |
| `TRN003` | Enveloped-signature transform missing | medium | A signature nested inside the element it references must remove itself from the digest input. |
| `TRN004` | Unexpected transform algorithm | medium | SAML needs exactly enveloped-signature followed by exclusive canonicalisation. |
| `TRN005` | Reference has no Transforms element | high | With no transforms, the digest input is the raw referenced subtree including the signature itself, which cannot have been computed by the signer. |
| `TRN006` | Non-exclusive canonicalisation | medium | Inclusive c14n serialises inherited namespace context. |
| `TRN007` | CanonicalizationMethod missing from SignedInfo | medium | SignedInfo itself must state how it was canonicalised. |
| `TRN008` | Transform algorithm attribute missing or empty | medium | A Transform with no Algorithm cannot be interpreted; implementations variously skip it, fail, or fall back to a default. |

**Crypto and trust**

| ID | Name | Severity | Mechanism (first sentence; `--list-checks --json` prints all of it) |
| --- | --- | --- | --- |
| `CRY001` | Weak DigestMethod | high | SHA-1 and MD5 digests are collision-prone. |
| `CRY002` | Weak SignatureMethod | high | RSA-SHA1, RSA-MD5 and DSA-SHA1 inherit the collision weakness of their hash and are rejected by current guidance. |
| `CRY003` | HMAC SignatureMethod | critical | HMAC means the signature is keyed by a shared secret rather than by the IdP's private key. |
| `CRY004` | KeyInfo carries its own X509Certificate | info | The document is shipping the key it wants to be verified against. |
| `CRY005` | Embedded certificate does not match --cert | critical | The document is signed by a key other than the trusted one. |
| `CRY006` | Embedded certificate matches --cert | info | The embedded certificate is byte-identical to the supplied trusted certificate. |
| `CRY007` | Certificate is self-signed | info | Self-signed certificates are the norm for SAML signing keys, which are pinned by metadata rather than validated by a chain. |
| `CRY008` | Certificate has expired | medium | Expiry of the signing certificate is a deployment problem rather than a bypass, but implementations differ on whether they enforce it, and some fail open. |
| `CRY009` | Certificate is not yet valid | medium | A notBefore in the future means the certificate is not usable yet, and in practice usually means it was fabricated or generated with a wrong clock. |
| `CRY010` | Certificate public key smaller than 2048 bits | high | An RSA key below 2048 bits is below current minimums; 512- and 768-bit moduli have been factored outright. |
| `CRY011` | KeyInfo points at a URL | high | A ds:RetrievalMethod, X509 CRL URI or URL-shaped KeyName asks the verifier to fetch key material at verification time. |
| `CRY012` | RSAKeyValue modulus smaller than 2048 bits | high | A bare RSAKeyValue is a raw public key with no certificate and no chain. |
| `CRY013` | Signature has no KeyInfo | low | Without KeyInfo the verifier must already know which key to use, which is the correct design. |
| `CRY014` | Certificate could not be parsed | medium | The base64 in X509Certificate did not decode to a DER certificate this tool can read. |
| `CRY015` | Several distinct certificates in one document | medium | More than one signing certificate means more than one candidate key. |
| `CRY016` | Self-signature does not verify | medium | The certificate claims to be self-signed (issuer equals subject) but its signature does not verify against its own public key. |

**Assertion semantics**

| ID | Name | Severity | Mechanism (first sentence; `--list-checks --json` prints all of it) |
| --- | --- | --- | --- |
| `SEM001` | Assertion has no Conditions element | high | With no Conditions there is no validity window and no audience: the assertion is replayable forever and at any service provider that accepts the IdP. |
| `SEM002` | Conditions has no NotBefore | medium | An open-ended lower bound means an assertion minted in the past, or pre-dated by an attacker with a signing oracle, is still inside its window. |
| `SEM003` | Conditions has no NotOnOrAfter | high | An assertion with no upper bound never expires, so one capture - from a log, a proxy, a browser history or a shared machine - is a permanent credential for that subject at that service provider. |
| `SEM004` | Validity window wider than the configured maximum | medium | A wide window extends the replay opportunity for anything that can read the assertion in transit or at rest (logs, proxies, browser history). |
| `SEM005` | No AudienceRestriction | high | Without an audience, an assertion minted for one service provider is accepted by another. |
| `SEM006` | No SubjectConfirmationData | high | Bearer confirmation data is what binds the assertion to this delivery: recipient, request id and an expiry. |
| `SEM007` | SubjectConfirmationData has no Recipient | medium | Recipient is the assertion saying which ACS endpoint it was minted for. |
| `SEM008` | Recipient does not match --acs-url | high | The assertion was minted for a different endpoint from the one being tested. |
| `SEM009` | SubjectConfirmationData has no InResponseTo | medium | InResponseTo ties the assertion to a specific AuthnRequest. |
| `SEM010` | Response has no Destination | medium | Destination is the signed statement of where the response was meant to be delivered. |
| `SEM011` | No AuthnStatement | medium | Without an authentication statement the assertion carries no record of when or how the subject authenticated, so session lifetime and step-up decisions have nothing to rest on. |
| `SEM012` | SessionNotOnOrAfter far in the future | low | A long IdP session bound into the assertion means revocation at the IdP does not reach the SP for that long. |
| `SEM013` | NameID has no Format | medium | With no Format, the SP has to guess what kind of identifier it is holding. |
| `SEM014` | NameID Format is unspecified | low | nameid-format:unspecified pushes identifier interpretation onto the SP, with the same collision risk as SEM013. |
| `SEM015` | NameID looks like a mutable identifier | medium | An email address is a mutable, often attacker-influenced identifier. |
| `SEM016` | No OneTimeUse condition | low | OneTimeUse asks the SP to refuse the assertion a second time. |
| `SEM017` | SubjectConfirmationData has no NotOnOrAfter | medium | The bearer confirmation has no expiry of its own, so the only limit is the Conditions window, if any. |
| `SEM018` | Response has no InResponseTo | low | An unsolicited response. |
| `SEM019` | Audience does not match --audience | high | The assertion names a different audience from the entity id being tested. |
| `SEM020` | Attribute value contains markup | low | Attribute values flow into application state and often into HTML. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Analysed; nothing at or above `--fail-on` (default `medium`) |
| `1` | Findings at or above `--fail-on` |
| `2` | Input refused and never analysed: DOCTYPE or entity construct, not well-formed, too large, or undecodable |
| `3` | Usage or I/O error: missing file, bad option, input unusable for `--generate` |

A refusal is deliberately not the same code as a finding. Exit 2 means *this tool declined
to interpret the document*, which for an XML security tool is a different statement from
*this document has problems*.

## Parsing attacker-controlled XML

A tool that reads hostile XML has to be more careful than the thing it is auditing.

- Only `xml.etree.ElementTree` is used. `xml.dom.minidom`, `xml.dom.pulldom`, `xml.sax` and
  `lxml` are not imported anywhere in the package, and a test asserts it.
- Before any parsing, the raw bytes are scanned. A `DOCTYPE`, an `<!ENTITY>` declaration, a
  parameter entity reference, a `SYSTEM`/`PUBLIC` identifier or a reference to an entity
  that is not one of the five predefined ones is a **refusal** (`XML001`-`XML005`). Comments
  and CDATA sections are stripped from the copy that is scanned, so a document that merely
  mentions `<!DOCTYPE` in a comment is not refused.
- This is the control, not a belt-and-braces measure. ElementTree *does* expand internal
  entities, and `tests/test_safexml.py` proves it rather than asserting it:

  ```python
  def test_elementtree_really_does_expand_entities(self):
      # Not a test of this tool: a test of the premise behind safexml.prescan.
      root = ET.fromstring(SMALL_BOMB)
      self.assertEqual(len(root.text or ""), 1000)
  ```

  The three-level bomb above expands to 1000 characters in the parser this tool uses. The
  nine-level fixture in `tests/data/unsafe-billion-laughs.xml` would expand to about a
  gigabyte; it is refused by a text scan in about 0.03 ms (measured over 100 calls) and never
  reaches the parser. `libxml2` rejects the same file too, but only after starting to expand it.
- Input size is capped (16 MiB by default, `--max-bytes`), and DEFLATE decompression is
  bounded by the same limit, so a compression bomb cannot be inflated past it.
- Percent-escapes are decoded without `urllib`, because `urllib` is not on the import
  allowlist.

## Options

```console
$ python -m saml_xsw_lint --help
usage: saml-xsw-lint [-h] [--version] [--base64] [--no-base64] [--inflate]
                     [--max-bytes MAX_BYTES] [--cert FILE] [--acs-url URL]
                     [--audience URI] [--max-window SECONDS]
                     [--max-session SECONDS] [--now ISO8601] [--json]
                     [--explain] [--quiet]
                     [--fail-on {info,low,medium,high,critical,never}]
                     [--ignore IDS] [--list-checks] [--generate]
                     [--variant VARIANT] [--out DIR] [--stdout]
                     [input]

Offline SAML response and XML-signature trust analyser.

Reads a local SAML Response or Assertion (raw XML, or base64 as it appears in a
SAMLResponse form field) and reports structural, canonicalisation, trust and
assertion-semantics findings. It never makes a network request, and it is not a
signature verifier: it reports whether a document is shaped so that a correct
verifier and the application behind it could disagree about what was signed.

positional arguments:
  input                 SAML Response/Assertion file, or - for stdin

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

input decoding:
  --base64              treat the input as base64 (default: auto-detect)
  --no-base64           never base64-decode the input
  --inflate             DEFLATE-decompress after base64 (HTTP-Redirect
                        binding)
  --max-bytes MAX_BYTES
                        refuse input larger than this (default 16777216)

deployment context (enables comparison checks):
  --cert FILE           trusted IdP certificate (PEM or DER) to compare
                        against KeyInfo
  --acs-url URL         expected SubjectConfirmationData/@Recipient
  --audience URI        expected saml:Audience value
  --max-window SECONDS  largest acceptable Conditions validity window (default
                        3600)
  --max-session SECONDS
                        largest acceptable SessionNotOnOrAfter span (default
                        86400)
  --now ISO8601         treat this instant as 'now' for certificate validity

output:
  --json                machine-readable output
  --explain             print the mechanism paragraph for each finding
  --quiet               summary line only
  --fail-on {info,low,medium,high,critical,never}
                        lowest severity that sets exit code 1 (default medium)
  --ignore IDS          comma-separated finding ids to suppress
  --list-checks         print the finding catalogue and exit

generation (offline, local):
  --generate            emit XSW variant documents built from the input
  --variant VARIANT     variant numbers to emit, e.g. 3 or 3,5 or all (default
                        all)
  --out DIR             directory to write variants into
  --stdout              write the generated documents to stdout instead of
                        files

exit codes:
  0  nothing at or above --fail-on
  1  findings at or above --fail-on
  2  input refused before analysis (DOCTYPE/entities, malformed, too large)
  3  usage or I/O error

examples:
  saml-xsw-lint response.xml
  saml-xsw-lint --json --cert idp.crt --acs-url https://sp.example/acs response.b64
  saml-xsw-lint --generate examples/benign-response.xml --out xsw-variants --variant all
```

`--cert`, `--acs-url` and `--audience` supply the deployment context. Without them the
comparison checks (`CRY005`, `CRY006`, `SEM008`, `SEM019`) cannot run, and the tool says
nothing rather than guessing.

## Tests and fixtures

```console
$ python -m unittest discover -s tests -t . -v
...
Ran 165 tests in 2.191s

OK
$ python -m tools.make_examples --check
62 generated file(s), 0 drifted
```

165 tests and a little over 300 assertion sites, many of them inside `subTest` loops. The
run above is on Python 3.14; the CI matrix covers 3.11, 3.12 and 3.13, which are the
versions the packaging metadata claims.

Every one of the 75 catalogued findings is produced by at least one fixture:
`tests.test_catalogue.Coverage.test_every_check_fires_somewhere` fails if a check is
documented but unreachable, and `test_no_catalogue_entry_is_unreachable` fails if a
catalogue entry is never raised by the code.

Everything in `examples/` and `tests/data/` is generated by `python -m tools.make_examples`
and compared byte-for-byte in CI, so the documents in the repository are provably the ones
this code produces.

**How the signed fixtures work without a committed private key.** A repository should never
contain a private key, and GitHub's push protection rejects one anyway. So the keys are
derived rather than stored: each named key comes from a published seed string through
`random.Random`, whose Mersenne Twister output is stable across CPython versions, so
`tools/keys.py` reproduces the same 2048-bit modulus on every machine. The certificate is
built from that key with a DER encoder in the same file and committed as PEM - public key
material, not a secret - and the fixtures are signed at generation time with the derived
key, which only ever exists in memory. The committed certificates are checked against
their seeds in `tests/test_der.py`, and a test asserts that no file under `examples/`
contains the string `PRIVATE KEY`.

These are test keys with published seeds. They are not secret and must never be used for
anything.

## Known limitations

Stated rather than discovered later:

- **No signature verification.** See above. The `SignatureValue` in your document is read
  and reported, never checked.
- **No canonicalisation in the tool.** `tools/c14n.py` implements exclusive c14n for the
  fixture subset only (no default namespace, no `xml:` attributes, no comments, no
  `InclusiveNamespaces` PrefixList). It is development tooling, it is not conformant, and
  the linter does not use it. The fixtures' signatures are verified by this repository's
  own code; **xmlsec1 was not available in the environment where they were built, so
  there is no claim that xmlsec1 accepts them.**
- **No certificate chain validation**, no name constraints, no key usage, no revocation.
  `CRY007` tells you a certificate is self-issued and whether its own signature checks
  out; that is all.
- **Encrypted assertions are not decrypted.** A response carrying only
  `<saml:EncryptedAssertion>` has no visible assertion, so the assertion-semantics and
  wrapping checks have nothing to work with and the document will look mostly empty.
  Decrypt it first, or test the plaintext response.
- **SAML 1.1 is not supported.** The checks are written against SAML 2.0 element names.
- **No line numbers.** ElementTree discards source positions, so findings are located by
  an XPath-like element path. Paths are 1-based and include an index only where a parent
  has several children with the same tag.
- **Id-attribute detection is schema-free.** With no DTD or XSD to say which attributes are
  of type `xsd:ID`, the tool treats `ID`, `Id`, `id`, `AssertionID`, `ResponseID` and
  `xml:id` as id-like and reports (`STR008`, `STR015`) when a reference resolves against
  anything other than SAML's `ID`. A verifier configured differently may disagree - which
  is itself the finding.
- **Expired assertions are not reported.** A captured response is always expired by the
  time anyone lints it, so reporting it would be noise. Missing, unbounded or implausibly
  wide windows are reported instead; `SEM004` compares `NotBefore` to `NotOnOrAfter`, not
  to the clock. Certificate expiry (`CRY008`) does use the clock, and `--now` overrides it.
- **Severities are judgement, not measurement.** Several findings are context-dependent:
  `STR012` (multiple references) and `CRY013` (no KeyInfo) are legitimate in some
  deployments.
- **The variant numbering is a convention.** Where published descriptions disagree, the
  predicate in the table above is what this tool actually matches.

## Further reading

- J. Somorovsky, A. Mayer, J. Schwenk, M. Kampmann, M. Jensen, *On Breaking SAML: Be
  Whoever You Want to Be*, USENIX Security 2012 - the systematic treatment of the class.
- W3C, *XML Signature Syntax and Processing* and *Exclusive XML Canonicalization* - where
  the reference-not-document semantics and the position independence come from.
- OASIS, *Profiles for the OASIS SAML V2.0* - the Web Browser SSO profile rules that
  `SEM001`-`SEM019` are drawn from.
- SAML Raider (Burp extension) - the origin of the XSW1-8 numbering used here.

## Licence

MIT. See [LICENSE](LICENSE).
