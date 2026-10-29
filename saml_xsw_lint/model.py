"""Document model: the tree facts every check is written against.

ElementTree gives no parent pointers and no element identity beyond the object
itself, so this module builds the bits the checks need: a parent map, an index of
id-like attributes, and a resolved view of each signature's SignedInfo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_DSIG = "http://www.w3.org/2000/09/xmldsig#"
NS_DSIG11 = "http://www.w3.org/2009/xmldsig11#"
NS_XENC = "http://www.w3.org/2001/04/xmlenc#"

PREFIXES = {
    NS_PROTOCOL: "samlp",
    NS_ASSERTION: "saml",
    NS_DSIG: "ds",
    NS_DSIG11: "dsig11",
    NS_XENC: "xenc",
    "http://www.w3.org/2001/XMLSchema": "xs",
    "http://www.w3.org/2001/XMLSchema-instance": "xsi",
    "http://www.w3.org/XML/1998/namespace": "xml",
}

#: Attribute names SAML 2.0 defines as xsd:ID on signed elements.
SAML_ID_ATTR = "ID"
#: Other spellings seen in the wild; a verifier may or may not index these.
OTHER_ID_ATTRS = ("Id", "id", "AssertionID", "ResponseID", "xml:id")

_NCNAME = re.compile(
    r"\A[A-Za-z_À-˿Ͱ-῿‌-‍⁰-↏"
    r"Ⰰ-⿯、-퟿豈-﷏ﷰ-�]"
    r"[A-Za-z0-9._·\-À-˿̀-ͯͰ-῿‌-‍"
    r"‿-⁀⁰-↏Ⰰ-⿯、-퟿豈-﷏"
    r"ﷰ-�]*\Z"
)


def is_ncname(value: str) -> bool:
    """True if ``value`` is a valid NCName, i.e. a usable xsd:ID."""
    return bool(_NCNAME.match(value))


def qname(tag: str) -> str:
    """``{uri}local`` -> ``prefix:local`` using the fixed prefix table."""
    if not tag.startswith("{"):
        return tag
    uri, _, local = tag[1:].partition("}")
    prefix = PREFIXES.get(uri)
    return f"{prefix}:{local}" if prefix else f"{{{uri}}}{local}"


def localname(tag: str) -> str:
    return tag.rpartition("}")[2] if tag.startswith("{") else tag


def nsuri(tag: str) -> str:
    return tag[1:].partition("}")[0] if tag.startswith("{") else ""


@dataclass
class Reference:
    """One ds:Reference inside a ds:SignedInfo."""

    element: ET.Element
    signature: ET.Element
    uri: str | None
    digest_method: str | None
    transforms: list[str]
    has_transforms_element: bool
    #: Resolved target element, if the URI is a same-document fragment that hit.
    target: ET.Element | None = None
    #: Name of the attribute the fragment resolved against.
    target_attr: str | None = None
    #: True when ``URI=""`` (the whole document).
    whole_document: bool = False

    @property
    def fragment(self) -> str | None:
        if self.uri is None or not self.uri.startswith("#"):
            return None
        return self.uri[1:]


@dataclass
class SignatureInfo:
    """A ds:Signature with its SignedInfo fields resolved."""

    element: ET.Element
    c14n_method: str | None
    signature_method: str | None
    references: list[Reference]
    key_info: ET.Element | None
    signature_value: str | None


@dataclass
class Document:
    """Parsed document plus the derived facts the checks consume."""

    root: ET.Element
    raw: bytes
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.parents: dict[int, ET.Element] = {}
        self.order: dict[int, int] = {}
        self.elements: list[ET.Element] = []
        for index, element in enumerate(self.root.iter()):
            self.elements.append(element)
            self.order[id(element)] = index
            for child in element:
                self.parents[id(child)] = element

        self.id_index: dict[str, list[tuple[ET.Element, str]]] = {}
        for element in self.elements:
            for attr, value in element.attrib.items():
                name = attr if not attr.startswith("{") else qname(attr)
                if name == SAML_ID_ATTR or name in OTHER_ID_ATTRS:
                    self.id_index.setdefault(value, []).append((element, name))

        self.assertions = [e for e in self.elements if e.tag == f"{{{NS_ASSERTION}}}Assertion"]
        self.responses = [e for e in self.elements if e.tag == f"{{{NS_PROTOCOL}}}Response"]
        self.signatures = [self._signature_info(e) for e in self.elements
                           if e.tag == f"{{{NS_DSIG}}}Signature"]

    # ------------------------------------------------------------------ helpers
    def parent(self, element: ET.Element) -> ET.Element | None:
        return self.parents.get(id(element))

    def ancestors(self, element: ET.Element) -> list[ET.Element]:
        chain: list[ET.Element] = []
        current = self.parent(element)
        while current is not None:
            chain.append(current)
            current = self.parent(current)
        return chain

    def is_ancestor(self, maybe_ancestor: ET.Element, element: ET.Element) -> bool:
        """True if ``maybe_ancestor`` is a strict ancestor of ``element``."""
        return any(a is maybe_ancestor for a in self.ancestors(element))

    def is_ancestor_or_self(self, maybe_ancestor: ET.Element, element: ET.Element) -> bool:
        return maybe_ancestor is element or self.is_ancestor(maybe_ancestor, element)

    def enclosed_by_localname(self, element: ET.Element, *names: str) -> ET.Element | None:
        """Nearest ancestor whose local name is in ``names``, if any."""
        for ancestor in self.ancestors(element):
            if localname(ancestor.tag) in names:
                return ancestor
        return None

    def path(self, element: ET.Element) -> str:
        """An XPath-like location for human output.

        ElementTree discards source line numbers, so a path is the most precise
        location this tool can report. Indices are 1-based and only shown when a
        parent has more than one child with that tag.
        """
        if element is self.root:
            return "/" + qname(element.tag)
        parent = self.parent(element)
        if parent is None:  # detached element, e.g. during generation
            return qname(element.tag)
        same = [c for c in parent if c.tag == element.tag]
        step = qname(element.tag)
        if len(same) > 1:
            step += f"[{same.index(element) + 1}]"
        return f"{self.path(parent)}/{step}"

    def document_order(self, element: ET.Element) -> int:
        return self.order.get(id(element), -1)

    def find_all(self, tag: str) -> list[ET.Element]:
        return [e for e in self.elements if e.tag == tag]

    def saml(self, element: ET.Element, *path: str) -> ET.Element | None:
        current: ET.Element | None = element
        for step in path:
            if current is None:
                return None
            current = current.find(f"{{{NS_ASSERTION}}}{step}")
        return current

    def id_of(self, element: ET.Element) -> str | None:
        return element.attrib.get(SAML_ID_ATTR)

    # -------------------------------------------------------------- signatures
    def _signature_info(self, signature: ET.Element) -> SignatureInfo:
        ds = f"{{{NS_DSIG}}}"
        signed_info = signature.find(f"{ds}SignedInfo")
        c14n = sig_method = None
        references: list[Reference] = []
        if signed_info is not None:
            node = signed_info.find(f"{ds}CanonicalizationMethod")
            c14n = node.attrib.get("Algorithm") if node is not None else None
            node = signed_info.find(f"{ds}SignatureMethod")
            sig_method = node.attrib.get("Algorithm") if node is not None else None
            for ref in signed_info.findall(f"{ds}Reference"):
                transforms_el = ref.find(f"{ds}Transforms")
                transforms = [
                    t.attrib.get("Algorithm", "")
                    for t in (transforms_el.findall(f"{ds}Transform") if transforms_el is not None else [])
                ]
                digest = ref.find(f"{ds}DigestMethod")
                references.append(
                    Reference(
                        element=ref,
                        signature=signature,
                        uri=ref.attrib.get("URI"),
                        digest_method=digest.attrib.get("Algorithm") if digest is not None else None,
                        transforms=transforms,
                        has_transforms_element=transforms_el is not None,
                        whole_document=ref.attrib.get("URI") == "",
                    )
                )
        value = signature.find(f"{ds}SignatureValue")
        info = SignatureInfo(
            element=signature,
            c14n_method=c14n,
            signature_method=sig_method,
            references=references,
            key_info=signature.find(f"{ds}KeyInfo"),
            signature_value="".join(value.itertext()).strip() if value is not None else None,
        )
        for ref in info.references:
            self._resolve(ref)
        return info

    def _resolve(self, ref: Reference) -> None:
        if ref.whole_document:
            ref.target = self.root
            ref.target_attr = None
            return
        fragment = ref.fragment
        if fragment is None:
            return
        candidates = self.id_index.get(fragment, [])
        preferred = [c for c in candidates if c[1] == SAML_ID_ATTR]
        chosen = preferred[0] if preferred else (candidates[0] if candidates else None)
        if chosen is not None:
            ref.target, ref.target_attr = chosen

    @property
    def covered_ids(self) -> set[str]:
        """Ids named by some Reference, i.e. plausibly signed."""
        out = set()
        for sig in self.signatures:
            for ref in sig.references:
                if ref.fragment:
                    out.add(ref.fragment)
        return out

    def signed_elements(self) -> list[ET.Element]:
        """Elements a Reference resolved to, in document order."""
        out: list[ET.Element] = []
        for sig in self.signatures:
            for ref in sig.references:
                if ref.target is not None and not any(e is ref.target for e in out):
                    out.append(ref.target)
        return sorted(out, key=self.document_order)

    def is_covered(self, element: ET.Element) -> bool:
        """True if ``element`` is a signed element or a descendant of one.

        A Response-level signature covers the assertion nested inside it, which
        is why coverage is transitive rather than an identity test. Wrapping
        attacks work precisely by leaving the forged content outside every
        signed subtree while keeping a signed subtree somewhere in the document.
        """
        return any(self.is_ancestor_or_self(signed, element) for signed in self.signed_elements())

    def unsigned_assertions(self) -> list[ET.Element]:
        return [a for a in self.assertions if not self.is_covered(a)]

    def covered_assertions(self) -> list[ET.Element]:
        return [a for a in self.assertions if self.is_covered(a)]
