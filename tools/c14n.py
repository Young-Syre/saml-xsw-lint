"""Exclusive XML canonicalisation, enough of it to build the fixtures.

This module is development tooling, not part of the linter. The linter neither
canonicalises nor verifies anything; this exists only so that the committed
example documents carry a digest and a signature that are actually consistent
with the committed certificate, rather than placeholder base64.

Scope and limits, stated plainly:

* Implements exclusive canonicalisation (https://www.w3.org/TR/xml-exc-c14n/)
  without comments, for the subset the fixtures use: no default namespace, no
  ``xml:`` attributes, no processing instructions, no comments, no
  ``InclusiveNamespaces`` PrefixList, no entity references.
* Namespace rendering follows the "visibly utilised" rule: a prefix is declared
  where it is used by an element name or an attribute name and is not already in
  scope with the same URI.
* It is not a conformant implementation and is not claimed to be. The committed
  fixtures are verified by this repository's own code
  (``tests/test_signature_fixture.py``); no claim is made that xmlsec1 or any
  other library accepts them.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from saml_xsw_lint.model import PREFIXES, localname, nsuri

SIGNATURE_TAG = "{http://www.w3.org/2000/09/xmldsig#}Signature"


def _escape_text(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\r", "&#xD;"))


def _escape_attr(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
            .replace("\t", "&#x9;").replace("\n", "&#xA;").replace("\r", "&#xD;"))


def _prefix_for(uri: str) -> str:
    prefix = PREFIXES.get(uri)
    if prefix is None:
        raise ValueError(f"fixture namespaces must be known; {uri!r} is not")
    return prefix


def _canonicalise(element: ET.Element, rendered: dict[str, str], out: list[str]) -> None:
    uri = nsuri(element.tag)
    utilised: dict[str, str] = {}
    if uri:
        utilised[_prefix_for(uri)] = uri
    for attribute in element.attrib:
        attribute_uri = nsuri(attribute)
        if attribute_uri:
            utilised[_prefix_for(attribute_uri)] = attribute_uri

    declarations = sorted(
        (prefix, value) for prefix, value in utilised.items() if rendered.get(prefix) != value
    )
    scope = dict(rendered)
    scope.update(dict(declarations))

    name = f"{_prefix_for(uri)}:{localname(element.tag)}" if uri else element.tag
    plain = sorted((key, value) for key, value in element.attrib.items() if not key.startswith("{"))
    qualified = sorted(
        (nsuri(key), localname(key), value)
        for key, value in element.attrib.items()
        if key.startswith("{")
    )
    rendered_attrs = "".join(f' {key}="{_escape_attr(value)}"' for key, value in plain)
    rendered_attrs += "".join(
        f' {_prefix_for(ns)}:{local}="{_escape_attr(value)}"' for ns, local, value in qualified
    )
    rendered_decls = "".join(f' xmlns:{prefix}="{_escape_attr(value)}"' for prefix, value in declarations)

    out.append(f"<{name}{rendered_decls}{rendered_attrs}>")
    if element.text:
        out.append(_escape_text(element.text))
    for child in element:
        _canonicalise(child, scope, out)
        if child.tail:
            out.append(_escape_text(child.tail))
    out.append(f"</{name}>")


def canonicalise(element: ET.Element) -> bytes:
    """Exclusive c14n of ``element`` as the apex, with nothing in scope."""
    out: list[str] = []
    _canonicalise(element, {}, out)
    return "".join(out).encode("utf-8")


def enveloped_digest_input(element: ET.Element) -> bytes:
    """Apply the enveloped-signature transform, then canonicalise.

    The referenced element is copied, every ds:Signature inside the copy is
    removed, and the result is canonicalised. Because exclusive c14n of a
    subtree does not depend on where that subtree sits in the document, the
    bytes produced here are the same before and after a wrapping attack moves
    the element - which is exactly why signature wrapping works.
    """
    import copy

    clone = copy.deepcopy(element)
    for parent in clone.iter():
        for child in list(parent):
            if child.tag == SIGNATURE_TAG:
                parent.remove(child)
    return canonicalise(clone)
