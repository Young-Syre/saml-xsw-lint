"""Deterministic serialisation.

``ElementTree.tostring`` invents namespace prefixes (``ns0``, ``ns1``) and has
changed its namespace handling between Python releases. The generated XSW
documents are committed to the repository and compared byte-for-byte in the test
suite, so they are written by this module instead: fixed prefixes, every
namespace declared once on the root element, no reordering of attributes and no
pretty-printing.

No pretty-printing is deliberate twice over. Real SAML responses arrive as a
single line, and inserting whitespace between elements would change the bytes
inside the signed assertion as it is moved around the tree, which would turn a
wrapping document into a merely corrupt one.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from .model import PREFIXES, nsuri

XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>'


def _escape_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_attr(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\t", "&#x9;")
        .replace("\n", "&#xA;")
        .replace("\r", "&#xD;")
    )


def used_namespaces(element: ET.Element) -> list[str]:
    """Namespace URIs used by tags or attributes anywhere in the subtree."""
    seen: list[str] = []
    for node in element.iter():
        if not isinstance(node.tag, str):  # comments and PIs
            continue
        for uri in (nsuri(node.tag), *(nsuri(a) for a in node.attrib)):
            if uri and uri not in seen:
                seen.append(uri)
    return seen


def _name(tag: str, prefix_map: dict[str, str]) -> str:
    if not tag.startswith("{"):
        return tag
    uri, _, local = tag[1:].partition("}")
    prefix = prefix_map.get(uri)
    if prefix is None:
        raise ValueError(f"no prefix registered for namespace {uri!r}")
    return f"{prefix}:{local}"


def _write(element: ET.Element, prefix_map: dict[str, str], declarations: str, out: list[str]) -> None:
    name = _name(element.tag, prefix_map)
    attributes = "".join(
        f' {_name(key, prefix_map)}="{_escape_attr(value)}"' for key, value in element.attrib.items()
    )
    children = list(element)
    text = element.text or ""
    if not children and not text:
        out.append(f"<{name}{declarations}{attributes}/>")
        return
    out.append(f"<{name}{declarations}{attributes}>")
    if text:
        out.append(_escape_text(text))
    for child in children:
        _write(child, prefix_map, "", out)
        if child.tail:
            out.append(_escape_text(child.tail))
    out.append(f"</{name}>")


def serialise(root: ET.Element, *, banner: str | None = None, declaration: bool = True) -> str:
    """Serialise ``root`` with all namespaces declared on the root element."""
    prefix_map: dict[str, str] = {}
    for index, uri in enumerate(used_namespaces(root)):
        prefix_map[uri] = PREFIXES.get(uri) or f"n{index}"
    declarations = "".join(
        f' xmlns:{prefix}="{_escape_attr(uri)}"'
        for uri, prefix in prefix_map.items()
        if prefix != "xml"
    )
    out: list[str] = []
    if declaration:
        out.append(XML_DECLARATION)
    if banner:
        out.append(f"<!--\n{banner.strip()}\n-->")
    _write(root, prefix_map, declarations, out)
    return "".join(out) + "\n"
