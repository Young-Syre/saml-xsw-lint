"""Input decoding and deliberately paranoid XML loading.

This module exists because the rest of the tool reads attacker-controlled XML.
The rule it enforces is simple: anything that could make a parser fetch, expand
or substitute content is detected in the raw bytes and the document is refused
*before* a parser sees it.

Specifically:

* ``xml.etree.ElementTree`` is the only parser used, and only after the prescan.
* ``xml.dom.minidom``, ``xml.sax``, ``xml.dom.pulldom`` and ``lxml`` are not
  imported anywhere in this package. The first three resolve entities by default
  in some configurations; lxml resolves external entities unless told not to.
* A DOCTYPE, an entity declaration, a parameter entity or a SYSTEM/PUBLIC
  identifier is a refusal, not a warning. Refusal happens on the text, so a
  billion-laughs document is never expanded.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from xml.etree import ElementTree as ET

from .findings import Finding

#: Default ceiling on decoded input. Overridable with ``--max-bytes``.
DEFAULT_MAX_BYTES = 16 * 1024 * 1024

_PREDEFINED_ENTITIES = frozenset({"amp", "lt", "gt", "apos", "quot"})

_COMMENT = re.compile(rb"<!--.*?-->", re.DOTALL)
_CDATA = re.compile(rb"<!\[CDATA\[.*?\]\]>", re.DOTALL)
_DOCTYPE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY_DECL = re.compile(rb"<!ENTITY", re.IGNORECASE)
_PARAM_ENTITY = re.compile(rb"%[A-Za-z_][A-Za-z0-9_.\-]*;")
_EXTERNAL_ID = re.compile(rb"<!(?:DOCTYPE|ENTITY|NOTATION)[^>]{0,400}?\b(SYSTEM|PUBLIC)\b")
_ENTITY_REF = re.compile(rb"&([^;&<>\s]{1,64});")
_NUMERIC_REF = re.compile(rb"#(?:[0-9]{1,8}|[xX][0-9A-Fa-f]{1,6})\Z")
_PERCENT = re.compile(rb"%([0-9A-Fa-f]{2})")
_B64_CHARS = re.compile(rb"\A[A-Za-z0-9+/=\s]+\Z")
_B64URL_CHARS = re.compile(rb"\A[A-Za-z0-9\-_=\s]+\Z")


class Refused(Exception):
    """The document was refused before parsing. Carries the findings that say why."""

    def __init__(self, findings: list[Finding]):
        self.findings = findings
        super().__init__("; ".join(f"{f.id} {f.detail}" for f in findings))


def _percent_decode(data: bytes) -> bytes:
    """Decode %XX escapes without importing urllib (see the no-network test).

    ``+`` is deliberately *not* translated to a space. In a URL-encoded form
    field a literal ``+`` means space, but base64 uses ``+`` as a character and
    encoders that care write it as ``%2B``; translating it here would corrupt
    more inputs than it rescued. Both the escaped and the raw bytes are tried.
    """
    return _PERCENT.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def _looks_like_xml(data: bytes) -> bool:
    head = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    return head.startswith(b"<")


def _base64_candidates(data: bytes) -> list[bytes]:
    """Every plausible base64 decoding of ``data``, best first."""
    out: list[bytes] = []
    sources = [data]
    if b"%" in data:
        sources.insert(0, _percent_decode(data))
    for source in sources:
        stripped = b"".join(source.split())
        if not stripped:
            continue
        padded = stripped + b"=" * (-len(stripped) % 4)
        for pattern, decoder in ((_B64_CHARS, base64.b64decode),
                                 (_B64URL_CHARS, base64.urlsafe_b64decode)):
            if not pattern.match(source):
                continue
            try:
                decoded = decoder(padded)
            except (binascii.Error, ValueError):
                continue
            if decoded and decoded not in out:
                out.append(decoded)
    return out


def _try_inflate(data: bytes, max_bytes: int) -> bytes | None:
    for wbits in (-15, 15, 47):
        try:
            out = zlib.decompressobj(wbits).decompress(data, max_bytes)
        except zlib.error:
            continue
        if _looks_like_xml(out):
            return out
    return None


def decode_input(
    raw: bytes,
    *,
    base64_mode: str = "auto",
    inflate: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> tuple[bytes, list[str]]:
    """Return ``(xml_bytes, notes)``.

    ``base64_mode`` is ``auto`` (decode only if the input is not already XML),
    ``always`` or ``never``. ``inflate`` additionally applies DEFLATE, as used by
    the HTTP-Redirect binding. Decompression is bounded by ``max_bytes``.
    """
    if len(raw) > max_bytes:
        raise Refused([Finding("XML006", "/", f"input is {len(raw)} bytes, limit is {max_bytes}")])

    if base64_mode == "never" or (base64_mode == "auto" and _looks_like_xml(raw)):
        if not _looks_like_xml(raw):
            raise Refused([Finding("XML008", "/", "input does not start with an XML element")])
        return raw, []

    candidates = _base64_candidates(raw)
    if not candidates:
        raise Refused([Finding("XML008", "/", "input is not valid base64")])

    for decoded in candidates:
        if len(decoded) > max_bytes:
            raise Refused([Finding(
                "XML006", "/", f"decoded input is {len(decoded)} bytes, limit is {max_bytes}")])
        if _looks_like_xml(decoded):
            return decoded, ["input was base64-decoded"]
        inflated = _try_inflate(decoded, max_bytes)
        if inflated is not None:
            return inflated, ["input was base64-decoded", "input was DEFLATE-decompressed"]
    if inflate:
        inflated = _try_inflate(raw, max_bytes)
        if inflated is not None:
            return inflated, ["input was DEFLATE-decompressed"]
    raise Refused([Finding("XML008", "/",
                           "input decoded but the result does not start with an XML element")])


def prescan(data: bytes) -> list[Finding]:
    """Detect DTD and entity constructs in the raw text.

    Comments and CDATA sections are removed first so that their contents cannot
    produce a false refusal; everything else is scanned literally.
    """
    findings: list[Finding] = []
    body = _CDATA.sub(b"", _COMMENT.sub(b"", data))

    if _DOCTYPE.search(body):
        findings.append(Finding("XML001", "/", "a DOCTYPE declaration is present; refused before parsing"))
    decls = len(_ENTITY_DECL.findall(body))
    if decls:
        findings.append(Finding("XML002", "/", f"{decls} <!ENTITY declaration(s) present; not expanded"))
    params = {m.group(0).decode("ascii", "replace") for m in _PARAM_ENTITY.finditer(body)}
    if params:
        findings.append(Finding("XML003", "/", "parameter entity reference(s): " + ", ".join(sorted(params))))
    ext = {m.group(1).decode("ascii", "replace") for m in _EXTERNAL_ID.finditer(body)}
    if ext:
        findings.append(Finding("XML004", "/", "external identifier keyword(s): " + ", ".join(sorted(ext))))

    bad_refs = set()
    for match in _ENTITY_REF.finditer(body):
        name = match.group(1)
        if name.startswith(b"#"):
            if not _NUMERIC_REF.match(name):
                bad_refs.add(name.decode("ascii", "replace"))
        elif name.decode("ascii", "replace") not in _PREDEFINED_ENTITIES:
            bad_refs.add(name.decode("ascii", "replace"))
    if bad_refs:
        findings.append(
            Finding("XML005", "/", "reference(s) to undeclared entities: "
                    + ", ".join("&" + n + ";" for n in sorted(bad_refs)))
        )
    return findings


def parse(data: bytes) -> ET.Element:
    """Parse with ElementTree after a successful prescan.

    Raises :class:`Refused` on a not-well-formed document.
    """
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise Refused([Finding("XML007", "/", f"not well-formed: {exc}")]) from None


def load(
    raw: bytes,
    *,
    base64_mode: str = "auto",
    inflate: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> tuple[ET.Element, bytes, list[str]]:
    """Decode, prescan, then parse. Returns ``(root, xml_bytes, notes)``."""
    data, notes = decode_input(raw, base64_mode=base64_mode, inflate=inflate, max_bytes=max_bytes)
    unsafe = prescan(data)
    if unsafe:
        raise Refused(unsafe)
    return parse(data), data, notes
