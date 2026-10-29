"""Input decoding and the refusal path.

The point of these tests is that nothing dangerous is ever handed to a parser.
``test_elementtree_really_does_expand_entities`` documents why: the parser this
tool uses will happily expand an internal entity, so the prescan is not
belt-and-braces, it is the control.
"""

from __future__ import annotations

import base64
import time
import unittest
import zlib
from xml.etree import ElementTree as ET

from saml_xsw_lint.safexml import DEFAULT_MAX_BYTES, Refused, decode_input, load, prescan

from .helpers import DATA, refusal_ids

BENIGN = b'<?xml version="1.0"?><r a="1">text</r>'

SMALL_BOMB = (
    '<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
    '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><r>&c;</r>'
)


class EntityHandling(unittest.TestCase):
    def test_elementtree_really_does_expand_entities(self):
        # Not a test of this tool: a test of the premise behind safexml.prescan.
        root = ET.fromstring(SMALL_BOMB)
        self.assertEqual(len(root.text or ""), 1000)

    def test_small_bomb_is_refused_by_load(self):
        with self.assertRaises(Refused) as caught:
            load(SMALL_BOMB.encode("utf-8"))
        ids = {finding.id for finding in caught.exception.findings}
        self.assertIn("XML001", ids)
        self.assertIn("XML002", ids)

    def test_billion_laughs_fixture_is_refused_and_not_expanded(self):
        path = DATA / "unsafe-billion-laughs.xml"
        started = time.monotonic()
        ids = refusal_ids(path)
        elapsed = time.monotonic() - started
        self.assertIn("XML001", ids)
        self.assertIn("XML002", ids)
        self.assertIn("XML005", ids)
        # A refusal is a text scan; expansion would be nine orders of magnitude slower.
        self.assertLess(elapsed, 2.0)

    def test_external_entity_fixture_is_refused(self):
        ids = refusal_ids(DATA / "unsafe-external-entity.xml")
        self.assertEqual({"XML001", "XML002", "XML004", "XML005"}, ids)

    def test_parameter_entity_fixture_is_refused(self):
        ids = refusal_ids(DATA / "unsafe-parameter-entity.xml")
        self.assertIn("XML003", ids)
        self.assertIn("XML004", ids)

    def test_doctype_alone_is_refused(self):
        self.assertEqual({"XML001"}, refusal_ids(DATA / "unsafe-doctype.xml"))

    def test_undeclared_entity_reference_is_refused(self):
        ids = refusal_ids(DATA / "unsafe-entity-reference.xml")
        self.assertEqual({"XML005"}, ids)

    def test_predefined_and_numeric_entities_are_accepted(self):
        document = b"<r>&amp;&lt;&gt;&quot;&apos;&#65;&#x41;</r>"
        self.assertEqual([], prescan(document))

    def test_doctype_inside_a_comment_is_not_a_refusal(self):
        document = b"<!-- <!DOCTYPE evil> --><r/>"
        self.assertEqual([], prescan(document))

    def test_doctype_after_a_comment_is_still_a_refusal(self):
        document = b"<!-- harmless --><!DOCTYPE r><r/>"
        self.assertEqual(["XML001"], [f.id for f in prescan(document)])

    def test_entity_in_cdata_is_not_a_refusal(self):
        self.assertEqual([], prescan(b"<r><![CDATA[<!ENTITY x 'y'> &nope;]]></r>"))


class Decoding(unittest.TestCase):
    def test_plain_xml_passes_through(self):
        data, notes = decode_input(BENIGN)
        self.assertEqual(BENIGN, data)
        self.assertEqual([], notes)

    def test_base64_is_auto_detected(self):
        data, notes = decode_input(base64.b64encode(BENIGN))
        self.assertEqual(BENIGN, data)
        self.assertIn("input was base64-decoded", notes)

    def test_base64_with_whitespace_and_percent_escapes(self):
        encoded = base64.b64encode(BENIGN).decode("ascii")
        wrapped = "\n".join(encoded[i:i + 20] for i in range(0, len(encoded), 20))
        mangled = wrapped.replace("=", "%3D")
        data, _ = decode_input(mangled.encode("ascii"))
        self.assertEqual(BENIGN, data)

    def test_urlsafe_base64(self):
        data, _ = decode_input(base64.urlsafe_b64encode(b'<r x="a?b/c+d-e_f"/>'))
        self.assertEqual(b'<r x="a?b/c+d-e_f"/>', data)

    def test_no_base64_mode_refuses_encoded_input(self):
        with self.assertRaises(Refused) as caught:
            decode_input(base64.b64encode(BENIGN), base64_mode="never")
        self.assertEqual("XML008", caught.exception.findings[0].id)

    def test_base64_always_mode_rejects_non_base64(self):
        with self.assertRaises(Refused) as caught:
            decode_input(b"\x00\x01not base64 at all", base64_mode="always")
        self.assertEqual("XML008", caught.exception.findings[0].id)

    def test_deflate_then_base64_is_decoded(self):
        compressor = zlib.compressobj(wbits=-15)
        deflated = compressor.compress(BENIGN) + compressor.flush()
        data, notes = decode_input(base64.b64encode(deflated), inflate=True)
        self.assertEqual(BENIGN, data)
        self.assertIn("input was DEFLATE-decompressed", notes)

    def test_oversized_input_is_refused_before_parsing(self):
        with self.assertRaises(Refused) as caught:
            decode_input(b"<r>" + b"a" * 100 + b"</r>", max_bytes=50)
        self.assertEqual("XML006", caught.exception.findings[0].id)

    def test_default_limit_is_sixteen_mebibytes(self):
        self.assertEqual(16 * 1024 * 1024, DEFAULT_MAX_BYTES)

    def test_malformed_document_is_refused_with_xml007(self):
        self.assertEqual({"XML007"}, refusal_ids(DATA / "malformed.xml"))

    def test_non_xml_input_is_refused_with_xml008(self):
        self.assertEqual({"XML008"}, refusal_ids(DATA / "not-xml.txt"))

    def test_load_returns_root_and_notes(self):
        root, data, notes = load(base64.b64encode(BENIGN))
        self.assertEqual("r", root.tag)
        self.assertEqual(BENIGN, data)
        self.assertEqual(["input was base64-decoded"], notes)


if __name__ == "__main__":
    unittest.main()
