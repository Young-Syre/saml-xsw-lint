"""Detection of the eight wrapping shapes against the committed examples."""

from __future__ import annotations

import unittest

from saml_xsw_lint import xsw

from .helpers import EXAMPLES, document, finding_ids

#: example file -> the single XSW finding it must raise
VARIANT_FILES = {
    "xsw-01-signed-response-in-signature.xml": "XSW001",
    "xsw-02-signed-response-beside-signature.xml": "XSW002",
    "xsw-03-forged-assertion-first.xml": "XSW003",
    "xsw-04-signed-assertion-nested.xml": "XSW004",
    "xsw-05-detached-signature.xml": "XSW005",
    "xsw-06-signed-assertion-in-signature.xml": "XSW006",
    "xsw-07-assertion-in-extensions.xml": "XSW007",
    "xsw-08-signed-assertion-in-object.xml": "XSW008",
}

ALL_XSW_IDS = {f"XSW{number:03d}" for number in range(1, 9)}


class VariantDetection(unittest.TestCase):
    def test_each_example_raises_exactly_its_own_variant(self):
        for filename, expected in VARIANT_FILES.items():
            with self.subTest(fixture=filename):
                ids = finding_ids(EXAMPLES / filename)
                self.assertIn(expected, ids)
                self.assertEqual({expected}, ids & ALL_XSW_IDS,
                                 "a variant fixture should match one shape, not several")

    def test_every_variant_file_exists(self):
        for filename in VARIANT_FILES:
            self.assertTrue((EXAMPLES / filename).is_file(), filename)

    def test_every_catalogued_variant_has_a_fixture(self):
        self.assertEqual(ALL_XSW_IDS, set(VARIANT_FILES.values()))
        self.assertEqual(8, len(xsw.VARIANTS))

    def test_benign_documents_match_no_variant(self):
        for name in ("benign-response.xml", "benign-response-signed.xml"):
            with self.subTest(fixture=name):
                self.assertEqual(set(), finding_ids(EXAMPLES / name) & ALL_XSW_IDS)

    def test_each_variant_also_reports_an_unsigned_assertion(self):
        for filename in VARIANT_FILES:
            with self.subTest(fixture=filename):
                ids = finding_ids(EXAMPLES / filename)
                self.assertIn("STR001", ids)
                self.assertIn("STR002", ids)
                self.assertIn("STR003", ids)

    def test_detached_signature_variants_report_str004(self):
        for filename in ("xsw-01-signed-response-in-signature.xml",
                         "xsw-02-signed-response-beside-signature.xml",
                         "xsw-05-detached-signature.xml",
                         "xsw-08-signed-assertion-in-object.xml"):
            with self.subTest(fixture=filename):
                self.assertIn("STR004", finding_ids(EXAMPLES / filename))

    def test_container_variants_report_str013(self):
        for filename in ("xsw-07-assertion-in-extensions.xml",
                         "xsw-08-signed-assertion-in-object.xml"):
            with self.subTest(fixture=filename):
                self.assertIn("STR013", finding_ids(EXAMPLES / filename))

    def test_first_assertion_is_the_forged_one_in_variant_three(self):
        doc = document(EXAMPLES / "xsw-03-forged-assertion-first.xml")
        self.assertEqual(2, len(doc.assertions))
        self.assertFalse(doc.is_covered(doc.assertions[0]))
        self.assertTrue(doc.is_covered(doc.assertions[1]))
        self.assertIn("STR014", finding_ids(EXAMPLES / "xsw-03-forged-assertion-first.xml"))

    def test_variant_four_nests_the_signed_assertion(self):
        doc = document(EXAMPLES / "xsw-04-signed-assertion-nested.xml")
        outer, inner = doc.assertions
        self.assertTrue(doc.is_ancestor(outer, inner))
        self.assertFalse(doc.is_covered(outer))
        self.assertTrue(doc.is_covered(inner))

    def test_variant_six_puts_the_assertion_inside_the_signature(self):
        doc = document(EXAMPLES / "xsw-06-signed-assertion-in-signature.xml")
        signature = doc.signatures[0]
        target = signature.references[0].target
        self.assertTrue(doc.is_ancestor(signature.element, target))
        self.assertIsNone(doc.enclosed_by_localname(target, "Object"))

    def test_variant_eight_puts_the_assertion_inside_an_object(self):
        doc = document(EXAMPLES / "xsw-08-signed-assertion-in-object.xml")
        target = doc.signatures[0].references[0].target
        self.assertIsNotNone(doc.enclosed_by_localname(target, "Object"))

    def test_variant_seven_puts_an_assertion_in_extensions(self):
        doc = document(EXAMPLES / "xsw-07-assertion-in-extensions.xml")
        inside = [a for a in doc.assertions
                  if doc.enclosed_by_localname(a, "Extensions") is not None]
        self.assertEqual(1, len(inside))
        self.assertTrue(doc.is_covered(inside[0]))


class VariantMetadata(unittest.TestCase):
    def test_variant_numbers_are_one_to_eight(self):
        self.assertEqual(list(range(1, 9)), [v.number for v in xsw.VARIANTS])

    def test_variant_finding_ids_are_in_the_catalogue(self):
        from saml_xsw_lint.findings import CATALOGUE

        for variant in xsw.VARIANTS:
            with self.subTest(variant=variant.number):
                self.assertIn(variant.finding_id, CATALOGUE)
                self.assertEqual("critical", CATALOGUE[variant.finding_id].severity.label)

    def test_variant_filenames_are_distinct_and_match_the_examples(self):
        names = [variant.filename for variant in xsw.VARIANTS]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(sorted(names), sorted(VARIANT_FILES))

    def test_each_variant_documents_its_shape(self):
        for variant in xsw.VARIANTS:
            with self.subTest(variant=variant.number):
                self.assertGreater(len(variant.shape), 40)
                self.assertIn(variant.signs, ("response", "assertion"))


if __name__ == "__main__":
    unittest.main()
