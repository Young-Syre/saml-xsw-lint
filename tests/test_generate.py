"""Generation: reproducibility, and the property that makes wrapping work.

The committed examples must be exactly what ``--generate`` produces, and in
every one of them the digest over the referenced element and the signature over
SignedInfo must still be correct. That second assertion is the thesis of the
whole tool: the signature keeps verifying while the document the application
reads has been rearranged underneath it.

"Verifies" here means verified by this repository's own canonicalisation and RSA
code (``tools/c14n.py``, ``saml_xsw_lint.der``). No claim is made that xmlsec1
or any other library accepts these documents.
"""

from __future__ import annotations

import base64
import hashlib
import unittest

from saml_xsw_lint import xsw
from saml_xsw_lint.der import Certificate, rsa_pkcs1_verify
from saml_xsw_lint.model import NS_DSIG
from tools import make_examples
from tools.c14n import canonicalise, enveloped_digest_input

from .helpers import EXAMPLES, document, read_cert

DS = f"{{{NS_DSIG}}}"
VARIANT_FILES = sorted(variant.filename for variant in xsw.VARIANTS)


class CommittedFixtures(unittest.TestCase):
    def test_committed_files_are_what_the_generator_produces(self):
        self.assertEqual(0, make_examples.main(["--check"]))

    def test_generator_builds_every_expected_path(self):
        files = make_examples.build()
        names = {path.name for path in files}
        for filename in VARIANT_FILES:
            self.assertIn(filename, names)
        self.assertIn("benign-response.xml", names)
        self.assertIn("benign-response-signed.xml", names)
        self.assertIn("idp.crt", names)

    def test_regeneration_is_deterministic(self):
        self.assertEqual(make_examples.build(), make_examples.build())


class SignatureSurvivesWrapping(unittest.TestCase):
    def setUp(self):
        self.certificate = Certificate.from_der(read_cert("idp"))

    def _check(self, filename):
        doc = document(EXAMPLES / filename)
        self.assertEqual(1, len(doc.signatures), filename)
        signature = doc.signatures[0]
        reference = signature.references[0]
        self.assertIsNotNone(reference.target, f"{filename}: reference did not resolve")

        digest_element = signature.element.find(f"{DS}SignedInfo/{DS}Reference/{DS}DigestValue")
        recomputed = base64.b64encode(
            hashlib.sha256(enveloped_digest_input(reference.target)).digest()
        ).decode("ascii")
        self.assertEqual(digest_element.text, recomputed,
                         f"{filename}: the digest no longer matches the referenced element")

        signed_info = signature.element.find(f"{DS}SignedInfo")
        key = self.certificate.public_key
        self.assertTrue(
            rsa_pkcs1_verify(key.modulus, key.exponent,
                             base64.b64decode(signature.signature_value),
                             canonicalise(signed_info), "sha256"),
            f"{filename}: SignedInfo signature no longer verifies",
        )

    def test_benign_fixtures_verify(self):
        for filename in ("benign-response.xml", "benign-response-signed.xml"):
            with self.subTest(fixture=filename):
                self._check(filename)

    def test_every_variant_still_verifies(self):
        for filename in VARIANT_FILES:
            with self.subTest(fixture=filename):
                self._check(filename)

    def test_digest_is_identical_in_benign_and_wrapped_documents(self):
        benign = document(EXAMPLES / "benign-response.xml")
        original = benign.signatures[0].element.find(
            f"{DS}SignedInfo/{DS}Reference/{DS}DigestValue").text
        for filename in VARIANT_FILES[2:]:  # the assertion-signed variants
            with self.subTest(fixture=filename):
                doc = document(EXAMPLES / filename)
                moved = doc.signatures[0].element.find(
                    f"{DS}SignedInfo/{DS}Reference/{DS}DigestValue").text
                self.assertEqual(original, moved)


class Banners(unittest.TestCase):
    def test_every_variant_carries_an_authorisation_notice(self):
        for filename in VARIANT_FILES:
            with self.subTest(fixture=filename):
                text = (EXAMPLES / filename).read_text()
                self.assertIn("FOR AUTHORISED TESTING ONLY", text)
                self.assertIn("written permission", text)
                self.assertIn("deliberately malformed", text)

    def test_variant_banner_names_its_number_and_finding(self):
        for variant in xsw.VARIANTS:
            with self.subTest(variant=variant.number):
                text = (EXAMPLES / variant.filename).read_text()
                self.assertIn(f"variant {variant.number}", text)
                self.assertIn(variant.finding_id, text)

    def test_benign_fixtures_say_they_are_fabricated(self):
        for filename in ("benign-response.xml", "benign-response-signed.xml"):
            with self.subTest(fixture=filename):
                text = (EXAMPLES / filename).read_text()
                self.assertIn("Entirely fabricated", text)
                self.assertIn("idp.example", text)

    def test_no_fixture_mentions_a_private_key_block(self):
        for path in sorted(EXAMPLES.rglob("*")):
            if path.is_file():
                with self.subTest(fixture=path.name):
                    self.assertNotIn("PRIVATE KEY", path.read_text())


class GenerationErrors(unittest.TestCase):
    def test_variant_for_the_wrong_signature_position_is_refused(self):
        doc = document(EXAMPLES / "benign-response.xml")  # signs the assertion
        with self.assertRaises(xsw.GenerationError):
            xsw.generate(doc, [xsw.BY_NUMBER[1]])

    def test_applicable_depends_on_what_is_signed(self):
        assertion_signed = document(EXAMPLES / "benign-response.xml")
        response_signed = document(EXAMPLES / "benign-response-signed.xml")
        self.assertEqual([3, 4, 5, 6, 7, 8],
                         [v.number for v in xsw.applicable(assertion_signed)])
        self.assertEqual([1, 2], [v.number for v in xsw.applicable(response_signed)])

    def test_signed_kind_reports_what_the_reference_covers(self):
        self.assertEqual("assertion", xsw.signed_kind(document(EXAMPLES / "benign-response.xml")))
        self.assertEqual("response",
                         xsw.signed_kind(document(EXAMPLES / "benign-response-signed.xml")))

    def test_document_with_several_references_cannot_be_used(self):
        # Generation has to know exactly which element is signed, so anything
        # ambiguous is refused rather than guessed at.
        from .helpers import DATA

        with self.assertRaises(xsw.GenerationError):
            xsw.signed_kind(document(DATA / "multiple-references.xml"))

    def test_document_whose_reference_does_not_resolve_cannot_be_used(self):
        from .helpers import DATA

        with self.assertRaises(xsw.GenerationError):
            xsw.signed_kind(document(DATA / "dangling-reference.xml"))

    def test_unsigned_document_cannot_be_used(self):
        from .helpers import DATA

        with self.assertRaises(xsw.GenerationError):
            xsw.signed_kind(document(DATA / "unsigned-response.xml"))

    def test_forged_content_is_relabelled(self):
        doc = document(EXAMPLES / "xsw-03-forged-assertion-first.xml")
        forged, signed = doc.assertions
        self.assertTrue(forged.attrib["ID"].endswith(xsw.FORGED_SUFFIX))
        self.assertFalse(signed.attrib["ID"].endswith(xsw.FORGED_SUFFIX))
        nameid_tag = "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        name_ids = [node.text for node in forged.iter(nameid_tag)]
        self.assertEqual([xsw.FORGED_NAMEID], name_ids)

    def test_forged_assertion_has_no_signature_of_its_own(self):
        doc = document(EXAMPLES / "xsw-03-forged-assertion-first.xml")
        forged = doc.assertions[0]
        self.assertEqual([], list(forged.iter(f"{DS}Signature")))


if __name__ == "__main__":
    unittest.main()
