"""One case per fixture: what must be reported, and what must not be.

The ``forbidden`` column matters as much as the expected one. A linter that
reports everything on every document is useless, so each fixture asserts the
absence of the findings it would be wrong to raise.
"""

from __future__ import annotations

import datetime as dt
import unittest

from saml_xsw_lint import analyse

from .helpers import CERTS, DATA, EXAMPLES, document, finding_ids, read_cert

#: fixture -> (must be reported, must not be reported)
CASES: dict[str, tuple[set[str], set[str]]] = {
    # structure
    "unsigned-response.xml": ({"STR010", "STR002", "STR003"}, {"STR001", "STR004", "CRY004"}),
    "duplicate-id.xml": ({"STR006", "STR001", "STR002"}, {"STR007", "STR009"}),
    "non-ncname-id.xml": ({"STR007"}, {"STR006", "STR008", "STR009", "STR002"}),
    "lowercase-id-attribute.xml": ({"STR008", "STR015"}, {"STR006", "STR009", "STR002"}),
    "dangling-reference.xml": ({"STR009", "STR002", "STR003"}, {"STR004", "STR006", "STR011"}),
    "reference-without-uri.xml": ({"STR009"}, {"STR011", "STR005"}),
    "absolute-uri-reference.xml": ({"STR011", "STR002"}, {"STR009", "STR004"}),
    "whole-document-reference.xml": ({"STR005", "STR001"}, {"STR002", "STR009", "STR004"}),
    "multiple-references.xml": ({"STR012"}, {"STR009", "STR005"}),
    # transforms
    "transform-xslt.xml": ({"TRN001"}, {"TRN002", "TRN004", "TRN005"}),
    "transform-xpath.xml": ({"TRN002"}, {"TRN001", "TRN004", "TRN005"}),
    "transform-missing-enveloped.xml": ({"TRN003"}, {"TRN004", "TRN005", "TRN001"}),
    "transform-unexpected.xml": ({"TRN004"}, {"TRN001", "TRN002", "TRN003"}),
    "transform-no-algorithm.xml": ({"TRN008"}, {"TRN001", "TRN004"}),
    "no-transforms.xml": ({"TRN005", "TRN003"}, {"TRN004", "TRN008"}),
    "inclusive-c14n.xml": ({"TRN006"}, {"TRN004", "TRN007"}),
    "no-c14n-method.xml": ({"TRN007"}, {"TRN006"}),
    # crypto and trust
    "weak-sha1.xml": ({"CRY001", "CRY002", "CRY004", "CRY007"}, {"CRY003", "CRY010", "CRY013"}),
    "hmac-signature.xml": ({"CRY003", "CRY013"}, {"CRY002", "CRY004"}),
    "no-keyinfo.xml": ({"CRY013"}, {"CRY004", "CRY005", "CRY011"}),
    "expired-certificate.xml": ({"CRY008", "CRY004", "CRY007"}, {"CRY009", "CRY010", "CRY016"}),
    "weak-key-certificate.xml": ({"CRY010", "CRY004"}, {"CRY008", "CRY012", "CRY016"}),
    "two-certificates.xml": ({"CRY015", "CRY004"}, {"CRY014", "CRY010"}),
    "unparseable-certificate.xml": ({"CRY014"}, {"CRY004", "CRY007", "CRY015"}),
    "tampered-self-signed.xml": ({"CRY016", "CRY007"}, {"CRY008", "CRY010"}),
    "keyinfo-retrieval-url.xml": ({"CRY011"}, {"CRY013", "CRY004"}),
    "rsa-keyvalue-short.xml": ({"CRY012"}, {"CRY004", "CRY010", "CRY013"}),
    # assertion semantics
    "assertion-no-conditions.xml": ({"SEM001"}, {"SEM002", "SEM003", "SEM005", "SEM016"}),
    "assertion-open-conditions.xml": ({"SEM002", "SEM003", "SEM005", "SEM016"}, {"SEM001", "SEM004"}),
    "wide-window.xml": ({"SEM004"}, {"SEM002", "SEM003", "SEM005"}),
    "no-subject-confirmation.xml": ({"SEM006"}, {"SEM007", "SEM009", "SEM017"}),
    "bare-confirmation-data.xml": ({"SEM007", "SEM009", "SEM017"}, {"SEM006", "SEM008"}),
    "response-no-destination.xml": ({"SEM010", "SEM018"}, {"SEM001", "SEM006"}),
    "no-authn-statement.xml": ({"SEM011"}, {"SEM012"}),
    "long-session.xml": ({"SEM012"}, {"SEM011"}),
    "nameid-no-format.xml": ({"SEM013"}, {"SEM014", "SEM015"}),
    "nameid-unspecified.xml": ({"SEM014"}, {"SEM013", "SEM015"}),
    "nameid-email.xml": ({"SEM015"}, {"SEM013", "SEM014"}),
    "attribute-value-markup.xml": ({"SEM020"}, {"SEM001", "SEM011"}),
    "bare-assertion.xml": (set(), {"SEM010", "SEM018", "STR001", "STR002", "STR010"}),
}


class FixtureExpectations(unittest.TestCase):
    def test_every_fixture_matches_its_expectations(self):
        for filename, (expected, forbidden) in CASES.items():
            with self.subTest(fixture=filename):
                ids = finding_ids(DATA / filename)
                self.assertLessEqual(expected, ids,
                                     f"{filename}: missing {sorted(expected - ids)}")
                self.assertEqual(set(), forbidden & ids,
                                 f"{filename}: unexpected {sorted(forbidden & ids)}")

    def test_every_fixture_has_a_case(self):
        fixtures = {
            path.name for path in DATA.iterdir()
            if path.suffix == ".xml" and not path.name.startswith("unsafe-")
            and path.name != "malformed.xml"
        }
        self.assertEqual(fixtures, set(CASES))


class OptionDrivenChecks(unittest.TestCase):
    """Findings that only exist once the deployment context is supplied."""

    def test_matching_certificate_is_reported_as_info(self):
        ids = finding_ids(EXAMPLES / "benign-response.xml", cert_der=read_cert("idp"))
        self.assertIn("CRY006", ids)
        self.assertNotIn("CRY005", ids)

    def test_different_certificate_is_a_mismatch(self):
        ids = finding_ids(EXAMPLES / "benign-response.xml", cert_der=read_cert("other-idp"))
        self.assertIn("CRY005", ids)
        self.assertNotIn("CRY006", ids)

    def test_certificate_comparison_is_silent_without_cert_option(self):
        ids = finding_ids(EXAMPLES / "benign-response.xml")
        self.assertNotIn("CRY005", ids)
        self.assertNotIn("CRY006", ids)

    def test_not_yet_valid_certificate(self):
        ids = finding_ids(DATA / "expired-certificate.xml",
                          now=dt.datetime(2007, 1, 1, tzinfo=dt.timezone.utc))
        self.assertIn("CRY009", ids)
        self.assertNotIn("CRY008", ids)

    def test_recipient_mismatch_needs_acs_url(self):
        clean = finding_ids(EXAMPLES / "benign-response.xml",
                            acs_url="https://sp.example/saml/acs")
        self.assertNotIn("SEM008", clean)
        mismatch = finding_ids(EXAMPLES / "benign-response.xml",
                               acs_url="https://other-sp.example/saml/acs")
        self.assertIn("SEM008", mismatch)

    def test_audience_mismatch_needs_audience(self):
        clean = finding_ids(EXAMPLES / "benign-response.xml",
                            audience="https://sp.example/metadata")
        self.assertNotIn("SEM019", clean)
        mismatch = finding_ids(EXAMPLES / "benign-response.xml",
                               audience="https://other-sp.example/metadata")
        self.assertIn("SEM019", mismatch)

    def test_window_threshold_is_configurable(self):
        self.assertNotIn("SEM004", finding_ids(EXAMPLES / "benign-response.xml"))
        self.assertIn("SEM004", finding_ids(EXAMPLES / "benign-response.xml",
                                            max_window_seconds=60))

    def test_session_threshold_is_configurable(self):
        self.assertNotIn("SEM012", finding_ids(EXAMPLES / "benign-response.xml"))
        self.assertIn("SEM012", finding_ids(EXAMPLES / "benign-response.xml",
                                            max_session_seconds=60))


class BenignDocuments(unittest.TestCase):
    def test_benign_documents_report_only_informational_findings(self):
        for name in ("benign-response.xml", "benign-response-signed.xml"):
            with self.subTest(fixture=name):
                findings = analyse(document(EXAMPLES / name))
                self.assertTrue(findings, "expected the informational trust findings")
                self.assertEqual(
                    {"CRY004", "CRY007"}, {f.id for f in findings},
                    "a benign fixture must not raise anything else",
                )
                self.assertTrue(all(f.severity.label == "info" for f in findings))

    def test_benign_assertion_is_covered_by_the_signature(self):
        doc = document(EXAMPLES / "benign-response.xml")
        self.assertEqual(1, len(doc.assertions))
        self.assertEqual([], doc.unsigned_assertions())
        self.assertTrue(doc.is_covered(doc.assertions[0]))

    def test_response_signed_fixture_covers_the_assertion_transitively(self):
        doc = document(EXAMPLES / "benign-response-signed.xml")
        self.assertEqual([doc.root], doc.signed_elements())
        self.assertTrue(doc.is_covered(doc.assertions[0]))
        self.assertEqual([], doc.unsigned_assertions())

    def test_certificates_directory_holds_only_certificates(self):
        for path in CERTS.iterdir():
            with self.subTest(certificate=path.name):
                text = path.read_text()
                self.assertTrue(text.startswith("-----BEGIN CERTIFICATE-----"))
                self.assertNotIn("PRIVATE KEY", text)


if __name__ == "__main__":
    unittest.main()
