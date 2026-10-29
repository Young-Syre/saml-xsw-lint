"""Catalogue integrity, and proof that the suite exercises every check.

``test_every_check_fires_somewhere`` is the test that keeps the README honest:
if a finding is documented but no fixture produces it, the claim is unproven and
this fails.
"""

from __future__ import annotations

import ast
import datetime as dt
import re
import unittest

from saml_xsw_lint.findings import CATALOGUE, GROUPS, Severity, specs_in_order

from .helpers import DATA, EXAMPLES, ROOT, finding_ids, read_cert, refusal_ids

PACKAGE = ROOT / "saml_xsw_lint"
ID_PATTERN = re.compile(r"\A(XML|STR|XSW|TRN|CRY|SEM)\d{3}\Z")


def ids_used_in_source() -> set[str]:
    """Every string literal in the package that looks like a finding id."""
    found: set[str] = set()
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if ID_PATTERN.match(node.value):
                    found.add(node.value)
    return found


def observed_findings() -> set[str]:
    """Every finding id the fixture corpus produces, options included."""
    seen: set[str] = set()
    for path in sorted(DATA.iterdir()) + sorted(EXAMPLES.glob("*.xml")):
        if path.name.startswith("unsafe-") or path.name in ("malformed.xml", "not-xml.txt"):
            seen |= refusal_ids(path)
        elif path.suffix == ".xml":
            seen |= finding_ids(path)
    benign = EXAMPLES / "benign-response.xml"
    seen |= finding_ids(benign, cert_der=read_cert("idp"))
    seen |= finding_ids(benign, cert_der=read_cert("other-idp"))
    seen |= finding_ids(benign, acs_url="https://elsewhere.example/acs")
    seen |= finding_ids(benign, audience="https://elsewhere.example/metadata")
    seen |= finding_ids(DATA / "expired-certificate.xml",
                        now=dt.datetime(2007, 1, 1, tzinfo=dt.timezone.utc))
    # XML006 is a size refusal, which needs an option rather than a fixture.
    from saml_xsw_lint.safexml import Refused, decode_input

    try:
        decode_input(b"<r>" + b"x" * 200 + b"</r>", max_bytes=16)
    except Refused as refusal:
        seen |= {finding.id for finding in refusal.findings}
    return seen


class CatalogueIntegrity(unittest.TestCase):
    def test_ids_are_well_formed_and_unique(self):
        specs = specs_in_order()
        self.assertEqual(len(specs), len(CATALOGUE))
        self.assertEqual(len(specs), len({spec.id for spec in specs}))
        for spec in specs:
            with self.subTest(finding=spec.id):
                self.assertRegex(spec.id, ID_PATTERN)

    def test_every_spec_has_a_name_and_a_mechanism(self):
        for spec in specs_in_order():
            with self.subTest(finding=spec.id):
                self.assertGreater(len(spec.name), 8)
                self.assertGreater(len(spec.mechanism), 80,
                                   "the mechanism text is the point of the catalogue")
                self.assertTrue(spec.mechanism.rstrip().endswith("."))
                self.assertIn(spec.group, GROUPS)
                self.assertIsInstance(spec.severity, Severity)

    def test_group_prefixes_match_group_names(self):
        prefixes = {"xml-safety": "XML", "structure": "STR", "xsw": "XSW",
                    "transforms": "TRN", "crypto": "CRY", "semantics": "SEM"}
        for spec in specs_in_order():
            with self.subTest(finding=spec.id):
                self.assertTrue(spec.id.startswith(prefixes[spec.group]))

    def test_no_catalogue_entry_is_unreachable(self):
        unused = set(CATALOGUE) - ids_used_in_source()
        self.assertEqual(set(), unused, f"catalogued but never raised: {sorted(unused)}")

    def test_no_check_raises_an_uncatalogued_id(self):
        unknown = ids_used_in_source() - set(CATALOGUE)
        self.assertEqual(set(), unknown, f"raised but not catalogued: {sorted(unknown)}")

    def test_severity_ordering(self):
        self.assertLess(Severity.INFO, Severity.LOW)
        self.assertLess(Severity.LOW, Severity.MEDIUM)
        self.assertLess(Severity.MEDIUM, Severity.HIGH)
        self.assertLess(Severity.HIGH, Severity.CRITICAL)
        self.assertEqual(Severity.HIGH, Severity.parse("HIGH"))
        self.assertEqual(Severity.LOW, Severity.parse("low"))
        with self.assertRaises(ValueError):
            Severity.parse("catastrophic")

    def test_xml_safety_findings_are_all_serious(self):
        for spec in specs_in_order():
            if spec.group == "xml-safety":
                with self.subTest(finding=spec.id):
                    self.assertGreaterEqual(spec.severity, Severity.HIGH)

    def test_wrapping_findings_are_critical(self):
        for spec in specs_in_order():
            if spec.group == "xsw":
                with self.subTest(finding=spec.id):
                    self.assertEqual(Severity.CRITICAL, spec.severity)


class Coverage(unittest.TestCase):
    def test_every_check_fires_somewhere(self):
        missing = set(CATALOGUE) - observed_findings()
        self.assertEqual(set(), missing, f"no fixture produces: {sorted(missing)}")

    def test_no_finding_is_produced_that_is_not_catalogued(self):
        self.assertEqual(set(), observed_findings() - set(CATALOGUE))


class ReadmeSync(unittest.TestCase):
    def setUp(self):
        self.readme = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_every_finding_id_is_documented(self):
        for spec in specs_in_order():
            with self.subTest(finding=spec.id):
                self.assertIn(spec.id, self.readme)

    def test_readme_states_what_the_tool_is_not(self):
        self.assertIn("not a signature verifier", self.readme.lower())
        self.assertIn("never makes a network request", self.readme.lower())

    def test_readme_documents_every_exit_code(self):
        for code in ("0", "1", "2", "3"):
            self.assertIn(f"| `{code}` |", self.readme)

    def test_readme_has_no_absolute_local_paths(self):
        for fragment in ("/home/", "/Users/"):
            self.assertNotIn(fragment, self.readme)


if __name__ == "__main__":
    unittest.main()
