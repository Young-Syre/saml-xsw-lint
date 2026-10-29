"""Command line behaviour and exit codes.

The exit codes are part of the interface - CI and other tools depend on them -
so each one has a test.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from saml_xsw_lint import __version__
from saml_xsw_lint.cli import EXIT_CLEAN, EXIT_FINDINGS, EXIT_REFUSED, EXIT_USAGE, main
from saml_xsw_lint.findings import CATALOGUE

from .helpers import CERTS, DATA, EXAMPLES


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


class ExitCodes(unittest.TestCase):
    def test_benign_document_is_clean(self):
        code, output, _ = run(str(EXAMPLES / "benign-response.xml"))
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("summary: 2 finding(s)", output)
        self.assertIn("2 info", output)

    def test_every_benign_fixture_is_clean_at_the_default_threshold(self):
        for name in ("benign-response.xml", "benign-response-signed.xml"):
            with self.subTest(fixture=name):
                code, _, _ = run(str(EXAMPLES / name))
                self.assertEqual(EXIT_CLEAN, code)

    def test_every_variant_document_fails(self):
        for path in sorted(EXAMPLES.glob("xsw-*.xml")):
            with self.subTest(fixture=path.name):
                code, output, _ = run(str(path))
                self.assertEqual(EXIT_FINDINGS, code)
                self.assertIn("CRITICAL", output)

    def test_refused_input_exits_two(self):
        for name in ("unsafe-doctype.xml", "unsafe-billion-laughs.xml",
                     "unsafe-external-entity.xml", "unsafe-parameter-entity.xml",
                     "malformed.xml", "not-xml.txt"):
            with self.subTest(fixture=name):
                code, output, _ = run(str(DATA / name))
                self.assertEqual(EXIT_REFUSED, code)
                self.assertIn("refused before parsing", output)

    def test_missing_file_is_a_usage_error(self):
        code, _, err = run(str(DATA / "no-such-file.xml"))
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("cannot read", err)

    def test_no_input_is_a_usage_error(self):
        code, _, err = run()
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("an input file is required", err)

    def test_unknown_ignore_id_is_a_usage_error(self):
        code, _, err = run(str(EXAMPLES / "benign-response.xml"), "--ignore", "NOPE999")
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("unknown finding id", err)

    def test_bad_now_is_a_usage_error(self):
        code, _, err = run(str(EXAMPLES / "benign-response.xml"), "--now", "yesterday")
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("ISO 8601", err)

    def test_unparseable_cert_option_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.crt"
            path.write_bytes(b"not a certificate")
            code, _, err = run(str(EXAMPLES / "benign-response.xml"), "--cert", str(path))
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("not a certificate this tool can parse", err)

    def test_missing_cert_file_is_a_usage_error(self):
        code, _, err = run(str(EXAMPLES / "benign-response.xml"), "--cert", "/nonexistent.crt")
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("cannot read", err)


class Thresholds(unittest.TestCase):
    def test_fail_on_never_always_exits_clean(self):
        code, _, _ = run(str(EXAMPLES / "xsw-03-forged-assertion-first.xml"),
                         "--fail-on", "never")
        self.assertEqual(EXIT_CLEAN, code)

    def test_fail_on_info_catches_the_benign_document(self):
        code, _, _ = run(str(EXAMPLES / "benign-response.xml"), "--fail-on", "info")
        self.assertEqual(EXIT_FINDINGS, code)

    def test_fail_on_critical_ignores_high_findings(self):
        code, _, _ = run(str(DATA / "unsigned-response.xml"), "--fail-on", "critical")
        self.assertEqual(EXIT_CLEAN, code)

    def test_ignore_suppresses_a_finding(self):
        _, with_finding, _ = run(str(DATA / "duplicate-id.xml"))
        self.assertIn("STR006", with_finding)
        code, without, _ = run(str(DATA / "duplicate-id.xml"), "--ignore", "str006",
                               "--fail-on", "critical")
        self.assertNotIn("STR006", without)
        self.assertEqual(EXIT_CLEAN, code)

    def test_ignore_accepts_several_ids(self):
        _, output, _ = run(str(EXAMPLES / "xsw-03-forged-assertion-first.xml"),
                           "--ignore", "XSW003,STR001,STR002")
        for ident in ("XSW003", "STR001", "STR002"):
            self.assertNotIn(ident, output)


class OutputFormats(unittest.TestCase):
    def test_json_output_shape(self):
        code, output, _ = run(str(EXAMPLES / "xsw-06-signed-assertion-in-signature.xml"), "--json")
        payload = json.loads(output)
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertEqual("saml-xsw-lint", payload["tool"])
        self.assertEqual(__version__, payload["version"])
        self.assertFalse(payload["refused"])
        self.assertEqual("medium", payload["fail_on"])
        self.assertEqual(EXIT_FINDINGS, payload["exit_code"])
        self.assertEqual(payload["summary"]["total"], len(payload["findings"]))
        first = payload["findings"][0]
        self.assertEqual({"id", "name", "severity", "group", "where", "detail", "mechanism"},
                         set(first) - {"extra"})
        self.assertEqual("XSW006", first["id"])
        self.assertEqual("critical", first["severity"])

    def test_json_output_for_a_refusal(self):
        code, output, _ = run(str(DATA / "unsafe-external-entity.xml"), "--json")
        payload = json.loads(output)
        self.assertEqual(EXIT_REFUSED, code)
        self.assertTrue(payload["refused"])
        self.assertIn("XML004", [finding["id"] for finding in payload["findings"]])

    def test_findings_are_sorted_most_severe_first(self):
        _, output, _ = run(str(EXAMPLES / "xsw-08-signed-assertion-in-object.xml"), "--json")
        severities = [finding["severity"] for finding in json.loads(output)["findings"]]
        order = ["critical", "high", "medium", "low", "info"]
        self.assertEqual(sorted(severities, key=order.index), severities)

    def test_quiet_prints_only_the_summary(self):
        _, output, _ = run(str(DATA / "duplicate-id.xml"), "--quiet")
        self.assertNotIn("STR006", output)
        self.assertIn("summary:", output)

    def test_explain_prints_the_mechanism(self):
        _, output, _ = run(str(DATA / "duplicate-id.xml"), "--explain")
        self.assertIn("why:", output)
        self.assertIn("parser-dependent", output)

    def test_notes_are_printed_for_decoded_input(self):
        import base64

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "response.b64"
            path.write_bytes(base64.b64encode((EXAMPLES / "benign-response.xml").read_bytes()))
            _, output, _ = run(str(path))
        self.assertIn("note: input was base64-decoded", output)

    def test_stdin_input(self):
        data = (EXAMPLES / "benign-response.xml").read_bytes()
        stdin = mock.Mock()
        stdin.buffer.read.return_value = data
        with mock.patch("saml_xsw_lint.cli.sys.stdin", stdin):
            code, output, _ = run("-")
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("saml-xsw-lint", output)

    def test_list_checks_text(self):
        code, output, _ = run("--list-checks")
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn(f"{len(CATALOGUE)} checks", output)
        for group in ("xml-safety", "structure", "xsw", "transforms", "crypto", "semantics"):
            self.assertIn(f"[{group}]", output)

    def test_list_checks_json(self):
        code, output, _ = run("--list-checks", "--json")
        payload = json.loads(output)
        self.assertEqual(EXIT_CLEAN, code)
        self.assertEqual(len(CATALOGUE), len(payload))
        self.assertEqual({"id", "name", "severity", "group", "mechanism"}, set(payload[0]))

    def test_version(self):
        import contextlib

        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), self.assertRaises(SystemExit) as caught:
            run("--version")
        self.assertEqual(0, caught.exception.code)
        self.assertIn(__version__, stream.getvalue())


class ContextOptions(unittest.TestCase):
    def test_matching_cert_reports_cry006(self):
        _, output, _ = run(str(EXAMPLES / "benign-response.xml"),
                           "--cert", str(CERTS / "idp.crt"), "--fail-on", "never")
        self.assertIn("CRY006", output)

    def test_mismatched_cert_reports_cry005_and_fails(self):
        code, output, _ = run(str(EXAMPLES / "benign-response.xml"),
                              "--cert", str(CERTS / "other-idp.crt"))
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertIn("CRY005", output)

    def test_acs_url_mismatch_reports_sem008(self):
        code, output, _ = run(str(EXAMPLES / "benign-response.xml"),
                              "--acs-url", "https://evil-sp.example/acs")
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertIn("SEM008", output)

    def test_audience_mismatch_reports_sem019(self):
        code, output, _ = run(str(EXAMPLES / "benign-response.xml"),
                              "--audience", "https://other.example/metadata")
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertIn("SEM019", output)

    def test_max_bytes_refuses_a_large_document(self):
        code, output, _ = run(str(EXAMPLES / "benign-response.xml"), "--max-bytes", "100")
        self.assertEqual(EXIT_REFUSED, code)
        self.assertIn("XML006", output)

    def test_no_base64_mode_refuses_encoded_input(self):
        import base64

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "response.b64"
            path.write_bytes(base64.b64encode((EXAMPLES / "benign-response.xml").read_bytes()))
            code, output, _ = run(str(path), "--no-base64")
        self.assertEqual(EXIT_REFUSED, code)
        self.assertIn("XML008", output)

    def test_now_option_changes_certificate_validity(self):
        _, output, _ = run(str(DATA / "expired-certificate.xml"), "--now", "2009-01-01",
                           "--fail-on", "never")
        self.assertNotIn("CRY008", output)
        _, later, _ = run(str(DATA / "expired-certificate.xml"), "--now", "2026-01-01",
                          "--fail-on", "never")
        self.assertIn("CRY008", later)


class Generation(unittest.TestCase):
    def test_generate_writes_the_assertion_signed_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            code, output, _ = run("--generate", str(EXAMPLES / "benign-response.xml"),
                                  "--out", directory)
            written = sorted(path.name for path in Path(directory).iterdir())
        self.assertEqual(EXIT_CLEAN, code)
        self.assertEqual(6, len(written))
        self.assertIn("xsw-03-forged-assertion-first.xml", written)
        self.assertIn("wrote", output)

    def test_generate_writes_the_response_signed_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            run("--generate", str(EXAMPLES / "benign-response-signed.xml"), "--out", directory)
            written = sorted(path.name for path in Path(directory).iterdir())
        self.assertEqual(["xsw-01-signed-response-in-signature.xml",
                          "xsw-02-signed-response-beside-signature.xml"], written)

    def test_generated_file_matches_the_committed_example(self):
        with tempfile.TemporaryDirectory() as directory:
            run("--generate", str(EXAMPLES / "benign-response.xml"), "--out", directory,
                "--variant", "7")
            produced = (Path(directory) / "xsw-07-assertion-in-extensions.xml").read_text()
        self.assertEqual((EXAMPLES / "xsw-07-assertion-in-extensions.xml").read_text(), produced)

    def test_generate_single_variant_to_stdout(self):
        code, output, _ = run("--generate", str(EXAMPLES / "benign-response.xml"),
                              "--variant", "4", "--stdout")
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("FOR AUTHORISED TESTING ONLY", output)
        self.assertIn("xsw-04-signed-assertion-nested.xml", output)

    def test_generate_rejects_an_inapplicable_variant(self):
        code, _, err = run("--generate", str(EXAMPLES / "benign-response.xml"),
                           "--variant", "1", "--stdout")
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("needs a document whose signature covers the response", err)

    def test_generate_rejects_an_unknown_variant(self):
        code, _, err = run("--generate", str(EXAMPLES / "benign-response.xml"),
                           "--variant", "99", "--stdout")
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("unknown variant", err)

    def test_generate_rejects_an_unsigned_document(self):
        code, _, err = run("--generate", str(DATA / "unsigned-response.xml"), "--stdout")
        self.assertEqual(EXIT_USAGE, code)
        self.assertIn("exactly one ds:Signature", err)

    def test_generated_documents_are_detected_by_the_linter(self):
        with tempfile.TemporaryDirectory() as directory:
            run("--generate", str(EXAMPLES / "benign-response.xml"), "--out", directory)
            for path in sorted(Path(directory).iterdir()):
                with self.subTest(fixture=path.name):
                    code, output, _ = run(str(path))
                    self.assertEqual(EXIT_FINDINGS, code)
                    number = int(path.name.split("-")[1])
                    self.assertIn(f"XSW{number:03d}", output)


if __name__ == "__main__":
    unittest.main()
