"""The tool must not be able to make a network request.

Rather than trusting a promise in the README, this walks the package's own
syntax tree and asserts that every import is on a short allowlist. A metadata
fetch, a key fetch or an OCSP lookup would have to import something, and
anything new has to be added here deliberately.
"""

from __future__ import annotations

import ast
import tokenize
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "saml_xsw_lint"

ALLOWED_IMPORTS = {
    "argparse",
    "base64",
    "binascii",
    "copy",
    "dataclasses",
    "datetime",
    "enum",
    "hashlib",
    "json",
    "pathlib",
    "re",
    "sys",
    "textwrap",
    "xml.etree.ElementTree",
    "zlib",
    "__future__",
}

FORBIDDEN_IMPORTS = {
    "asyncio", "ftplib", "http", "httpx", "imaplib", "lxml", "nntplib", "poplib",
    "requests", "select", "selectors", "smtplib", "socket", "socketserver", "ssl",
    "subprocess", "telnetlib", "urllib", "urllib3", "webbrowser", "xmlrpc",
    "xml.dom", "xml.dom.minidom", "xml.dom.pulldom", "xml.sax",
}

FORBIDDEN_SOURCE_FRAGMENTS = (
    "urlopen", "socket.", "requests.", "http.client", "HTTPConnection",
    "minidom", "resolve_entities", "load_dtd",
)


def package_modules() -> list[Path]:
    return sorted(PACKAGE.rglob("*.py"))


def code_only(path: Path) -> str:
    """The module with comments and string literals removed.

    Needed because this package's docstrings name the parsers it refuses to use,
    and a naive substring search would flag its own documentation.
    """
    pieces = []
    with path.open("rb") as handle:
        for token in tokenize.tokenize(handle.readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            pieces.append(token.string)
    return " ".join(pieces)


def imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import inside the package
                continue
            module = node.module or ""
            if module == "xml.etree":
                names.update(f"xml.etree.{alias.name}" for alias in node.names)
            else:
                names.add(module)
    return names


class Imports(unittest.TestCase):
    def test_package_has_modules(self):
        self.assertGreaterEqual(len(package_modules()), 8)

    def test_every_import_is_on_the_allowlist(self):
        for path in package_modules():
            with self.subTest(module=path.name):
                unexpected = imported_names(path) - ALLOWED_IMPORTS
                self.assertEqual(set(), unexpected,
                                 f"{path.name} imports {sorted(unexpected)}")

    def test_no_networking_or_resolving_parser_is_imported(self):
        for path in package_modules():
            with self.subTest(module=path.name):
                self.assertEqual(set(), imported_names(path) & FORBIDDEN_IMPORTS)

    def test_no_networking_calls_appear_in_the_code(self):
        for path in package_modules():
            code = code_only(path)
            for fragment in FORBIDDEN_SOURCE_FRAGMENTS:
                with self.subTest(module=path.name, fragment=fragment):
                    self.assertFalse(fragment in code,
                                     f"{path.name} contains {fragment!r} outside a docstring")

    def test_only_elementtree_is_used_to_parse(self):
        for path in package_modules():
            code = code_only(path)
            with self.subTest(module=path.name):
                for fragment in ("xml.sax", "xml.dom", "lxml"):
                    self.assertFalse(fragment in code, f"{path.name} uses {fragment}")

    def test_the_allowlist_itself_is_minimal(self):
        # An unused allowlist entry would quietly widen the permitted surface.
        used: set[str] = set()
        for path in package_modules():
            used |= imported_names(path)
        self.assertEqual(set(), used - ALLOWED_IMPORTS, "an import is not on the allowlist")
        self.assertEqual(set(), ALLOWED_IMPORTS - used, "an allowlist entry is unused")


class KeyFetchingReporting(unittest.TestCase):
    def test_url_in_keyinfo_is_reported_and_not_fetched(self):
        from .helpers import DATA, findings

        url_findings = [f for f in findings(DATA / "keyinfo-retrieval-url.xml") if f.id == "CRY011"]
        self.assertEqual(2, len(url_findings))
        details = " ".join(f.detail for f in url_findings)
        self.assertIn("169.254.169.254", details)
        self.assertIn("not fetched", details)


if __name__ == "__main__":
    unittest.main()
