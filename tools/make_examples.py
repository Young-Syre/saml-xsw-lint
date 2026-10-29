"""Regenerate every committed fixture.

    python -m tools.make_examples           # write the files
    python -m tools.make_examples --check   # fail if the committed files have drifted

Everything is deterministic: the keys come from fixed seeds, the documents are
serialised by ``saml_xsw_lint.emit``, and the XSW variants are produced by the
tool's own ``--generate`` code path. ``--check`` is what the test suite and CI
use to prove the examples in the repository are the ones this code produces.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from saml_xsw_lint import xsw
from saml_xsw_lint.model import Document
from saml_xsw_lint.safexml import load

from . import samlfixtures, testdata

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
CERTS = EXAMPLES / "certs"
DATA = ROOT / "tests" / "data"

README_NOTE = """\
These files are generated. Do not edit them by hand; run

    python -m tools.make_examples

The two benign responses are fabricated and signed with a key derived from a
published seed (tools/keys.py), so the matching certificate can be committed
while the private key never exists on disk. Every xsw-*.xml file is produced by
this repository's own --generate mode from the benign response above it, which
is why the digest and signature values in them are unchanged: exclusive
canonicalisation of the referenced element does not depend on where that element
sits in the document, and that is precisely why wrapping works.

FOR AUTHORISED TESTING ONLY. The xsw-*.xml documents are attack payloads. Send
them only to systems you own or have written permission to test.
"""


def build() -> dict[Path, str]:
    """Every generated file, keyed by absolute path."""
    files: dict[Path, str] = {}

    for name in samlfixtures.CERTIFICATES:
        files[CERTS / f"{name}.crt"] = samlfixtures.certificate_pem(name)

    benign = samlfixtures.benign_documents()
    for filename, xml in benign.items():
        files[EXAMPLES / filename] = xml
        root, raw, _ = load(xml.encode("utf-8"))
        doc = Document(root=root, raw=raw)
        for generated in xsw.generate(doc, xsw.applicable(doc), source=filename):
            files[EXAMPLES / generated.filename] = generated.xml

    for filename, text in testdata.documents().items():
        files[DATA / filename] = text

    files[EXAMPLES / "README.md"] = README_NOTE
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="compare against the committed files instead of writing")
    args = parser.parse_args(argv)

    files = build()
    if args.check:
        drifted = []
        for path, content in sorted(files.items()):
            if not path.exists():
                drifted.append(f"missing: {path.relative_to(ROOT)}")
            elif path.read_text(encoding="utf-8") != content:
                drifted.append(f"differs: {path.relative_to(ROOT)}")
        for line in drifted:
            print(line)
        print(f"{len(files)} generated file(s), {len(drifted)} drifted")
        return 1 if drifted else 0

    for path, content in sorted(files.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(f"wrote {len(files)} file(s) under {EXAMPLES.name}/ and tests/data/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
