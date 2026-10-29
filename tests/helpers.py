"""Shared test helpers."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from saml_xsw_lint.checks import Options
from saml_xsw_lint.engine import analyse
from saml_xsw_lint.model import Document
from saml_xsw_lint.safexml import Refused, load

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data"
EXAMPLES = ROOT / "examples"
CERTS = EXAMPLES / "certs"

#: Fixed instant inside the fixture certificates' validity window, so that
#: certificate expiry findings do not depend on the day the tests are run.
NOW = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)


def document(path: Path) -> Document:
    root, raw, notes = load(path.read_bytes())
    return Document(root=root, raw=raw, notes=notes)


def findings(path: Path, **options) -> list:
    options.setdefault("now", NOW)
    return analyse(document(path), Options(**options))


def finding_ids(path: Path, **options) -> set[str]:
    return {finding.id for finding in findings(path, **options)}


def refusal_ids(path: Path) -> set[str]:
    try:
        load(path.read_bytes())
    except Refused as refusal:
        return {finding.id for finding in refusal.findings}
    raise AssertionError(f"{path.name} was not refused")


def read_cert(name: str) -> bytes:
    from saml_xsw_lint.der import load_certificate_file

    return load_certificate_file((CERTS / f"{name}.crt").read_bytes())
