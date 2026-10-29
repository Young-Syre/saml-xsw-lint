"""Run every check against one document."""

from __future__ import annotations

from . import checks, xsw
from .findings import Finding, sort_findings
from .model import Document

CHECKS = (
    checks.check_structure,
    xsw.detect,
    checks.check_transforms,
    checks.check_crypto,
    checks.check_semantics,
)


def analyse(doc: Document, options: checks.Options | None = None) -> list[Finding]:
    """Every finding for ``doc``, highest severity first."""
    opts = options or checks.Options()
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(doc, opts))
    return sort_findings(findings)
