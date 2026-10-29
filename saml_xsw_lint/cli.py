"""Command line interface.

Exit codes (also documented in the README):

* ``0`` - the document was analysed and nothing was found at or above the
  ``--fail-on`` threshold.
* ``1`` - findings at or above the threshold.
* ``2`` - the input was refused and never analysed: a DOCTYPE or entity
  construct, not well-formed, too large, or not decodable.
* ``3`` - usage or I/O error (missing file, bad option, unusable input for
  ``--generate``).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import textwrap
from pathlib import Path

from . import __version__, der, xsw
from .checks import Options
from .engine import analyse
from .findings import CATALOGUE, Finding, Severity, sort_findings, specs_in_order
from .model import Document
from .safexml import DEFAULT_MAX_BYTES, Refused, load

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_REFUSED = 2
EXIT_USAGE = 3

PROGRAM = "saml-xsw-lint"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Offline SAML response and XML-signature trust analyser.\n\n"
            "Reads a local SAML Response or Assertion (raw XML, or base64 as it appears in a\n"
            "SAMLResponse form field) and reports structural, canonicalisation, trust and\n"
            "assertion-semantics findings. It never makes a network request, and it is not a\n"
            "signature verifier: it reports whether a document is shaped so that a correct\n"
            "verifier and the application behind it could disagree about what was signed."
        ),
        epilog=textwrap.dedent(
            f"""\
            exit codes:
              {EXIT_CLEAN}  nothing at or above --fail-on
              {EXIT_FINDINGS}  findings at or above --fail-on
              {EXIT_REFUSED}  input refused before analysis (DOCTYPE/entities, malformed, too large)
              {EXIT_USAGE}  usage or I/O error

            examples:
              {PROGRAM} response.xml
              {PROGRAM} --json --cert idp.crt --acs-url https://sp.example/acs response.b64
              {PROGRAM} --generate examples/benign-response.xml --out xsw-variants --variant all
            """
        ),
    )
    parser.add_argument("input", nargs="?", help="SAML Response/Assertion file, or - for stdin")
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")

    decode = parser.add_argument_group("input decoding")
    decode.add_argument("--base64", dest="base64_mode", action="store_const", const="always",
                        default="auto", help="treat the input as base64 (default: auto-detect)")
    decode.add_argument("--no-base64", dest="base64_mode", action="store_const", const="never",
                        help="never base64-decode the input")
    decode.add_argument("--inflate", action="store_true",
                        help="DEFLATE-decompress after base64 (HTTP-Redirect binding)")
    decode.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help=f"refuse input larger than this (default {DEFAULT_MAX_BYTES})")

    context = parser.add_argument_group("deployment context (enables comparison checks)")
    context.add_argument("--cert", metavar="FILE",
                         help="trusted IdP certificate (PEM or DER) to compare against KeyInfo")
    context.add_argument("--acs-url", metavar="URL",
                         help="expected SubjectConfirmationData/@Recipient")
    context.add_argument("--audience", metavar="URI", help="expected saml:Audience value")
    context.add_argument("--max-window", type=int, default=3600, metavar="SECONDS",
                         help="largest acceptable Conditions validity window (default 3600)")
    context.add_argument("--max-session", type=int, default=86400, metavar="SECONDS",
                         help="largest acceptable SessionNotOnOrAfter span (default 86400)")
    context.add_argument("--now", metavar="ISO8601",
                         help="treat this instant as 'now' for certificate validity")

    output = parser.add_argument_group("output")
    output.add_argument("--json", action="store_true", help="machine-readable output")
    output.add_argument("--explain", action="store_true",
                        help="print the mechanism paragraph for each finding")
    output.add_argument("--quiet", action="store_true", help="summary line only")
    output.add_argument("--fail-on", default="medium",
                        choices=["info", "low", "medium", "high", "critical", "never"],
                        help="lowest severity that sets exit code 1 (default medium)")
    output.add_argument("--ignore", metavar="IDS", default="",
                        help="comma-separated finding ids to suppress")
    output.add_argument("--list-checks", action="store_true",
                        help="print the finding catalogue and exit")

    generate = parser.add_argument_group("generation (offline, local)")
    generate.add_argument("--generate", action="store_true",
                          help="emit XSW variant documents built from the input")
    generate.add_argument("--variant", default="all",
                          help="variant numbers to emit, e.g. 3 or 3,5 or all (default all)")
    generate.add_argument("--out", metavar="DIR", help="directory to write variants into")
    generate.add_argument("--stdout", action="store_true",
                          help="write the generated documents to stdout instead of files")
    return parser


def _read_input(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _render_text(findings: list[Finding], *, source: str, notes: list[str], explain: bool,
                 quiet: bool, threshold: Severity | None) -> str:
    lines = [f"{PROGRAM} {__version__} - {source}"]
    for note in notes:
        lines.append(f"note: {note}")
    counts = {severity: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity] += 1
    if not quiet:
        lines.append("")
        if not findings:
            lines.append("no findings")
        for finding in findings:
            lines.append(f"{finding.severity.label.upper():<8} {finding.id}  {finding.name}")
            lines.append(f"         at {finding.where}")
            if finding.detail:
                for chunk in textwrap.wrap(finding.detail, width=92,
                                           initial_indent="         ", subsequent_indent="         "):
                    lines.append(chunk)
            if explain:
                for chunk in textwrap.wrap(finding.spec.mechanism, width=88,
                                           initial_indent="         why: ",
                                           subsequent_indent="              "):
                    lines.append(chunk)
            lines.append("")
    summary = ", ".join(
        f"{counts[severity]} {severity.label}"
        for severity in sorted(Severity, reverse=True)
        if counts[severity]
    )
    lines.append(f"summary: {len(findings)} finding(s)" + (f" - {summary}" if summary else ""))
    if threshold is not None:
        lines.append(f"fail-on: {threshold.label}")
    return "\n".join(lines).rstrip() + "\n"


def _render_json(findings: list[Finding], *, source: str, notes: list[str], refused: bool,
                 threshold: Severity | None, exit_code: int) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.label] = counts.get(finding.severity.label, 0) + 1
    payload = {
        "tool": PROGRAM,
        "version": __version__,
        "input": source,
        "notes": notes,
        "refused": refused,
        "fail_on": threshold.label if threshold is not None else "never",
        "summary": {"total": len(findings), "by_severity": counts},
        "findings": [finding.to_dict() for finding in findings],
        "exit_code": exit_code,
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


def _list_checks(as_json: bool) -> str:
    specs = specs_in_order()
    if as_json:
        return json.dumps(
            [
                {"id": s.id, "name": s.name, "severity": s.severity.label,
                 "group": s.group, "mechanism": s.mechanism}
                for s in specs
            ],
            indent=2,
        ) + "\n"
    lines = [f"{PROGRAM} {__version__} - {len(specs)} checks"]
    group = None
    for spec in specs:
        if spec.group != group:
            group = spec.group
            lines.append("")
            lines.append(f"[{group}]")
        lines.append(f"  {spec.id}  {spec.severity.label:<8} {spec.name}")
    return "\n".join(lines) + "\n"


def _parse_variants(text: str, available: list[xsw.Variant]) -> list[xsw.Variant]:
    if text.strip().lower() == "all":
        return available
    chosen = []
    for piece in text.split(","):
        piece = piece.strip()
        if not piece.isdigit() or int(piece) not in xsw.BY_NUMBER:
            raise ValueError(f"unknown variant {piece!r}; known variants are 1-8")
        chosen.append(xsw.BY_NUMBER[int(piece)])
    return chosen


def _run_generate(args, doc: Document, source: str, out, err) -> int:
    try:
        available = xsw.applicable(doc)
        variants = _parse_variants(args.variant, available)
        produced = xsw.generate(doc, variants, source=Path(source).name)
    except (xsw.GenerationError, ValueError) as exc:
        print(f"{PROGRAM}: cannot generate: {exc}", file=err)
        return EXIT_USAGE

    if args.stdout or not args.out:
        for item in produced:
            out.write(f"<!-- {item.filename} -->\n")
            out.write(item.xml)
        return EXIT_CLEAN

    directory = Path(args.out)
    directory.mkdir(parents=True, exist_ok=True)
    for item in produced:
        (directory / item.filename).write_text(item.xml, encoding="utf-8")
        out.write(f"wrote {directory / item.filename}  (variant {item.variant.number}, "
                  f"expects {item.variant.finding_id})\n")
    return EXIT_CLEAN


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = out or sys.stdout
    err = err or sys.stderr

    if args.list_checks:
        out.write(_list_checks(args.json))
        return EXIT_CLEAN
    if not args.input:
        parser.print_usage(err)
        print(f"{PROGRAM}: an input file is required (or - for stdin)", file=err)
        return EXIT_USAGE

    try:
        raw = _read_input(args.input)
    except OSError as exc:
        print(f"{PROGRAM}: cannot read {args.input}: {exc.strerror}", file=err)
        return EXIT_USAGE

    threshold = None if args.fail_on == "never" else Severity.parse(args.fail_on)
    ignored = {piece.strip().upper() for piece in args.ignore.split(",") if piece.strip()}
    unknown = ignored - set(CATALOGUE)
    if unknown:
        print(f"{PROGRAM}: unknown finding id(s) in --ignore: {', '.join(sorted(unknown))}", file=err)
        return EXIT_USAGE

    try:
        root, data, notes = load(raw, base64_mode=args.base64_mode, inflate=args.inflate,
                                 max_bytes=args.max_bytes)
    except Refused as refusal:
        findings = sort_findings([f for f in refusal.findings if f.id not in ignored])
        if args.json:
            out.write(_render_json(findings, source=args.input, notes=[], refused=True,
                                   threshold=threshold, exit_code=EXIT_REFUSED))
        else:
            out.write(_render_text(findings, source=args.input,
                                   notes=["input refused before parsing; nothing was expanded"],
                                   explain=args.explain, quiet=args.quiet, threshold=threshold))
        return EXIT_REFUSED

    doc = Document(root=root, raw=data, notes=notes)

    if args.generate:
        return _run_generate(args, doc, args.input, out, err)

    cert_der = None
    if args.cert:
        try:
            cert_der = der.load_certificate_file(Path(args.cert).read_bytes())
            der.Certificate.from_der(cert_der)
        except OSError as exc:
            print(f"{PROGRAM}: cannot read {args.cert}: {exc.strerror}", file=err)
            return EXIT_USAGE
        except (der.DERError, ValueError) as exc:
            print(f"{PROGRAM}: --cert is not a certificate this tool can parse: {exc}", file=err)
            return EXIT_USAGE

    now = dt.datetime.now(dt.timezone.utc)
    if args.now:
        try:
            parsed = dt.datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        except ValueError:
            print(f"{PROGRAM}: --now is not an ISO 8601 instant: {args.now!r}", file=err)
            return EXIT_USAGE
        now = parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)

    options = Options(
        cert_der=cert_der,
        acs_url=args.acs_url,
        audience=args.audience,
        max_window_seconds=args.max_window,
        max_session_seconds=args.max_session,
        now=now,
    )
    findings = [f for f in analyse(doc, options) if f.id not in ignored]
    exit_code = EXIT_CLEAN
    if threshold is not None and any(f.severity >= threshold for f in findings):
        exit_code = EXIT_FINDINGS

    if args.json:
        out.write(_render_json(findings, source=args.input, notes=notes, refused=False,
                               threshold=threshold, exit_code=exit_code))
    else:
        out.write(_render_text(findings, source=args.input, notes=notes, explain=args.explain,
                               quiet=args.quiet, threshold=threshold))
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
