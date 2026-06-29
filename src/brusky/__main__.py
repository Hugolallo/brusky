"""Brusky CLI — a standalone, driver-based dependency security monitor.

    brusky scan [PATH] [--json] [--all] [--only npm,composer]
                       [--no-llm] [--db FILE] [--fail-on SEVERITY]

Designed to be invoked daily from cron/CI. Detection is deterministic and needs
no API key; `--no-llm` is accepted for forward-compatibility with the upcoming
fix-guidance layer.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import structlog

from brusky import report
from brusky.model import ScanResult, Severity
from brusky.scan import run_scan
from brusky.state import State


def _setup_logging(verbose: bool) -> None:
    """Route logs to stderr so stdout carries only the report (JSON stays valid)."""
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.INFO if verbose else logging.WARNING
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="brusky", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a project for vulnerable dependencies.")
    scan.add_argument("path", nargs="?", default=".", help="Project directory (default: .)")
    scan.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    scan.add_argument("--all", action="store_true", help="Show all findings, not just new ones.")
    scan.add_argument("--only", default="", help="Comma-separated ecosystems (e.g. npm,composer).")
    scan.add_argument("--no-llm", action="store_true", help="Skip LLM fix guidance (M3).")
    scan.add_argument("--db", default="", help="State DB path (default: ~/.brusky/state.db).")
    scan.add_argument("--verbose", action="store_true", help="Log progress to stderr.")
    scan.add_argument(
        "--fail-on",
        default="none",
        choices=["none", "low", "medium", "high", "critical"],
        help="Exit non-zero if a NEW finding meets/exceeds this severity (for CI).",
    )

    args = parser.parse_args(argv)
    if args.command == "scan":
        _setup_logging(args.verbose)
        return _cmd_scan(args)
    parser.error(f"unknown command {args.command!r}")
    return 2


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.is_dir():
        print(f"error: not a directory: {target}", file=sys.stderr)
        return 2

    enabled = {e.strip() for e in args.only.split(",") if e.strip()} or None
    state = State(Path(args.db)) if args.db else None

    try:
        result = run_scan(target, enabled=enabled, state=state)
    finally:
        if state is not None:
            state.close()

    output = (
        report.to_json(result)
        if args.json
        else report.to_markdown(result, only_new=not args.all)
    )
    print(output)

    return _exit_code(result, args.fail_on)


def _exit_code(result: ScanResult, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity.parse(fail_on)
    triggered = any(
        f.severity >= threshold and f.status in ("NEW", "WORSENED")
        for f in result.findings
    )
    return 1 if triggered else 0


if __name__ == "__main__":
    raise SystemExit(main())
