"""The deterministic scan pipeline: collect → match → diff → result.

This is the heart of the monitor and runs with zero LLM and zero infra. The
optional fix-guidance step (LLM) is layered on by the CLI *after* this returns,
so a complete vulnerability report is always available even with no API key.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import structlog

from brusky import collectors
from brusky.advisories import OSVClient
from brusky.model import ScanResult
from brusky.prioritize import assemble
from brusky.state import State

log = structlog.get_logger()


def run_scan(
    target: Path,
    *,
    enabled: set[str] | None = None,
    state: State | None = None,
    osv: OSVClient | None = None,
) -> ScanResult:
    """Scan `target` and return a diffed, ranked ScanResult.

    `enabled` filters which ecosystem collectors run (None = all detected).
    `state` and `osv` are injectable for testing; created/closed here otherwise.
    """
    target = target.resolve()
    now = datetime.now(UTC).isoformat(timespec="seconds")
    result = ScanResult(target=str(target), timestamp=now)

    active = collectors.active_collectors(target, enabled)
    if not active:
        result.errors.append("No supported lockfiles found (composer.lock / package-lock.json).")
        return result
    result.ecosystems = [c.name for c in active]

    deps = []
    for collector in active:
        found = collector.collect(target)
        log.info("scan.collected", ecosystem=collector.name, count=len(found))
        deps.extend(found)
    result.scanned_deps = len(deps)

    if not deps:
        return result

    owns_osv = osv is None
    osv = osv or OSVClient()
    try:
        vuln_map = osv.find_vulnerabilities(deps)
    finally:
        if owns_osv:
            osv.close()

    result.findings = assemble(deps, vuln_map)

    owns_state = state is None
    state = state or State()
    try:
        state.classify(str(target), result.findings, now)
        state.record(str(target), result.findings, now)
    finally:
        if owns_state:
            state.close()

    return result
