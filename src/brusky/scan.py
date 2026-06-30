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
from brusky.advisories import EOLClient, OSVClient
from brusky.model import ResolvedDep, ScanResult, Vulnerability
from brusky.prioritize import assemble
from brusky.state import State

log = structlog.get_logger()

# Which advisory driver judges which ecosystem.
_OSV_ECOSYSTEMS = {"npm", "Packagist"}
_EOL_ECOSYSTEMS = {"Docker"}


def run_scan(
    target: Path,
    *,
    enabled: set[str] | None = None,
    state: State | None = None,
    osv: OSVClient | None = None,
    eol: EOLClient | None = None,
) -> ScanResult:
    """Scan `target` and return a diffed, ranked ScanResult.

    `enabled` filters which ecosystem collectors run (None = all detected).
    `state`, `osv`, and `eol` are injectable for testing; created/closed here
    otherwise.
    """
    target = target.resolve()
    now = datetime.now(UTC).isoformat(timespec="seconds")
    result = ScanResult(target=str(target), timestamp=now)

    active = collectors.active_collectors(target, enabled)
    if not active:
        result.errors.append(
            "No supported manifests found (composer.lock / package-lock.json / Dockerfile)."
        )
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

    vuln_map = _match_advisories(deps, osv, eol)
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


def _match_advisories(
    deps: list[ResolvedDep],
    osv: OSVClient | None,
    eol: EOLClient | None,
) -> dict[str, list[Vulnerability]]:
    """Route each ecosystem to its advisory driver and merge the results.

    OSV.dev judges package ecosystems; endoflife.date judges Docker base images.
    Clients are created on demand only when there are deps that need them, so a
    project with no Dockerfile never touches endoflife.date (and vice versa).
    """
    osv_deps = [d for d in deps if d.ecosystem in _OSV_ECOSYSTEMS]
    eol_deps = [d for d in deps if d.ecosystem in _EOL_ECOSYSTEMS]
    vuln_map: dict[str, list[Vulnerability]] = {}

    if osv_deps:
        owns = osv is None
        osv = osv or OSVClient()
        try:
            vuln_map.update(osv.find_vulnerabilities(osv_deps))
        finally:
            if owns:
                osv.close()

    if eol_deps:
        owns = eol is None
        eol = eol or EOLClient()
        try:
            vuln_map.update(eol.check(eol_deps))
        finally:
            if owns:
                eol.close()

    return vuln_map
