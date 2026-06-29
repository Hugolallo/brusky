"""Assemble Findings from resolved deps + matched vulnerabilities.

Pairs each (dep, vuln) into a Finding. Ranking lives on the model
(`Finding.sort_key`, `ScanResult.ranked`); day-over-day diffing lives in
`state.State`. Reachability tagging is a no-op in M1 (left as None) and is
filled in by a later milestone.
"""

from __future__ import annotations

from brusky.model import Finding, ResolvedDep, Vulnerability


def assemble(deps: list[ResolvedDep], vuln_map: dict[str, list[Vulnerability]]) -> list[Finding]:
    findings: list[Finding] = []
    for dep in deps:
        for vuln in vuln_map.get(dep.coordinate, []):
            findings.append(Finding(dep=dep, vuln=vuln))
    return findings
