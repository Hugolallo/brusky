"""Assemble Findings from resolved deps + matched vulnerabilities.

Pairs each (dep, vuln) into a Finding and applies a light reachability tag for
noise control. Ranking lives on the model (`Finding.sort_key`,
`ScanResult.ranked`); day-over-day diffing lives in `state.State`.
"""

from __future__ import annotations

from brusky.model import Finding, ResolvedDep, Vulnerability


def _reachable(dep: ResolvedDep) -> bool:
    """A coarse but defensible reachability signal for deprioritizing noise.

    Dev-only dependencies don't ship to production, so an attacker can't reach
    them at runtime — they're deprioritized. Everything that ships (runtime
    packages, transitive deps, base images) is treated as reachable.
    """
    return not dep.dev


def assemble(deps: list[ResolvedDep], vuln_map: dict[str, list[Vulnerability]]) -> list[Finding]:
    findings: list[Finding] = []
    for dep in deps:
        for vuln in vuln_map.get(dep.coordinate, []):
            findings.append(Finding(dep=dep, vuln=vuln, reachable=_reachable(dep)))
    return findings
