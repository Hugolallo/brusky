"""Core data model for the dependency security monitor.

These dataclasses are the contract between the deterministic pipeline stages:

    collectors  -> list[ResolvedDep]
    advisories  -> list[Vulnerability]   (matched to deps)
    prioritize  -> list[Finding]         (dep + vuln + rank + diff status)
    report      <- ScanResult

Everything here is plain data — no I/O, no LLM. The model is designed so a full
vulnerability report can be produced with zero network calls beyond OSV.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity. Higher = worse, so findings sort naturally descending."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | None) -> Severity:
        if not value:
            return cls.UNKNOWN
        return _SEVERITY_NAMES.get(value.strip().upper(), cls.UNKNOWN)

    @property
    def label(self) -> str:
        return self.name.capitalize()


# GHSA labels deviate from CVSS naming ("MODERATE" == MEDIUM), so alias them.
_SEVERITY_NAMES: dict[str, Severity] = {s.name: s for s in Severity}
_SEVERITY_NAMES["MODERATE"] = Severity.MEDIUM


@dataclass(frozen=True)
class ResolvedDep:
    """A single dependency resolved to a concrete installed version.

    Always sourced from a *lockfile* (composer.lock / package-lock.json), never
    from a manifest range — `version` is exact. `direct` distinguishes top-level
    deps from transitive ones; `dev` marks dev-only deps for deprioritization.
    """

    ecosystem: str        # OSV ecosystem name: "npm", "Packagist", "Docker", ...
    name: str
    version: str
    direct: bool = False
    dev: bool = False
    source: str = ""      # relative path of the lockfile this came from

    @property
    def coordinate(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass
class Vulnerability:
    """A vulnerability advisory from OSV, normalized to what the report needs."""

    id: str                                   # primary id, e.g. GHSA-xxxx or CVE-xxxx
    summary: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = None
    fixed_version: str | None = None          # first safe version (the upgrade target)
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def advisory_url(self) -> str:
        for ref in self.references:
            if "github.com/advisories" in ref or "/GHSA-" in ref:
                return ref
        return f"https://osv.dev/vulnerability/{self.id}"


@dataclass
class Finding:
    """A vulnerability matched to an installed dependency, plus rank + diff state."""

    dep: ResolvedDep
    vuln: Vulnerability
    reachable: bool | None = None             # None = not analyzed yet
    status: str = "EXISTING"                  # NEW | EXISTING | WORSENED
    first_seen: str = ""                       # ISO timestamp, filled from state

    @property
    def key(self) -> str:
        """Stable identity for dedup + day-over-day diffing.

        Intentionally excludes version so a finding that persists across a
        version bump still matches; the version lives on `dep` for display.
        """
        return f"{self.dep.ecosystem}:{self.dep.name}:{self.vuln.id}"

    @property
    def severity(self) -> Severity:
        return self.vuln.severity

    def sort_key(self) -> tuple:
        """Descending severity, then direct/runtime deps before transitive/dev."""
        return (
            int(self.vuln.severity),
            self.dep.direct,
            not self.dep.dev,
            self.reachable is True,
        )


@dataclass
class ScanResult:
    """Everything one scan produces — the input to the report renderer."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    scanned_deps: int = 0
    ecosystems: list[str] = field(default_factory=list)
    timestamp: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def new_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status in ("NEW", "WORSENED")]

    def ranked(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key(), reverse=True)
