"""OSV.dev advisory client — the single source of vulnerability truth.

Two-step protocol:
  1. POST /v1/querybatch  — cheap batch lookup of (ecosystem, name, version)
     tuples; returns only vulnerability IDs per query.
  2. GET  /v1/vulns/{id}  — fetch full details (severity, fixed version,
     references) for each *unique* id, cached so shared vulns are fetched once.

Deterministic and self-contained: given the same lockfile + OSV state, it
returns the same findings. No LLM, no toolchain.
"""

from __future__ import annotations

import httpx
import structlog

from brusky.model import ResolvedDep, Severity, Vulnerability

log = structlog.get_logger()

_API = "https://api.osv.dev"
_BATCH_LIMIT = 500          # OSV accepts up to 1000 queries per batch; stay conservative
_TIMEOUT = 30.0


class OSVClient:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(base_url=_API, timeout=_TIMEOUT)
        self._owns_client = client is None
        self._detail_cache: dict[str, Vulnerability | None] = {}

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> OSVClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── Public API ───────────────────────────────────────────────────────────

    def find_vulnerabilities(self, deps: list[ResolvedDep]) -> dict[str, list[Vulnerability]]:
        """Map each dep coordinate -> its vulnerabilities (empty list if clean)."""
        result: dict[str, list[Vulnerability]] = {}
        for chunk in _chunk(deps, _BATCH_LIMIT):
            ids_per_dep = self._querybatch(chunk)
            for dep, vuln_ids in zip(chunk, ids_per_dep):
                vulns = [v for vid in vuln_ids if (v := self._detail(vid, dep))]
                if vulns:
                    result[dep.coordinate] = vulns
        return result

    # ── Internal ─────────────────────────────────────────────────────────────

    def _querybatch(self, deps: list[ResolvedDep]) -> list[list[str]]:
        payload = {
            "queries": [
                {"package": {"ecosystem": d.ecosystem, "name": d.name}, "version": d.version}
                for d in deps
            ]
        }
        try:
            resp = self._client.post("/v1/querybatch", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("osv.querybatch_failed", error=str(exc), count=len(deps))
            return [[] for _ in deps]

        results = resp.json().get("results", [])
        out: list[list[str]] = []
        for entry in results:
            out.append([v["id"] for v in entry.get("vulns", []) if "id" in v])
        # OSV returns one result per query, in order; pad if truncated.
        while len(out) < len(deps):
            out.append([])
        return out

    def _detail(self, vuln_id: str, dep: ResolvedDep) -> Vulnerability | None:
        if vuln_id not in self._detail_cache:
            self._detail_cache[vuln_id] = self._fetch_detail(vuln_id)
        base = self._detail_cache[vuln_id]
        if base is None:
            return None
        # fixed_version is package-specific, so resolve it per dep.
        return Vulnerability(
            id=base.id,
            summary=base.summary,
            severity=base.severity,
            cvss_score=base.cvss_score,
            fixed_version=self._fixed_version(base, dep) or base.fixed_version,
            aliases=base.aliases,
            references=base.references,
        )

    def _fetch_detail(self, vuln_id: str) -> Vulnerability | None:
        try:
            resp = self._client.get(f"/v1/vulns/{vuln_id}")
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("osv.detail_failed", id=vuln_id, error=str(exc))
            return None
        return self._parse(resp.json())

    @staticmethod
    def _parse(data: dict) -> Vulnerability:
        severity, score = _severity_from(data)
        refs = [r["url"] for r in data.get("references", []) if r.get("url")]
        vuln = Vulnerability(
            id=data.get("id", "UNKNOWN"),
            summary=data.get("summary") or data.get("details", "")[:200],
            severity=severity,
            cvss_score=score,
            aliases=data.get("aliases", []),
            references=refs,
        )
        # store full data for per-dep fixed-version resolution
        vuln._affected = data.get("affected", [])  # type: ignore[attr-defined]
        return vuln

    @staticmethod
    def _fixed_version(vuln: Vulnerability, dep: ResolvedDep) -> str | None:
        affected = getattr(vuln, "_affected", [])
        for entry in affected:
            pkg = entry.get("package", {})
            if pkg.get("name") != dep.name or pkg.get("ecosystem") != dep.ecosystem:
                continue
            fixed: list[str] = []
            for rng in entry.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed.append(event["fixed"])
            if fixed:
                return fixed[-1]   # last published fix is the safest known target
        return None


def _severity_from(data: dict) -> tuple[Severity, float | None]:
    """Resolve severity, preferring a numeric CVSS score, then a GHSA label.

    OSV stores CVSS as a *vector* string (not a number) under `severity`, so we
    compute the base score from the vector. A computed score is preferred over
    the coarse GHSA label because it also feeds `--fail-on` thresholds.
    """
    score: float | None = None
    for sev in data.get("severity", []):
        raw = sev.get("score", "")
        try:
            score = float(raw)            # rare: a bare numeric base score
        except (TypeError, ValueError):
            score = _cvss_base_score(raw)  # the common case: a CVSS vector
        if score is not None:
            break

    if score is not None:
        return _bucket(score), score

    label = data.get("database_specific", {}).get("severity")
    return Severity.parse(label), None


# ── CVSS v3.x base score (FIRST.org specification) ───────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _cvss_base_score(vector: str) -> float | None:
    """Compute a CVSS v3.0/3.1 base score from a vector string, or None."""
    if not vector.startswith("CVSS:3"):
        return None
    m = {p.split(":")[0]: p.split(":")[1] for p in vector.split("/") if ":" in p}
    try:
        scope_changed = m["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = (
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
            if scope_changed
            else 6.42 * iss
        )
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    total = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(total, 10.0))


def _roundup(value: float) -> float:
    """CVSS-specific round-up to one decimal place."""
    import math

    return math.ceil(value * 10) / 10


def _bucket(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN


def _chunk(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]
