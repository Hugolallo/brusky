"""End-of-life advisory for Docker base images, backed by endoflife.date.

OSV does not track base-image freshness, so this is a separate advisory driver
(see docs: "the two driver families"). It judges the ResolvedDeps produced by
the Docker collector and emits synthetic Vulnerabilities:

  EOL       (HIGH)    — the image's release cycle no longer receives patches
  UNPINNED  (MEDIUM)  — the image uses a floating `latest` tag

Digest-pinned images are treated as good practice and produce no finding. Images
whose cycle can't be located on endoflife.date are skipped rather than guessed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import httpx
import structlog

from brusky.model import ResolvedDep, Severity, Vulnerability

log = structlog.get_logger()

_API = "https://endoflife.date"
_TIMEOUT = 30.0
_LEADING_VERSION = re.compile(r"^(\d[\d.]*)")

# Docker image name → endoflife.date product slug, where they differ.
# endoflife also 301-redirects most legacy names, which we follow as a fallback.
_PRODUCT_ALIASES = {
    "node": "nodejs",
    "golang": "go",
    "postgres": "postgresql",
    "mongo": "mongodb",
}


class EOLClient:
    def __init__(self, client: httpx.Client | None = None, *, today: str | None = None) -> None:
        self._client = client or httpx.Client(
            base_url=_API, timeout=_TIMEOUT, follow_redirects=True
        )
        self._owns_client = client is None
        self._today = today or datetime.now(UTC).date().isoformat()
        self._product_cache: dict[str, list[dict] | None] = {}

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> EOLClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── Public API ───────────────────────────────────────────────────────────

    def check(self, deps: list[ResolvedDep]) -> dict[str, list[Vulnerability]]:
        result: dict[str, list[Vulnerability]] = {}
        for dep in deps:
            vuln = self._check_one(dep)
            if vuln:
                result[dep.coordinate] = [vuln]
        return result

    # ── Internal ─────────────────────────────────────────────────────────────

    def _check_one(self, dep: ResolvedDep) -> Vulnerability | None:
        if dep.version == "(digest)":
            return None                       # digest-pinned: immutable, good
        if dep.version in ("", "latest"):
            return self._unpinned(dep)

        cycles = self._product(dep.name)
        if not cycles:
            return None                       # unknown product → don't guess
        match = _match_cycle(dep.version, cycles)
        if match is None:
            return None
        return self._eol_finding(dep, match, cycles)

    def _unpinned(self, dep: ResolvedDep) -> Vulnerability:
        return Vulnerability(
            id=f"UNPINNED-{dep.name}",
            summary=(
                f"Base image '{dep.name}' uses a floating tag; pin to a specific "
                "version for reproducible, auditable builds."
            ),
            severity=Severity.MEDIUM,
            references=[f"{_API}/{dep.name}"],
        )

    def _eol_finding(
        self, dep: ResolvedDep, cycle: dict, cycles: list[dict]
    ) -> Vulnerability | None:
        eol = cycle.get("eol")
        is_eol = eol is True or (isinstance(eol, str) and eol <= self._today)
        if not is_eol:
            return None
        when = eol if isinstance(eol, str) else "an unspecified date"
        return Vulnerability(
            id=f"EOL-{dep.name}-{cycle.get('cycle')}",
            summary=(
                f"{dep.name} {cycle.get('cycle')} reached end-of-life on {when} "
                "and no longer receives security updates."
            ),
            severity=Severity.HIGH,
            fixed_version=_latest_supported(cycles, self._today),
            references=[f"{_API}/{dep.name}"],
        )

    def _product(self, product: str) -> list[dict] | None:
        slug = _PRODUCT_ALIASES.get(product, product)
        if slug not in self._product_cache:
            self._product_cache[slug] = self._fetch_product(slug)
        return self._product_cache[slug]

    def _fetch_product(self, product: str) -> list[dict] | None:
        try:
            resp = self._client.get(f"/api/{product}.json")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("eol.fetch_failed", product=product, error=str(exc))
            return None
        data = resp.json()
        return data if isinstance(data, list) else None


def _match_cycle(version: str, cycles: list[dict]) -> dict | None:
    """Find the endoflife cycle for a tag, trying most-specific first.

    Tag '18.20.1' tries '18.20.1', '18.20', '18'; '16-alpine' tries '16'.
    """
    m = _LEADING_VERSION.match(version)
    if not m:
        return None
    parts = m.group(1).rstrip(".").split(".")
    by_cycle = {str(c.get("cycle")): c for c in cycles}
    for i in range(len(parts), 0, -1):
        candidate = ".".join(parts[:i])
        if candidate in by_cycle:
            return by_cycle[candidate]
    return None


def _latest_supported(cycles: list[dict], today: str) -> str | None:
    """The newest cycle that is not yet EOL — the recommended upgrade target."""
    for cycle in cycles:        # endoflife.date lists newest first
        eol = cycle.get("eol")
        if eol is False or (isinstance(eol, str) and eol > today):
            return str(cycle.get("cycle"))
    return None
