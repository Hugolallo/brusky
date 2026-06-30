"""Select findings, reuse cache, and orchestrate the LLM enrichment.

Runs after the deterministic scan. Picks the findings worth explaining (NEW +
High/Critical by default), reuses cached guidance when a finding's versions are
unchanged, and otherwise gathers real facts (changelog + call sites) and asks
the advisor. Bounded concurrency; every per-finding failure is swallowed so the
report is never broken by the optional layer.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import structlog

from brusky.config import get_settings
from brusky.fixguide.advisor import generate_guidance
from brusky.fixguide.callsites import find_callsites
from brusky.fixguide.changelog import fetch_changelog
from brusky.llm.provider import LLMProvider, get_llm
from brusky.model import Finding, ScanResult, Severity
from brusky.state import State

log = structlog.get_logger()

_CONCURRENCY = 5


def select_findings(result: ScanResult, scope: str, top_n: int) -> list[Finding]:
    """Which findings to enrich, ranked, honoring scope + optional ceiling."""
    if scope == "none":
        return []
    ranked = result.ranked()
    if scope == "all":
        chosen = ranked
    else:  # "auto": newly-actionable, High or above
        chosen = [
            f for f in ranked
            if f.status in ("NEW", "WORSENED") and f.severity >= Severity.HIGH
        ]
    return chosen[:top_n] if top_n > 0 else chosen


async def enrich(
    result: ScanResult,
    target: Path,
    *,
    state: State,
    scope: str = "auto",
    top_n: int = 0,
    llm: LLMProvider | None = None,
    changelog_client: httpx.AsyncClient | None = None,
    token: str | None = None,
) -> int:
    """Attach `FixGuidance` to selected findings in place. Returns the count enriched."""
    targets = select_findings(result, scope, top_n)
    if not targets:
        return 0

    llm = llm or get_llm("fix_guidance", "advisor")
    token = token if token is not None else get_settings().github_token
    owns_client = changelog_client is None
    changelog_client = changelog_client or httpx.AsyncClient(timeout=30.0)
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def worker(finding: Finding) -> bool:
        async with sem:
            return await _enrich_one(
                finding, str(target), state, llm, changelog_client, token
            )

    try:
        results = await asyncio.gather(*(worker(f) for f in targets))
    finally:
        if owns_client:
            await changelog_client.aclose()
    return sum(results)


async def _enrich_one(
    finding: Finding,
    target: str,
    state: State,
    llm: LLMProvider,
    client: httpx.AsyncClient,
    token: str,
) -> bool:
    dep, vuln = finding.dep, finding.vuln
    fixed = vuln.fixed_version or ""

    cached = state.get_guidance(target, finding.key, dep.version, fixed)
    if cached is not None:
        finding.guidance = cached
        return False  # reused, no LLM call

    changelog_text, sources = await fetch_changelog(
        dep.ecosystem, dep.name, dep.version, vuln.fixed_version, client=client, token=token
    )
    callsites = find_callsites(dep.ecosystem, dep.name, Path(target))

    guidance = await generate_guidance(
        finding,
        changelog_text=changelog_text,
        changelog_sources=sources,
        callsites=callsites,
        llm=llm,
    )
    if guidance is None:
        return False

    finding.guidance = guidance
    state.save_guidance(target, finding.key, dep.version, fixed, guidance)
    log.info("fixguide.enriched", finding=finding.key, confidence=guidance.confidence)
    return True
