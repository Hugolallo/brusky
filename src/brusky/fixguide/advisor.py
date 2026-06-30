"""Turn (finding + advisory + changelog + call sites) into structured guidance.

A single LLM call produces both the explainer (why it's broken, impact, severity
rationale) and the upgrade guidance (what to change). The model is fed real
facts and constrained to them: it may only cite breaking changes present in the
supplied changelog and only reference call sites that were actually found.
Output is parsed into a `FixGuidance`; anything the model invents beyond the
provided call sites is dropped.
"""

from __future__ import annotations

import json

import structlog

from brusky.llm.provider import LLMProvider
from brusky.model import Finding, FixGuidance

log = structlog.get_logger()

_SYSTEM = (
    "You are a precise software-security assistant helping a developer understand "
    "and fix a vulnerable dependency. Explain clearly and never overstate. You may "
    "ONLY cite breaking changes that appear in the provided changelog, and ONLY "
    "reference code locations from the provided call sites. If the changelog or "
    "call sites are missing, say so and lower your confidence. Respond with a "
    "single JSON object and nothing else."
)

_SCHEMA_HINT = """Return JSON with exactly these keys:
{
  "why_vulnerable": "1-3 sentences on the actual flaw",
  "impact": "what an attacker gains / what is at risk",
  "severity_rationale": "why this severity, in plain terms",
  "upgrade_summary": "the concrete upgrade move",
  "breaking_changes": ["only items present in the changelog; [] if none/unknown"],
  "code_touchpoints": [{"file": "...", "line": 0, "note": "what to check/change"}],
  "effort": "trivial | moderate | significant",
  "confidence": "high | medium | low"
}"""


async def generate_guidance(
    finding: Finding,
    *,
    changelog_text: str,
    changelog_sources: list[str],
    callsites: list[dict],
    llm: LLMProvider,
) -> FixGuidance | None:
    prompt = _build_prompt(finding, changelog_text, callsites)
    try:
        resp = await llm.complete([{"role": "user", "content": prompt}], system=_SYSTEM)
    except Exception as exc:  # noqa: BLE001 — any LLM failure must not break the report
        log.warning("advisor.llm_failed", finding=finding.key, error=str(exc))
        return None

    data = _parse_json(resp.content)
    if data is None:
        log.warning("advisor.parse_failed", finding=finding.key)
        return None

    allowed = {(c["file"], c["line"]) for c in callsites}
    touchpoints = [
        t for t in _as_list(data.get("code_touchpoints"))
        if isinstance(t, dict) and (t.get("file"), t.get("line")) in allowed
    ]
    sources = _dedupe([finding.vuln.advisory_url, *changelog_sources])

    return FixGuidance(
        why_vulnerable=str(data.get("why_vulnerable", "")),
        impact=str(data.get("impact", "")),
        severity_rationale=str(data.get("severity_rationale", "")),
        upgrade_summary=str(data.get("upgrade_summary", "")),
        breaking_changes=[str(b) for b in _as_list(data.get("breaking_changes"))],
        code_touchpoints=touchpoints,
        effort=str(data.get("effort", "")),
        confidence=str(data.get("confidence", "")),
        sources=sources,
        model=resp.model,
    )


def _build_prompt(finding: Finding, changelog_text: str, callsites: list[dict]) -> str:
    dep, vuln = finding.dep, finding.vuln
    kind = "direct" if dep.direct else "transitive"
    if dep.dev:
        kind += ", dev-only"
    sites = (
        "\n".join(f"- {c['file']}:{c['line']}  {c['text']}" for c in callsites)
        if callsites
        else "(none found in this repo)"
    )
    transitive_note = (
        ""
        if dep.direct
        else (
            "\nNOTE: this is a transitive dependency — the fix is usually to bump the "
            "parent package or add an override/constraint, not to edit application code."
        )
    )
    return f"""A dependency scan found a vulnerability. Produce guidance.

PACKAGE: {dep.name} ({dep.ecosystem}), installed {dep.version}, {kind}
FIXED VERSION: {vuln.fixed_version or "unknown"}
SEVERITY: {vuln.severity.label}
ADVISORY ({vuln.id}): {vuln.summary}{transitive_note}

CHANGELOG (installed -> fixed):
{changelog_text or "(no changelog available)"}

CALL SITES in this repo:
{sites}

{_SCHEMA_HINT}"""


def _parse_json(content: str) -> dict | None:
    start, end = content.find("{"), content.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        data = json.loads(content[start:end + 1])
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for it in items:
        if it and it not in seen:
            seen.add(it)
            out.append(it)
    return out
