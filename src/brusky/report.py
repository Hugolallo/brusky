"""Render a ScanResult as Markdown (human) or JSON (machine).

Markdown leads with NEW/worsened findings (the point of a daily run) and keeps
the full backlog in a collapsed section to control alert fatigue. JSON is the
complete, stable structure for CI consumption.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from brusky.htmlreport import to_html
from brusky.model import Finding, ScanResult, Severity

__all__ = ["to_html", "to_json", "to_markdown"]

_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "⚪",
    Severity.UNKNOWN: "❔",
}


def to_json(result: ScanResult) -> str:
    payload = {
        "target": result.target,
        "timestamp": result.timestamp,
        "scanned_deps": result.scanned_deps,
        "ecosystems": result.ecosystems,
        "errors": result.errors,
        "summary": _counts(result.findings),
        "findings": [_finding_dict(f) for f in result.ranked()],
    }
    return json.dumps(payload, indent=2)


def to_markdown(result: ScanResult, *, only_new: bool = True) -> str:
    ranked = result.ranked()
    new = [f for f in ranked if f.status in ("NEW", "WORSENED")]
    counts = _counts(ranked)

    lines: list[str] = []
    lines.append("# Brusky Dependency Security Report")
    lines.append("")
    lines.append(f"**Target:** `{result.target}`  ")
    lines.append(f"**Scanned:** {result.timestamp}  ")
    lines.append(
        f"**Dependencies:** {result.scanned_deps} across "
        f"{', '.join(result.ecosystems) or 'none'}  "
    )
    lines.append(
        "**Findings:** "
        + _summary_line(counts)
        + f" — {len(new)} new/worsened since last scan"
    )
    lines.append("")

    if result.errors:
        lines.append("> ⚠️ " + "; ".join(result.errors))
        lines.append("")

    headline = new if only_new else ranked
    title = "New & worsened findings" if only_new else "All findings"

    if not headline:
        lines.append(f"✅ No {'new ' if only_new else ''}vulnerabilities to report.")
    else:
        lines.append(f"## {title}")
        lines.append("")
        lines.append(_table(headline))
        explainers = [f for f in headline if f.guidance]
        if explainers:
            lines.append("")
            lines.append("### Explainers & upgrade guidance")
            lines.append("")
            for f in explainers:
                lines.append(_explainer(f))

    if only_new and ranked:
        backlog = [f for f in ranked if f.status == "EXISTING"]
        if backlog:
            lines.append("")
            lines.append("<details>")
            lines.append(f"<summary>{len(backlog)} existing finding(s) — already known</summary>")
            lines.append("")
            lines.append(_table(backlog))
            lines.append("</details>")

    lines.append("")
    return "\n".join(lines)


# ── helpers ──────────────────────────────────────────────────────────────────


def _table(findings: list[Finding]) -> str:
    head = (
        "| | Package | Installed | Fix | Severity | Vulnerability | Status |\n"
        "|---|---|---|---|---|---|---|"
    )
    rows = [head]
    for f in findings:
        fix = f.vuln.fixed_version or "—"
        tags = []
        if f.dep.dev:
            tags.append("dev")
        if not f.dep.direct:
            tags.append("transitive")
        tag_str = f" _{'/'.join(tags)}_" if tags else ""
        rows.append(
            f"| {_SEV_ICON[f.severity]} "
            f"| `{f.dep.name}`{tag_str} "
            f"| {f.dep.version} "
            f"| {fix} "
            f"| {f.severity.label} "
            f"| [{f.vuln.id}]({f.vuln.advisory_url}) — {_clip(f.vuln.summary)} "
            f"| {f.status} |"
        )
    return "\n".join(rows)


def _summary_line(counts: dict[str, int]) -> str:
    parts = [f"{counts[s]} {s.lower()}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    return ", ".join(parts) or "0"


def _counts(findings: list[Finding]) -> dict[str, int]:
    out = {s.name: 0 for s in Severity}
    for f in findings:
        out[f.severity.name] += 1
    return out


def _finding_dict(f: Finding) -> dict:
    return {
        "key": f.key,
        "status": f.status,
        "first_seen": f.first_seen,
        "severity": f.severity.label,
        "reachable": f.reachable,
        "package": {
            "ecosystem": f.dep.ecosystem,
            "name": f.dep.name,
            "version": f.dep.version,
            "direct": f.dep.direct,
            "dev": f.dep.dev,
            "source": f.dep.source,
        },
        "vulnerability": {
            "id": f.vuln.id,
            "summary": f.vuln.summary,
            "fixed_version": f.vuln.fixed_version,
            "cvss_score": f.vuln.cvss_score,
            "aliases": f.vuln.aliases,
            "advisory_url": f.vuln.advisory_url,
            "references": f.vuln.references,
        },
        "guidance": asdict(f.guidance) if f.guidance else None,
    }


def _explainer(f: Finding) -> str:
    """A collapsible block beneath an enriched row: explainer + upgrade guidance.

    Advisory/changelog-grounded facts and code-touchpoint inference are kept
    visually separate, and the model + confidence are always shown.
    """
    g = f.guidance
    assert g is not None
    out = [
        "<details>",
        f"<summary><code>{f.dep.name}</code> — {f.vuln.id} "
        f"({g.confidence or 'unrated'} confidence)</summary>",
        "",
        "**Why it's vulnerable**",
        g.why_vulnerable or "_n/a_",
        "",
        "**Impact**",
        g.impact or "_n/a_",
        "",
        f"**Severity rationale** — {g.severity_rationale or 'n/a'}",
        "",
        f"**Upgrade** ({g.effort or 'effort unrated'})",
        g.upgrade_summary or "_n/a_",
    ]
    if g.breaking_changes:
        out.append("")
        out.append("**Breaking changes (from changelog)**")
        out.extend(f"- {b}" for b in g.breaking_changes)
    if g.code_touchpoints:
        out.append("")
        out.append("**Code to check in this repo**")
        out.extend(
            f"- `{t.get('file')}:{t.get('line')}` — {t.get('note', '')}"
            for t in g.code_touchpoints
        )
    if g.sources:
        out.append("")
        out.append("**Sources:** " + " · ".join(f"[{i + 1}]({u})" for i, u in enumerate(g.sources)))
    out.append("")
    out.append(f"<sub>generated by {g.model or 'llm'} — verify before applying</sub>")
    out.append("</details>")
    out.append("")
    return "\n".join(out)


def _clip(text: str, limit: int = 80) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
