"""Render a ScanResult as Markdown (human) or JSON (machine).

Markdown leads with NEW/worsened findings (the point of a daily run) and keeps
the full backlog in a collapsed section to control alert fatigue. JSON is the
complete, stable structure for CI consumption.
"""

from __future__ import annotations

import json

from brusky.model import Finding, ScanResult, Severity

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
    }


def _clip(text: str, limit: int = 80) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
