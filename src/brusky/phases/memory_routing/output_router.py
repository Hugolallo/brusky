"""
Phase 05 — Output Router (Conditional Router)

Applies routing rules, escalates regressions, then dispatches each finding
to the correct output channel(s). Channels fail independently — a failed
Slack post never blocks the graph write or Bitbucket PR comment.

Channels:
  slack_immediate    — rich Slack block for P0 and P1-from-PR
  pagerduty          — PagerDuty Events API v2 (P0 only)
  bitbucket_pr_comment — PR comment with patch (P1 + PR trigger)
  ci_block           — non-zero exit signal (P0)
  digest             — accumulate for end-of-scan grouped report (P1–P3 scheduled)
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

from brusky.config import get_settings
from brusky.phases.fix_generation.models import EnrichedFix
from brusky.phases.memory_routing.models import (
    DigestReport,
    RegressionInfo,
    RoutedFinding,
    ScanContext,
)

log = structlog.get_logger()

_SEVERITY_ORDER = ["P0", "P1", "P2", "P3"]

# Bitbucket API base
_BB_API = "https://api.bitbucket.org/2.0"
# PagerDuty Events API v2
_PD_API = "https://events.pagerduty.com/v2/enqueue"


class OutputRouter:
    def __init__(self, context: ScanContext) -> None:
        self._ctx = context
        self._settings = get_settings()
        self._digest_findings: list[RoutedFinding] = []
        self._ci_blocked = False
        self._failed_channels: list[str] = []

    async def route(
        self,
        fix: EnrichedFix,
        regression: RegressionInfo,
    ) -> RoutedFinding:
        # Determine effective (possibly escalated) severity
        routed_sev = _escalate(fix.severity) if regression.is_regression else fix.severity

        channels = _select_channels(routed_sev, self._ctx.trigger)

        routed = RoutedFinding(
            finding_id=fix.finding_id,
            severity=fix.severity,
            routed_severity=routed_sev,
            cwe_id=fix.cwe_id,
            service_name=fix.service_name,
            file=fix.file,
            patch=fix.patch,
            developer_note=fix.developer_note,
            references=fix.references,
            manual_fix_required=fix.manual_fix_required,
            attack_path=fix.attack_path,
            entry_point=fix.entry_point,
            business_impact=fix.business_impact,
            is_regression=regression.is_regression,
            regression_info=regression,
            channels=channels,
            contextual_score=fix.contextual_score,
        )

        # Dispatch channels independently
        tasks: dict[str, Any] = {}
        if "ci_block" in channels:
            self._ci_blocked = True
        if "slack_immediate" in channels and self._settings.slack_webhook_url:
            tasks["slack_immediate"] = _post_slack_immediate(routed, self._settings.slack_webhook_url)
        if "pagerduty" in channels and self._settings.pagerduty_api_key:
            tasks["pagerduty"] = _post_pagerduty(routed, self._settings.pagerduty_api_key)
        if "bitbucket_pr_comment" in channels and self._ctx.pr_id and self._ctx.repo_full_name:
            tasks["bitbucket_pr_comment"] = _post_bitbucket_comment(
                routed, fix, self._ctx, self._settings.bitbucket_access_token
            )
        if "digest" in channels:
            self._digest_findings.append(routed)

        if tasks:
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for name, result in zip(tasks.keys(), results):
                if isinstance(result, Exception):
                    log.error(f"output_router.{name}.error", finding_id=fix.finding_id, error=str(result))
                    self._failed_channels.append(name)

        return routed

    async def post_digest(self) -> DigestReport:
        """Build and post the end-of-scan digest to Slack. Always call once per scan."""
        report = _build_digest(self._digest_findings, self._ctx, self._ci_blocked)

        if self._digest_findings and self._settings.slack_webhook_url:
            try:
                await _post_slack_digest(report, self._settings.slack_webhook_url)
            except Exception as exc:
                log.error("output_router.digest.error", error=str(exc))
                self._failed_channels.append("digest")

        return report

    @property
    def ci_blocked(self) -> bool:
        return self._ci_blocked

    @property
    def failed_channels(self) -> list[str]:
        return list(self._failed_channels)


# ── Routing rules ──────────────────────────────────────────────────────────────

def _select_channels(severity: str, trigger: str) -> list[str]:
    channels: list[str] = []
    if severity == "P0":
        channels = ["ci_block", "slack_immediate", "pagerduty"]
    elif severity == "P1" and trigger == "pr":
        channels = ["bitbucket_pr_comment", "slack_immediate"]
    elif severity in ("P1", "P2"):
        channels = ["digest"]
    else:  # P3
        channels = ["digest"]
    return channels


def _escalate(severity: str) -> str:
    idx = _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 3
    return _SEVERITY_ORDER[max(0, idx - 1)]


# ── Channel implementations ────────────────────────────────────────────────────

async def _post_slack_immediate(routed: RoutedFinding, webhook_url: str) -> None:
    sev_emoji = {"P0": ":rotating_light:", "P1": ":warning:"}.get(routed.routed_severity, ":info:")
    regression_note = ""
    if routed.is_regression:
        regression_note = (
            f"\n:repeat: *Regression* — first seen {routed.regression_info.first_seen or 'unknown'}, "
            f"previously fixed in `{routed.regression_info.fix_commit or 'unknown commit'}`"
        )

    patch_block = []
    if routed.patch:
        patch_block = [{"type": "section", "text": {"type": "mrkdwn",
            "text": f"*Suggested fix:*\n```{routed.patch[:800]}```"}}]

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": (
            f"{sev_emoji} *{routed.routed_severity} — {routed.cwe_id}* "
            f"[`{routed.service_name}`]{regression_note}\n"
            f"`{routed.file}`\n"
            f"{routed.developer_note[:300]}"
        )}},
        *patch_block,
        {"type": "context", "elements": [{"type": "mrkdwn",
            "text": " · ".join(routed.references[:2])}]},
    ]

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(webhook_url, json={"blocks": blocks})
        resp.raise_for_status()


async def _post_pagerduty(routed: RoutedFinding, routing_key: str) -> None:
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": routed.finding_id,
        "payload": {
            "summary": f"[{routed.routed_severity}] {routed.cwe_id} — {routed.service_name}",
            "severity": "critical",
            "source": "brusky",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "custom_details": {
                "file": routed.file,
                "attack_path": routed.attack_path[:500],
                "business_impact": routed.business_impact,
                "patch_available": bool(routed.patch),
                "is_regression": routed.is_regression,
            },
        },
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(_PD_API, json=payload)
        resp.raise_for_status()


async def _post_bitbucket_comment(
    routed: RoutedFinding,
    fix: EnrichedFix,
    ctx: ScanContext,
    access_token: str,
) -> None:
    if not access_token:
        raise ValueError("BITBUCKET_ACCESS_TOKEN not configured")

    regression_banner = ""
    if routed.is_regression:
        regression_banner = (
            f"\n> :repeat: **Regression** — this vulnerability was previously fixed "
            f"(commit `{routed.regression_info.fix_commit or 'unknown'}`) "
            f"and has reappeared.\n"
        )

    patch_section = ""
    if routed.patch:
        patch_section = f"\n**Suggested fix:**\n```diff\n{routed.patch[:1_200]}\n```\n"
    elif fix.manual_fix_required:
        issues = "\n".join(f"- {i}" for i in fix.validation_issues[:3])
        patch_section = f"\n> **Manual fix required** — auto-patch generation failed:\n{issues}\n"

    refs = " · ".join(f"[{r.split('/')[-2]}]({r})" for r in routed.references[:3] if "/" in r)

    body = (
        f"## :shield: Brusky Security Finding — {routed.routed_severity}\n\n"
        f"**{routed.cwe_id}** in `{routed.file}`\n"
        f"{regression_banner}\n"
        f"{routed.developer_note}\n"
        f"{patch_section}"
        f"\n{refs}"
    )

    url = f"{_BB_API}/repositories/{ctx.repo_full_name}/pullrequests/{ctx.pr_id}/comments"
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15.0,
    ) as client:
        resp = await client.post(url, json={"content": {"raw": body}})
        resp.raise_for_status()


def _build_digest(
    findings: list[RoutedFinding],
    ctx: ScanContext,
    ci_blocked: bool,
) -> DigestReport:
    summary: dict[str, int] = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "regressions": 0}
    by_service: dict[str, list[dict[str, Any]]] = {}

    for f in findings:
        summary[f.routed_severity] = summary.get(f.routed_severity, 0) + 1
        if f.is_regression:
            summary["regressions"] += 1
        entry: dict[str, Any] = {
            "severity": f.routed_severity,
            "cwe_id": f.cwe_id,
            "file": f.file,
            "patch_available": bool(f.patch),
            "is_regression": f.is_regression,
        }
        by_service.setdefault(f.service_name, []).append(entry)

    return DigestReport(
        scan_id=ctx.scan_id,
        trigger=ctx.trigger,
        generated_at=datetime.now(timezone.utc).isoformat(),
        summary=summary,
        by_service=by_service,
        ci_blocked=ci_blocked,
    )


async def _post_slack_digest(report: DigestReport, webhook_url: str) -> None:
    s = report.summary
    header = (
        f":memo: *Brusky scan digest* — `{report.scan_id}` ({report.trigger})\n"
        f"P0: {s['P0']} · P1: {s['P1']} · P2: {s['P2']} · P3: {s['P3']} "
        f"· Regressions: {s['regressions']}"
    )
    service_blocks = []
    for service, items in sorted(report.by_service.items()):
        lines = "\n".join(
            f"  {'🔁 ' if i['is_regression'] else ''}{i['severity']} {i['cwe_id']} — `{i['file']}`"
            for i in sorted(items, key=lambda x: _SEVERITY_ORDER.index(x["severity"]))
        )
        service_blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"*{service}*\n{lines}"}})

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {"type": "divider"},
        *service_blocks[:20],  # Slack block limit
    ]
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(webhook_url, json={"blocks": blocks})
        resp.raise_for_status()
