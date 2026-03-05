"""
Phase 05 — Graph Updater (Write Node)

Writes confirmed findings and scan metadata back to the Neo4j world model.
This is the accumulation step — each scan makes the graph richer so the
Regression Detector has history to query on the next run.

No LLM. Pure graph writes using the existing GraphClient.
"""

from __future__ import annotations

from datetime import datetime, timezone

import structlog

from brusky.memory.graph import Finding, GraphClient
from brusky.phases.fix_generation.models import EnrichedFix
from brusky.phases.memory_routing.models import ScanContext

log = structlog.get_logger()

# Severity → integer for the service risk_score field (higher = worse)
_SEVERITY_INT = {"P0": 4, "P1": 3, "P2": 2, "P3": 1}


class GraphUpdater:
    def __init__(self, graph: GraphClient) -> None:
        self._graph = graph

    async def write_findings(
        self,
        fixes: list[EnrichedFix],
        context: ScanContext,
    ) -> int:
        """
        Write all confirmed findings to the graph and mark the scan complete.
        Returns the number of findings successfully written.
        """
        written = 0

        for fix in fixes:
            try:
                finding = Finding(
                    id=fix.finding_id,
                    service_name=fix.service_name,
                    cwe_id=fix.cwe_id,
                    phase="03",
                    file=fix.file,
                    line=fix.line,
                    description=_description(fix),
                    severity=fix.severity,
                    contextual_score=fix.contextual_score,
                    justification=fix.developer_note[:500] if fix.developer_note else "",
                    patch=fix.patch,
                    status="open",
                    first_seen=_now(),
                )
                await self._graph.write_finding(finding, scan_id=context.scan_id)
                written += 1
                log.debug(
                    "graph_updater.finding_written",
                    finding_id=fix.finding_id,
                    severity=fix.severity,
                    service=fix.service_name,
                )
            except Exception as exc:
                log.error(
                    "graph_updater.write_error",
                    finding_id=fix.finding_id,
                    error=str(exc),
                )

        # Mark the scan complete
        try:
            await self._graph.complete_scan(
                scan_id=context.scan_id,
                finding_count=written,
            )
        except Exception as exc:
            log.warning("graph_updater.scan_complete_error", error=str(exc))

        # Update service risk scores
        await self._update_risk_scores(fixes)

        log.info(
            "graph_updater.complete",
            scan_id=context.scan_id,
            written=written,
            total=len(fixes),
        )
        return written

    async def _update_risk_scores(self, fixes: list[EnrichedFix]) -> None:
        """Set each service's risk_score to its worst open finding severity."""
        worst: dict[str, int] = {}
        for fix in fixes:
            score = _SEVERITY_INT.get(fix.severity, 0)
            if score > worst.get(fix.service_name, 0):
                worst[fix.service_name] = score

        for service_name, score in worst.items():
            try:
                async with self._graph._session() as s:
                    await s.run(
                        "MATCH (svc:Service {name: $name}) SET svc.risk_score = $score",
                        name=service_name,
                        score=score,
                    )
            except Exception as exc:
                log.warning(
                    "graph_updater.risk_score_error",
                    service=service_name,
                    error=str(exc),
                )


def _description(fix: EnrichedFix) -> str:
    base = fix.developer_note or f"{fix.cwe_id} vulnerability"
    return base[:300]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
