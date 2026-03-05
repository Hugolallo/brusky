"""
Phase 05 — Memory & Routing orchestrator.

Three agents run in sequence for each confirmed finding:

  [Regression Detector]  → is this a known vulnerability that came back?
  [Graph Updater]        → write findings + scan record to Neo4j
  [Output Router]        → dispatch to Slack / PagerDuty / Bitbucket / digest
"""

from __future__ import annotations

import uuid

import structlog

from brusky.memory.graph import GraphClient, get_graph
from brusky.phases.fix_generation.models import EnrichedFix
from brusky.phases.memory_routing.graph_updater import GraphUpdater
from brusky.phases.memory_routing.models import PhaseResult, ScanContext
from brusky.phases.memory_routing.output_router import OutputRouter
from brusky.phases.memory_routing.regression_detector import RegressionDetector

log = structlog.get_logger()


async def run_memory_routing(
    enriched_fixes: list[EnrichedFix],
    context: ScanContext | None = None,
    graph: GraphClient | None = None,
) -> PhaseResult:
    """
    Run Phase 05 — Memory & Routing.

    Args:
        enriched_fixes: Patched findings from Phase 04.
        context:        Trigger context (PR ID, repo, trigger type). A minimal
                        ScanContext is auto-created for manual/scheduled runs.
        graph:          Optional pre-connected GraphClient (useful in tests).

    Returns:
        PhaseResult with ci_blocked flag, routed findings, digest, and any
        channel errors. The caller is responsible for acting on ci_blocked.
    """
    g = graph or await get_graph()

    if context is None:
        context = ScanContext(
            scan_id=str(uuid.uuid4())[:8],
            trigger="manual",
        )

    log.info(
        "phase05.start",
        scan_id=context.scan_id,
        trigger=context.trigger,
        finding_count=len(enriched_fixes),
    )

    detector = RegressionDetector(graph=g)
    updater = GraphUpdater(graph=g)
    router = OutputRouter(context=context)

    # ── Step 1: write findings to graph ──────────────────────────────────────
    written = await updater.write_findings(enriched_fixes, context)

    # ── Step 2: regression check + routing per finding ───────────────────────
    routed = []
    for fix in enriched_fixes:
        regression = await detector.check(fix)
        routed_finding = await router.route(fix, regression)
        routed.append(routed_finding)

    # ── Step 3: post end-of-scan digest ──────────────────────────────────────
    digest = await router.post_digest()

    log.info(
        "phase05.complete",
        scan_id=context.scan_id,
        written=written,
        routed=len(routed),
        ci_blocked=router.ci_blocked,
        regressions=sum(1 for r in routed if r.is_regression),
        channels_failed=router.failed_channels,
        digest_summary=digest.summary,
    )

    return PhaseResult(
        ci_blocked=router.ci_blocked,
        routed=routed,
        digest=digest,
        channels_failed=router.failed_channels,
    )
