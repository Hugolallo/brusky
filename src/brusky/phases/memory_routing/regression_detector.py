"""
Phase 05 — Regression Detector (Graph Query Node)

Queries Neo4j for each confirmed finding: has this CWE + service + file
combination appeared before and been marked fixed? If yes, it's a regression —
previously closed vulnerability that reappeared.

No LLM. Pure graph query using the existing GraphClient.get_regressions().
"""

from __future__ import annotations

import structlog

from brusky.memory.graph import GraphClient
from brusky.phases.fix_generation.models import EnrichedFix
from brusky.phases.memory_routing.models import RegressionInfo

log = structlog.get_logger()


class RegressionDetector:
    def __init__(self, graph: GraphClient) -> None:
        self._graph = graph

    async def check(self, fix: EnrichedFix) -> RegressionInfo:
        try:
            prior = await self._graph.get_regressions(
                service_name=fix.service_name,
                cwe_id=fix.cwe_id,
                file=fix.file,
            )
        except Exception as exc:
            log.warning(
                "regression_detector.query_error",
                finding_id=fix.finding_id,
                error=str(exc),
            )
            return _no_regression()

        if not prior:
            return _no_regression()

        # Sort by first_seen ascending so earliest appearance is index 0
        prior_sorted = sorted(prior, key=lambda f: f.get("first_seen", ""))

        info = RegressionInfo(
            is_regression=True,
            first_seen=prior_sorted[0].get("first_seen"),
            fix_commit=prior_sorted[-1].get("fix_commit"),   # most recent fix
            regression_count=len(prior),
            prior_finding_ids=[f["id"] for f in prior if f.get("id")],
        )

        log.info(
            "regression_detector.found",
            finding_id=fix.finding_id,
            service=fix.service_name,
            cwe=fix.cwe_id,
            regression_count=info.regression_count,
            first_seen=info.first_seen,
        )

        return info


def _no_regression() -> RegressionInfo:
    return RegressionInfo(
        is_regression=False,
        first_seen=None,
        fix_commit=None,
        regression_count=0,
        prior_finding_ids=[],
    )


