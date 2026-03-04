"""
Phase 04 — Fix Generation orchestrator.

ReAct + Reflection loop per confirmed finding from Phase 03:

  confirmed finding
      │
  [Fix Drafter]     → FixDraft (patch + explanation)
      │
  [Fix Validator]   → ValidationResult (valid? issues?)
      │
      ├─ valid ──────────────────────────────────┐
      │                                          │
      └─ invalid → retry with issues (attempt 2) │
                       │                         │
                       ├─ valid ─────────────────┤
                       │                         │
                       └─ still invalid          │
                           manual_fix_required   │
                                                 ▼
                                       [Context Enricher]  →  EnrichedFix
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from brusky.memory.graph import GraphClient, Service, get_graph
from brusky.phases.exploitability.models import ScoredFinding
from brusky.phases.fix_generation.context_enricher import ContextEnricher
from brusky.phases.fix_generation.fix_drafter import FixDrafter
from brusky.phases.fix_generation.fix_validator import FixValidator
from brusky.phases.fix_generation.models import EnrichedFix, FixDraft

log = structlog.get_logger()

_MAX_ITERATIONS = 2


async def run_fix_generation(
    confirmed_findings: list[ScoredFinding],
    services: list[Service],
    scan_id: str | None = None,
    graph: GraphClient | None = None,
) -> list[EnrichedFix]:
    """
    Run Phase 04 — Fix Generation.

    Args:
        confirmed_findings: Scored findings from Phase 03.
        services:           Enriched Service objects from Phase 01.
        scan_id:            Correlation ID. Auto-generated if not provided.
        graph:              Optional pre-connected GraphClient (used for related findings).

    Returns:
        list[EnrichedFix] — one per confirmed finding, ready for Phase 05.
        manual_fix_required=True on entries where reflection loop hit the cap.
    """
    scan_id = scan_id or str(uuid.uuid4())[:8]

    log.info(
        "phase04.start",
        scan_id=scan_id,
        finding_count=len(confirmed_findings),
    )

    g = graph or await get_graph()
    service_map = {s.name: s for s in services}

    drafter = FixDrafter()
    validator = FixValidator()
    enricher = ContextEnricher()

    results: list[EnrichedFix] = []

    for idx, finding in enumerate(confirmed_findings):
        service = service_map.get(finding.service_name, services[0] if services else _dummy_service())

        log.debug(
            "phase04.loop.start",
            scan_id=scan_id,
            idx=idx + 1,
            total=len(confirmed_findings),
            finding_id=finding.id,
            severity=finding.severity,
            cwe=finding.cwe_id,
        )

        # ── ReAct + Reflection loop ────────────────────────────────────────────
        draft: FixDraft | None = None
        validation_issues: list[str] = []
        manual_fix_required = False
        iterations = 0

        for attempt in range(1, _MAX_ITERATIONS + 1):
            iterations = attempt
            draft = await drafter.draft(
                finding, service,
                prior_issues=validation_issues if attempt > 1 else None,
                attempt=attempt,
            )
            validation = await validator.validate(draft, finding, service.language)

            if validation.fix_valid:
                log.info(
                    "phase04.loop.fix_valid",
                    finding_id=finding.id,
                    attempt=attempt,
                    approach=draft.approach,
                )
                break

            validation_issues = validation.issues
            log.info(
                "phase04.loop.fix_invalid",
                finding_id=finding.id,
                attempt=attempt,
                issue_count=len(validation_issues),
            )

            if attempt == _MAX_ITERATIONS:
                manual_fix_required = True
                log.warning(
                    "phase04.loop.manual_fix_required",
                    finding_id=finding.id,
                    issues=validation_issues,
                )

        # ── Context enrichment (always runs) ──────────────────────────────────
        note, references, related_ids = await enricher.enrich(
            finding,
            draft if not manual_fix_required else None,
            service,
            g,
        )

        results.append(EnrichedFix(
            finding_id=finding.id,
            scan_id=scan_id,
            service_name=finding.service_name,
            cwe_id=finding.cwe_id,
            severity=finding.severity,
            contextual_score=finding.contextual_score,
            patch=draft.patch if (draft and not manual_fix_required) else "",
            fix_explanation=draft.fix_explanation if draft else "",
            fix_valid=not manual_fix_required,
            manual_fix_required=manual_fix_required,
            validation_issues=validation_issues,
            iterations=iterations,
            developer_note=note,
            references=references,
            related_finding_ids=related_ids,
            attack_path=finding.attack_context.attack_path,
            entry_point=finding.attack_context.entry_point,
            business_impact=finding.business_impact,
            controls_present=finding.controls_present,
            is_regression=finding.is_regression,
        ))

    manual_count = sum(1 for r in results if r.manual_fix_required)
    log.info(
        "phase04.complete",
        scan_id=scan_id,
        total=len(results),
        patched=len(results) - manual_count,
        manual_fix_required=manual_count,
    )

    return results


def _dummy_service() -> Service:
    """Fallback when no services are provided (e.g. in tests)."""
    from brusky.memory.graph import Service
    return Service(name="unknown", language="unknown")
