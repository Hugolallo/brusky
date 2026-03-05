"""Phase 04 — Fix Generation data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FixDraft:
    patch: str            # unified diff — "--- a/file\n+++ b/file\n@@..."
    fix_explanation: str  # one-paragraph explanation of what the fix does
    approach: str         # brief label: "ownership-scoped query", "parameterised statement", etc.


@dataclass
class ValidationResult:
    fix_valid: bool
    issues: list[str]   # populated when fix_valid=False — fed back to Fix Drafter on retry
    reason: str


@dataclass
class EnrichedFix:
    """Final output of Phase 04 — one per confirmed finding."""

    finding_id: str
    scan_id: str
    service_name: str
    cwe_id: str
    severity: str           # P0–P3 from Phase 03
    contextual_score: float

    # Patch (may be empty if manual_fix_required=True)
    patch: str
    fix_explanation: str
    fix_valid: bool
    manual_fix_required: bool
    validation_issues: list[str]   # issues from final failed validation, if any
    iterations: int                # 1 or 2

    # Developer context (always present, even on manual fix)
    developer_note: str
    references: list[str]
    related_finding_ids: list[str]

    # Source location — needed by Phase 05 for regression detection + PR comments
    file: str = ""
    line: int = 0

    # Pass-through from Phase 03 for Phase 05 routing
    attack_path: str = ""
    entry_point: str | None = None
    business_impact: str = ""
    controls_present: list[str] = field(default_factory=list)
    is_regression: bool = False
