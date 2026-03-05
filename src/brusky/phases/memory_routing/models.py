"""Phase 05 — Memory & Routing data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanContext:
    """Trigger context passed into Phase 05 — controls routing decisions."""

    scan_id: str
    trigger: str                    # "pr" | "scheduled" | "manual"
    pr_id: int | None = None        # Bitbucket PR ID (PR trigger only)
    repo_full_name: str | None = None  # "workspace/repo" (PR trigger only)
    target: str = ""                # repo path scanned


@dataclass
class RegressionInfo:
    """Result of the Regression Detector for a single finding."""

    is_regression: bool
    first_seen: str | None         # ISO timestamp of original finding
    fix_commit: str | None         # commit that supposedly fixed it
    regression_count: int          # how many times it's appeared + been fixed
    prior_finding_ids: list[str]


@dataclass
class RoutedFinding:
    """A finding after regression check + channel routing decisions are applied."""

    finding_id: str
    severity: str                  # base severity from Phase 03
    routed_severity: str           # may be escalated if is_regression
    cwe_id: str
    service_name: str
    file: str
    patch: str
    developer_note: str
    references: list[str]
    manual_fix_required: bool
    attack_path: str
    entry_point: str | None
    business_impact: str
    is_regression: bool
    regression_info: RegressionInfo
    channels: list[str]            # channels this finding was dispatched to
    contextual_score: float = 0.0


@dataclass
class DigestReport:
    """End-of-scan summary — accumulated P1–P3 findings, posted once to Slack."""

    scan_id: str
    trigger: str
    generated_at: str
    summary: dict[str, int]        # {"P0": 0, "P1": 2, "P2": 5, "P3": 11, "regressions": 1}
    by_service: dict[str, list[dict[str, Any]]]
    ci_blocked: bool


@dataclass
class PhaseResult:
    """Return value of run_memory_routing."""

    ci_blocked: bool               # True if any P0 was found — caller should fail CI
    routed: list[RoutedFinding]
    digest: DigestReport
    channels_failed: list[str]     # channel names that errored (logged but not raised)
