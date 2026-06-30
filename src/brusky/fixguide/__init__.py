"""Optional LLM layer: explainer + upgrade guidance (M3).

Runs after the deterministic scan. `enrich()` attaches `FixGuidance` to selected
findings; detection is unaffected and the report renders unchanged when this
layer is skipped.
"""

from __future__ import annotations

from brusky.fixguide.runner import enrich, select_findings

__all__ = ["enrich", "select_findings"]
