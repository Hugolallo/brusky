"""
Phase 04 — Fix Drafter (LLM Node)

Generates a concrete code patch for a confirmed vulnerability finding.
Language and framework aware — produces idiomatic fixes, not generic advice.

LLM: Sonnet, temp 0.1 — slight variation helps with code generation creativity.
Max context around the vulnerable line: 2 000 chars.
"""

from __future__ import annotations

import json
import re
from typing import Any

import structlog

from brusky.llm import get_llm
from brusky.memory.graph import Service
from brusky.phases.exploitability.models import ScoredFinding
from brusky.phases.fix_generation.models import FixDraft

log = structlog.get_logger()

_MAX_SNIPPET = 2_000

_SYSTEM = """\
You are a senior security engineer writing code fixes for confirmed vulnerabilities.

Generate a concrete, ready-to-apply patch — not advice, not "use prepared statements". \
Write the actual code change.

Respond ONLY with valid JSON — no markdown, no explanation outside the JSON:
{
  "patch": "<unified diff OR before/after block if diff is impractical>",
  "fix_explanation": "<1-2 paragraphs: what changed, why it fixes the CWE, any caveats>",
  "approach": "<5-10 word label for the fix strategy>"
}

Patch format rules:
- Prefer unified diff: --- a/path\\n+++ b/path\\n@@ ... @@\\n-old\\n+new
- If the fix is a single logical change with no line number context, a before/after block is acceptable:
  BEFORE:\\n```\\n<vulnerable code>\\n```\\nAFTER:\\n```\\n<fixed code>\\n```
- Do NOT output a full file — only the changed lines plus ~3 lines of context
- Do NOT wrap the patch in markdown fences inside the JSON value

Fix quality rules:
- Be idiomatic for the language/framework — a Laravel codebase uses Eloquent, not raw PDO
- Fix the vulnerability CLASS, not just the specific instance shown
- Do not introduce new vulnerabilities (XSS via string concat, etc.)
- If the fix requires a new import or dependency, include it in the patch
"""


class FixDrafter:
    def __init__(self) -> None:
        self._llm = get_llm("fix_generation", "fix_drafter")

    async def draft(
        self,
        finding: ScoredFinding,
        service: Service,
        prior_issues: list[str] | None = None,
        attempt: int = 1,
    ) -> FixDraft:
        prompt = _build_prompt(finding, service, prior_issues, attempt)
        try:
            response = await self._llm.complete(
                [{"role": "user", "content": prompt}],
                system=_SYSTEM,
            )
            return _parse(response.content)
        except Exception as exc:
            log.error("fix_drafter.error", finding_id=finding.id, attempt=attempt, error=str(exc))
            return FixDraft(patch="", fix_explanation="Patch generation failed.", approach="failed")


def _build_prompt(
    finding: ScoredFinding,
    service: Service,
    prior_issues: list[str] | None,
    attempt: int,
) -> str:
    snippet = finding.snippet[:_MAX_SNIPPET] if finding.snippet else "(snippet not available)"
    attack_summary = (
        f"Attack path: {finding.attack_context.attack_path[:300]}\n"
        f"Attacker gain: {finding.attack_context.attacker_gain}"
    )
    retry_block = ""
    if prior_issues and attempt > 1:
        issues_str = "\n".join(f"  - {i}" for i in prior_issues)
        retry_block = (
            f"\n## RETRY — attempt {attempt}\n"
            f"Your previous patch had these issues:\n{issues_str}\n"
            f"Address all issues in this new version.\n"
        )

    return (
        f"## Finding to fix\n"
        f"Severity: {finding.severity} (score {finding.contextual_score})\n"
        f"CWE: {finding.cwe_id}\n"
        f"File: {finding.file} line {finding.line}\n"
        f"Description: {finding.description}\n"
        f"Justification: {finding.justification}\n\n"
        f"## Vulnerable code\n"
        f"```\n{snippet}\n```\n\n"
        f"## Attack context\n"
        f"{attack_summary}\n\n"
        f"## Service context\n"
        f"Language/framework: {service.language}\n"
        f"Purpose: {service.purpose}\n"
        f"Sensitivity: {service.sensitivity}"
        f"{retry_block}"
    )


def _parse(raw: str) -> FixDraft:
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip(), flags=re.MULTILINE)
    try:
        data = json.loads(cleaned)
        return FixDraft(
            patch=str(data.get("patch", "")),
            fix_explanation=str(data.get("fix_explanation", "")),
            approach=str(data.get("approach", "")),
        )
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        log.warning("fix_drafter.parse_failed", error=str(exc))
        return FixDraft(patch="", fix_explanation=raw[:500], approach="parse-failed")
