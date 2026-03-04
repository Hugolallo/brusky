"""
Phase 04 — Fix Validator (Reflection Node)

The Fix Drafter critiques its own output. Checks whether the patch actually
fixes the vulnerability class, introduces no new issues, is idiomatic, and
is safe to apply without breaking existing behaviour.

LLM: Sonnet, temp 0.0 — validation must be deterministic and consistent.
"""

from __future__ import annotations

import json
import re
from typing import Any

import structlog

from brusky.llm import get_llm
from brusky.phases.exploitability.models import ScoredFinding
from brusky.phases.fix_generation.models import FixDraft, ValidationResult

log = structlog.get_logger()

_SYSTEM = """\
You are a security code reviewer validating a patch that was generated to fix \
a confirmed vulnerability.

Check the patch against these four criteria:
1. Fixes the CWE class — not just the specific instance, but the entire vulnerability pattern
2. No new issues — the patch must not introduce XSS, injection, type errors, or logic bugs
3. Idiomatic — the fix must match the language/framework conventions in the codebase
4. Safe to apply — no breaking changes to API contracts or behaviour for legitimate users

Respond ONLY with valid JSON — no markdown, no explanation outside the JSON:
{
  "fix_valid": <true|false>,
  "issues": ["<issue 1>", "<issue 2>", ...],
  "reason": "<one sentence summary of the validation result>"
}

If fix_valid=true, issues must be an empty list.
If fix_valid=false, issues must be non-empty and specific — each issue should describe \
exactly what is wrong and what the correct approach would be.
Be strict: a vague or incomplete fix is not valid.
"""


class FixValidator:
    def __init__(self) -> None:
        self._llm = get_llm("fix_generation", "fix_validator")

    async def validate(
        self,
        draft: FixDraft,
        finding: ScoredFinding,
        service_language: str,
    ) -> ValidationResult:
        if not draft.patch:
            return ValidationResult(
                fix_valid=False,
                issues=["No patch was generated"],
                reason="Fix Drafter produced an empty patch",
            )

        prompt = _build_prompt(draft, finding, service_language)
        try:
            response = await self._llm.complete(
                [{"role": "user", "content": prompt}],
                system=_SYSTEM,
            )
            return _parse(response.content)
        except Exception as exc:
            log.error("fix_validator.error", finding_id=finding.id, error=str(exc))
            return ValidationResult(
                fix_valid=False,
                issues=["Validation LLM call failed"],
                reason=str(exc),
            )


def _build_prompt(draft: FixDraft, finding: ScoredFinding, service_language: str) -> str:
    return (
        f"## Original finding\n"
        f"CWE: {finding.cwe_id}\n"
        f"File: {finding.file} line {finding.line}\n"
        f"Description: {finding.description}\n"
        f"Severity: {finding.severity}\n\n"
        f"## Vulnerable code (original)\n"
        f"```\n{finding.snippet[:1_500]}\n```\n\n"
        f"## Proposed patch\n"
        f"Approach: {draft.approach}\n"
        f"Explanation: {draft.fix_explanation}\n\n"
        f"Patch:\n{draft.patch[:3_000]}\n\n"
        f"## Language/framework\n"
        f"{service_language}"
    )


def _parse(raw: str) -> ValidationResult:
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip(), flags=re.MULTILINE)
    try:
        data = json.loads(cleaned)
        valid = bool(data.get("fix_valid", False))
        issues = [str(i) for i in data.get("issues", [])]
        reason = str(data.get("reason", ""))
        return ValidationResult(fix_valid=valid, issues=issues, reason=reason)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        log.warning("fix_validator.parse_failed", error=str(exc))
        return ValidationResult(
            fix_valid=False,
            issues=["Validator response could not be parsed"],
            reason=str(exc),
        )
