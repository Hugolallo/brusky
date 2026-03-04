"""
Phase 04 — Context Enricher (LLM Node)

Adds developer-facing context to every confirmed fix. Runs regardless of whether
a patch was generated — a manual-fix finding still gets OWASP references and
a plain-language explanation of the attack scenario.

LLM: Haiku, temp 0.0 — structured enrichment, no creative reasoning needed.
CWE → OWASP/reference mapping is handled via lookup table (no LLM for URLs).
"""

from __future__ import annotations

import json
import re
from typing import Any

import structlog

from brusky.llm import get_llm
from brusky.memory.graph import GraphClient, Service
from brusky.phases.exploitability.models import ScoredFinding
from brusky.phases.fix_generation.models import FixDraft

log = structlog.get_logger()

# ── CWE → reference lookup (no LLM needed for static URLs) ────────────────────

_OWASP_BASE = "https://owasp.org/Top10"
_CWE_BASE = "https://cwe.mitre.org/data/definitions"
_CS_BASE = "https://cheatsheetseries.owasp.org/cheatsheets"

_CWE_REFS: dict[str, list[str]] = {
    "CWE-89":  [f"{_OWASP_BASE}/A03_2021-Injection/",
                f"{_CWE_BASE}/89.html",
                f"{_CS_BASE}/SQL_Injection_Prevention_Cheat_Sheet.html"],
    "CWE-79":  [f"{_OWASP_BASE}/A03_2021-Injection/",
                f"{_CWE_BASE}/79.html",
                f"{_CS_BASE}/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    "CWE-502": [f"{_OWASP_BASE}/A08_2021-Software_and_Data_Integrity_Failures/",
                f"{_CWE_BASE}/502.html",
                f"{_CS_BASE}/Deserialization_Cheat_Sheet.html"],
    "CWE-639": [f"{_OWASP_BASE}/A01_2021-Broken_Access_Control/",
                f"{_CWE_BASE}/639.html",
                f"{_CS_BASE}/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"],
    "CWE-287": [f"{_OWASP_BASE}/A07_2021-Identification_and_Authentication_Failures/",
                f"{_CWE_BASE}/287.html",
                f"{_CS_BASE}/Authentication_Cheat_Sheet.html"],
    "CWE-798": [f"{_OWASP_BASE}/A02_2021-Cryptographic_Failures/",
                f"{_CWE_BASE}/798.html",
                f"{_CS_BASE}/Cryptographic_Storage_Cheat_Sheet.html"],
    "CWE-78":  [f"{_OWASP_BASE}/A03_2021-Injection/",
                f"{_CWE_BASE}/78.html",
                f"{_CS_BASE}/OS_Command_Injection_Defense_Cheat_Sheet.html"],
    "CWE-22":  [f"{_OWASP_BASE}/A01_2021-Broken_Access_Control/",
                f"{_CWE_BASE}/22.html",
                f"{_CS_BASE}/File_Upload_Cheat_Sheet.html"],
    "CWE-918": [f"{_OWASP_BASE}/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                f"{_CWE_BASE}/918.html",
                f"{_CS_BASE}/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    "CWE-601": [f"{_OWASP_BASE}/A01_2021-Broken_Access_Control/",
                f"{_CWE_BASE}/601.html"],
    "CWE-269": [f"{_OWASP_BASE}/A01_2021-Broken_Access_Control/",
                f"{_CWE_BASE}/269.html",
                f"{_CS_BASE}/Authorization_Cheat_Sheet.html"],
    "CWE-327": [f"{_OWASP_BASE}/A02_2021-Cryptographic_Failures/",
                f"{_CWE_BASE}/327.html",
                f"{_CS_BASE}/Cryptographic_Storage_Cheat_Sheet.html"],
    "CWE-94":  [f"{_OWASP_BASE}/A03_2021-Injection/",
                f"{_CWE_BASE}/94.html"],
    "CWE-1321":[f"{_OWASP_BASE}/A08_2021-Software_and_Data_Integrity_Failures/",
                f"{_CWE_BASE}/1321.html"],
}

_SYSTEM = """\
You are a security educator writing developer-facing context for a confirmed vulnerability.

Write a developer_note that explains:
1. What the vulnerability is and why the pattern is dangerous
2. What an attacker would actually do (in plain language, no jargon)
3. One sentence on the broader impact if unpatched

Respond ONLY with valid JSON — no markdown, no explanation outside the JSON:
{
  "developer_note": "<2-4 sentences, plain English, developer-focused>"
}

Do not include URLs — those are added separately.
Do not repeat the file path or line number — those are shown separately.
Assume the reader is a developer who understands code but may not know security terminology.
"""


class ContextEnricher:
    def __init__(self) -> None:
        self._llm = get_llm("fix_generation", "context_enricher")

    async def enrich(
        self,
        finding: ScoredFinding,
        draft: FixDraft | None,
        service: Service,
        graph: GraphClient,
    ) -> tuple[str, list[str], list[str]]:
        """
        Returns (developer_note, references, related_finding_ids).
        Runs regardless of whether a patch exists.
        """
        # Static URL lookup — no LLM needed
        references = _CWE_REFS.get(finding.cwe_id, [f"{_CWE_BASE}/{_cwe_num(finding.cwe_id)}.html"])

        # Related findings from the same service in the graph
        related_ids = await _fetch_related(graph, finding)

        # LLM for the developer note
        note = await self._generate_note(finding, draft, service)

        return note, references, related_ids

    async def _generate_note(
        self,
        finding: ScoredFinding,
        draft: FixDraft | None,
        service: Service,
    ) -> str:
        patch_summary = draft.approach if draft and draft.patch else "manual fix required"
        prompt = (
            f"CWE: {finding.cwe_id}\n"
            f"Description: {finding.description}\n"
            f"Attack scenario: {finding.attack_context.attacker_gain}\n"
            f"Service handles: {', '.join(finding.affected_data_types) or service.sensitivity + ' data'}\n"
            f"Fix approach: {patch_summary}"
        )
        try:
            response = await self._llm.complete(
                [{"role": "user", "content": prompt}],
                system=_SYSTEM,
            )
            return _parse_note(response.content)
        except Exception as exc:
            log.error("context_enricher.error", finding_id=finding.id, error=str(exc))
            return f"{finding.description} — see CWE {finding.cwe_id} for details."


async def _fetch_related(graph: GraphClient, finding: ScoredFinding) -> list[str]:
    """Query the graph for other open findings on the same service."""
    try:
        others = await graph.get_service_findings(finding.service_name, status="open")
        return [
            f["id"] for f in others
            if f.get("id") != finding.id and f.get("id")
        ][:5]  # cap at 5
    except Exception as exc:
        log.warning("context_enricher.related_fetch_error", error=str(exc))
        return []


def _parse_note(raw: str) -> str:
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip(), flags=re.MULTILINE)
    try:
        data = json.loads(cleaned)
        return str(data.get("developer_note", cleaned))
    except (json.JSONDecodeError, ValueError):
        # If it's not JSON just return the raw text (Haiku sometimes skips the wrapper)
        return raw.strip()[:600]


def _cwe_num(cwe_id: str) -> str:
    """Extract numeric part from 'CWE-89' → '89'."""
    return cwe_id.replace("CWE-", "")
