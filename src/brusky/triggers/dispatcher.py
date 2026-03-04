"""PR scan dispatcher — reads PREvents off the queue, runs skill scans, notifies Slack."""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import httpx
import structlog

from brusky.llm.provider import LLMProvider
from brusky.skills.registry import Skill, SkillRegistry, load_registry
from brusky.triggers.bitbucket import BitbucketClient
from brusky.triggers.models import PREvent

log = structlog.get_logger()

# Skill prompts live in .claude/commands/<command>.md — compute from env or default
_COMMANDS_DIR = Path(
    os.environ.get(
        "BRUSKY_COMMANDS_DIR",
        str(Path(__file__).parent.parent.parent.parent / ".claude" / "commands"),
    )
)

# Cap file content sent to the LLM per skill to avoid token blowout
_MAX_FILE_BYTES = 12_000
# Max number of files to include in a single skill prompt
_MAX_FILES_PER_SKILL = 20


class ScanQueue:
    """Thin asyncio.Queue wrapper so the type is explicit throughout the codebase."""

    def __init__(self) -> None:
        self._q: asyncio.Queue[PREvent] = asyncio.Queue()

    async def put(self, event: PREvent) -> None:
        await self._q.put(event)

    async def get(self) -> PREvent:
        return await self._q.get()

    def task_done(self) -> None:
        self._q.task_done()


async def scan_worker(
    queue: ScanQueue,
    access_token: str,
    slack_webhook_url: str,
) -> None:
    """Long-running coroutine — processes PREvents from the queue one at a time."""
    registry = load_registry()
    log.info("dispatcher.worker.started", skills=len(registry.all))

    while True:
        event = await queue.get()
        try:
            await _process_event(event, access_token, registry, slack_webhook_url)
        except Exception as exc:
            log.error("dispatcher.worker.error", pr=event.pr_url, error=str(exc))
        finally:
            queue.task_done()


async def _process_event(
    event: PREvent,
    access_token: str,
    registry: SkillRegistry,
    slack_webhook_url: str,
) -> None:
    log.info(
        "dispatcher.scan.started",
        repo=event.repo_full_name,
        pr=event.pr_id,
        title=event.pr_title,
    )

    # 1. Fetch diff from Bitbucket
    bb = BitbucketClient(access_token)
    try:
        event = await bb.enrich_pr_event(event)
    finally:
        await bb.close()

    if not event.changed_files:
        log.info("dispatcher.scan.no_changed_files", pr=event.pr_id)
        return

    log.info("dispatcher.scan.files_fetched", count=len(event.changed_files))

    # 2. Write changed files to a temp directory so registry.match() can glob them
    with tempfile.TemporaryDirectory(prefix="brusky-pr-") as tmp:
        tmp_path = Path(tmp)
        for cf in event.changed_files:
            if cf.status == "removed" or not cf.content:
                continue
            dest = tmp_path / cf.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(cf.content, encoding="utf-8", errors="replace")

        skills = registry.match(tmp_path)

    if not skills:
        log.info("dispatcher.scan.no_skills_matched", pr=event.pr_id)
        return

    log.info("dispatcher.scan.skills_matched", skills=[s.id for s in skills])

    # 3. Run each matched skill via LLM
    all_findings: list[dict[str, str]] = []
    for skill in skills:
        findings = await _run_skill(skill, event)
        all_findings.extend(findings)

    log.info(
        "dispatcher.scan.complete",
        pr=event.pr_id,
        skills_run=len(skills),
        findings=len(all_findings),
    )

    # 4. Notify Slack
    if slack_webhook_url:
        await notify_slack(slack_webhook_url, event, skills, all_findings)


async def _run_skill(skill: Skill, event: PREvent) -> list[dict[str, str]]:
    """Run one skill against the PR's changed files. Returns list of finding dicts."""
    prompt_text = _load_skill_prompt(skill)
    if not prompt_text:
        log.warning("dispatcher.skill.prompt_not_found", skill=skill.id)
        return []

    # Build the file section — only files matched by this skill's patterns
    matched_paths = {
        cf.path
        for cf in event.changed_files
        if cf.content and _file_matches_skill(cf.path, skill)
    }
    if not matched_paths:
        return []

    files_section = _build_files_section(
        [cf for cf in event.changed_files if cf.path in matched_paths]
    )

    user_message = (
        f"PR: {event.pr_title} ({event.pr_url})\n"
        f"Branch: {event.source_branch} → {event.destination_branch}\n\n"
        f"{files_section}\n\n"
        "Apply the security audit above to the files provided. "
        "Only report findings present in the changed code shown."
    )

    messages = [
        {"role": "system", "content": prompt_text},
        {"role": "user", "content": user_message},
    ]

    llm = LLMProvider("analysis", skill.id)
    try:
        response = await llm.complete(messages)
        return [{"skill": skill.id, "findings": response.content}]
    except Exception as exc:
        log.error("dispatcher.skill.llm_error", skill=skill.id, error=str(exc))
        return []


def _load_skill_prompt(skill: Skill) -> str:
    """Read the skill's Markdown prompt file from .claude/commands/."""
    prompt_path = _COMMANDS_DIR / f"{skill.command}.md"
    if not prompt_path.exists():
        return ""
    return prompt_path.read_text(encoding="utf-8")


def _file_matches_skill(file_path: str, skill: Skill) -> bool:
    """Check whether a file path matches any of the skill's trigger patterns."""
    from fnmatch import fnmatch
    from brusky.skills.registry import _glob_match  # reuse existing helper

    if not skill.trigger_patterns:
        return True
    return any(_glob_match(pat, file_path) for pat in skill.trigger_patterns)


def _build_files_section(changed_files: list) -> str:  # type: ignore[type-arg]
    """Build a readable block of file contents to embed in the LLM prompt."""
    parts: list[str] = []
    total = 0
    for cf in changed_files[:_MAX_FILES_PER_SKILL]:
        content = cf.content[:_MAX_FILE_BYTES] if cf.content else "(removed)"
        total += len(content)
        parts.append(f"### {cf.path} [{cf.status}]\n```\n{content}\n```")
        if total >= _MAX_FILE_BYTES * _MAX_FILES_PER_SKILL:
            parts.append("*(truncated — too many files)*")
            break
    return "\n\n".join(parts)


async def notify_slack(
    webhook_url: str,
    event: PREvent,
    skills: list[Skill],
    findings: list[dict[str, str]],
) -> None:
    """Post a scan summary to Slack via incoming webhook."""
    skills_run = ", ".join(s.id for s in skills)
    finding_count = sum(1 for f in findings if f.get("findings", "").strip())

    # Build blocks
    header = (
        f":mag: *Brusky scan complete* — "
        f"<{event.pr_url}|{event.repo_full_name} #{event.pr_id}>\n"
        f"*{event.pr_title}*\n"
        f"`{event.source_branch}` → `{event.destination_branch}`"
    )
    summary = (
        f"Skills run: {skills_run}\n"
        f"Changed files scanned: {len(event.changed_files)}\n"
        f"Skills with findings: {finding_count}"
    )

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
    ]

    # Append each skill's findings as a collapsed section (truncated at 3000 chars)
    for item in findings:
        text = item.get("findings", "").strip()
        if not text:
            continue
        skill_id = item.get("skill", "unknown")
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{skill_id}*\n```{text[:2800]}```",
            },
        })

    payload = {"blocks": blocks}

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            log.info("dispatcher.slack.notified", pr=event.pr_id)
        except Exception as exc:
            log.error("dispatcher.slack.error", error=str(exc))
