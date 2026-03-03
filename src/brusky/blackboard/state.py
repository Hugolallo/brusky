"""
Redis-backed blackboard for Phase 02 — Analysis.

The blackboard is the shared communication channel between specialist agents
during a single scan. The Controller seeds it with scope, each specialist
posts raw findings, and the Controller reads them to decide routing.

Namespaced by scan_id so concurrent scans don't collide.

Keys (all prefixed with `brusky:{scan_id}:`):
  scope          → JSON — the current scan scope (files, diff, service)
  findings       → Redis List — raw finding dicts, appended by each specialist
  coverage       → Redis Hash — {specialist: "done"|"skipped"|"pending"}
  status         → string — "running" | "complete" | "error"
  meta           → JSON — scan metadata (trigger, target, started_at)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
import structlog

from brusky.config import get_settings

log = structlog.get_logger()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Blackboard ─────────────────────────────────────────────────────────────────

class Blackboard:
    """
    Async Redis blackboard, namespaced per scan.

    Usage:
        bb = await get_blackboard("scan-abc123")
        await bb.set_scope({"files": [...], "service": "auth-api"})
        await bb.post_finding({"file": "...", "cwe": "89", ...})
        findings = await bb.get_findings()
    """

    TTL_SECONDS = 60 * 60 * 24   # 24 hours — scans are ephemeral

    def __init__(self, scan_id: str, client: aioredis.Redis) -> None:
        self.scan_id = scan_id
        self._r = client
        self._prefix = f"brusky:{scan_id}"

    # ── Scope (what the controller seeds before dispatching) ───────────────────

    async def set_scope(self, scope: dict[str, Any]) -> None:
        await self._set("scope", scope)

    async def get_scope(self) -> dict[str, Any]:
        return await self._get("scope") or {}

    # ── Findings (raw — severity not yet assigned) ─────────────────────────────

    async def post_finding(self, finding: dict[str, Any]) -> None:
        """Append a raw finding from any specialist agent."""
        key = f"{self._prefix}:findings"
        await self._r.rpush(key, json.dumps(finding))
        await self._r.expire(key, self.TTL_SECONDS)

    async def get_findings(self) -> list[dict[str, Any]]:
        """Return all raw findings posted so far."""
        key = f"{self._prefix}:findings"
        raw = await self._r.lrange(key, 0, -1)
        return [json.loads(item) for item in raw]

    async def finding_count(self) -> int:
        return await self._r.llen(f"{self._prefix}:findings")

    # ── Agent coverage tracking ────────────────────────────────────────────────

    async def mark_agent(self, agent_name: str, result: str) -> None:
        """Record that an agent has finished. result: 'done' | 'skipped' | 'error'"""
        key = f"{self._prefix}:coverage"
        await self._r.hset(key, agent_name, result)
        await self._r.expire(key, self.TTL_SECONDS)

    async def get_coverage(self) -> dict[str, str]:
        key = f"{self._prefix}:coverage"
        raw = await self._r.hgetall(key)
        return {k.decode(): v.decode() for k, v in raw.items()}

    async def is_agent_done(self, agent_name: str) -> bool:
        key = f"{self._prefix}:coverage"
        val = await self._r.hget(key, agent_name)
        return val in (b"done", b"skipped")

    # ── Scan status ────────────────────────────────────────────────────────────

    async def set_status(self, status: str) -> None:
        await self._r.set(f"{self._prefix}:status", status, ex=self.TTL_SECONDS)

    async def get_status(self) -> str:
        val = await self._r.get(f"{self._prefix}:status")
        return val.decode() if val else "unknown"

    # ── Metadata ───────────────────────────────────────────────────────────────

    async def init(self, trigger: str, target: str) -> None:
        """Initialise a new scan on the blackboard."""
        meta = {
            "scan_id": self.scan_id,
            "trigger": trigger,
            "target": target,
            "started_at": _now(),
        }
        await self._set("meta", meta)
        await self.set_status("running")
        log.info("blackboard.init", scan_id=self.scan_id, trigger=trigger, target=target)

    async def get_meta(self) -> dict[str, Any]:
        return await self._get("meta") or {}

    # ── Teardown ───────────────────────────────────────────────────────────────

    async def clear(self) -> None:
        """Delete all keys for this scan (called after Phase 05 writes to graph)."""
        keys = await self._r.keys(f"{self._prefix}:*")
        if keys:
            await self._r.delete(*keys)
        log.debug("blackboard.cleared", scan_id=self.scan_id)

    # ── Internals ──────────────────────────────────────────────────────────────

    async def _set(self, suffix: str, value: Any) -> None:
        key = f"{self._prefix}:{suffix}"
        await self._r.set(key, json.dumps(value), ex=self.TTL_SECONDS)

    async def _get(self, suffix: str) -> Any:
        key = f"{self._prefix}:{suffix}"
        raw = await self._r.get(key)
        return json.loads(raw) if raw else None


# ── Factory ────────────────────────────────────────────────────────────────────

_redis_client: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = aioredis.from_url(
            settings.redis_url,
            decode_responses=False,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        await _redis_client.ping()
        log.info("redis.connected")
    return _redis_client


async def get_blackboard(scan_id: str) -> Blackboard:
    """Return a Blackboard instance for the given scan_id."""
    client = await _get_redis()
    return Blackboard(scan_id, client)
