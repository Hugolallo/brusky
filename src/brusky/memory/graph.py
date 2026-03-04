"""
Neo4j graph client — persistent world model for the Brusky agent.

Schema (nodes):
  (:Service)   — a discovered microservice / repo
  (:Finding)   — a confirmed security finding
  (:Scan)      — a scan run (timestamp + trigger)

Relationships:
  (:Service)-[:HAS_FINDING]->(:Finding)
  (:Finding)-[:FOUND_IN]->(:Scan)
  (:Service)-[:CALLS]->(:Service)
  (:Service)-[:DEPENDS_ON]->(:Service)

This graph persists between runs. Each scan enriches it.
The Regression Detector (Phase 05) queries this graph to detect
findings that were supposedly fixed but have reappeared.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import structlog
from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
from neo4j.exceptions import ServiceUnavailable

from brusky.config import get_settings

log = structlog.get_logger()


# ── Data shapes ────────────────────────────────────────────────────────────────

class Service:
    __slots__ = (
        "name", "purpose", "language", "team",
        "sensitivity", "exposure", "repo_path",
        "data_types", "entry_points",
    )

    def __init__(
        self,
        name: str,
        purpose: str = "",
        language: str = "",
        team: str = "",
        sensitivity: str = "medium",    # critical | high | medium | low
        exposure: str = "internal",     # public | internal | admin
        repo_path: str = "",
        data_types: list[str] | None = None,    # e.g. ["PII", "auth_tokens"]
        entry_points: list[str] | None = None,  # e.g. ["GET /api/* [public]"]
    ) -> None:
        self.name = name
        self.purpose = purpose
        self.language = language
        self.team = team
        self.sensitivity = sensitivity
        self.exposure = exposure
        self.repo_path = repo_path
        self.data_types: list[str] = data_types or []
        self.entry_points: list[str] = entry_points or []


class Finding:
    __slots__ = (
        "id", "service_name", "cwe_id", "phase", "file", "line",
        "description", "severity", "contextual_score", "justification",
        "patch", "status", "first_seen", "fix_commit",
    )

    def __init__(
        self,
        id: str,
        service_name: str,
        cwe_id: str,
        phase: str,
        file: str,
        line: int,
        description: str,
        severity: str,         # P0 | P1 | P2 | P3
        contextual_score: float = 0.0,
        justification: str = "",
        patch: str = "",
        status: str = "open",  # open | fixed | wont_fix | regression
        first_seen: str = "",
        fix_commit: str = "",
    ) -> None:
        self.id = id
        self.service_name = service_name
        self.cwe_id = cwe_id
        self.phase = phase
        self.file = file
        self.line = line
        self.description = description
        self.severity = severity
        self.contextual_score = contextual_score
        self.justification = justification
        self.patch = patch
        self.status = status
        self.first_seen = first_seen or _now()
        self.fix_commit = fix_commit


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Client ─────────────────────────────────────────────────────────────────────

class GraphClient:
    """
    Async Neo4j client for the Brusky world model.

    Usage:
        async with GraphClient() as g:
            await g.upsert_service(service)
            findings = await g.get_regressions("auth-service")
    """

    def __init__(self) -> None:
        s = get_settings()
        self._driver: AsyncDriver = AsyncGraphDatabase.driver(
            s.neo4j_uri,
            auth=(s.neo4j_user, s.neo4j_password),
            max_connection_lifetime=3600,
        )

    async def connect(self) -> None:
        """Verify connectivity and ensure schema constraints exist."""
        try:
            await self._driver.verify_connectivity()
            log.info("neo4j.connected")
        except ServiceUnavailable as e:
            log.error("neo4j.unavailable", error=str(e))
            raise

        await self._ensure_schema()

    async def close(self) -> None:
        await self._driver.close()

    async def __aenter__(self) -> "GraphClient":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ── Schema ─────────────────────────────────────────────────────────────────

    async def _ensure_schema(self) -> None:
        constraints = [
            "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
            "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
            "CREATE CONSTRAINT scan_id IF NOT EXISTS FOR (s:Scan) REQUIRE s.id IS UNIQUE",
        ]
        async with self._session() as s:
            for c in constraints:
                await s.run(c)
        log.debug("neo4j.schema_ready")

    # ── Service operations ─────────────────────────────────────────────────────

    async def upsert_service(self, service: Service) -> None:
        """Create or update a service node in the world model."""
        async with self._session() as s:
            await s.run(
                """
                MERGE (svc:Service {name: $name})
                SET svc.purpose = $purpose,
                    svc.language = $language,
                    svc.team = $team,
                    svc.sensitivity = $sensitivity,
                    svc.exposure = $exposure,
                    svc.repo_path = $repo_path,
                    svc.data_types = $data_types,
                    svc.entry_points = $entry_points,
                    svc.updated_at = $now
                """,
                name=service.name,
                purpose=service.purpose,
                language=service.language,
                team=service.team,
                sensitivity=service.sensitivity,
                exposure=service.exposure,
                repo_path=service.repo_path,
                data_types=service.data_types,
                entry_points=service.entry_points,
                now=_now(),
            )

    async def update_service_sensitivity(
        self,
        service_name: str,
        sensitivity: str,
        data_types: list[str],
    ) -> None:
        """Update sensitivity classification on an existing service node."""
        async with self._session() as s:
            await s.run(
                """
                MATCH (svc:Service {name: $name})
                SET svc.sensitivity = $sensitivity,
                    svc.data_types = $data_types,
                    svc.updated_at = $now
                """,
                name=service_name,
                sensitivity=sensitivity,
                data_types=data_types,
                now=_now(),
            )

    async def update_service_exposure(
        self,
        service_name: str,
        exposure: str,
        entry_points: list[str],
    ) -> None:
        """Update exposure classification and entry points on an existing service node."""
        async with self._session() as s:
            await s.run(
                """
                MATCH (svc:Service {name: $name})
                SET svc.exposure = $exposure,
                    svc.entry_points = $entry_points,
                    svc.updated_at = $now
                """,
                name=service_name,
                exposure=exposure,
                entry_points=entry_points,
                now=_now(),
            )

    async def add_service_calls(self, from_service: str, to_service: str) -> None:
        """Record that from_service makes runtime HTTP calls to to_service."""
        async with self._session() as s:
            await s.run(
                """
                MATCH (a:Service {name: $from_name})
                MATCH (b:Service {name: $to_name})
                MERGE (a)-[r:CALLS]->(b)
                SET r.updated_at = $now
                """,
                from_name=from_service,
                to_name=to_service,
                now=_now(),
            )

    async def add_service_depends_on(self, from_service: str, to_service: str) -> None:
        """Record that from_service depends on to_service at startup (docker-compose)."""
        async with self._session() as s:
            await s.run(
                """
                MATCH (a:Service {name: $from_name})
                MATCH (b:Service {name: $to_name})
                MERGE (a)-[r:DEPENDS_ON]->(b)
                SET r.updated_at = $now
                """,
                from_name=from_service,
                to_name=to_service,
                now=_now(),
            )

    async def get_service(self, name: str) -> dict[str, Any] | None:
        async with self._session() as s:
            result = await s.run("MATCH (svc:Service {name: $name}) RETURN svc", name=name)
            record = await result.single()
            return dict(record["svc"]) if record else None

    async def get_all_services(self) -> list[dict[str, Any]]:
        async with self._session() as s:
            result = await s.run("MATCH (svc:Service) RETURN svc ORDER BY svc.name")
            return [dict(r["svc"]) async for r in result]

    # ── Finding operations ─────────────────────────────────────────────────────

    async def write_finding(self, finding: Finding, scan_id: str) -> None:
        """Persist a confirmed finding and link it to the scan + service."""
        async with self._session() as s:
            await s.run(
                """
                MERGE (f:Finding {id: $id})
                SET f.service_name = $service_name,
                    f.cwe_id = $cwe_id,
                    f.phase = $phase,
                    f.file = $file,
                    f.line = $line,
                    f.description = $description,
                    f.severity = $severity,
                    f.contextual_score = $contextual_score,
                    f.justification = $justification,
                    f.patch = $patch,
                    f.status = $status,
                    f.first_seen = $first_seen,
                    f.fix_commit = $fix_commit,
                    f.updated_at = $now

                WITH f
                MATCH (svc:Service {name: $service_name})
                MERGE (svc)-[:HAS_FINDING]->(f)

                WITH f
                MATCH (sc:Scan {id: $scan_id})
                MERGE (f)-[:FOUND_IN]->(sc)
                """,
                id=finding.id,
                service_name=finding.service_name,
                cwe_id=finding.cwe_id,
                phase=finding.phase,
                file=finding.file,
                line=finding.line,
                description=finding.description,
                severity=finding.severity,
                contextual_score=finding.contextual_score,
                justification=finding.justification,
                patch=finding.patch,
                status=finding.status,
                first_seen=finding.first_seen,
                fix_commit=finding.fix_commit,
                now=_now(),
                scan_id=scan_id,
            )

    async def mark_finding_fixed(self, finding_id: str, fix_commit: str) -> None:
        async with self._session() as s:
            await s.run(
                "MATCH (f:Finding {id: $id}) SET f.status = 'fixed', f.fix_commit = $commit, f.fixed_at = $now",
                id=finding_id,
                commit=fix_commit,
                now=_now(),
            )

    # ── Regression detection ───────────────────────────────────────────────────

    async def get_regressions(self, service_name: str, cwe_id: str, file: str) -> list[dict[str, Any]]:
        """
        Find prior findings with the same service + CWE + file that were
        previously marked as fixed. These are regressions — higher priority.
        """
        async with self._session() as s:
            result = await s.run(
                """
                MATCH (svc:Service {name: $service_name})-[:HAS_FINDING]->(f:Finding)
                WHERE f.cwe_id = $cwe_id
                  AND f.file = $file
                  AND f.status = 'fixed'
                RETURN f
                ORDER BY f.first_seen DESC
                """,
                service_name=service_name,
                cwe_id=cwe_id,
                file=file,
            )
            return [dict(r["f"]) async for r in result]

    async def get_service_findings(
        self,
        service_name: str,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "MATCH (svc:Service {name: $name})-[:HAS_FINDING]->(f:Finding)"
        if status:
            query += " WHERE f.status = $status"
        query += " RETURN f ORDER BY f.severity, f.contextual_score DESC"

        async with self._session() as s:
            result = await s.run(query, name=service_name, status=status)
            return [dict(r["f"]) async for r in result]

    # ── Scan operations ────────────────────────────────────────────────────────

    async def create_scan(self, scan_id: str, trigger: str, target: str) -> None:
        async with self._session() as s:
            await s.run(
                """
                MERGE (sc:Scan {id: $id})
                SET sc.trigger = $trigger,
                    sc.target = $target,
                    sc.started_at = $now,
                    sc.status = 'running'
                """,
                id=scan_id,
                trigger=trigger,
                target=target,
                now=_now(),
            )

    async def complete_scan(self, scan_id: str, finding_count: int) -> None:
        async with self._session() as s:
            await s.run(
                """
                MATCH (sc:Scan {id: $id})
                SET sc.status = 'complete',
                    sc.completed_at = $now,
                    sc.finding_count = $count
                """,
                id=scan_id,
                now=_now(),
                count=finding_count,
            )

    # ── Helper ─────────────────────────────────────────────────────────────────

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        async with self._driver.session() as session:
            yield session


# ── Singleton factory ──────────────────────────────────────────────────────────

_instance: GraphClient | None = None


async def get_graph() -> GraphClient:
    """Return the connected singleton GraphClient."""
    global _instance
    if _instance is None:
        _instance = GraphClient()
        await _instance.connect()
    return _instance
