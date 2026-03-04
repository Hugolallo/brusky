"""
Phase 01 — Service Discoverer (Tool Node)

Crawls one or more repositories, reads READMEs, API schemas, Dockerfiles,
and CI configs to map each service into the Neo4j world model graph.

Outputs written to Neo4j:
  (:Service) nodes  — {name, purpose, language, team, repo_path}
  (:Service)-[:DEPENDS_ON]->(:Service)  — from docker-compose depends_on
  (:Service)-[:CALLS]->(:Service)       — from HTTP client patterns in source

The LLM is used for one task only: synthesising name/purpose/team from
raw file contents. All file reading and dependency extraction is pure Python.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from pathlib import Path
from typing import Any

import structlog

from brusky.llm import get_llm
from brusky.memory.graph import GraphClient, Service, get_graph
from brusky.phases.world_model.dependency_mapper import Edge, map_all_dependencies
from brusky.phases.world_model.file_reader import (
    ServiceFiles,
    detect_service_roots,
    read_service_files,
)

log = structlog.get_logger()


# ── LLM synthesis ──────────────────────────────────────────────────────────────

_SYNTHESIS_PROMPT = """\
You are extracting structured metadata for a software service.
Return ONLY a JSON object — no markdown, no explanation, no surrounding text.

Files found in the service directory:
{context}

Return this exact shape:
{{
  "name": "short service name (use directory name '{dir_name}' if unclear)",
  "purpose": "one sentence: what does this service do?",
  "team": "team or owner name if found in the files, else null"
}}"""


async def _synthesise_metadata(files: ServiceFiles) -> dict[str, Any]:
    """
    Call the LLM to extract name, purpose, and team from raw file contents.
    Falls back to sensible defaults if the LLM call fails or returns invalid JSON.
    """
    llm = get_llm("world_model", "service_discoverer")

    context_parts: list[str] = []

    if files.readme:
        context_parts.append(f"README:\n{files.readme[:1500]}")

    for fname, content in list(files.language_manifests.items())[:2]:
        snippet = (
            json.dumps(content, indent=2)[:600]
            if isinstance(content, dict) and "_raw" not in content
            else str(content.get("_raw", ""))[:400]
        )
        context_parts.append(f"{fname}:\n{snippet}")

    if files.codeowners:
        context_parts.append(f"CODEOWNERS:\n{files.codeowners[:300]}")

    if files.openapi_specs:
        spec = files.openapi_specs[0]["data"]
        if isinstance(spec, dict):
            info = spec.get("info", {})
            context_parts.append(
                f"OpenAPI info:\n{json.dumps(info, indent=2)[:300]}"
            )

    if not context_parts:
        # No useful content — skip LLM, return defaults
        return {"name": files.name, "purpose": "", "team": None}

    prompt = _SYNTHESIS_PROMPT.format(
        context="\n\n".join(context_parts),
        dir_name=files.name,
    )

    try:
        response = await llm.complete(
            [{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=256,
        )
        raw = response.content.strip()

        # Strip markdown code fences if the model wrapped the JSON
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        data = json.loads(raw)
        return {
            "name": str(data.get("name") or files.name),
            "purpose": str(data.get("purpose") or ""),
            "team": data.get("team") or None,
        }
    except Exception as exc:
        log.warning("world_model.synthesis_failed", service=files.name, error=str(exc))
        return {"name": files.name, "purpose": "", "team": None}


# ── Main discoverer ────────────────────────────────────────────────────────────

class ServiceDiscoverer:
    """
    Tool Node for Phase 01 — discovers services and writes them to the graph.

    Usage:
        discoverer = ServiceDiscoverer()
        services = await discoverer.discover("/path/to/repo", scan_id="scan-abc")
    """

    def __init__(self, graph: GraphClient | None = None) -> None:
        self._graph = graph   # injected or lazily fetched

    async def _get_graph(self) -> GraphClient:
        if self._graph is None:
            self._graph = await get_graph()
        return self._graph

    async def discover(
        self,
        target_path: str | Path,
        scan_id: str | None = None,
    ) -> list[Service]:
        """
        Main entry point. Discovers all services under target_path, writes
        them to Neo4j, and returns the list of Service objects.

        Args:
            target_path: Root directory to scan (single repo or monorepo).
            scan_id:     Optional scan identifier for logging correlation.
        """
        target = Path(target_path).resolve()
        scan_id = scan_id or str(uuid.uuid4())[:8]

        log.info("world_model.discoverer.start", target=str(target), scan_id=scan_id)

        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        # Step 1 — detect service boundaries
        roots = detect_service_roots(target)
        log.info("world_model.discoverer.roots_found", count=len(roots), scan_id=scan_id)

        # Step 2 — read files for every service root (I/O bound, run concurrently)
        files_list: list[ServiceFiles] = await asyncio.gather(
            *[asyncio.to_thread(read_service_files, root) for root in roots]
        )

        # Step 3 — synthesise metadata via LLM (network bound, run concurrently)
        metadata_list: list[dict[str, Any]] = await asyncio.gather(
            *[_synthesise_metadata(f) for f in files_list]
        )

        # Step 4 — build Service objects
        services: list[Service] = []
        service_roots: dict[str, Path] = {}

        for files, meta in zip(files_list, metadata_list):
            svc = Service(
                name=meta["name"],
                purpose=meta["purpose"],
                language=files.language_summary(),
                team=meta["team"] or "",
                repo_path=str(files.root),
            )
            services.append(svc)
            service_roots[svc.name] = files.root

        # Step 5 — map dependencies (compose + source scan)
        # Use the first docker-compose found across all file sets
        compose: dict[str, Any] = {}
        for f in files_list:
            if f.docker_compose:
                compose = f.docker_compose
                break

        edges = map_all_dependencies(service_roots, compose)

        # Step 6 — write everything to the graph
        graph = await self._get_graph()
        await self._write_services(graph, services)
        await self._write_edges(graph, edges, service_roots)

        log.info(
            "world_model.discoverer.complete",
            services=[s.name for s in services],
            edges=len(edges),
            scan_id=scan_id,
        )
        return services

    # ── Graph writes ───────────────────────────────────────────────────────────

    async def _write_services(self, graph: GraphClient, services: list[Service]) -> None:
        await asyncio.gather(*[graph.upsert_service(s) for s in services])
        log.debug("world_model.discoverer.services_written", count=len(services))

    async def _write_edges(
        self,
        graph: GraphClient,
        edges: list[Edge],
        service_roots: dict[str, Path],
    ) -> None:
        known = set(service_roots.keys())
        tasks = []
        for edge in edges:
            # Only write edges between services that exist in the graph
            if edge.from_service not in known or edge.to_service not in known:
                continue
            if edge.rel_type == "DEPENDS_ON":
                tasks.append(graph.add_service_depends_on(edge.from_service, edge.to_service))
            elif edge.rel_type == "CALLS":
                tasks.append(graph.add_service_calls(edge.from_service, edge.to_service))

        if tasks:
            await asyncio.gather(*tasks)
        log.debug("world_model.discoverer.edges_written", count=len(tasks))
