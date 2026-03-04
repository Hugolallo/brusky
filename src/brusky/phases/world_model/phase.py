"""
Phase 01 — World Model orchestrator.

Chains the three agents in sequence and returns the enriched service list
ready for Phase 02 Analysis.

  Step 1 — Service Discoverer (Tool Node)
    Detects service boundaries, reads READMEs/manifests/Dockerfiles/CI,
    synthesises name/purpose/team via LLM, maps dependency edges.
    → writes Service nodes + CALLS/DEPENDS_ON edges to Neo4j

  Step 2 — Sensitivity Classifier (LLM Node)
    Reads model files, routes, and dependencies to classify what data
    each service handles. Assigns sensitivity_level + data_types.
    → updates Service nodes: sensitivity, data_types

  Step 3 — Attack Surface Mapper (Tool + LLM Node)
    Reads docker-compose ports, Nginx vhosts, Traefik labels, K8s Ingress,
    and route middleware to classify each service's network exposure.
    → updates Service nodes: exposure, entry_points

The graph persists between runs — every scan enriches it.
By run 5, the agent knows your architecture better than most engineers.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import structlog

from brusky.memory.graph import GraphClient, Service, get_graph
from brusky.phases.world_model.attack_surface_mapper import AttackSurfaceMapper
from brusky.phases.world_model.sensitivity_classifier import SensitivityClassifier
from brusky.phases.world_model.service_discoverer import ServiceDiscoverer

log = structlog.get_logger()


async def run_world_model(
    target_path: str | Path,
    scan_id: str | None = None,
    graph: GraphClient | None = None,
) -> list[Service]:
    """
    Run Phase 01 — World Model.

    Args:
        target_path: Root directory to scan. Can be a single repo or monorepo.
        scan_id:     Correlation ID carried through all phases. Auto-generated
                     if not provided.
        graph:       Optional pre-connected GraphClient (useful in tests).

    Returns:
        List of fully enriched Service objects (sensitivity + exposure set).
    """
    scan_id = scan_id or str(uuid.uuid4())[:8]
    target = Path(target_path).resolve()

    log.info(
        "phase01.start",
        target=str(target),
        scan_id=scan_id,
    )

    # Resolve graph once and share it across all agents
    g = graph or await get_graph()

    # ── Step 1: Service Discoverer ────────────────────────────────────────────
    log.info("phase01.step1.service_discoverer", scan_id=scan_id)
    discoverer = ServiceDiscoverer(graph=g)
    services = await discoverer.discover(target, scan_id=scan_id)

    if not services:
        log.warning("phase01.no_services_found", target=str(target), scan_id=scan_id)
        return []

    # Pull the docker-compose data from the discoverer's file reads — the
    # Attack Surface Mapper needs it for port/network analysis.
    compose = await _load_compose(target)

    # ── Step 2: Sensitivity Classifier ────────────────────────────────────────
    log.info(
        "phase01.step2.sensitivity_classifier",
        service_count=len(services),
        scan_id=scan_id,
    )
    classifier = SensitivityClassifier(graph=g)
    sensitivity_results = await classifier.classify_all(services)

    # Propagate results back onto the Service objects (graph is the source
    # of truth, but we want them on the objects for Phase 02 consumption)
    for svc in services:
        if svc.name in sensitivity_results:
            level, data_types = sensitivity_results[svc.name]
            svc.sensitivity = level
            svc.data_types = data_types

    # ── Step 3: Attack Surface Mapper ─────────────────────────────────────────
    log.info(
        "phase01.step3.attack_surface_mapper",
        service_count=len(services),
        scan_id=scan_id,
    )
    mapper = AttackSurfaceMapper(graph=g)
    exposure_results = await mapper.map_all(services, compose=compose)

    for svc in services:
        if svc.name in exposure_results:
            exposure, entry_points = exposure_results[svc.name]
            svc.exposure = exposure
            svc.entry_points = entry_points

    log.info(
        "phase01.complete",
        scan_id=scan_id,
        services=[
            {
                "name": s.name,
                "sensitivity": s.sensitivity,
                "exposure": s.exposure,
                "data_types": s.data_types,
                "entry_points": len(s.entry_points),
            }
            for s in services
        ],
    )

    return services


# ── Helper ─────────────────────────────────────────────────────────────────────

async def _load_compose(target: Path) -> dict[str, Any]:
    """Read the root docker-compose file if present."""
    import asyncio
    import yaml

    def _read() -> dict[str, Any]:
        for name in ("docker-compose.yml", "docker-compose.yaml"):
            p = target / name
            if p.exists():
                try:
                    with p.open() as f:
                        return yaml.safe_load(f) or {}
                except Exception:
                    pass
        return {}

    return await asyncio.to_thread(_read)
