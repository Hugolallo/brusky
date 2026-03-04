"""
Dependency mapper — extracts service-to-service edges.

Two sources:
  1. docker-compose.yml — `depends_on` gives DEPENDS_ON edges (infra truth)
  2. HTTP client calls in source files — gives CALLS edges (runtime truth)
     (lightweight regex scan, not full AST — catches the obvious patterns)

Edge types mirror the Neo4j schema in memory/graph.py:
  DEPENDS_ON  — service A needs service B to start (docker-compose depends_on)
  CALLS       — service A makes HTTP requests to service B at runtime
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger()


@dataclass(frozen=True)
class Edge:
    from_service: str
    to_service: str
    rel_type: str    # "CALLS" | "DEPENDS_ON"


# ── Docker Compose edges ───────────────────────────────────────────────────────

def edges_from_compose(compose: dict[str, Any], service_name: str) -> list[Edge]:
    """
    Extract DEPENDS_ON edges from a docker-compose dict for a named service.

    Handles both list form:
      depends_on:
        - redis
        - postgres

    And condition form (Compose v3):
      depends_on:
        redis:
          condition: service_healthy
    """
    services = compose.get("services", {})
    svc_cfg = services.get(service_name, {})
    if not isinstance(svc_cfg, dict):
        return []

    deps = svc_cfg.get("depends_on", [])
    dep_names: list[str]

    if isinstance(deps, list):
        dep_names = [str(d) for d in deps]
    elif isinstance(deps, dict):
        dep_names = list(deps.keys())
    else:
        dep_names = []

    return [
        Edge(from_service=service_name, to_service=dep, rel_type="DEPENDS_ON")
        for dep in dep_names
    ]


def all_compose_edges(compose: dict[str, Any]) -> list[Edge]:
    """Return DEPENDS_ON edges for every service in a docker-compose file."""
    edges: list[Edge] = []
    for svc_name in compose.get("services", {}):
        edges.extend(edges_from_compose(compose, svc_name))
    return edges


# ── HTTP call edges (lightweight regex) ───────────────────────────────────────

# Patterns that suggest an outbound HTTP call.
# We look for known service names appearing in URL strings.
_HTTP_PATTERNS = [
    re.compile(r"""https?://([a-zA-Z0-9_\-]+)[:/]"""),          # http://service-name:port
    re.compile(r"""['"](https?://\$\{?([A-Z_]+)_(?:HOST|URL|BASE)[^'"]*)['"]\s*"""),
    re.compile(r"""env\(['"]([A-Z_]+)_(?:HOST|URL|BASE)['"]\)"""),
    re.compile(r"""getenv\(['"]([A-Z_]+)_(?:HOST|URL|BASE)['"]\)"""),
]


def edges_from_source(
    service_name: str,
    root: Path,
    known_services: set[str],
    max_files: int = 50,
) -> list[Edge]:
    """
    Scan source files for outbound HTTP calls to known service names.

    This is intentionally shallow — it catches hardcoded hostnames and
    environment variable names that follow the pattern SERVICE_HOST/URL/BASE.
    It is not a full call graph — that requires runtime tracing or full AST.
    """
    if not known_services:
        return []

    edges: set[Edge] = set()
    extensions = {".php", ".py", ".js", ".ts", ".go", ".rb", ".java"}
    files_scanned = 0

    for path in root.rglob("*"):
        if files_scanned >= max_files:
            break
        if not path.is_file() or path.suffix not in extensions:
            continue
        if any(part in {".git", "vendor", "node_modules", "__pycache__"} for part in path.parts):
            continue

        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue

        files_scanned += 1

        # Direct hostname match: look for known service names in URLs
        for svc in known_services:
            if svc == service_name:
                continue
            # Match service name as a standalone hostname segment
            pattern = re.compile(rf"""https?://{re.escape(svc)}[:/\s'"]""")
            if pattern.search(text):
                edges.add(Edge(from_service=service_name, to_service=svc, rel_type="CALLS"))
                continue

            # Match env var convention: SERVICENAME_HOST or SERVICENAME_URL
            env_pattern = re.compile(
                rf"""['"_]?{re.escape(svc.upper().replace("-", "_"))}_(?:HOST|URL|BASE|ENDPOINT)['"_]?""",
                re.IGNORECASE,
            )
            if env_pattern.search(text):
                edges.add(Edge(from_service=service_name, to_service=svc, rel_type="CALLS"))

    log.debug(
        "world_model.dep_mapper.source_scan",
        service=service_name,
        files_scanned=files_scanned,
        edges_found=len(edges),
    )
    return list(edges)


# ── Combined mapper ────────────────────────────────────────────────────────────

def map_all_dependencies(
    service_roots: dict[str, Path],
    compose: dict[str, Any],
) -> list[Edge]:
    """
    Build the full edge list across all known services.

    Args:
        service_roots: {service_name: root_path}
        compose:       parsed docker-compose dict (may be empty)

    Returns:
        Deduplicated list of Edges with rel_type DEPENDS_ON or CALLS.
    """
    known = set(service_roots.keys())
    all_edges: set[Edge] = set()

    # Compose-level DEPENDS_ON (highest confidence)
    for edge in all_compose_edges(compose):
        # Only add edges between known services (filter out infra like redis/postgres)
        if edge.to_service in known:
            all_edges.add(edge)

    # Source-level CALLS (best-effort)
    for svc_name, root in service_roots.items():
        for edge in edges_from_source(svc_name, root, known):
            all_edges.add(edge)

    log.info(
        "world_model.dep_mapper.complete",
        total_edges=len(all_edges),
        depends_on=sum(1 for e in all_edges if e.rel_type == "DEPENDS_ON"),
        calls=sum(1 for e in all_edges if e.rel_type == "CALLS"),
    )
    return list(all_edges)
