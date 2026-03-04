"""
Phase 01 — Attack Surface Mapper (Tool + LLM Node)

Reads ingress configs, API gateways, and route definitions to determine
which services are internet-facing and where their public entry points are.

This is what makes exploitability scoring in Phase 03 meaningful:
a SQL injection on a public /api endpoint is P0 material; the same pattern
on an internal-only admin tool behind a VPN is P2 at most.

Tool part (pure Python):
  - docker-compose ports/networks (published ports = externally reachable)
  - Nginx/Apache virtual host configs (server_name, location blocks)
  - Traefik labels (Host() rules, middlewares)
  - Kubernetes Ingress manifests (kind: Ingress, LoadBalancer Services)
  - Route files — auth middleware presence per path group

LLM part (Haiku):
  - Synthesises ambiguous signals into a final exposure verdict
  - Enumerates concrete entry points with exposure tier

Outputs written to Neo4j service node:
  exposure:      public | internal | admin
  entry_points:  ["GET /api/* [public]", "* /admin/* [admin,auth_required]", …]
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
import structlog

from brusky.llm import get_llm
from brusky.memory.graph import GraphClient, Service, get_graph

log = structlog.get_logger()


# ── Network signal data model ──────────────────────────────────────────────────

@dataclass
class NetworkSignals:
    """Raw signals collected from infra config files — no LLM involved."""
    # Docker
    published_ports: list[str] = field(default_factory=list)   # ["80:8080"]
    is_on_internal_network: bool = False
    traefik_rules: list[str] = field(default_factory=list)      # ["Host(`api.example.com`)"]
    traefik_auth_middlewares: list[str] = field(default_factory=list)

    # Nginx / Apache
    nginx_server_names: list[str] = field(default_factory=list) # ["api.example.com"]
    nginx_locations: list[str] = field(default_factory=list)    # ["/api", "/admin"]

    # Kubernetes
    k8s_ingress_hosts: list[str] = field(default_factory=list)  # ["api.example.com/api"]
    k8s_loadbalancer_ports: list[str] = field(default_factory=list)

    # Routes
    public_route_groups: list[str] = field(default_factory=list)    # ["GET /", "GET /api/v1/*"]
    auth_route_groups: list[str] = field(default_factory=list)      # ["* /dashboard/*"]
    admin_route_groups: list[str] = field(default_factory=list)     # ["* /admin/*"]

    def is_clearly_internal(self) -> bool:
        """No published ports, no ingress, no external hostname."""
        return (
            not self.published_ports
            and not self.nginx_server_names
            and not self.traefik_rules
            and not self.k8s_ingress_hosts
            and not self.k8s_loadbalancer_ports
        )

    def has_admin_surface(self) -> bool:
        return bool(
            self.admin_route_groups
            or any("/admin" in loc for loc in self.nginx_locations)
        )

    def summary(self) -> str:
        parts: list[str] = []
        if self.published_ports:
            parts.append(f"Published ports: {', '.join(self.published_ports)}")
        if self.nginx_server_names:
            parts.append(f"Nginx vhosts: {', '.join(self.nginx_server_names)}")
        if self.traefik_rules:
            parts.append(f"Traefik rules: {', '.join(self.traefik_rules)}")
        if self.k8s_ingress_hosts:
            parts.append(f"K8s ingress: {', '.join(self.k8s_ingress_hosts)}")
        if self.is_on_internal_network:
            parts.append("On internal-only Docker network")
        if self.public_route_groups:
            parts.append(f"Public routes: {', '.join(self.public_route_groups[:6])}")
        if self.auth_route_groups:
            parts.append(f"Auth-protected routes: {', '.join(self.auth_route_groups[:6])}")
        if self.admin_route_groups:
            parts.append(f"Admin routes: {', '.join(self.admin_route_groups[:6])}")
        return "\n".join(parts) if parts else "(no network signals found)"


# ── Tool: Docker Compose signals ──────────────────────────────────────────────

def _signals_from_compose(
    compose: dict[str, Any],
    service_name: str,
) -> NetworkSignals:
    """Extract network exposure signals for one service from docker-compose data."""
    signals = NetworkSignals()
    services = compose.get("services", {})
    svc = services.get(service_name, {})
    if not isinstance(svc, dict):
        return signals

    # Published ports
    for port in svc.get("ports", []):
        port_str = str(port)
        if ":" in port_str or port_str.isdigit():
            signals.published_ports.append(port_str)

    # Internal network check
    compose_networks = compose.get("networks", {})
    svc_networks = svc.get("networks", {})
    if isinstance(svc_networks, list):
        svc_network_names = svc_networks
    elif isinstance(svc_networks, dict):
        svc_network_names = list(svc_networks.keys())
    else:
        svc_network_names = []

    for net_name in svc_network_names:
        net_cfg = compose_networks.get(net_name, {})
        if isinstance(net_cfg, dict) and net_cfg.get("internal") is True:
            signals.is_on_internal_network = True

    # Traefik labels
    labels = svc.get("labels", {})
    if isinstance(labels, list):
        labels = {lbl.split("=")[0]: lbl.split("=", 1)[1] for lbl in labels if "=" in lbl}
    for key, val in labels.items():
        if "traefik.http.routers" in key and ".rule" in key:
            signals.traefik_rules.append(str(val))
        if "traefik.http.middlewares" in key and ("auth" in key.lower() or "basic" in key.lower()):
            signals.traefik_auth_middlewares.append(key)

    return signals


# ── Tool: Nginx / Apache signals ──────────────────────────────────────────────

_NGINX_GLOBS = [
    "nginx.conf", "conf.d/*.conf", "conf.d/**/*.conf",
    "sites-available/*.conf", "sites-enabled/*.conf",
    "nginx/**/*.conf", "docker/nginx/**/*.conf",
]
_APACHE_GLOBS = ["httpd.conf", "apache2.conf", "sites-available/*.conf"]


def _signals_from_nginx(root: Path) -> NetworkSignals:
    signals = NetworkSignals()
    texts: list[str] = []

    for glob in _NGINX_GLOBS + _APACHE_GLOBS:
        for path in root.glob(glob):
            if path.is_file():
                try:
                    texts.append(path.read_text(errors="replace")[:3_000])
                except OSError:
                    pass

    combined = "\n".join(texts)
    if not combined:
        return signals

    # server_name directives
    for m in re.finditer(r"server_name\s+([^;]+);", combined):
        for name in m.group(1).split():
            name = name.strip()
            if name and name != "_" and "localhost" not in name and "127.0.0.1" not in name:
                signals.nginx_server_names.append(name)

    # location blocks
    for m in re.finditer(r"location\s+([^\s{]+)\s*\{", combined):
        signals.nginx_locations.append(m.group(1))

    return signals


# ── Tool: Kubernetes signals ───────────────────────────────────────────────────

def _signals_from_kubernetes(root: Path) -> NetworkSignals:
    signals = NetworkSignals()

    for path in list(root.rglob("*.yaml"))[:40] + list(root.rglob("*.yml"))[:40]:
        if any(p in {".git", "vendor", "node_modules"} for p in path.parts):
            continue
        try:
            with path.open() as f:
                docs = list(yaml.safe_load_all(f))
        except Exception:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")

            if kind == "Ingress":
                spec = doc.get("spec", {}) or {}
                for rule in spec.get("rules", []):
                    if not isinstance(rule, dict):
                        continue
                    host = rule.get("host", "")
                    for path_item in (rule.get("http") or {}).get("paths", []):
                        p = (path_item.get("path") or "/") if isinstance(path_item, dict) else "/"
                        signals.k8s_ingress_hosts.append(f"{host}{p}".rstrip("/") or "/")

            elif kind == "Service":
                svc_type = (doc.get("spec") or {}).get("type", "ClusterIP")
                if svc_type in ("LoadBalancer", "NodePort"):
                    for port in (doc.get("spec") or {}).get("ports", []):
                        if isinstance(port, dict):
                            signals.k8s_loadbalancer_ports.append(str(port.get("port", "")))

    return signals


# ── Tool: Route file signals ───────────────────────────────────────────────────

_AUTH_PATTERNS = re.compile(
    r"auth|sanctum|authenticate|login_required|@login|@auth|jwt_required|protect",
    re.IGNORECASE,
)
_ADMIN_PATTERNS = re.compile(
    r"/admin|admin\b|role.*admin|is_staff|is_superuser|@staff",
    re.IGNORECASE,
)
_ROUTE_GLOBS = [
    "routes/api.php", "routes/web.php",
    "**/urls.py", "**/routes.py",
    "**/routes/**/*.ts", "**/routes/**/*.js",
    "config/routes.rb",
    "**/router/index.js", "**/router/index.ts",
]


def _signals_from_routes(root: Path) -> NetworkSignals:
    signals = NetworkSignals()

    for glob in _ROUTE_GLOBS:
        for path in root.glob(glob):
            if not path.is_file():
                continue
            try:
                text = path.read_text(errors="replace")[:4_000]
            except OSError:
                continue

            # Extract path strings from route definitions
            paths_found = re.findall(r"""['"](/[a-zA-Z0-9/_\-{}:*]+)['"]\s*""", text)

            for route_path in paths_found:
                # Classify the context around this route definition
                # Find a window of 200 chars around the match
                idx = text.find(f"'{route_path}'")
                if idx == -1:
                    idx = text.find(f'"{route_path}"')
                window = text[max(0, idx - 100): idx + 200] if idx != -1 else ""

                if _ADMIN_PATTERNS.search(route_path) or _ADMIN_PATTERNS.search(window):
                    signals.admin_route_groups.append(route_path)
                elif _AUTH_PATTERNS.search(window):
                    signals.auth_route_groups.append(route_path)
                else:
                    signals.public_route_groups.append(route_path)

    # Deduplicate
    signals.public_route_groups = list(dict.fromkeys(signals.public_route_groups))[:20]
    signals.auth_route_groups = list(dict.fromkeys(signals.auth_route_groups))[:20]
    signals.admin_route_groups = list(dict.fromkeys(signals.admin_route_groups))[:10]

    return signals


def _merge_signals(*parts: NetworkSignals) -> NetworkSignals:
    merged = NetworkSignals()
    for s in parts:
        merged.published_ports.extend(s.published_ports)
        merged.traefik_rules.extend(s.traefik_rules)
        merged.traefik_auth_middlewares.extend(s.traefik_auth_middlewares)
        merged.nginx_server_names.extend(s.nginx_server_names)
        merged.nginx_locations.extend(s.nginx_locations)
        merged.k8s_ingress_hosts.extend(s.k8s_ingress_hosts)
        merged.k8s_loadbalancer_ports.extend(s.k8s_loadbalancer_ports)
        merged.public_route_groups.extend(s.public_route_groups)
        merged.auth_route_groups.extend(s.auth_route_groups)
        merged.admin_route_groups.extend(s.admin_route_groups)
        if s.is_on_internal_network:
            merged.is_on_internal_network = True
    return merged


def collect_network_signals(
    repo_path: Path,
    service_name: str,
    compose: dict[str, Any],
) -> NetworkSignals:
    compose_signals = _signals_from_compose(compose, service_name)
    nginx_signals = _signals_from_nginx(repo_path)
    k8s_signals = _signals_from_kubernetes(repo_path)
    route_signals = _signals_from_routes(repo_path)
    return _merge_signals(compose_signals, nginx_signals, k8s_signals, route_signals)


# ── LLM: exposure classification ──────────────────────────────────────────────

_EXPOSURE_PROMPT = """\
Classify the network exposure of this software service and list its entry points.

Service: {name}
Purpose: {purpose}

Network signals collected from infra config files:
{signals_summary}

Exposure tiers:
  public  — reachable from the internet with no network-level barrier
  admin   — reachable only from restricted networks / VPN / internal IP,
            or has exclusively admin/staff routes
  internal — no external exposure; only reachable within the service mesh

Entry point format: "{method} {path} [{tier}]"
  tier must be one of: public, admin, internal
  Use * for method when not restricted to a specific verb.
  Include auth_required in brackets if all routes at that path require auth.
  Examples: "GET /api/v1/* [public]", "* /admin/* [admin,auth_required]"

Return ONLY valid JSON (no markdown):
{{
  "exposure": "public|internal|admin",
  "entry_points": ["list", "of", "entry", "point", "strings"],
  "reasoning": "one sentence"
}}

If there are no signals at all, return exposure=internal and empty entry_points."""


async def _llm_classify_exposure(
    service: Service,
    signals: NetworkSignals,
) -> tuple[str, list[str]]:
    """
    Call the LLM with collected network signals to get final exposure verdict.
    Falls back to signal-based heuristic if the LLM call fails.
    """
    llm = get_llm("world_model", "attack_surface_mapper")

    prompt = _EXPOSURE_PROMPT.format(
        name=service.name,
        purpose=service.purpose or "(unknown)",
        signals_summary=signals.summary(),
    )

    try:
        response = await llm.complete(
            [{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=512,
        )
        raw = response.content.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        data = json.loads(raw)
        exposure = str(data.get("exposure", "internal"))
        entry_points = [str(ep) for ep in data.get("entry_points", [])]

        if exposure not in {"public", "internal", "admin"}:
            exposure = "internal"

        log.debug(
            "world_model.mapper.llm_result",
            service=service.name,
            exposure=exposure,
            entry_point_count=len(entry_points),
            reasoning=data.get("reasoning", ""),
        )
        return exposure, entry_points

    except Exception as exc:
        log.warning("world_model.mapper.llm_failed", service=service.name, error=str(exc))
        return _heuristic_exposure(signals), _heuristic_entry_points(signals)


def _heuristic_exposure(signals: NetworkSignals) -> str:
    """Derive exposure level from signals without LLM."""
    if signals.is_clearly_internal():
        return "internal"
    if signals.has_admin_surface() and not signals.public_route_groups:
        return "admin"
    return "public"


def _heuristic_entry_points(signals: NetworkSignals) -> list[str]:
    """Build a basic entry point list from signals without LLM."""
    eps: list[str] = []
    for path in signals.public_route_groups[:10]:
        eps.append(f"* {path} [public]")
    for path in signals.admin_route_groups[:5]:
        eps.append(f"* {path} [admin,auth_required]")
    for host in (signals.nginx_server_names + signals.k8s_ingress_hosts)[:3]:
        if not any(host in ep for ep in eps):
            eps.append(f"* {host} [public]")
    return eps


# ── Main mapper ────────────────────────────────────────────────────────────────

class AttackSurfaceMapper:
    """
    Tool + LLM Node for Phase 01 — maps network exposure for each service.

    Usage:
        mapper = AttackSurfaceMapper()
        await mapper.map_all(services, compose=compose_dict)
    """

    def __init__(self, graph: GraphClient | None = None) -> None:
        self._graph = graph

    async def _get_graph(self) -> GraphClient:
        if self._graph is None:
            self._graph = await get_graph()
        return self._graph

    async def map(
        self,
        service: Service,
        compose: dict[str, Any],
    ) -> tuple[str, list[str]]:
        """
        Map exposure for a single service. Returns (exposure, entry_points).
        Updates the graph node in place.
        """
        repo_path = Path(service.repo_path) if service.repo_path else None

        if repo_path and repo_path.exists():
            signals = await asyncio.to_thread(
                collect_network_signals, repo_path, service.name, compose
            )
        else:
            signals = NetworkSignals()

        exposure, entry_points = await _llm_classify_exposure(service, signals)

        graph = await self._get_graph()
        await graph.update_service_exposure(service.name, exposure, entry_points)

        log.info(
            "world_model.mapper.done",
            service=service.name,
            exposure=exposure,
            entry_points=entry_points,
        )
        return exposure, entry_points

    async def map_all(
        self,
        services: list[Service],
        compose: dict[str, Any] | None = None,
    ) -> dict[str, tuple[str, list[str]]]:
        """
        Map exposure for all services concurrently.
        Returns {service_name: (exposure, entry_points)}.
        """
        compose = compose or {}
        semaphore = asyncio.Semaphore(4)

        async def _bounded(svc: Service) -> tuple[str, tuple[str, list[str]]]:
            async with semaphore:
                result = await self.map(svc, compose)
                return svc.name, result

        results = await asyncio.gather(*[_bounded(s) for s in services])

        exposure_summary = {name: exp for name, (exp, _) in results}
        log.info(
            "world_model.mapper.all_done",
            count=len(results),
            breakdown=exposure_summary,
        )
        return dict(results)
