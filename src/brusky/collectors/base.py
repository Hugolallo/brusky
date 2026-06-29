"""Collector (ecosystem driver) protocol + registry.

A collector reads one ecosystem's resolved dependency state from a target
directory. Collectors are deterministic and offline — they parse lockfiles on
disk and never hit the network. The registry lets the CLI auto-discover which
ecosystems apply to a given repo via `detect()`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from brusky.model import ResolvedDep


@runtime_checkable
class Collector(Protocol):
    """One ecosystem driver: detect presence, then collect resolved deps."""

    name: str

    def detect(self, root: Path) -> bool:
        """True if this ecosystem's manifest/lockfile exists under `root`."""
        ...

    def collect(self, root: Path) -> list[ResolvedDep]:
        """Return resolved dependencies (direct + transitive, with versions)."""
        ...


_REGISTRY: list[Collector] = []


def register(collector: Collector) -> Collector:
    _REGISTRY.append(collector)
    return collector


def all_collectors() -> list[Collector]:
    return list(_REGISTRY)


def active_collectors(root: Path, enabled: set[str] | None = None) -> list[Collector]:
    """Collectors that both `detect()` in `root` and are enabled (if a filter is given)."""
    out = []
    for c in _REGISTRY:
        if enabled is not None and c.name not in enabled:
            continue
        if c.detect(root):
            out.append(c)
    return out
