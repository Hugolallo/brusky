"""npm (JavaScript / npm) collector.

Reads package-lock.json for resolved versions of every package in the tree.
Handles both modern (lockfileVersion 2/3, `packages` map) and legacy
(lockfileVersion 1, nested `dependencies`) formats. OSV's ecosystem name is
"npm". Direct vs transitive is taken from package.json's dependency sections.
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from brusky.collectors.base import register
from brusky.model import ResolvedDep

log = structlog.get_logger()

ECOSYSTEM = "npm"


def _name_from_pkg_path(path: str) -> str:
    """'node_modules/@scope/pkg/node_modules/bar' -> 'bar'."""
    marker = "node_modules/"
    idx = path.rfind(marker)
    return path[idx + len(marker):] if idx >= 0 else path


class NpmCollector:
    name = "npm"

    def detect(self, root: Path) -> bool:
        return (root / "package-lock.json").is_file()

    def collect(self, root: Path) -> list[ResolvedDep]:
        lock_path = root / "package-lock.json"
        try:
            lock = json.loads(lock_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("npm.lock_parse_error", error=str(exc))
            return []

        rel = "package-lock.json"
        direct = self._direct_names(root)

        if "packages" in lock:
            return self._collect_v2(lock["packages"], direct, rel)
        if "dependencies" in lock:
            return self._collect_v1(lock["dependencies"], direct, rel)
        return []

    def _collect_v2(self, packages: dict, direct: set[str], rel: str) -> list[ResolvedDep]:
        deps: list[ResolvedDep] = []
        for path, entry in packages.items():
            if path == "":      # the project root itself, not a dependency
                continue
            name = entry.get("name") or _name_from_pkg_path(path)
            version = entry.get("version")
            if not name or not version:
                continue
            deps.append(
                ResolvedDep(
                    ecosystem=ECOSYSTEM,
                    name=name,
                    version=version,
                    direct=name in direct,
                    dev=bool(entry.get("dev", False)),
                    source=rel,
                )
            )
        return deps

    def _collect_v1(self, tree: dict, direct: set[str], rel: str) -> list[ResolvedDep]:
        deps: list[ResolvedDep] = []

        def walk(node: dict) -> None:
            for name, entry in node.items():
                version = entry.get("version")
                if name and version:
                    deps.append(
                        ResolvedDep(
                            ecosystem=ECOSYSTEM,
                            name=name,
                            version=version,
                            direct=name in direct,
                            dev=bool(entry.get("dev", False)),
                            source=rel,
                        )
                    )
                if isinstance(entry.get("dependencies"), dict):
                    walk(entry["dependencies"])

        walk(tree)
        return deps

    @staticmethod
    def _direct_names(root: Path) -> set[str]:
        manifest = root / "package.json"
        if not manifest.is_file():
            return set()
        try:
            data = json.loads(manifest.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            return set()
        names: set[str] = set()
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            names.update(data.get(section, {}).keys())
        return names


register(NpmCollector())
