"""Composer (PHP / Packagist) collector.

Reads composer.lock for resolved versions of every package (direct +
transitive), and composer.json to classify which are direct and which are
dev-only. OSV's ecosystem name for Composer packages is "Packagist".
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from brusky.collectors.base import register
from brusky.model import ResolvedDep

log = structlog.get_logger()

ECOSYSTEM = "Packagist"


def _normalize_version(raw: str) -> str:
    """Composer often prefixes release tags with 'v' (v1.2.3); OSV wants 1.2.3."""
    v = raw.strip()
    if len(v) > 1 and v[0] in "vV" and v[1].isdigit():
        return v[1:]
    return v


class ComposerCollector:
    name = "composer"

    def detect(self, root: Path) -> bool:
        return (root / "composer.lock").is_file()

    def collect(self, root: Path) -> list[ResolvedDep]:
        lock_path = root / "composer.lock"
        try:
            lock = json.loads(lock_path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("composer.lock_parse_error", error=str(exc))
            return []

        direct, direct_dev = self._direct_names(root)

        deps: list[ResolvedDep] = []
        rel = "composer.lock"

        for section, is_dev in (("packages", False), ("packages-dev", True)):
            for pkg in lock.get(section, []):
                name = pkg.get("name")
                version = pkg.get("version")
                if not name or not version:
                    continue
                deps.append(
                    ResolvedDep(
                        ecosystem=ECOSYSTEM,
                        name=name,
                        version=_normalize_version(version),
                        direct=name in (direct_dev if is_dev else direct),
                        dev=is_dev,
                        source=rel,
                    )
                )
        return deps

    @staticmethod
    def _direct_names(root: Path) -> tuple[set[str], set[str]]:
        """Direct package names from composer.json require / require-dev."""
        manifest = root / "composer.json"
        if not manifest.is_file():
            return set(), set()
        try:
            data = json.loads(manifest.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            return set(), set()
        require = {k for k in data.get("require", {}) if "/" in k}
        require_dev = {k for k in data.get("require-dev", {}) if "/" in k}
        return require, require_dev


register(ComposerCollector())
