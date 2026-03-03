"""
Skill registry — discovers and matches skills to a scan target.

Skills are declared as YAML manifests in config/skills/*.yaml.
The registry loads all manifests and, given a target directory, returns
only the skills whose trigger patterns match files that actually exist.

This is what makes the agent stack-agnostic: it never hardcodes which
scanners to run. Someone adding a Django stack drops in:
  config/skills/audit-django.yaml
  .claude/commands/audit-django.md
and the agent picks them up automatically on the next scan.

Usage:
    registry = load_registry()
    active = registry.match(target_path="/path/to/repo")
    for skill in active:
        print(skill.command, skill.matched_by)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import structlog
import yaml

log = structlog.get_logger()

_SKILLS_DIR = Path(__file__).parent.parent.parent.parent / "config" / "skills"


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class Skill:
    id: str
    name: str
    command: str
    version: str
    description: str
    category: str                   # static | deps | config | framework | frontend | infra
    stack_languages: list[str]
    stack_frameworks: list[str]
    trigger_patterns: list[str]
    output_format: str
    severity_levels: list[str]
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    # Set after matching — which patterns triggered this skill
    matched_by: list[str] = field(default_factory=list, repr=False)

    @classmethod
    def from_yaml(cls, data: dict[str, Any]) -> "Skill":
        stack = data.get("stack", {})
        output = data.get("output", {})
        triggers = data.get("triggers", {})
        return cls(
            id=data["id"],
            name=data["name"],
            command=data["command"],
            version=str(data.get("version", "1.0")),
            description=data.get("description", ""),
            category=data.get("category", "static"),
            stack_languages=stack.get("languages", []),
            stack_frameworks=stack.get("frameworks", []),
            trigger_patterns=triggers.get("file_patterns", []),
            output_format=output.get("format", "grouped_by_severity"),
            severity_levels=output.get("severity_levels", ["Critical", "High", "Medium", "Low"]),
            raw=data,
        )


# ── Registry ───────────────────────────────────────────────────────────────────

class SkillRegistry:
    """
    Holds all discovered skills and matches them to a target directory.

    The registry is the single source of truth for what scanners are available.
    The Phase 02 Controller calls `registry.match(target)` to get the list of
    specialists to dispatch, then posts each to the blackboard.
    """

    def __init__(self, skills: list[Skill]) -> None:
        self._skills = skills

    @property
    def all(self) -> list[Skill]:
        return list(self._skills)

    def get(self, skill_id: str) -> Skill | None:
        return next((s for s in self._skills if s.id == skill_id), None)

    def by_category(self, category: str) -> list[Skill]:
        return [s for s in self._skills if s.category == category]

    def match(self, target_path: str | Path) -> list[Skill]:
        """
        Return skills whose trigger patterns match at least one file
        in the given target directory.

        Walks the target once and tests each file path against all patterns.
        Skills with no trigger patterns are always included.
        """
        target = Path(target_path).resolve()
        if not target.exists():
            log.warning("skills.match.target_not_found", path=str(target))
            return []

        # Collect relative file paths (limit depth to keep it fast)
        file_paths = _walk_relative(target, max_depth=6)
        log.debug("skills.match.files_scanned", count=len(file_paths), target=str(target))

        matched: list[Skill] = []
        for skill in self._skills:
            if not skill.trigger_patterns:
                # No pattern restriction — always run
                skill.matched_by = ["(always)"]
                matched.append(skill)
                continue

            hits = _find_pattern_hits(skill.trigger_patterns, file_paths)
            if hits:
                import copy
                s = copy.copy(skill)
                s.matched_by = hits
                matched.append(s)

        log.info(
            "skills.match.result",
            total=len(self._skills),
            matched=[s.id for s in matched],
            skipped=[s.id for s in self._skills if s.id not in {m.id for m in matched}],
        )
        return matched

    def summary(self) -> str:
        """Human-readable registry summary — used by audit-stack orchestrator."""
        lines = [f"Registered skills ({len(self._skills)}):"]
        for s in self._skills:
            lines.append(f"  [{s.category:10s}] {s.id:25s} — {s.name}")
        return "\n".join(lines)


# ── Loader ─────────────────────────────────────────────────────────────────────

def load_registry(skills_dir: str | Path | None = None) -> SkillRegistry:
    """
    Discover all skill manifests in the skills directory and return a registry.

    Args:
        skills_dir: Override the default `config/skills/` directory.
                    Useful in tests or when running from a non-standard location.
    """
    directory = Path(skills_dir or os.environ.get("BRUSKY_SKILLS_DIR", str(_SKILLS_DIR)))

    if not directory.exists():
        log.warning("skills.registry.dir_not_found", path=str(directory))
        return SkillRegistry([])

    skills: list[Skill] = []
    for yaml_path in sorted(directory.glob("*.yaml")):
        try:
            with yaml_path.open() as f:
                data = yaml.safe_load(f)
            if not data or "id" not in data:
                log.warning("skills.registry.invalid_manifest", file=yaml_path.name)
                continue
            skills.append(Skill.from_yaml(data))
            log.debug("skills.registry.loaded", skill=data["id"])
        except Exception as exc:
            log.error("skills.registry.load_error", file=yaml_path.name, error=str(exc))

    log.info("skills.registry.ready", count=len(skills), ids=[s.id for s in skills])
    return SkillRegistry(skills)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _walk_relative(root: Path, max_depth: int) -> list[str]:
    """Return relative POSIX paths for all files under root (up to max_depth)."""
    result: list[str] = []
    root_str = str(root)
    for dirpath, dirnames, filenames in os.walk(root_str):
        # Prune ignored directories
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
        ]
        # Enforce depth limit
        depth = dirpath[len(root_str):].count(os.sep)
        if depth >= max_depth:
            dirnames.clear()
            continue
        rel_dir = os.path.relpath(dirpath, root_str)
        for fname in filenames:
            rel = os.path.join(rel_dir, fname).replace("\\", "/")
            if rel.startswith("./"):
                rel = rel[2:]
            result.append(rel)
    return result


def _find_pattern_hits(patterns: list[str], file_paths: list[str]) -> list[str]:
    """
    Return unique patterns that matched at least one file path.
    Supports glob syntax (fnmatch for path components, ** for any depth).
    """
    hits: list[str] = []
    for pattern in patterns:
        if any(_glob_match(pattern, fp) for fp in file_paths):
            hits.append(pattern)
    return hits


def _glob_match(pattern: str, path: str) -> bool:
    """
    Match a glob pattern against a relative file path.
    Handles ** (matches any number of path segments) and * (matches within segment).
    """
    # Direct fnmatch for simple patterns without **
    if "**" not in pattern:
        return fnmatch(path, pattern) or fnmatch(Path(path).name, pattern)

    # For ** patterns, try matching from any depth
    parts = path.split("/")
    pat_parts = pattern.split("/")

    return _match_parts(pat_parts, parts)


def _match_parts(pat: list[str], path: list[str]) -> bool:
    """Recursive glob matching with ** support."""
    if not pat:
        return not path
    if pat[0] == "**":
        # ** matches zero or more path segments
        if len(pat) == 1:
            return True
        # Try consuming 0 to N path segments for **
        for i in range(len(path) + 1):
            if _match_parts(pat[1:], path[i:]):
                return True
        return False
    if not path:
        return False
    if not fnmatch(path[0], pat[0]):
        return False
    return _match_parts(pat[1:], path[1:])
