"""Docker base-image collector.

Parses every Dockerfile under the target for its `FROM` instructions and turns
each *external* base image into a ResolvedDep in the synthetic "Docker"
ecosystem. Unlike composer/npm, there is no lockfile — the "version" is the
image tag as written. Freshness (EOL / unpinned) is judged later by the EOL
advisory, not here; the collector only reads.

Stage references (`FROM build AS ...` then `FROM build`) are skipped so we don't
treat an internal stage alias as a public image.
"""

from __future__ import annotations

import re
from pathlib import Path

import structlog

from brusky.collectors.base import register
from brusky.model import ResolvedDep

log = structlog.get_logger()

ECOSYSTEM = "Docker"

# Dockerfiles we recognize: `Dockerfile`, `Dockerfile.prod`, `api.Dockerfile`.
_DOCKERFILE_GLOBS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile")
_SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build"}

_FROM_RE = re.compile(r"^\s*FROM\s+(.*)$", re.IGNORECASE)


def _parse_image_ref(ref: str) -> tuple[str, str]:
    """Split an image reference into (product, version).

    product is the final path segment (the endoflife.date-style name), version
    is the tag, "latest" when omitted, or "(digest)" when pinned by digest.
        node:16-alpine            -> ("node", "16-alpine")
        library/python:3.9        -> ("python", "3.9")
        myreg:5000/api/node       -> ("node", "latest")
        php@sha256:abc…           -> ("php", "(digest)")
    """
    if "@" in ref:
        name, _ = ref.split("@", 1)
        version = "(digest)"
    else:
        name = ref
        version = "latest"
        last_segment_start = ref.rfind("/") + 1
        colon = ref.find(":", last_segment_start)
        if colon != -1:
            name = ref[:colon]
            version = ref[colon + 1:]
    product = name.rsplit("/", 1)[-1].lower()
    return product, version


class DockerCollector:
    name = "docker"

    def detect(self, root: Path) -> bool:
        return any(self._dockerfiles(root))

    def collect(self, root: Path) -> list[ResolvedDep]:
        deps: list[ResolvedDep] = []
        seen: set[tuple[str, str]] = set()
        for path in self._dockerfiles(root):
            deps.extend(self._parse_file(path, root, seen))
        return deps

    def _parse_file(
        self, path: Path, root: Path, seen: set[tuple[str, str]]
    ) -> list[ResolvedDep]:
        try:
            text = path.read_text(errors="replace")
        except OSError as exc:
            log.warning("docker.read_error", file=str(path), error=str(exc))
            return []

        rel = str(path.relative_to(root)) if path.is_relative_to(root) else path.name
        stage_aliases: set[str] = set()
        out: list[ResolvedDep] = []

        for line in text.splitlines():
            m = _FROM_RE.match(line)
            if not m:
                continue
            tokens = [t for t in m.group(1).split() if not t.startswith("--")]
            if not tokens:
                continue
            ref = tokens[0]
            # Track `AS <alias>` and skip references to internal stages.
            if len(tokens) >= 3 and tokens[1].lower() == "as":
                stage_aliases.add(tokens[2].lower())
            if ref.lower() in stage_aliases:
                continue
            if ref.lower() == "scratch":
                continue

            product, version = _parse_image_ref(ref)
            key = (product, version)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                ResolvedDep(
                    ecosystem=ECOSYSTEM,
                    name=product,
                    version=version,
                    direct=True,        # base images are always declared, never transitive
                    dev=False,
                    source=rel,
                )
            )
        return out

    def _dockerfiles(self, root: Path):
        for pattern in _DOCKERFILE_GLOBS:
            for path in root.rglob(pattern):
                if path.is_file() and not (set(path.parts) & _SKIP_DIRS):
                    yield path


register(DockerCollector())
