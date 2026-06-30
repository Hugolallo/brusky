"""Find where a dependency is actually used in the target repo.

This grounds the "what code to change" half of the guidance: the advisor only
ever references call sites that were really found here. Best-effort and
language-aware — npm imports are precise; Composer namespaces are approximated
from the package name, so those are lower-confidence signals.

Returns a list of {file, line, text} dicts (relative paths), capped to keep the
prompt small and the scan fast.
"""

from __future__ import annotations

import re
from pathlib import Path

_EXTS = {
    "npm": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"),
    "Packagist": (".php",),
}
_SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "storage", ".venv"}
_MAX_MATCHES = 15
_MAX_FILES = 3000


def find_callsites(
    ecosystem: str, name: str, root: Path, *, limit: int = _MAX_MATCHES
) -> list[dict]:
    exts = _EXTS.get(ecosystem)
    if not exts:
        return []                       # Docker and unknown ecosystems have no call sites
    pattern = _npm_pattern(name) if ecosystem == "npm" else _composer_pattern(name)
    if pattern is None:
        return []

    matches: list[dict] = []
    files_seen = 0
    for path in _source_files(root, exts):
        files_seen += 1
        if files_seen > _MAX_FILES:
            break
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for i, line in enumerate(lines, start=1):
            if pattern.search(line):
                matches.append({"file": rel, "line": i, "text": line.strip()[:200]})
                if len(matches) >= limit:
                    return matches
    return matches


def _npm_pattern(name: str) -> re.Pattern:
    n = re.escape(name)
    # require('name'), import … from 'name', import 'name', import('name')
    return re.compile(
        rf"""(?:require\(\s*|from\s+|import\s*\(?\s*)['"]{n}(?:/[^'"]*)?['"]"""
    )


def _composer_pattern(name: str) -> re.Pattern | None:
    """Approximate a Composer package's namespace tokens for grepping `use`.

    'guzzlehttp/guzzle' -> tokens {guzzlehttp, guzzle}; matched case-insensitively
    against `use …;` statements. Imprecise by nature — flagged as lower confidence
    upstream.
    """
    parts = [p for seg in name.split("/") for p in re.split(r"[-_]", seg) if p]
    if not parts:
        return None
    alt = "|".join(re.escape(p) for p in parts)
    return re.compile(rf"^\s*use\s+.*(?:{alt})", re.IGNORECASE)


def _source_files(root: Path, exts: tuple[str, ...]):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in exts:
            continue
        if set(path.parts) & _SKIP_DIRS:
            continue
        yield path
