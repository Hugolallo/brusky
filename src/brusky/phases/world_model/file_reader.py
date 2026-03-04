"""
Service file reader — pure parsing, no LLM.

Given a directory, detects service boundaries and reads all the files the
Service Discoverer needs to build the world model:
  - README (purpose text)
  - Language manifests (composer.json, package.json, go.mod, …)
  - Dockerfile (runtime context)
  - docker-compose.yml (service topology)
  - CI configs (.github/workflows, .gitlab-ci.yml, …)
  - OpenAPI / Swagger specs
  - CODEOWNERS (team attribution)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
import structlog

log = structlog.get_logger()

# ── Language / framework detection tables ─────────────────────────────────────

# file name → language it signals
_LANG_MARKERS: dict[str, str] = {
    "composer.json": "php",
    "package.json": "javascript",
    "tsconfig.json": "typescript",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "Pipfile": "python",
    "go.mod": "go",
    "Gemfile": "ruby",
    "pom.xml": "java",
    "build.gradle": "java",
    "Cargo.toml": "rust",
}

# file name → framework it signals (only root-level presence checked)
_FRAMEWORK_MARKERS: dict[str, str] = {
    "artisan": "laravel",
    "nuxt.config.js": "nuxt",
    "nuxt.config.ts": "nuxt",
    "manage.py": "django",
    "app.py": "flask",           # refined by content if needed
    "config/routes.rb": "rails",
    "Jenkinsfile": "jenkins",    # CI, not a framework — kept for completeness
}

# extensions → language (used for counting source files)
_EXT_LANG: dict[str, str] = {
    ".php": "php",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".py": "python",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java",
    ".rs": "rust",
    ".vue": "javascript",       # Vue SFCs are JS ecosystem
}

# OpenAPI spec file names to probe
_OPENAPI_NAMES = {
    "openapi.yaml", "openapi.yml", "openapi.json",
    "swagger.yaml", "swagger.yml", "swagger.json",
    "api.yaml", "api.yml", "api.json",
    "api-docs.yaml", "api-docs.yml", "api-docs.json",
}

_CI_PATHS = [
    ".github/workflows",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    "bitbucket-pipelines.yml",
    ".drone.yml",
]

_README_NAMES = {"README.md", "README.txt", "README.rst", "README", "readme.md"}
_CODEOWNERS_PATHS = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]

_MAX_README_BYTES = 4_000    # cap sent to LLM
_MAX_MANIFEST_BYTES = 2_000


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class ServiceFiles:
    """Raw file contents for one service root, ready for LLM synthesis."""
    root: Path
    name: str                                      # directory name fallback

    readme: str = ""
    dockerfile: str = ""
    language_manifests: dict[str, Any] = field(default_factory=dict)  # filename → parsed content
    docker_compose: dict[str, Any] = field(default_factory=dict)
    ci_configs: list[dict[str, Any]] = field(default_factory=list)
    openapi_specs: list[dict[str, Any]] = field(default_factory=list)
    codeowners: str = ""

    detected_languages: list[str] = field(default_factory=list)
    detected_frameworks: list[str] = field(default_factory=list)

    def has_content(self) -> bool:
        return bool(self.readme or self.language_manifests or self.dockerfile)

    def language_summary(self) -> str:
        langs = self.detected_languages or ["unknown"]
        fws = self.detected_frameworks
        parts = [", ".join(langs)]
        if fws:
            parts.append(f"({', '.join(fws)})")
        return " ".join(parts)


# ── Service root detection ─────────────────────────────────────────────────────

def detect_service_roots(target: Path) -> list[Path]:
    """
    Return a list of directories that each represent one deployable service.

    Detection order (first match wins):
      1. docker-compose.yml at target root — build-context paths are service roots
      2. Subdirectories containing a Dockerfile — each is a service
      3. Target itself has a language manifest — treat whole repo as one service
      4. Fallback — return target itself
    """
    # 1 — docker-compose
    compose_path = target / "docker-compose.yml"
    if not compose_path.exists():
        compose_path = target / "docker-compose.yaml"

    if compose_path.exists():
        roots = _roots_from_compose(target, compose_path)
        if roots:
            log.debug("world_model.roots.from_compose", count=len(roots))
            return roots

    # 2 — subdirectories with Dockerfile
    subdir_roots = [
        d for d in sorted(target.iterdir())
        if d.is_dir()
        and not d.name.startswith(".")
        and d.name not in {"node_modules", "vendor", "__pycache__", "dist", "build"}
        and (d / "Dockerfile").exists()
    ]
    if subdir_roots:
        log.debug("world_model.roots.from_dockerfiles", count=len(subdir_roots))
        return subdir_roots

    # 3 — single service (any language manifest at root)
    for marker in _LANG_MARKERS:
        if (target / marker).exists():
            log.debug("world_model.roots.single_service", path=str(target))
            return [target]

    # 4 — fallback
    log.debug("world_model.roots.fallback", path=str(target))
    return [target]


def _roots_from_compose(target: Path, compose_path: Path) -> list[Path]:
    """Extract build context directories from a docker-compose file."""
    try:
        with compose_path.open() as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        log.warning("world_model.compose_parse_error", error=str(exc))
        return []

    roots: list[Path] = []
    for svc_name, svc_cfg in data.get("services", {}).items():
        if not isinstance(svc_cfg, dict):
            continue
        build = svc_cfg.get("build")
        if build is None:
            # image-only service — treat compose root as the service directory
            # but only add target once as a fallback below
            continue
        if isinstance(build, str):
            ctx = target / build
        elif isinstance(build, dict):
            ctx = target / build.get("context", ".")
        else:
            continue

        ctx = ctx.resolve()
        if ctx.exists() and ctx not in roots:
            roots.append(ctx)

    # If compose exists but all services use external images, return target itself
    if not roots and data.get("services"):
        roots = [target]

    return roots


# ── File reader ────────────────────────────────────────────────────────────────

def read_service_files(root: Path) -> ServiceFiles:
    """
    Read all relevant files from a service root directory.
    Returns a ServiceFiles instance populated with raw content.
    """
    files = ServiceFiles(root=root, name=root.name)

    _read_readme(files)
    _read_language_manifests(files)
    _read_dockerfile(files)
    _read_docker_compose(files)
    _read_ci_configs(files)
    _read_openapi_specs(files)
    _read_codeowners(files)
    _detect_languages_and_frameworks(files)

    log.debug(
        "world_model.files_read",
        service=files.name,
        languages=files.detected_languages,
        frameworks=files.detected_frameworks,
        has_readme=bool(files.readme),
    )
    return files


def _read_readme(files: ServiceFiles) -> None:
    for name in _README_NAMES:
        path = files.root / name
        if path.exists():
            try:
                files.readme = path.read_text(errors="replace")[:_MAX_README_BYTES]
            except OSError:
                pass
            return


def _read_language_manifests(files: ServiceFiles) -> None:
    for filename in _LANG_MARKERS:
        path = files.root / filename
        if not path.exists():
            continue
        try:
            raw = path.read_text(errors="replace")[:_MAX_MANIFEST_BYTES]
            if filename.endswith(".json"):
                files.language_manifests[filename] = json.loads(raw)
            elif filename.endswith((".yaml", ".yml", ".toml")):
                files.language_manifests[filename] = {"_raw": raw}
            else:
                files.language_manifests[filename] = {"_raw": raw}
        except Exception as exc:
            log.debug("world_model.manifest_parse_error", file=filename, error=str(exc))
            files.language_manifests[filename] = {"_raw": ""}


def _read_dockerfile(files: ServiceFiles) -> None:
    path = files.root / "Dockerfile"
    if path.exists():
        try:
            files.dockerfile = path.read_text(errors="replace")[:1_000]
        except OSError:
            pass


def _read_docker_compose(files: ServiceFiles) -> None:
    for name in ("docker-compose.yml", "docker-compose.yaml"):
        path = files.root / name
        if path.exists():
            try:
                with path.open() as f:
                    files.docker_compose = yaml.safe_load(f) or {}
            except Exception as exc:
                log.debug("world_model.compose_read_error", error=str(exc))
            return


def _read_ci_configs(files: ServiceFiles) -> None:
    for ci_path in _CI_PATHS:
        full = files.root / ci_path
        if full.is_dir():
            for yml in sorted(full.glob("*.yml"))[:3]:
                try:
                    with yml.open() as f:
                        data = yaml.safe_load(f)
                    if data:
                        files.ci_configs.append({"file": yml.name, "data": data})
                except Exception:
                    pass
        elif full.is_file():
            try:
                with full.open() as f:
                    data = yaml.safe_load(f) if str(full).endswith((".yml", ".yaml")) else {"_raw": f.read(500)}
                if data:
                    files.ci_configs.append({"file": ci_path, "data": data})
            except Exception:
                pass


def _read_openapi_specs(files: ServiceFiles) -> None:
    search_dirs = [files.root] + [
        files.root / d
        for d in ("docs", "api", "spec", "specs", "swagger", "openapi")
        if (files.root / d).is_dir()
    ]
    seen: set[Path] = set()
    for directory in search_dirs:
        for name in _OPENAPI_NAMES:
            path = directory / name
            if path in seen or not path.exists():
                continue
            seen.add(path)
            try:
                with path.open() as f:
                    if name.endswith(".json"):
                        data = json.load(f)
                    else:
                        data = yaml.safe_load(f)
                # Confirm it's actually an OpenAPI/Swagger doc
                if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                    files.openapi_specs.append({"file": str(path.relative_to(files.root)), "data": data})
            except Exception:
                pass


def _read_codeowners(files: ServiceFiles) -> None:
    for co_path in _CODEOWNERS_PATHS:
        path = files.root / co_path
        if path.exists():
            try:
                files.codeowners = path.read_text(errors="replace")[:500]
            except OSError:
                pass
            return


def _detect_languages_and_frameworks(files: ServiceFiles) -> None:
    langs: set[str] = set()
    fws: set[str] = set()

    # From manifest files present
    for filename, lang in _LANG_MARKERS.items():
        if filename in files.language_manifests:
            langs.add(lang)
            # Handle typescript: if tsconfig.json is present alongside package.json
            if filename == "tsconfig.json":
                langs.discard("javascript")
                langs.add("typescript")

    # From framework markers at root
    for filename, fw in _FRAMEWORK_MARKERS.items():
        path = files.root / filename
        if path.exists():
            fws.add(fw)
            # Laravel implies PHP
            if fw == "laravel":
                langs.add("php")
            # Nuxt/Vue implies JS
            if fw in ("nuxt",):
                langs.add("javascript")
            # Django/Flask implies Python
            if fw in ("django", "flask"):
                langs.add("python")
            # Rails implies Ruby
            if fw == "rails":
                langs.add("ruby")

    # Vue: count .vue files
    vue_count = len(list(files.root.glob("**/*.vue")))
    if vue_count > 0:
        fws.add("vue")
        langs.add("javascript")

    # Express: check package.json dependencies
    pkg = files.language_manifests.get("package.json", {})
    if isinstance(pkg, dict):
        all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if "express" in all_deps:
            fws.add("express")
        if "next" in all_deps:
            fws.add("nextjs")
        if "react" in all_deps:
            fws.add("react")

    # Fallback: count source file extensions to pick dominant language
    if not langs:
        ext_counts: dict[str, int] = {}
        for p in files.root.rglob("*"):
            if p.is_file() and p.suffix in _EXT_LANG:
                lang = _EXT_LANG[p.suffix]
                ext_counts[lang] = ext_counts.get(lang, 0) + 1
        if ext_counts:
            dominant = max(ext_counts, key=lambda k: ext_counts[k])
            langs.add(dominant)

    files.detected_languages = sorted(langs)
    files.detected_frameworks = sorted(fws)
