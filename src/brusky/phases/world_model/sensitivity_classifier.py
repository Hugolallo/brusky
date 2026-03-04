"""
Phase 01 — Sensitivity Classifier (LLM Node)

For each service discovered in Phase 01, reasons about what category of data
it handles and assigns a sensitivity level. This score travels with every
finding — a SQL injection in a PII-handling service is fundamentally different
from the same pattern in a static asset server.

Outputs written to the Neo4j service node:
  sensitivity:  critical | high | medium | low
  data_types:   list of data categories present (e.g. ["PII", "auth_tokens"])

Sensitivity tiers:
  critical — payment card data, government IDs, medical/health records, SSNs
  high     — PII (name/email/address), auth credentials, financial data
  medium   — user-generated content, internal business data, preferences
  low      — public content, static assets, operational metrics only

The classifier reads code signals (model files, routes, dependency names) to
give the LLM concrete evidence rather than just the purpose string. This
prevents misclassification of vaguely-named services.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

import structlog

from brusky.llm import get_llm
from brusky.memory.graph import GraphClient, Service, get_graph

log = structlog.get_logger()

# ── Known data-type signals ────────────────────────────────────────────────────

# Each entry: (data_type_label, [keywords that signal its presence])
# Matched against: model/entity field names, class names, route paths,
# dependency names, and README text.
_DATA_SIGNALS: list[tuple[str, list[str]]] = [
    ("payment_data",    ["payment", "card", "billing", "stripe", "paypal", "braintree",
                         "invoice", "checkout", "credit", "debit", "transaction", "cvv", "iban"]),
    ("PII",             ["email", "phone", "address", "dob", "birth", "gender", "national",
                         "personal", "profile", "customer", "user_data", "full_name", "surname",
                         "first_name", "last_name", "mobile", "postcode", "zipcode", "ssn"]),
    ("auth_tokens",     ["token", "jwt", "session", "oauth", "credentials", "password", "secret",
                         "api_key", "access_token", "refresh_token", "bearer", "auth", "login",
                         "passphrase", "2fa", "mfa", "totp"]),
    ("health_data",     ["health", "medical", "diagnosis", "prescription", "patient", "clinical",
                         "hipaa", "ehr", "medication", "symptom", "treatment", "doctor"]),
    ("government_id",   ["ssn", "passport", "national_id", "tax_id", "ein", "driver_license",
                         "government", "identity_document"]),
    ("financial_data",  ["salary", "income", "bank_account", "iban", "swift", "investment",
                         "portfolio", "loan", "mortgage", "credit_score", "balance"]),
    ("behavioral_data", ["analytics", "tracking", "event", "pageview", "click", "session_id",
                         "fingerprint", "telemetry", "usage", "audit_log"]),
    ("user_content",    ["comment", "post", "message", "review", "content", "upload",
                         "attachment", "file", "media", "image", "document"]),
    ("internal_config", ["config", "setting", "environment", "secret", "key", "credential",
                         "admin", "internal", "system"]),
    ("public_data",     ["public", "static", "asset", "landing", "blog", "news", "cdn",
                         "marketing", "docs", "faq"]),
]

# Libraries/packages whose presence implies a data category
_DEPENDENCY_SIGNALS: dict[str, str] = {
    # payment
    "stripe": "payment_data", "paypal": "payment_data", "braintree": "payment_data",
    "square": "payment_data", "adyen": "payment_data",
    # auth
    "passport": "auth_tokens", "jwt": "auth_tokens", "oauth": "auth_tokens",
    "tymon/jwt-auth": "auth_tokens", "laravel/sanctum": "auth_tokens",
    "firebase-admin": "auth_tokens",
    # analytics / behavioral
    "mixpanel": "behavioral_data", "amplitude": "behavioral_data",
    "segment": "behavioral_data", "analytics": "behavioral_data",
    # health
    "fhir": "health_data", "hl7": "health_data",
}

# Globs for files that reveal stored/processed data
_MODEL_GLOBS = [
    "app/Models/**/*.php", "app/**/*Model.php",            # Laravel
    "**/models.py", "**/model.py", "**/*_model.py",       # Django / SQLAlchemy
    "**/*.model.ts", "**/*.entity.ts", "**/*.schema.ts",  # TypeScript ORMs
    "**/*.go",                                              # Go structs (filtered by content)
    "**/*.rb",                                              # Rails ActiveRecord
]
_ROUTE_GLOBS = [
    "routes/api.php", "routes/web.php",                    # Laravel
    "**/urls.py",                                           # Django
    "**/routes/**/*.ts", "**/routes/**/*.js",              # Express / Fastify
    "config/routes.rb",                                     # Rails
]

_MAX_SIGNAL_FILES = 8
_MAX_FILE_BYTES = 1_200


# ── Code signal extraction (pure Python, no LLM) ──────────────────────────────

def _collect_code_signals(repo_path: Path) -> dict[str, Any]:
    """
    Collect lightweight text signals from the codebase that reveal data handling.
    Returns a dict with lists of identifiers found in models, routes, and deps.
    """
    signals: dict[str, Any] = {
        "model_identifiers": [],   # field names / class names from model files
        "route_paths": [],         # URL path strings from route files
        "dependencies": [],        # package names from manifests
        "readme_excerpt": "",
    }

    # — Model / entity files
    model_texts: list[str] = []
    for glob in _MODEL_GLOBS:
        for path in sorted(repo_path.glob(glob))[:_MAX_SIGNAL_FILES]:
            if path.is_file() and _not_ignored(path):
                try:
                    model_texts.append(path.read_text(errors="replace")[:_MAX_FILE_BYTES])
                except OSError:
                    pass
        if len(model_texts) >= _MAX_SIGNAL_FILES:
            break

    signals["model_identifiers"] = _extract_identifiers("\n".join(model_texts))

    # — Route files
    route_texts: list[str] = []
    for glob in _ROUTE_GLOBS:
        for path in sorted(repo_path.glob(glob))[:3]:
            if path.is_file() and _not_ignored(path):
                try:
                    route_texts.append(path.read_text(errors="replace")[:_MAX_FILE_BYTES])
                except OSError:
                    pass

    signals["route_paths"] = _extract_route_paths("\n".join(route_texts))

    # — Package dependencies
    signals["dependencies"] = _extract_dependencies(repo_path)

    # — README first 500 chars
    for readme in ("README.md", "readme.md", "README.txt"):
        p = repo_path / readme
        if p.exists():
            try:
                signals["readme_excerpt"] = p.read_text(errors="replace")[:500]
            except OSError:
                pass
            break

    return signals


def _extract_identifiers(text: str) -> list[str]:
    """Pull camelCase, snake_case, and PascalCase identifiers from source."""
    # Match variable/field/class names — at least 4 chars, not all uppercase
    raw = re.findall(r"\b([a-z][a-zA-Z0-9_]{3,}|[A-Z][a-zA-Z0-9]{3,})\b", text)
    # Deduplicate, lowercase for matching, keep only informative ones
    seen: set[str] = set()
    result: list[str] = []
    for word in raw:
        lw = word.lower()
        if lw not in seen and not lw.startswith(("http", "this", "self", "true", "false")):
            seen.add(lw)
            result.append(lw)
    return result[:120]  # cap to keep prompt concise


def _extract_route_paths(text: str) -> list[str]:
    """Extract URL path strings from route definitions."""
    paths = re.findall(r"""['"](/[a-zA-Z0-9/_\-{}:]+)['"]\s*""", text)
    return list(dict.fromkeys(paths))[:30]


def _extract_dependencies(repo_path: Path) -> list[str]:
    """Read package names from composer.json and package.json."""
    deps: list[str] = []

    composer = repo_path / "composer.json"
    if composer.exists():
        try:
            data = json.loads(composer.read_text())
            for section in ("require", "require-dev"):
                deps.extend(data.get(section, {}).keys())
        except Exception:
            pass

    pkg = repo_path / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            for section in ("dependencies", "devDependencies"):
                deps.extend(data.get(section, {}).keys())
        except Exception:
            pass

    return deps[:60]


def _not_ignored(path: Path) -> bool:
    return not any(
        part in {"vendor", "node_modules", "__pycache__", ".git", "dist", "build"}
        for part in path.parts
    )


# ── Pre-classification (keyword matching, no LLM) ─────────────────────────────

def _pre_classify(signals: dict[str, Any]) -> set[str]:
    """
    Keyword-scan the collected signals for known data-type markers.
    Returns a set of likely data_types — used to seed the LLM prompt
    and as a fallback if the LLM call fails.
    """
    # Combine all text signal sources into one searchable string
    combined = " ".join([
        " ".join(signals.get("model_identifiers", [])),
        " ".join(signals.get("route_paths", [])),
        " ".join(signals.get("dependencies", [])),
        signals.get("readme_excerpt", ""),
    ]).lower()

    found: set[str] = set()

    for data_type, keywords in _DATA_SIGNALS:
        if any(kw in combined for kw in keywords):
            found.add(data_type)

    # Dependency-level signals (exact package name match)
    dep_names = {d.lower() for d in signals.get("dependencies", [])}
    for pkg, data_type in _DEPENDENCY_SIGNALS.items():
        if pkg.lower() in dep_names:
            found.add(data_type)

    return found


# ── LLM classification ─────────────────────────────────────────────────────────

_CLASSIFY_PROMPT = """\
Classify the data sensitivity of this software service.

Service: {name}
Purpose: {purpose}
Language/framework: {language}

Code signals found (model field names, route paths, dependencies):
{signals_text}

Pre-detected data categories from keyword scan: {pre_detected}

Sensitivity tiers:
  critical — payment card data, government IDs, medical/health records, biometrics
  high     — PII (names, emails, addresses), auth credentials, financial data
  medium   — user-generated content, internal business data, preferences, logs
  low      — only public content, static assets, or operational metrics

Return ONLY valid JSON (no markdown, no extra text):
{{
  "sensitivity_level": "critical|high|medium|low",
  "data_types": ["only", "types", "actually", "present"],
  "reasoning": "one sentence"
}}

Valid data_type values: payment_data, PII, auth_tokens, health_data,
government_id, financial_data, behavioral_data, user_content,
internal_config, public_data"""


async def _llm_classify(
    service: Service,
    signals: dict[str, Any],
    pre_detected: set[str],
) -> tuple[str, list[str]]:
    """
    Call the LLM to produce a final sensitivity classification.
    Falls back to keyword-based classification if the call fails.
    """
    llm = get_llm("world_model", "sensitivity_classifier")

    # Build a concise signals summary for the prompt
    signal_lines: list[str] = []
    if signals["model_identifiers"]:
        signal_lines.append(f"Model fields: {', '.join(signals['model_identifiers'][:40])}")
    if signals["route_paths"]:
        signal_lines.append(f"Routes: {', '.join(signals['route_paths'][:15])}")
    if signals["dependencies"]:
        signal_lines.append(f"Packages: {', '.join(signals['dependencies'][:20])}")
    if signals["readme_excerpt"]:
        signal_lines.append(f"README: {signals['readme_excerpt'][:200]}")

    prompt = _CLASSIFY_PROMPT.format(
        name=service.name,
        purpose=service.purpose or "(unknown)",
        language=service.language or "(unknown)",
        signals_text="\n".join(signal_lines) or "(no code signals found)",
        pre_detected=", ".join(sorted(pre_detected)) or "none",
    )

    try:
        response = await llm.complete(
            [{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=256,
        )
        raw = response.content.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        data = json.loads(raw)
        level = str(data.get("sensitivity_level", "medium"))
        types = [str(t) for t in data.get("data_types", [])]

        if level not in {"critical", "high", "medium", "low"}:
            level = "medium"

        log.debug(
            "world_model.classifier.llm_result",
            service=service.name,
            level=level,
            types=types,
            reasoning=data.get("reasoning", ""),
        )
        return level, types

    except Exception as exc:
        log.warning("world_model.classifier.llm_failed", service=service.name, error=str(exc))
        # Fallback: derive level from pre-detected types
        return _level_from_types(pre_detected), sorted(pre_detected)


def _level_from_types(data_types: set[str]) -> str:
    """Derive a conservative sensitivity level from detected data types."""
    if data_types & {"payment_data", "health_data", "government_id"}:
        return "critical"
    if data_types & {"PII", "auth_tokens", "financial_data"}:
        return "high"
    if data_types & {"user_content", "behavioral_data", "internal_config"}:
        return "medium"
    return "low"


# ── Main classifier ────────────────────────────────────────────────────────────

class SensitivityClassifier:
    """
    LLM Node for Phase 01 — classifies each service's data sensitivity.

    Runs after ServiceDiscoverer has written service nodes to the graph.
    Updates each node with `sensitivity` and `data_types` properties.

    Usage:
        classifier = SensitivityClassifier()
        await classifier.classify_all(services)
    """

    def __init__(self, graph: GraphClient | None = None) -> None:
        self._graph = graph

    async def _get_graph(self) -> GraphClient:
        if self._graph is None:
            self._graph = await get_graph()
        return self._graph

    async def classify(self, service: Service) -> tuple[str, list[str]]:
        """
        Classify one service. Returns (sensitivity_level, data_types).
        Also updates the graph node in place.
        """
        repo_path = Path(service.repo_path) if service.repo_path else None

        if repo_path and repo_path.exists():
            signals = await asyncio.to_thread(_collect_code_signals, repo_path)
            pre_detected = _pre_classify(signals)
        else:
            signals = {"model_identifiers": [], "route_paths": [], "dependencies": [], "readme_excerpt": ""}
            pre_detected = set()

        level, data_types = await _llm_classify(service, signals, pre_detected)

        graph = await self._get_graph()
        await graph.update_service_sensitivity(service.name, level, data_types)

        log.info(
            "world_model.classifier.done",
            service=service.name,
            sensitivity=level,
            data_types=data_types,
        )
        return level, data_types

    async def classify_all(self, services: list[Service]) -> dict[str, tuple[str, list[str]]]:
        """
        Classify all services concurrently. Returns {service_name: (level, types)}.
        Concurrency is bounded — Haiku is cheap but we don't want to burst.
        """
        semaphore = asyncio.Semaphore(4)  # max 4 concurrent LLM calls

        async def _bounded(svc: Service) -> tuple[str, tuple[str, list[str]]]:
            async with semaphore:
                result = await self.classify(svc)
                return svc.name, result

        results = await asyncio.gather(*[_bounded(s) for s in services])

        log.info(
            "world_model.classifier.all_done",
            count=len(results),
            breakdown={name: level for name, (level, _) in results},
        )
        return dict(results)
