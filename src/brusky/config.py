"""Brusky configuration — loads models.yaml + environment variables."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Pydantic settings (reads .env + environment) ──────────────────────────────

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM fallback (overridden by models.yaml) — only used by the optional
    # fix-guidance layer. Detection works with none of these set.
    llm_provider: str = Field("anthropic", alias="LLM_PROVIDER")
    llm_model: str = Field("claude-sonnet-4-6", alias="LLM_MODEL")

    # API keys
    anthropic_api_key: str = Field("", alias="ANTHROPIC_API_KEY")
    openai_api_key: str = Field("", alias="OPENAI_API_KEY")
    groq_api_key: str = Field("", alias="GROQ_API_KEY")
    mistral_api_key: str = Field("", alias="MISTRAL_API_KEY")
    ollama_api_base: str = Field("", alias="OLLAMA_API_BASE")
    azure_api_key: str = Field("", alias="AZURE_API_KEY")
    azure_api_base: str = Field("", alias="AZURE_API_BASE")
    azure_api_version: str = Field("2024-02-01", alias="AZURE_API_VERSION")

    # GitHub token — used by the changelog fetcher (M3) to avoid rate limits.
    github_token: str = Field("", alias="GITHUB_TOKEN")

    brusky_env: str = Field("development", alias="BRUSKY_ENV")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


# ── Model config (models.yaml) ─────────────────────────────────────────────────

_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "models.yaml"


@lru_cache(maxsize=1)
def _load_models_yaml() -> dict[str, Any]:
    path = Path(os.environ.get("BRUSKY_CONFIG_PATH", str(_CONFIG_PATH)))
    if not path.exists():
        return {}
    with path.open() as f:
        return yaml.safe_load(f) or {}


def get_model_config(phase: str, agent: str) -> dict[str, Any]:
    """
    Return merged model config for a specific phase + agent.

    Resolution order (highest priority first):
      1. config/models.yaml → phase.agent
      2. config/models.yaml → default
      3. env vars LLM_PROVIDER / LLM_MODEL
    """
    raw = _load_models_yaml()
    settings = get_settings()

    env_default = {
        "provider": settings.llm_provider,
        "model": settings.llm_model,
        "temperature": 0.1,
        "max_tokens": 4096,
    }

    yaml_default: dict[str, Any] = raw.get("default", {})
    phase_agent: dict[str, Any] = raw.get(phase, {}).get(agent, {})
    retry_cfg: dict[str, Any] = raw.get("retry", {})

    merged = {**env_default, **yaml_default, **phase_agent}

    # Inject api_base for Ollama if not already set in yaml
    if merged.get("provider") == "ollama" and settings.ollama_api_base:
        merged.setdefault("api_base", settings.ollama_api_base)

    merged["_retry"] = retry_cfg
    return merged


def get_retry_config() -> dict[str, Any]:
    raw = _load_models_yaml()
    return raw.get("retry", {"max_attempts": 3, "wait_seconds": 2})
