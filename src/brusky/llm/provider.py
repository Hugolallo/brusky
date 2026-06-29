"""
Model-agnostic LLM provider built on LiteLLM.

Usage:
    llm = get_llm("analysis", "logic_flaw_detector")
    response = await llm.complete([{"role": "user", "content": "..."}])

The provider reads model selection from config/models.yaml so swapping
providers (Anthropic → OpenAI → Ollama) requires only a config change.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import litellm
import structlog
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from brusky.config import get_model_config, get_retry_config, get_settings

log = structlog.get_logger()

# LiteLLM verbose logging only in dev
litellm.set_verbose = False


# ── Message types ──────────────────────────────────────────────────────────────

Message = dict[str, str]   # {"role": "user"|"assistant"|"system", "content": str}


@dataclass
class LLMResponse:
    content: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    raw: Any = field(default=None, repr=False)


# ── Provider ───────────────────────────────────────────────────────────────────

class LLMProvider:
    """
    Wraps LiteLLM with per-agent configuration and retry logic.

    Each agent gets its own provider instance via `get_llm(phase, agent)`.
    The model, temperature, and max_tokens are resolved from config/models.yaml
    with environment variable fallbacks — callers never hardcode a model name.
    """

    def __init__(self, phase: str, agent: str) -> None:
        self.phase = phase
        self.agent = agent
        self._cfg = get_model_config(phase, agent)
        self._retry_cfg = get_retry_config()
        self._settings = get_settings()
        self._model_str = self._resolve_model_string()
        self._inject_api_keys()

    # ── Public API ─────────────────────────────────────────────────────────────

    async def complete(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        system: str | None = None,
    ) -> LLMResponse:
        """Send a chat completion request. Retries on transient errors."""
        if system:
            messages = [{"role": "system", "content": system}, *messages]

        params = self._build_params(messages, temperature, max_tokens)

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._retry_cfg.get("max_attempts", 3)),
            wait=wait_fixed(self._retry_cfg.get("wait_seconds", 2)),
            retry=retry_if_exception_type(
                (litellm.RateLimitError, litellm.ServiceUnavailableError, litellm.Timeout)
            ),
            reraise=True,
        ):
            with attempt:
                log.debug("llm.request", phase=self.phase, agent=self.agent, model=self._model_str)
                response = await litellm.acompletion(**params)

        return LLMResponse(
            content=response.choices[0].message.content or "",
            model=response.model,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
            },
            raw=response,
        )

    async def stream(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
    ) -> AsyncIterator[str]:
        """Streaming completion — yields content chunks as they arrive."""
        if system:
            messages = [{"role": "system", "content": system}, *messages]

        params = {**self._build_params(messages, None, None), "stream": True}
        response = await litellm.acompletion(**params)

        async for chunk in response:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta

    def complete_sync(self, messages: list[Message], **kwargs: Any) -> LLMResponse:
        """Synchronous wrapper — useful in non-async contexts."""
        return asyncio.get_event_loop().run_until_complete(self.complete(messages, **kwargs))

    @property
    def model_id(self) -> str:
        return self._model_str

    @property
    def config(self) -> dict[str, Any]:
        return dict(self._cfg)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _resolve_model_string(self) -> str:
        """
        Build the LiteLLM model string.

        LiteLLM uses provider-prefixed strings for non-OpenAI providers:
          anthropic  → "claude-sonnet-4-6"  (no prefix needed)
          openai     → "gpt-4o"             (no prefix needed)
          ollama     → "ollama/llama3:70b"
          groq       → "groq/llama3-70b-8192"
          mistral    → "mistral/mistral-large-latest"
          azure      → "azure/<deployment>"
          bedrock    → "bedrock/..."
        """
        provider = self._cfg.get("provider", "anthropic")
        model = self._cfg.get("model", "claude-sonnet-4-6")

        prefix_map = {
            "ollama": "ollama/",
            "groq": "groq/",
            "mistral": "mistral/",
        }

        prefix = prefix_map.get(provider, "")
        # Avoid double-prefixing if yaml already includes the prefix
        if prefix and not model.startswith(prefix):
            return f"{prefix}{model}"
        return model

    def _build_params(
        self,
        messages: list[Message],
        temperature: float | None,
        max_tokens: int | None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": self._model_str,
            "messages": messages,
            "temperature": temperature if temperature is not None else self._cfg.get("temperature", 0.1),
            "max_tokens": max_tokens if max_tokens is not None else self._cfg.get("max_tokens", 4096),
        }

        # Ollama needs api_base
        if api_base := self._cfg.get("api_base"):
            params["api_base"] = api_base

        # Azure needs extra params
        if self._cfg.get("provider") == "azure":
            if self._settings.azure_api_base:
                params["api_base"] = self._settings.azure_api_base
            if self._settings.azure_api_version:
                params["api_version"] = self._settings.azure_api_version

        return params

    def _inject_api_keys(self) -> None:
        """Set provider API keys in litellm from settings (avoids env var conflicts)."""
        s = self._settings
        provider = self._cfg.get("provider", "anthropic")

        key_map = {
            "anthropic": ("ANTHROPIC_API_KEY", s.anthropic_api_key),
            "openai": ("OPENAI_API_KEY", s.openai_api_key),
            "groq": ("GROQ_API_KEY", s.groq_api_key),
            "mistral": ("MISTRAL_API_KEY", s.mistral_api_key),
            "azure": ("AZURE_API_KEY", s.azure_api_key),
        }

        if provider in key_map:
            env_name, value = key_map[provider]
            if value:
                import os
                os.environ.setdefault(env_name, value)


# ── Factory ────────────────────────────────────────────────────────────────────

_cache: dict[str, LLMProvider] = {}


def get_llm(phase: str, agent: str) -> LLMProvider:
    """
    Return a cached LLMProvider for a given phase + agent pair.

    Example:
        llm = get_llm("analysis", "logic_flaw_detector")
        result = await llm.complete([{"role": "user", "content": prompt}])
    """
    key = f"{phase}:{agent}"
    if key not in _cache:
        _cache[key] = LLMProvider(phase, agent)
    return _cache[key]
