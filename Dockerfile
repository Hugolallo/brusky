# ── Base ──────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# System deps (git for any pip+git deps, curl for health probes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# ── Dependencies ──────────────────────────────────────────────────────────────
FROM base AS deps

COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install -e ".[dev]"

# ── Development (default) — mounts src/ from host ─────────────────────────────
FROM deps AS development

ENV BRUSKY_ENV=development

COPY config/ ./config/
COPY src/ ./src/

CMD ["python", "-m", "brusky"]

# ── Production — copies source, no dev tools ──────────────────────────────────
FROM base AS production

ENV BRUSKY_ENV=production

COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install -e "."

COPY config/ ./config/
COPY src/ ./src/

# Non-root user
RUN useradd -m -u 1001 brusky && chown -R brusky:brusky /app
USER brusky

CMD ["python", "-m", "brusky"]
