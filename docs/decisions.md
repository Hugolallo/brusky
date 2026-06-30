# The rewrite: path & decisions

This document records why Brusky was rebuilt and the decisions that shaped the
new design. It's the "why" companion to [architecture.md](architecture.md).

## Where it started

Brusky 0.1 was a **5-phase, LLM-driven security-audit agent**:

| Phase | Role |
|---|---|
| 01 World Model | Build a Neo4j graph of services, exposure, sensitivity |
| 02 Analysis | Dispatch audit skills via a Redis blackboard |
| 03 Exploitability | Simulate attack paths, score findings |
| 04 Fix Generation | Draft + validate code patches |
| 05 Memory & Routing | Persist findings, route to Slack/PagerDuty/Bitbucket |

It ran as a long-lived FastAPI server backed by Neo4j (graph memory), Redis
(blackboard), LiteLLM, and a Bitbucket PR webhook. Powerful, but heavy: standing
infrastructure, a broad LLM surface, and a scope far larger than the actual need.

## The new goal

A **small, self-contained, driver-based dependency security monitor** that runs
**daily** from cron/CI, inspects **composer / npm / Docker base images**, finds
dependencies that are **vulnerable or end-of-life**, and reports — for findings
worth acting on — what code likely needs to change to upgrade safely.

## The brutal-review findings that shaped the design

A pre-rewrite architecture review surfaced concepts the original framing missed.
These became non-negotiable constraints:

1. **"Driver" is two families, not one.** Reading manifests (collectors) and
   sourcing vulnerability truth (advisories) are orthogonal. See
   [architecture.md](architecture.md#the-two-driver-families).
2. **"Out of date" ≠ "vulnerable."** They need different data and have wildly
   different signal. Lead with *vulnerable* + *EOL*; treat *outdated* as a quiet
   secondary signal to avoid alert fatigue.
3. **Manifests lie; lockfiles tell the truth.** Match resolved versions, not
   declared ranges.
4. **Transitive deps are where the bugs are.** ~80% of CVEs are in deps-of-deps;
   walk the lockfile tree.
5. **"Daily" means diffing.** Persist findings and surface only what's new or
   newly-worse, or the report becomes noise.
6. **"Tell me what code to change" is the killer feature *and* the killer risk.**
   It only works if the LLM is fed the *real* upstream changelog — never its
   training memory — and it must carry confidence levels and never auto-apply.

## The four key decisions

| # | Decision | Chosen | Why |
|---|---|---|---|
| 1 | Codebase strategy | **Greenfield standalone CLI** | "Standalone" is incompatible with a server + Neo4j + Redis. Salvage parsing/LLM/config; drop the rest. |
| 2 | Source of vulnerability truth | **OSV.dev API** | Free, canonical, covers npm + Packagist + more, needs no toolchain, deterministic, testable. |
| 3 | Fix-guidance ambition | **LLM advisory notes from real changelogs** | Best-effort upgrade notes with confidence + source links. Never auto-applies. (Roadmap M3.) |
| 4 | Docker scope (v1) | **Base-image freshness only** | Flag EOL/outdated/unpinned `FROM` tags. Full image CVE scans (Trivy) are heavier; deferred. |

The decision that makes the whole thing trustworthy follows from these:
**detection is 100% deterministic and runs with zero LLM**; the LLM is an
optional final step that only narrates fixes. A correct vulnerability report is
produced even with no API key set.

## What was removed

`phases/` (all five), `memory/` (Neo4j), `blackboard/` (Redis), `triggers/`
(FastAPI + Bitbucket webhook), `setup/` (web UI), and `skills/` (the audit-skill
registry). Dependencies dropped: `neo4j`, `redis`, `langgraph`, `langchain-core`,
`fastapi`, `uvicorn`.

## What was salvaged

- **`llm/provider.py`** — the LiteLLM wrapper, reused unchanged for M3.
- **`config.py`** — trimmed to LLM keys + `GITHUB_TOKEN` + `models.yaml` loading.
- **Lockfile-parsing know-how** from the old `world_model` file readers, rebuilt
  in `collectors/` with the missing pieces added (lockfiles, exact versions,
  transitive trees).
- **The registry pattern** from the old skills registry, recast as the
  collector/advisory driver registry.

## Why not just use Dependabot / Renovate / Snyk?

They already do detection and version bumping well. Brusky's deliberate
differentiator is decision #3 — **explaining what code to change to upgrade**,
fed by real changelogs — which those tools do poorly. The deterministic core
exists to be a trustworthy, self-hostable foundation for that wedge, not to
out-detect the incumbents.

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| **M1** | Deterministic core: composer + npm collectors, OSV client + CVSS, SQLite diff, Markdown/JSON report, CLI | ✅ Done, tested vs live OSV |
| **M2** | Docker base-image freshness (endoflife.date), dev-dep/reachability deprioritization | ✅ Done, tested vs live endoflife.date |
| **M3** | LLM fix guidance: changelog fetch + call-site grep + advisor (confidence + source links) | Planned |
| **M4** | Packaging polish: `brusky.example.yml` rewrite, README/docs finalization, retire old `docs-local/` + audit skills | In progress |
