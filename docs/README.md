# Brusky Documentation

Brusky is a standalone, driver-based **dependency security monitor**. It runs
daily (from cron/CI), reads your lockfiles, asks [OSV.dev](https://osv.dev) what's
vulnerable, diffs against yesterday, and reports only what changed — plus
(optionally) what code you'd need to touch to upgrade.

> **History:** Brusky was previously a 5-phase LLM security-audit *agent*
> (FastAPI + Neo4j + Redis). It was rewritten in June 2026 into the focused tool
> documented here. See [decisions.md](decisions.md) for why and how.

## Contents

| Doc | What's in it |
|---|---|
| [usage.md](usage.md) | Install, run a scan, read the report, schedule it in CI |
| [architecture.md](architecture.md) | The pipeline, modules, data model, and the "two driver families" model |
| [decisions.md](decisions.md) | The rewrite path: why pivot, the four key decisions, what was removed, the roadmap |

## TL;DR

```bash
pip install -e .
brusky scan /path/to/project          # Markdown report of NEW/worsened vulns
brusky scan . --json                  # machine-readable, for CI
brusky scan . --fail-on critical      # exit 1 if a new critical appears
```

Detection is **100% deterministic** and needs **no API key** — the LLM is only
used for the optional fix-guidance narrative (roadmap milestone M3).
