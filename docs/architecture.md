# Architecture

Brusky is a single deterministic pipeline with an optional LLM tail. It has no
server, no database service, and no message broker — just a CLI, the standard
library's `sqlite3`, and `httpx` for talking to OSV.

## The pipeline

```
                 ┌─────────────┐
  target dir ──▶ │  collectors │  read lockfiles → ResolvedDep[]
                 └──────┬──────┘  (direct + transitive, exact versions)
                        │
                        ▼
                 ┌─────────────┐
                 │  advisories │  OSV.dev batch query → Vulnerability[]
                 └──────┬──────┘  (+ CVSS v3.1 base-score calculation)
                        │
                        ▼
                 ┌─────────────┐
                 │ prioritize  │  pair (dep, vuln) → Finding[]
                 └──────┬──────┘
                        │
                        ▼
                 ┌─────────────┐
                 │   state     │  diff vs SQLite baseline → NEW / WORSENED / EXISTING
                 └──────┬──────┘
                        │
                        ▼
                 ┌─────────────┐
                 │   report    │  Markdown (human) + JSON (machine)
                 └─────────────┘
```

Everything above runs with **zero LLM and zero network beyond OSV**. The
optional fix-guidance step (roadmap M3) is layered on by the CLI *after* the
pipeline returns, so a complete vulnerability report is always available even
with no API key.

## The two driver families

The core insight behind the design is that "check my dependencies" hides two
orthogonal concerns. Brusky models each as its own pluggable driver family:

| Family | Axis | Answers | Lives in |
|---|---|---|---|
| **Collectors** | Where state is *read from* | "what is installed, and at what exact version?" | `collectors/` |
| **Advisories** | Where vuln *truth comes from* | "is this version known-vulnerable?" | `advisories/` |

Adding an ecosystem (e.g. PyPI) is a new collector; changing the source of truth
(e.g. adding GitHub Advisory) is a new advisory driver. They compose freely.

## Modules

All under `src/brusky/`:

| Module | Responsibility |
|---|---|
| `model.py` | Plain dataclasses — the contract between stages. `Severity`, `ResolvedDep`, `Vulnerability`, `Finding`, `ScanResult`. No I/O. |
| `collectors/base.py` | `Collector` protocol + a registry (`register`, `active_collectors`). |
| `collectors/composer.py` | Parses `composer.lock` (+ `composer.json` for direct/dev), ecosystem `Packagist`. |
| `collectors/npm.py` | Parses `package-lock.json` v1 and v2/v3 formats, ecosystem `npm`. |
| `advisories/osv.py` | OSV.dev client (batch query → per-id detail, cached) + CVSS v3.1 base-score calculator. |
| `prioritize.py` | Pairs deps with their vulns into `Finding`s. Ranking lives on the model. |
| `state.py` | SQLite baseline. `classify()` sets NEW/WORSENED/EXISTING; `record()` persists. |
| `report.py` | Renders `ScanResult` to Markdown (NEW-first, backlog collapsed) or JSON. |
| `scan.py` | `run_scan()` — wires collect → match → diff into a `ScanResult`. |
| `__main__.py` | The `brusky` CLI. Routes logs to stderr so stdout stays clean. |
| `llm/provider.py` | Salvaged LiteLLM wrapper, reserved for the M3 fix-guidance layer. |
| `config.py` | Pydantic settings (LLM keys + `GITHUB_TOKEN`) and `models.yaml` loading. |

## Key data structures

- **`ResolvedDep`** — an *exact* installed version from a lockfile (never a
  manifest range). Carries `direct`/`dev` flags and the source file. `coordinate`
  is `ecosystem:name@version`.
- **`Finding.key`** — `ecosystem:name:vuln_id`. Deliberately **excludes the
  version** so a finding that survives a version bump still matches the baseline
  and isn't re-reported as NEW.
- **`Severity`** — an `IntEnum`, so findings sort by severity naturally and
  `--fail-on` is a simple `>=` comparison.

## Why these choices keep it trustworthy

- **Match against lockfiles, not manifests.** `composer.json`/`package.json`
  declare ranges; the resolved version lives in the lockfile. CVE matching is
  meaningless against a range.
- **Transitive deps are walked.** Most CVEs live in deps-of-deps, which never
  appear in a manifest. Both collectors walk the full resolved tree.
- **Detection is deterministic.** Given the same lockfile and OSV state, the
  output is identical. No LLM means no hallucinated CVEs and no stale training
  knowledge in the detection path.
- **Severity is computed, not trusted blindly.** OSV stores CVSS as a *vector*
  string; `advisories/osv.py` computes the v3.1 base score from it (and maps the
  GHSA `MODERATE` label to `MEDIUM`), so `--fail-on` thresholds are meaningful.

## Persistence

State is a single SQLite file (default `~/.brusky/state.db`, override with
`--db`). One table, `findings`, keyed by `(target, key)`, storing the severity
at first sight and a `first_seen` timestamp. This is the entire "memory" that
makes a *daily* run report only what changed.
