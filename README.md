# Brusky

A standalone, driver-based **dependency security monitor**. Run it daily; it
reads your lockfiles, asks [OSV.dev](https://osv.dev) what's vulnerable, diffs
against yesterday, and reports only what changed.

```bash
brusky scan /path/to/project
```

```
# Brusky Dependency Security Report

**Dependencies:** 2 critical, 4 high, 6 medium — 12 new/worsened since last scan

## New & worsened findings

| | Package | Installed | Fix | Severity | Vulnerability | Status |
|---|---|---|---|---|---|---|
| 🔴 | `lodash` | 4.17.4 | 4.17.12 | Critical | GHSA-jf85-cpcp-j695 — Prototype Pollution | NEW |
| 🔴 | `minimist` _dev/transitive_ | 1.2.0 | 1.2.6 | Critical | GHSA-xvch-5gv4-984h — Prototype Pollution | NEW |
| 🟠 | `lodash` | 4.17.4 | 4.17.21 | High | GHSA-35jh-r3h4-6jhm — Command Injection | NEW |
| … | | | | | | |
```

---

## What it does

- **Reads lockfiles, not manifests** — resolves *exact* installed versions,
  including the full **transitive** dependency tree, where most CVEs actually live.
- **Asks OSV.dev** — the canonical, free vulnerability database. No toolchain,
  no API key, no vendor lock-in.
- **Diffs against a baseline** — a local SQLite file remembers what it has seen,
  so a daily run surfaces only **new / worsened** findings instead of the whole
  backlog. Alert fatigue is the enemy.
- **Computes real severity** — derives CVSS v3.1 base scores from advisory
  vectors, so `--fail-on high` means something in CI.
- **Stays out of your way** — a CLI you schedule from cron/CI. No server, no
  Neo4j, no Redis, no daemon.

> **Detection is 100% deterministic and needs no API key.** The LLM is reserved
> for an optional fix-guidance layer (see [roadmap](#roadmap)) that explains what
> code to change to upgrade — and is fed real upstream changelogs, never trusted
> to invent them.

---

## Quick start

Requires Python 3.12+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .

brusky scan .                     # Markdown report of new/worsened vulns
brusky scan . --all               # include the known backlog too
brusky scan . --json > out.json   # machine-readable (logs go to stderr)
brusky scan . --fail-on critical  # exit 1 if a new critical appears (for CI)
```

| Flag | Effect |
|---|---|
| `--json` | JSON instead of Markdown |
| `--all` | Show all findings, not just new/worsened |
| `--only npm,composer` | Restrict to specific ecosystems |
| `--db FILE` | State DB path (default `~/.brusky/state.db`) |
| `--fail-on {none,low,medium,high,critical}` | Non-zero exit on a new finding at/above this severity |
| `--verbose` | Log progress to stderr |

Full reference: [docs/usage.md](docs/usage.md).

---

## Supported ecosystems

| Ecosystem | Reads | Advisory source | Status |
|---|---|---|---|
| **Composer** (PHP) | `composer.lock` + `composer.json` | OSV.dev (`Packagist`) | ✅ |
| **npm** (JS/TS) | `package-lock.json` (v1 / v2 / v3) | OSV.dev (`npm`) | ✅ |
| **Docker** base images | `Dockerfile` `FROM` instructions | endoflife.date | ✅ |

Docker support flags **end-of-life** base-image cycles (no more security
patches) and **unpinned** `latest` tags; digest-pinned images are treated as
good practice. Full image CVE scanning (Trivy) is a later milestone.

Adding an ecosystem is a new **collector**; changing the vulnerability source is
a new **advisory** driver. See [docs/architecture.md](docs/architecture.md#the-two-driver-families).

---

## Schedule it (the "daily" part)

Brusky has no daemon — you invoke it from a scheduler. A GitHub Actions cron that
persists the state DB so only new findings surface:

```yaml
on:
  schedule: [{ cron: "0 6 * * *" }]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - uses: actions/cache@v4
        with: { path: ~/.brusky, key: brusky-state-${{ github.repository }} }
      - run: pip install -e .
      - run: brusky scan . --fail-on high
```

More (system cron, exit codes, state management): [docs/usage.md](docs/usage.md).

---

## Documentation

| Doc | What's in it |
|---|---|
| [docs/usage.md](docs/usage.md) | Install, run, read the report, schedule in CI |
| [docs/architecture.md](docs/architecture.md) | Pipeline, modules, data model, the two driver families |
| [docs/decisions.md](docs/decisions.md) | The rewrite path: why pivot, key decisions, what changed, roadmap |

---

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| **M1** | Composer + npm collectors, OSV + CVSS, SQLite diff, Markdown/JSON report, CLI | ✅ Done |
| **M2** | Docker base-image freshness (endoflife.date), dev-dep/reachability deprioritization | ✅ Done |
| **M3** | LLM fix guidance — changelog fetch + call-site grep + advisor with confidence and source links | Planned |
| **M4** | Packaging polish: example config, docs finalization | In progress |

> **History:** Brusky was previously a 5-phase LLM security-audit *agent*
> (FastAPI + Neo4j + Redis + Bitbucket webhooks). It was rewritten into the
> focused tool above; the [decisions doc](docs/decisions.md) explains why and how.

---

## Development

```bash
pip install -e ".[dev]"
pytest          # unit tests + one live-OSV-shaped path (mocked)
ruff check src/brusky tests
```

---

## License

MIT
