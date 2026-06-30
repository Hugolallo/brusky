# Usage

## Install

Requires Python 3.12+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # add ".[dev]" for the test toolchain
```

This installs the `brusky` console script.

## Run a scan

```bash
brusky scan [PATH]
```

`PATH` defaults to the current directory. Brusky auto-detects which ecosystems
apply by looking for lockfiles (`composer.lock`, `package-lock.json`) and scans
each one it finds.

### Options

| Flag | Effect |
|---|---|
| `--json` | Emit JSON instead of Markdown (stable shape for CI). |
| `--all` | Show all findings, not just NEW/worsened ones. |
| `--only npm,composer` | Restrict to specific ecosystems. |
| `--db FILE` | State DB path (default `~/.brusky/state.db`). |
| `--fail-on {none,low,medium,high,critical}` | Exit non-zero if a NEW finding meets/exceeds this severity. Default `none`. |
| `--no-llm` | Skip the LLM fix-guidance layer (roadmap M3; accepted now for forward-compat). |
| `--verbose` | Log progress to stderr. |

> Logs always go to **stderr**, so `brusky scan . --json > report.json` produces
> valid JSON with nothing else mixed in.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no NEW finding met the `--fail-on` threshold. |
| `1` | A NEW/worsened finding met/exceeded `--fail-on`. |
| `2` | Bad invocation (e.g. `PATH` is not a directory). |

## Reading the report

The Markdown report leads with **new & worsened** findings since the last scan
(the point of a daily run) and tucks the already-known backlog into a collapsed
section. Each finding shows the installed version, the recommended fix version,
the computed severity, the advisory link, and tags for `dev` / `transitive`
dependencies so you can judge what actually matters.

Findings are classified by diffing against the state DB:

- **NEW** — first time this vulnerability has been seen for this package.
- **WORSENED** — seen before, but its severity has increased.
- **EXISTING** — already known at the same-or-lower severity.

## State & the daily diff

The state DB (`~/.brusky/state.db`) is what lets "daily" mean *"what changed"*
rather than re-reporting the whole backlog every morning. Keep it across runs.

- **CI:** cache or persist the DB file between runs (see below), or point `--db`
  at a checked-in/cached location.
- **Fresh baseline:** delete the DB file (or use a new `--db` path) to treat
  every current finding as NEW again.

## Scheduling (the "daily" part)

Brusky is a CLI invoked by an external scheduler — there is no daemon. The
recommended path is a CI cron job.

### GitHub Actions

```yaml
# .github/workflows/brusky.yml
name: Dependency security scan
on:
  schedule:
    - cron: "0 6 * * *"     # 06:00 UTC daily
  workflow_dispatch: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      # Persist the state DB across runs so only NEW findings surface
      - uses: actions/cache@v4
        with:
          path: ~/.brusky
          key: brusky-state-${{ github.repository }}
      - run: pip install -e .
      - run: brusky scan . --fail-on high
```

### System cron

```cron
0 6 * * *  cd /path/to/project && /path/to/.venv/bin/brusky scan . --json >> /var/log/brusky.jsonl 2>>/var/log/brusky.err
```

## No API key required

Detection works with no LLM provider configured. API keys
(`ANTHROPIC_API_KEY`, etc.) and `GITHUB_TOKEN` are only consulted by the optional
fix-guidance layer (roadmap M3). See [decisions.md](decisions.md) for why
detection is kept deterministic.
