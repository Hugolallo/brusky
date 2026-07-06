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
apply by looking for `composer.lock`, `package-lock.json`, and `Dockerfile`(s),
and scans each one it finds. Package vulnerabilities come from OSV.dev; Docker
base-image freshness (EOL cycles, unpinned `latest` tags) comes from
endoflife.date.

### Options

| Flag | Effect |
|---|---|
| `--json` | Emit JSON instead of Markdown (stable shape for CI). |
| `--html [FILE]` | Also write a self-contained visual HTML report (default `brusky-report.html`). Open it by double-clicking — no server, no build step, no network. |
| `--all` | Show all findings, not just NEW/worsened ones. |
| `--only npm,composer` | Restrict to specific ecosystems. |
| `--explain {auto,all,none}` | LLM explainer + fix guidance. `auto` (default) = new High/Critical findings; `all` = every finding; `none` = off. |
| `--explain-top N` | Cap how many findings the LLM enriches (0 = no cap). |
| `--no-llm` | Disable the LLM layer entirely (same as `--explain none`). |
| `--db FILE` | State DB path (default `~/.brusky/state.db`). |
| `--fail-on {none,low,medium,high,critical}` | Exit non-zero if a NEW finding meets/exceeds this severity. Default `none`. |
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

## The visual HTML report

For a share-friendly, non-technical view of a scan, add `--html`:

```bash
brusky scan . --html                 # writes ./brusky-report.html
brusky scan . --html report.html     # or a path of your choice
```

The result is a **single, self-contained `.html` file** — all styling and
interactivity are inlined, so there is nothing to install and no server to run.
Double-click it to open in any browser (it works straight off the filesystem).
It shows:

- a **risk posture** headline (Clean / Low / Moderate / High / Critical) and the
  total count of vulnerable dependencies;
- a **severity breakdown** bar plus stat tiles for new/worsened, already-known,
  fixable, reachable-in-code, and AI-explained findings;
- one **card per finding** with the installed → fix version, severity, status,
  `dev`/`transitive`/`reachable` tags, CVSS, and a link to the advisory;
- the **AI explainer & upgrade guidance** (when the LLM layer ran) inline in a
  collapsible block per finding;
- live **filters** — by severity, ecosystem, new-only, and free-text search —
  and a light/dark theme toggle.

`--html` is additive: it writes the file *and* still prints the Markdown (or
JSON, with `--json`) report to stdout, so it composes with CI piping. The
"HTML report written to …" confirmation goes to **stderr**. It always renders
the full finding set (not just new ones), regardless of `--all`.

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

## The explainer + fix-guidance layer (optional)

With an LLM provider configured, Brusky adds a collapsible block under each
enriched finding: **why it's vulnerable**, the **impact**, a **severity
rationale**, the **upgrade move**, **breaking changes** (only those found in the
real upstream changelog), **code touchpoints** (only call sites actually found
in your repo), plus an **effort** estimate, a **confidence** rating, and cited
**sources**. It never edits code — it's advisory text you verify.

- **Scope** is controlled by `--explain` (default `auto` = new High/Critical) and
  `--explain-top N`.
- **Caching:** guidance is stored in the state DB keyed by the finding and its
  versions, so daily reruns only call the LLM when something actually changed.
- **Provider/model** come from `config/models.yaml` (`fix_guidance.advisor`),
  defaulting to the global default. Set `GITHUB_TOKEN` to raise the GitHub API
  rate limit used for changelog fetching.

## No API key required

Detection works with no LLM provider configured. If no key is set (or with
`--no-llm` / `--explain none`), the explainer layer is silently skipped and the
report renders exactly as it does without it. API keys (`ANTHROPIC_API_KEY`,
etc.) and `GITHUB_TOKEN` are only consulted by this layer. See
[decisions.md](decisions.md) for why detection is kept deterministic.
