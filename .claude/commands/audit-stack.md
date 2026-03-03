# Security Audit Orchestrator

Run a comprehensive security audit of the target at `$ARGUMENTS` (defaults to current directory) by discovering available skills and running only those that match the target.

This orchestrator is **stack-agnostic** — it does not assume any particular language or framework. It discovers which audit skills are registered in `config/skills/` and activates only those whose trigger patterns match files in the target.

To add support for a new stack, create:
- `config/skills/audit-<stack>.yaml` — manifest declaring triggers and metadata
- `.claude/commands/audit-<stack>.md` — the audit instructions for that stack

---

## Step 1: Discover registered skills

Read every `.yaml` file in `config/skills/`. For each file, extract:
- `id` — skill identifier
- `name` — human-readable name
- `command` — the slash command to invoke
- `triggers.file_patterns` — glob patterns that activate this skill
- `category` — type of check (static, deps, framework, frontend, infra, config)
- `description` — what it checks

Build a table of all registered skills before proceeding.

---

## Step 2: Detect what's in scope

For each skill's `triggers.file_patterns`, check whether matching files exist under `$ARGUMENTS`.

Use Glob to check patterns. Mark each skill as **active** or **skipped**.

Output a scope detection summary before running any skill:

```
Scope detection for: <target path>
────────────────────────────────────────────────
ACTIVE   audit-php        matched: **/*.php
ACTIVE   audit-laravel    matched: artisan, **/*.blade.php
ACTIVE   audit-redis      matched: docker-compose.yml, config/database.php
ACTIVE   audit-frontend   matched: **/*.vue, nuxt.config.js
ACTIVE   audit-deps       matched: composer.json, package.json
SKIPPED  audit-django     no matching files found
────────────────────────────────────────────────
Running 5 of 6 registered skills
```

---

## Step 3: Run active skills

For each active skill, invoke its command: `/<command> $ARGUMENTS`

Run skills grouped by category in this order (allows findings to inform later layers):
1. `deps` — dependency CVEs first (sets the version context)
2. `static` — language-level patterns
3. `framework` — framework-specific patterns
4. `infra` — infrastructure and config
5. `frontend` — frontend patterns

---

## Step 4: Cross-cutting analysis

After all skills have run, perform these cross-cutting checks that span multiple layers. Only perform checks relevant to the active skills.

### Deserialization attack surface map

Relevant if: any `static` or `framework` skill was active.

Produce a table of every deserialization point found across all active skills:

| Location | Data source | User-controlled? | Severity |
|---|---|---|---|

### Secret exposure map

Relevant if: any `framework`, `infra`, or `frontend` skill was active.

Produce a table of every location where secrets could leak:

| Location | Exposure type | Severity |
|---|---|---|

### Authentication architecture review

If findings span both a backend framework and a frontend skill, assess whether:
- Auth tokens are stored securely (httpOnly cookies vs localStorage)
- API endpoints perform server-side authorization (not just frontend route guards)
- CSRF protection is configured end-to-end

---

## Step 5: Unified report

Aggregate all findings from all active skills into a single structured report.

```
# Brusky Security Audit Report
Date: <today>
Target: <path>
Skills run: <list of active skill names>

## Executive Summary
<3–5 sentence overview of overall risk posture based on actual findings>

## Critical Findings (block deployment)
<findings from all skills at Critical severity>

## High Findings
<findings from all skills at High severity>

## Medium Findings
<findings from all skills at Medium severity>

## Low / Informational Findings
<condensed list>

## Cross-Cutting: Deserialization Attack Surface
<table from Step 4 — only if relevant>

## Cross-Cutting: Secret Exposure Map
<table from Step 4 — only if relevant>

## Dependency Audit Results
<from audit-deps if active — summarized>

## EOL / End-of-Life Framework Status
<list any EOL frameworks detected by active skills>

## Prioritized Remediation Plan

### Immediate (block deployment)
<Critical findings — specific actions>

### Sprint 1
<High findings — specific actions>

### Sprint 2
<Medium findings — specific actions>

### Roadmap
<Low findings + EOL migration planning>

## Total Finding Counts
Critical: X | High: X | Medium: X | Low: X
(from X skills across Y layers)
```

---

## Adding a new stack

To extend Brusky for a different stack (e.g., Django, Rails, Go, React):

1. Create `config/skills/audit-<stack>.yaml`:
   ```yaml
   id: audit-<stack>
   name: <Stack> Security Audit
   command: audit-<stack>
   version: "1.0"
   description: <what it checks>
   category: framework   # static | deps | config | framework | frontend | infra
   stack:
     languages: [python]
     frameworks: [django]
   triggers:
     file_patterns:
       - "manage.py"
       - "**/*.py"
       - "requirements.txt"
   output:
     severity_levels: [Critical, High, Medium, Low]
     format: grouped_by_severity
   ```

2. Create `.claude/commands/audit-<stack>.md` with the audit instructions.

3. Done — this orchestrator will automatically discover and run the new skill on the next scan.
