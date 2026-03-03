# Dependency Audit

Run `composer audit` and `npm audit` for the project at `$ARGUMENTS` (defaults to current directory), then interpret and triage the results.

## Instructions

You are a security auditor checking third-party dependencies against known CVEs. All audit knowledge is contained in this skill file.

---

## Step 1: Detect What's Present

Before running audits, check which package files exist:
- `composer.json` / `composer.lock` — PHP dependencies
- `package.json` / `package-lock.json` or `yarn.lock` — JS dependencies

If a lockfile is missing, flag it immediately:
> **High**: No `composer.lock` / `package-lock.json` found. Without a lockfile, installs are non-deterministic and vulnerable to supply chain attacks — a malicious version could be pulled on the next `install`.

---

## Step 2: Run the Audits

Run both commands (skip whichever has no manifest):

```bash
composer audit --format=json 2>&1
```

```bash
npm audit --json 2>&1
```

If `npm` is not available but `yarn` is:
```bash
yarn audit --json 2>&1
```

If either command is not available (e.g. no Composer or Node installed), note it and move on — still perform the static checks in Step 3.

---

## Step 3: Parse and Triage Results

### For `composer audit` output:
Map each advisory to a severity tier:
- **Critical**: CVSS ≥ 9.0 or any RCE/auth-bypass
- **High**: CVSS 7.0–8.9 or significant data exposure
- **Medium**: CVSS 4.0–6.9
- **Low**: CVSS < 4.0 or informational

For each advisory, report:
| Field | Value |
|---|---|
| Package | e.g. `laravel/framework` |
| Installed version | |
| CVE / Advisory ID | |
| CVSS | |
| Description | one line |
| Fix version | minimum safe version |
| Upgrade command | `composer require package/name:^x.y` |

### For `npm audit` output:
Same structure. Parse the JSON — do not just print the raw output. Group by severity.

For each vulnerability, report:
| Field | Value |
|---|---|
| Package | |
| Via (dependency path) | e.g. `nuxt > serialize-javascript` |
| CVE | |
| Severity | |
| Description | |
| Fix | `npm audit fix` or manual upgrade |

---

## Step 4: Cross-Reference Against Known Stack CVEs

Regardless of audit output, explicitly check the installed versions of these packages against their known-vulnerable ranges from the security guide:

### PHP / Composer
| Package | Check | Vulnerable Range | CVE |
|---|---|---|---|
| `laravel/framework` | version in composer.lock | <6.20.45, <8.83.28, <10.48.23, <11.31.0 | CVE-2024-52301 |
| `laravel/framework` | version in composer.lock | <11.44.1, <12.1.1 | CVE-2025-27515 |
| `laravel/framework` | version in composer.lock | 11.9.0–11.35.1 | CVE-2024-13918/19 |
| `facade/ignition` | present + APP_DEBUG=true | ≤2.5.1 (Laravel ≤8.4.2) | CVE-2021-3129 |
| `tymon/jwt-auth` | present | any version on Laravel 10+ | Effectively abandoned — recommend `php-open-source-saver/jwt-auth` |

### JS / npm
| Package | Check | Vulnerable Range | CVE / Issue |
|---|---|---|---|
| `vue` | version | 2.x (all) | CVE-2024-6783 — unpatched prototype pollution |
| `nuxt` | version | 2.x (all) | EOL June 2024, accumulating unpatched deps |
| `serialize-javascript` | version | <2.1.1 | CVE-2019-16769, CVE-2019-16772 (SSR XSS) |
| `@nuxt/devalue` | version | <1.2.3 | SSR serialization XSS |
| `vuetify` | version | 2.x | CVE-2025-8083 (mergeDeep prototype pollution, CVSS 8.6) |
| `vue-i18n` | version | affected versions | CVE-2025-27597 (handleFlatJson prototype pollution) |

For each package above, read the actual installed version from `composer.lock` (`.packages[].version`) or `package-lock.json` (`.packages["node_modules/pkg"].version`) and report whether it falls in the vulnerable range.

---

## Step 5: Lockfile Integrity Check

- Verify `composer.lock` is committed (check `.gitignore` — it must NOT list `composer.lock`)
- Verify `package-lock.json` is committed (same check)
- If either lockfile is in `.gitignore`, flag as **High** — supply chain risk, deterministic installs impossible

---

## Step 6: Automated Monitoring Recommendations

Based on what's found, recommend the appropriate tooling:

**If no automated dep monitoring is set up** (no `dependabot.yml` or `renovate.json` in the repo):
- Suggest adding GitHub Dependabot:
  ```yaml
  # .github/dependabot.yml
  version: 2
  updates:
    - package-ecosystem: "composer"
      directory: "/"
      schedule:
        interval: "weekly"
    - package-ecosystem: "npm"
      directory: "/"
      schedule:
        interval: "weekly"
  ```
- Or suggest adding `composer audit` and `npm audit --audit-level=high` as CI steps that fail the build on High+ findings

---

## Output Format

```
# Dependency Audit Report
Date: [today]
Target: [path]

## Summary
Composer: X critical, X high, X medium, X low
npm: X critical, X high, X medium, X low

## Critical Findings
[table per finding]

## High Findings
[table per finding]

## Medium / Low Findings
[condensed list]

## Stack-Specific CVE Check
[table: package | installed | vulnerable? | CVE]

## Lockfile Status
[pass/fail per lockfile]

## Recommended Next Steps
1. [highest priority upgrade]
2. ...
```
