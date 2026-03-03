# Brusky

A stack-agnostic security defense agent. It scans codebases for vulnerabilities using a plugin-style skill system — you tell it which stacks to understand by dropping in skill files, and it figures out which ones to run based on what's in the target directory.

---

## How it works

Brusky runs a 5-phase pipeline:

| Phase | What it does |
|---|---|
| 01 World Model | Builds a Neo4j knowledge graph of the codebase — services, dependencies, exposure, sensitivity |
| 02 Analysis | Discovers and dispatches audit skills via blackboard; each skill scans one layer |
| 03 Exploitability | Simulates attack paths before scoring — eliminates false positives |
| 04 Fix Generation | Generates actual code patches, reflects on them before output |
| 05 Memory & Routing | Detects regressions, writes findings to the graph, routes to output channels |

The agent runs on **Neo4j** (graph memory) + **Redis** (inter-agent blackboard state), orchestrated via Docker.

---

## Skills

Skills are the audit modules. Each skill is two files:

| File | Purpose |
|---|---|
| `config/skills/<id>.yaml` | Manifest — declares what triggers the skill and what it checks |
| `.claude/commands/<id>.md` | Audit prompt — the actual vulnerability checks |

The orchestrator (`/audit-stack`) reads all manifests, globs the target directory, and runs only the skills whose trigger patterns match. **It never hardcodes a stack.**

### Built-in skills

| Skill | Command | Triggers on | Checks |
|---|---|---|---|
| PHP | `/audit-php` | `**/*.php`, `php.ini` | SQLi, type juggling, unserialize, dangerous functions, LFI, XSS |
| Laravel | `/audit-laravel` | `artisan`, `**/*.blade.php`, `app/Jobs/**` | Raw queries, mass assignment, Blade XSS, APP_KEY, queue encryption, CORS, CVEs |
| Redis | `/audit-redis` | `redis.conf`, `docker-compose.yml`, `config/database.php` | Auth, bind, protected-mode, port exposure, DB separation, deserialization |
| Vue 2 / Nuxt 2 | `/audit-frontend` | `**/*.vue`, `nuxt.config.js` | v-html XSS, CSTI, CVE-2024-6783, localStorage tokens, SSR XSS, headers |
| Dependencies | `/audit-deps` | `composer.json`, `package.json`, `yarn.lock` | composer audit, npm audit, lockfile integrity, stack-specific CVE cross-reference |

---

## Adding a skill for a new stack

Two files. Nothing else needs to change — the orchestrator picks them up automatically.

### Step 1 — create the manifest

Create `config/skills/audit-<stack>.yaml`:

```yaml
id: audit-<stack>
name: <Stack> Security Audit
command: audit-<stack>
version: "1.0"
description: >
  One or two sentences describing what this skill checks.

category: framework   # static | deps | config | framework | frontend | infra

stack:
  languages: [python]           # languages this skill covers
  frameworks: [django]          # frameworks (empty [] if pure language)

triggers:
  # Skill activates when ANY of these glob patterns match files in the target.
  # Use ** for any depth, * for any filename segment.
  file_patterns:
    - "manage.py"               # Django project root marker
    - "**/*.py"
    - "requirements.txt"
    - "requirements/**/*.txt"

output:
  severity_levels: [Critical, High, Medium, Low]
  format: grouped_by_severity
  finding_fields: [file, line, vulnerability_type, snippet, fix]
```

**Category values:**

| Category | Use for |
|---|---|
| `static` | Language-level patterns (SQLi, XSS, dangerous functions) |
| `framework` | Framework-specific patterns (ORM misuse, middleware gaps) |
| `deps` | Package manager CVE audits |
| `infra` | Databases, caches, message queues, config files |
| `frontend` | Browser-side code (JS frameworks, CSP, token storage) |
| `config` | CI/CD, Kubernetes, Terraform, env files |

### Step 2 — create the audit prompt

Create `.claude/commands/audit-<stack>.md`:

```markdown
# <Stack> Security Audit

Perform a security audit of `$ARGUMENTS` (defaults to current directory).

## Instructions

You are a security auditor scanning a <Stack> codebase for vulnerabilities.
All audit knowledge is contained in this skill file.

For each finding, report:
- **File and line number** (as a clickable link)
- **Severity**: Critical / High / Medium / Low
- **Vulnerability type**
- **Vulnerable code snippet**
- **Recommended fix**

---

### 1. <Vulnerability class>
<Description of what to search for and how to flag it>

### 2. <Vulnerability class>
...

---

## Output Format

Group findings by severity (Critical first). Summarize with a count per severity at the end.
```

### Step 3 — verify

Run `/audit-stack /path/to/a-<stack>-project` and confirm your skill appears in the scope detection table as ACTIVE.

---

### Examples for common stacks

<details>
<summary>Django / Python</summary>

**Trigger patterns:** `manage.py`, `**/*.py`, `requirements.txt`
**Key checks:** raw SQL via `cursor.execute()` with string format, `ALLOWED_HOSTS = ['*']`, `DEBUG = True` in settings, `SECRET_KEY` in source, missing CSRF middleware, `eval()`/`exec()` on user input, unsafe deserialization via `pickle`

</details>

<details>
<summary>Rails / Ruby</summary>

**Trigger patterns:** `Gemfile`, `config/routes.rb`, `**/*.rb`
**Key checks:** `ActiveRecord::Base.where("#{params[...]}")`, `render inline:`, `send(params[:method])`, mass assignment without `permit`, `Marshal.load` on user input, `RAILS_ENV` exposure

</details>

<details>
<summary>Express / Node.js</summary>

**Trigger patterns:** `package.json`, `**/*.js`, `**/*.ts`, `app.js`, `server.js`
**Key checks:** `eval(req.body...)`, template injection in EJS/Pug, `child_process.exec` with user input, JWT `alg: none`, `helmet` missing, CORS `origin: '*'` with credentials, prototype pollution via `merge`/`extend`

</details>

<details>
<summary>Go</summary>

**Trigger patterns:** `go.mod`, `**/*.go`
**Key checks:** `fmt.Sprintf` in SQL queries, `html/template` vs `text/template` misuse, `os/exec` with user input, hardcoded credentials, SSRF via `http.Get(userInput)`, path traversal in file serving

</details>

---

## Docker setup

```bash
# Copy env template, set your passwords and API key
cp .env.example .env

# Start Neo4j + Redis (agent infra)
docker compose up -d

# Start everything including the agent
docker compose --profile agent up -d

# Neo4j browser UI — log in with username neo4j and your NEO4J_PASSWORD
open http://localhost:7474
```

Docker will refuse to start if `NEO4J_PASSWORD` or `REDIS_PASSWORD` are not set in `.env`.

---

## Model configuration

Model selection lives in `config/models.yaml`. Each agent in each phase can use a different model. No code changes needed to switch providers.

```yaml
# Use a local Ollama model for everything
default:
  provider: ollama
  model: llama3:70b
  api_base: http://host.docker.internal:11434

# Or mix: cheap model for routing, expensive for logic flaws
analysis:
  logic_flaw_detector:
    model: claude-opus-4-6     # most reasoning-intensive task
  controller:
    model: claude-haiku-4-5-20251001   # routing decision — fast + cheap
```

**Supported providers** (via LiteLLM):

| Provider | Example model | Key env var |
|---|---|---|
| `anthropic` | `claude-sonnet-4-6` | `ANTHROPIC_API_KEY` |
| `openai` | `gpt-4o` | `OPENAI_API_KEY` |
| `groq` | `llama3-70b-8192` | `GROQ_API_KEY` |
| `mistral` | `mistral-large-latest` | `MISTRAL_API_KEY` |
| `ollama` | `llama3:70b` | — (no key, set `OLLAMA_API_BASE`) |
| `azure` | `azure/<deployment>` | `AZURE_API_KEY` + `AZURE_API_BASE` |
| `bedrock` | `bedrock/anthropic.claude-3-5-sonnet-...` | AWS credentials |

---

## License

MIT
