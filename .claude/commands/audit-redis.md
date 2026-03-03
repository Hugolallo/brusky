# Redis Security Audit

Audit Redis configuration and Laravel's Redis integration at `$ARGUMENTS` (defaults to current directory).

## Instructions

You are a security auditor checking Redis security posture. All audit knowledge is contained in this skill file.

Redis is the highest-risk data layer in this stack: unauthenticated instances are actively exploited (P2PInfect malware, ~60,000 exposed instances per Wiz research). CVE-2025-49844 ("RediShell") scores CVSS 10.0.

For each finding, report:
- **Location** (file/config section as a clickable link, or "redis.conf" / "environment")
- **Severity**: Critical / High / Medium / Low
- **Vulnerability**
- **Recommended fix**

---

### 1. redis.conf Hardening
Search for `redis.conf` or `redis/redis.conf` in the project. If found, check:

| Setting | Insecure Value | Required Value |
|---|---|---|
| `requirepass` | missing or empty | Strong password ≥32 chars |
| `bind` | `0.0.0.0` or missing | `127.0.0.1 ::1` |
| `protected-mode` | `no` | `yes` |
| `FLUSHALL` command | not renamed | `rename-command FLUSHALL ""` |
| `CONFIG` command | not renamed | `rename-command CONFIG "CONFIG_<random>"` |
| `DEBUG` command | not renamed | `rename-command DEBUG ""` |
| `SLAVEOF`/`REPLICAOF` | not renamed | rename or disable |

Also flag if TLS is not configured for production (`tls-port`, `tls-cert-file`, `tls-key-file`).

### 2. docker-compose.yml Redis Service
Search for `docker-compose.yml` or `docker-compose.yaml`. For the `redis` service, check:
- Is `requirepass` passed via environment variable or `--requirepass` command flag?
- Is Redis on an `internal: true` network (no external exposure)?
- Are dangerous commands renamed in the `command:` block?
- Is the port `6379` published to the host (`ports: - "6379:6379"`)? Flag as Critical if so.

### 3. Laravel `.env` Redis Configuration
Search `.env`, `.env.example`, and `config/database.php` for:
- `REDIS_PASSWORD` missing or empty — Critical
- `REDIS_HOST` set to `0.0.0.0` — Critical
- `REDIS_CLIENT` — `phpredis` is preferred over `predis`; note if `predis` is used without TLS

### 4. Laravel Redis Database Separation
Read `config/database.php`. Check the `redis` connection array:
- Are `default`, `cache`, `session`, and `queue` connections using **separate database numbers** (0, 1, 2, 3)?
- Using the same database for all purposes (database 0) means a compromised cache key can read session data

**Secure pattern:**
```php
'cache'   => ['database' => '1'],
'session' => ['database' => '2'],
'queue'   => ['database' => '3'],
```

### 5. Session Encryption
Check `config/session.php`:
- `'driver' => 'redis'` — if Redis sessions are used, is `'encrypt' => true` set?
- Without encryption, anyone with Redis access can read and forge session data

### 6. Queue Deserialization Risk
Search `app/Jobs/` for classes with `ShouldQueue`. Note that Laravel's queue handler calls `unserialize()` **before** verifying the signature when using Redis queues. Flag all jobs that do not implement `ShouldBeEncrypted` as High severity.

Reference: Laravel Reverb GHSA-m27r-m6rx-mhm4 (CVSS 9.8, January 2026) — `unserialize()` on PubSub data without class restrictions.

### 7. SSRF-to-Redis Attack Surface
Search application code for:
- `file_get_contents($url)` where `$url` is user-controlled without scheme whitelisting
- `Http::get($request->input(` or similar Guzzle/HTTP client calls with user-controlled URLs
- Missing URL scheme validation (should block `gopher://`, `dict://`, `file://`)

If SSRF vulnerabilities exist alongside an unauthenticated Redis, the combined risk is Critical (attacker can write webshells or SSH keys to disk).

### 8. Cached Data Deserialization
Search for `Cache::get(` results that are passed to `unserialize(`. Also search for `Redis::get(` calls where the result feeds into `unserialize()` without `allowed_classes` restriction. Flag as Critical.

### 9. ACL Configuration
If Redis 6+ is available (check `redis-server --version` if accessible, or docker image tag), recommend ACL setup:
```
ACL SETUSER webapp on >AppStr0ngPass ~laravel:* +@all -@dangerous -EVAL -CONFIG -DEBUG -FLUSHALL
```
Note if only password auth is used (no ACLs) — this is acceptable for Redis < 6 but should be noted.

---

## Output Format

Lead with a **Risk Summary** showing the overall Redis security posture (Secure / At Risk / Critical). Then list findings by severity. End with the top 3 highest-priority fixes specific to this codebase.
