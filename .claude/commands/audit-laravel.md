# Laravel Security Audit

Perform a Laravel-specific security audit of the project at `$ARGUMENTS` (defaults to the current directory).

## Instructions

You are a security auditor scanning a Laravel 8–11 codebase for vulnerabilities. All audit knowledge is contained in this skill file.

For each finding, report:
- **File and line number** (as a clickable link)
- **Severity**: Critical / High / Medium / Low
- **Vulnerability type**
- **Vulnerable code snippet**
- **Recommended fix**

---

### 1. Raw Query Injection
Search all `.php` files for:
- `whereRaw(` — flag if the first argument contains string interpolation or concatenation with request variables
- `DB::raw(` — flag if the argument is not a static string
- `->orderBy($request->` or `->orderBy($` — flag unwhitelisted column names from user input
- `->selectRaw(` with variables

**Safe pattern**: `$request->validate(['sortBy' => 'in:price,updated_at']); Product::orderBy($request->validated()['sortBy'])`

### 2. Mass Assignment Vulnerabilities
Search all Model files (`app/Models/*.php` or `app/*.php`) for:
- `protected $guarded = []` — flag as unprotected (disables all mass assignment protection)
- `Model::unguard()` outside of seeders
- `forceFill(` or `forceCreate(` with request input

Search Controllers for:
- `->update($request->all())` — should use `$request->validated()` or `$request->only()`
- `->create($request->all())` — same issue
- `new Model($request->all())` — same issue

### 3. Blade XSS — Raw Output
Search all `.blade.php` files for `{!! ` (unescaped output). For each occurrence:
- Flag if the variable could contain user-controlled data
- Flag JavaScript contexts that use `{{ }}` instead of `Js::from()` (Laravel 9+) or `json_encode()` with hex flags
- Flag unquoted HTML attributes: `<tag attr={{ $var }}>` (missing quotes around the attribute value)

### 4. `.env` and APP_KEY Exposure
- Check if `APP_DEBUG` is set to `true` in any `.env` file (Critical)
- Check if `.env` is listed in `.gitignore`
- Check `config/app.php` for hardcoded `APP_KEY` values
- Look for Nginx/Apache config files and verify `.env` is blocked from web access
- Check `APP_ENV` — must be `production` in production config

### 5. Queue Jobs Without Encryption
Search `app/Jobs/*.php` for classes that implement `ShouldQueue` but do NOT also implement `ShouldBeEncrypted`. These jobs may carry sensitive serialized data through Redis queues vulnerable to injection.

### 6. CSRF and Middleware
- Check `bootstrap/app.php` (Laravel 11) or `app/Http/Kernel.php` (Laravel 8–10) for `TrustHosts` — flag if it's commented out or not configured
- Check `config/cors.php` for `'allowed_origins' => ['*']` combined with `'supports_credentials' => true` (Critical)
- Check `TrustProxies` — flag `'proxies' => '*'` as it enables IP spoofing

### 7. JWT Misconfiguration (if using JWT)
Search for `JWT::decode(` calls. Flag any where:
- The algorithm is read from the token (`$header->alg`) rather than hardcoded
- `tymon/jwt-auth` is in `composer.json` without a note about using the fork for Laravel 10+/11+

### 8. Version-Specific Issues
Read `composer.json` to determine the Laravel version:
- Laravel ≤ 8.4.2: flag CVE-2021-3129 (Ignition debug mode RCE) — check if `facade/ignition` is present with `APP_DEBUG=true`
- Laravel < 11.31.0: flag CVE-2024-52301 (ENV manipulation via query string)
- Laravel 11.9.0–11.35.1: flag CVE-2024-13918/19 (XSS in debug error page)
- Laravel < 11.44.1: flag CVE-2025-27515 (file validation bypass)

### 9. Session Configuration
Check `config/session.php` for:
- `'driver' => 'cookie'` — unencrypted cookie sessions (High)
- `'secure' => false` — cookies transmitted over HTTP
- `'http_only' => false` — cookies accessible to JavaScript
- `'same_site' => null` or missing — CSRF exposure

### 10. Input Validation Pattern
Search controllers for `$request->input(` or `$request->get(` that feed directly into database queries or file operations without going through `$request->validate()` first.

---

## Output Format

Group findings by severity (Critical → High → Medium → Low). For each finding include the file link, a one-line description, the vulnerable snippet, and the secure replacement. Summarize with a total count per severity at the end.
