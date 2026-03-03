# PHP Security Audit

Perform a security audit of PHP files in `$ARGUMENTS` (defaults to the current directory if not provided).

## Instructions

You are a security auditor scanning PHP code for vulnerabilities. All audit knowledge is contained in this skill file.

Search through all `.php` files in the target path and check for the following vulnerability categories. For each finding, report:
- **File and line number** (as a clickable link)
- **Severity**: Critical / High / Medium / Low
- **Vulnerability type**
- **Vulnerable code snippet**
- **Recommended fix**

### 1. SQL Injection — String Concatenation
Search for `mysqli_query`, `$conn->query`, or `pg_query` calls where the query string contains variable interpolation (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`). Flag any raw string concatenation with user input.

### 2. PHP Type Juggling
Search for loose comparisons (`==`) where one side may be a boolean or zero. Flag patterns like:
- `$input == $storedKey` without `is_string()` check before it
- `json_decode` result compared with `==` instead of `===`
- Missing `hash_equals()` for timing-safe string comparison

### 3. Dangerous `unserialize()`
Search for `unserialize(` calls. Flag any where:
- The input comes from user-controlled sources (`$_COOKIE`, `$_POST`, `$_GET`, `$_SESSION`, Redis/cache reads)
- No `allowed_classes` option is passed (PHP 7.0+)
- The `phar://` wrapper could reach it via file functions (`file_exists`, `is_file`, `fopen`, etc. on user input)

### 4. Dangerous Functions
Grep for any use of:
- **Code execution**: `eval(`, `assert(` (flag in PHP < 8.0 contexts), `` `$  `` (backtick operator with variables)
- **System commands**: `exec(`, `system(`, `passthru(`, `shell_exec(`, `popen(`, `proc_open(`
- **Variable injection**: `extract($_`, `parse_str($` without a second argument
- **Dynamic inclusion**: `include($`, `require($`, `include_once($`, `require_once($` with a variable

### 5. File Inclusion / Path Traversal
Flag `include`/`require` calls where the path contains user input. Look for missing path sanitization — `basename()` alone is insufficient if the extension is also user-controlled.

### 6. Command Injection
Flag `exec()`, `system()`, `shell_exec()` calls. Check whether arguments use `escapeshellarg()` / `escapeshellcmd()`. Note that even with escaping, tools like `tar`, `find`, `wget` can execute code via their own flags — recommend replacing with PHP native functions.

### 7. XSS — Missing Output Encoding
Search for `echo $_`, `print $_`, `echo $`, `print $` patterns where the variable is not wrapped in `htmlspecialchars()`. Also flag `echo` in JS contexts (inside `<script>` tags) not using `json_encode()` with `JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP`.

### 8. php.ini Hardening Check
If a `php.ini` file exists in the path, check for these critical missing settings:
- `expose_php = Off`
- `display_errors = Off`
- `allow_url_include = Off`
- `open_basedir` set
- `session.cookie_httponly = 1`
- `session.cookie_secure = 1`
- `session.cookie_samesite = Strict`

## Output Format

Present findings grouped by severity (Critical first). Use a table for the summary, then expand each finding with the code snippet and fix. If no issues are found in a category, state "No issues found" for that category. End with a count of total findings by severity.
