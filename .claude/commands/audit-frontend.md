# Frontend Security Audit (Vue 2 / Nuxt 2)

Audit Vue 2 and Nuxt 2 code at `$ARGUMENTS` (defaults to current directory).

## Instructions

You are a security auditor scanning a Vue 2 / Nuxt 2 frontend for vulnerabilities. All audit knowledge is contained in this skill file.

**Important context**: Vue 2 reached EOL December 31, 2023. Nuxt 2 reached EOL June 30, 2024. Both accumulate unpatched CVEs. The most critical open issue is **CVE-2024-6783** (prototype pollution in Vue 2's template compiler — unpatched in open source).

For each finding, report:
- **File and line number** (as a clickable link)
- **Severity**: Critical / High / Medium / Low
- **Vulnerability type**
- **Vulnerable code snippet**
- **Recommended fix**

---

## Vue 2 Checks

### 1. XSS via `v-html`
Search all `.vue` files for `v-html=`. For each occurrence:
- Check whether the bound value goes through `DOMPurify.sanitize()` in a computed property
- Flag raw binding of props, data, or store values as High severity
- Confirm `ALLOWED_TAGS` and `ALLOWED_ATTR` are restrictive (not `ADD_TAGS: ['script']`)

**Insecure**: `<div v-html="userComment"></div>`
**Secure**: Bind to a computed that calls `DOMPurify.sanitize(this.rawComment, { ALLOWED_TAGS: ['b','i','a'], ALLOWED_ATTR: ['href'] })`

### 2. Client-Side Template Injection (CSTI)
Flag any pattern where server-rendered content (from SSR, PHP blade, or API responses) is placed inside the Vue mount point without `v-pre`. Vue's template compiler will evaluate `{{ }}` expressions even in server-rendered HTML.

Search for:
- Vue instances mounted on elements that may contain user-generated content (`el: '#app'` where that element includes dynamic server output)
- Missing `v-pre` directive on blocks with server-rendered content
- Use of the full Vue build (`vue.min.js`) instead of the runtime-only build (`vue.runtime.min.js`) — the full build includes the template compiler, which is the CSTI attack surface

### 3. Prototype Pollution — CVE-2024-6783
Flag all Vue 2 projects as having this unpatched vulnerability. The in-browser template compiler's AST codegen is vulnerable to prototype pollution:
- `Object.prototype.staticClass` injection triggers XSS during render
- This affects **all Vue 2.x** versions — no open-source patch exists
- Also check for **CVE-2025-8083** (Vuetify v2's `mergeDeep` utility, CVSS 8.6) if `vuetify` is in `package.json`
- Check for **CVE-2025-27597** (vue-i18n's `handleFlatJson`) if `vue-i18n` is in `package.json`

### 4. Token Storage in `localStorage`
Search all `.js` and `.vue` files for:
- `localStorage.setItem(` with token-related keys (`token`, `auth`, `jwt`, `session`, `bearer`)
- `sessionStorage.setItem(` — also vulnerable to XSS (though tab-scoped)
- Flag these as High — any XSS on the domain can exfiltrate these tokens

**Secure**: Use httpOnly cookies via Laravel Sanctum cookie-based auth. Tokens in `localStorage` are accessible to any injected script.

### 5. DevTools in Production
Search `main.js`, `app.js`, or `plugins/`:
- `Vue.config.devtools = true` — should only be enabled when `NODE_ENV !== 'production'`
- Missing guard: `if (process.env.NODE_ENV === 'production') { Vue.config.devtools = false; }`

Vuex state is fully exposed via Vue DevTools and `window.__VUE_DEVTOOLS_GLOBAL_HOOK__` — any sensitive data in the store is visible.

### 6. Route Guards as Security Boundaries
Search `router/index.js` or `router.js` for `beforeEach` guards used for authorization. Flag these if the corresponding API endpoints do not perform server-side authorization — route guards are UX only and trivially bypassed by calling API endpoints directly.

---

## Nuxt 2 Checks

### 7. `publicRuntimeConfig` Secrets
Read `nuxt.config.js`. Check `publicRuntimeConfig` for:
- Any key whose value is `process.env.` followed by a name suggesting a secret (`SECRET`, `KEY`, `TOKEN`, `PASSWORD`, `PRIVATE`)
- These values are serialized into `window.__NUXT__.config` and sent to every browser

**Secure**: Move secrets to `privateRuntimeConfig`. Only truly public values (API base URL, feature flags) belong in `publicRuntimeConfig`.

Also check the top-level `env:` block — values there are baked into the webpack bundle at build time and visible in source maps.

### 8. `asyncData` SSR State Pollution (XSS)
Search all `.vue` files with `asyncData` for values returned from:
- `params` / `query` route properties (user-controlled URL segments)
- API responses with user-generated content

These values are serialized into `window.__NUXT__`. If they contain `</script>`, they break out of the script context. Verify that `@nuxt/devalue` >= 1.2.3 and `serialize-javascript` >= 2.1.1 are installed (`package.json`/`package-lock.json`).

Flag: CVE-2019-16769 and CVE-2019-16772 (serialize-javascript XSS) — check versions.

### 9. `nuxtServerInit` Sensitive Data in Store
Search `store/index.js` for `nuxtServerInit`. Flag if it commits:
- Full user records (including PII beyond what the UI needs)
- API tokens or session tokens
- Internal configuration data

All store data committed in `nuxtServerInit` appears in `window.__NUXT__` in the HTML source.

### 10. Missing Security Headers
Read `nuxt.config.js`. Check `serverMiddleware` or `render.csp` for security headers:
- `X-Content-Type-Options: nosniff` — flag if missing
- `X-Frame-Options: DENY` — flag if missing
- `Referrer-Policy` — flag if missing
- `Strict-Transport-Security` — flag if missing
- `Content-Security-Policy` — flag if absent (even `Report-Only` is better than nothing)

### 11. `@nuxtjs/proxy` SSRF
If `@nuxtjs/proxy` is in `package.json`, read `nuxt.config.js` proxy configuration:
- Flag any target derived from `req.url`, `req.query`, or other request properties
- Hardcoded targets are safe; dynamic targets enable SSRF to internal services (e.g., AWS metadata at `169.254.169.254`)

### 12. Axios Plugin Configuration
Search `plugins/axios.js` or `plugins/` for Axios configuration:
- Is `withCredentials: true` set? (Required for Sanctum cookie auth)
- Is `withXSRFToken: true` set? (Required for CSRF protection with cookie auth)
- Are Authorization headers set with tokens from `localStorage`? Flag as High.

---

## EOL Status Summary

Always include this notice in the report:
> **Vue 2** — EOL December 31, 2023. CVE-2024-6783 (prototype pollution, template compiler) is **unpatched** in the open-source release.
> **Nuxt 2** — EOL June 30, 2024. Dependency tree includes frozen webpack@4, postcss@7, core-js@2 with accumulating unpatched CVEs.
> **Action required**: Plan migration to Vue 3 / Nuxt 3. For continued Vue 2 support, evaluate HeroDevs Never-Ending Support (NES).

---

## Output Format

Group by: Vue 2 findings → Nuxt 2 findings → EOL Status. Within each group, sort by severity. Include the EOL notice as a fixed section at the top of the report.
