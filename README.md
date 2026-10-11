# Scoped XSS Suite

A Node.js command-line toolkit for testing explicitly configured bug bounty endpoints. It includes 10 harmless execution probes, Chromium verification, JSON/HTML reports, automated regression tests, and a loopback-only practice application. Use targets and request rates allowed by your program.

**A reflected string is not a confirmed XSS finding.** The suite reports `confirmed` only when a payload's unique marker reaches an instrumented `alert()` in an allowed browser frame with the expected effective origin. The page's CSP stays enabled. Reflection-only results are leads for manual review.

## Start with the local lab

Requires Node.js 22 or newer. From this directory:

```powershell
npm ci
npm run setup:browser
npm test
npm run test:browser
npm run demo:scan
```

`demo:scan` starts a temporary local server, runs every configured lab probe with writes enabled, saves `reports/local-demo/report.json` and `report.html`, then stops the server. It never scans a public target. The report includes the temporary port, which no longer serves pages once this command finishes.

For a persistent lab you can explore, run `npm run demo` in one terminal, then in another:

```powershell
node src/cli.js scan --config examples/local-demo.json --allow-writes --out reports/manual-demo
```

The lab listens on `http://127.0.0.1:8765`. Stop it with Ctrl+C. Its deliberately vulnerable pages are for local practice; stored messages live only in memory and are isolated by a session cookie. The local example uses faster request pacing than the target template.

## Configure an authorized target

Copy the template, replace its placeholder URLs and selectors, and remove cases that do not match the application:

```powershell
Copy-Item examples/target.template.json examples/target.local.json
node src/cli.js validate --config examples/target.local.json
node src/cli.js scan --config examples/target.local.json --dry-run
node src/cli.js scan --config examples/target.local.json --out reports/target
```

For explicit form/JSON submissions, add `--allow-writes`. These submissions may create persistent application records. Use your own testing account and clean up created records after testing. GET endpoints can also have side effects; select endpoints accordingly. The flag is a local control, not an indication that a program authorizes those actions.

A minimal query test:

```json
{
  "scope": ["https://your-authorized-target.example/search"],
  "defaults": { "delayMs": 1000, "maxProbes": 20, "maxRequests": 100 },
  "cases": [
    {
      "id": "search-q",
      "type": "query",
      "url": "https://your-authorized-target.example/search?lang=en",
      "param": "q"
    }
  ]
}
```

Scope entries require an exact scheme, host and port, plus a path-segment prefix. `/app` permits `/app` and `/app/search`, but not `/application`. There are no domain wildcards or automatic subdomain expansion. Browser assets outside scope are blocked too; this may prevent an application from working. Include necessary asset URLs only when the program's scope permits them. No crawling or automatic form discovery occurs.

## Test case types

| Type | Required fields | Behavior |
| --- | --- | --- |
| `query` | `url`, `param` | Replaces the named query parameter, navigates in Chromium, checks reflection and execution. Other parameters remain. Duplicate occurrences of the selected parameter become one value. |
| `fragment` | `url` | Injects the URL hash for DOM testing. Optional `fragmentTemplate`, such as `query={payload}`, must contain one placeholder. Payload is URL-encoded once. |
| `form` | `url`, `param` | Sends a URL-encoded POST; optional `data` preserves other form fields. The response alone is reflection evidence. |
| `json` | `url`, `param` | Sends a JSON POST, replacing one top-level property in optional `data`. The response alone is reflection evidence, even when its content type is HTML. |
| `browser-form` | `url`, `field`, `submit` | Opens the real form, fills the payload field by CSS/Playwright selector, then clicks the submit selector. Optional `fields` maps other text-field selectors to strings. |

Every case also needs a unique `id`. `form`, `json` and `browser-form` need `--allow-writes`. These types support `verifyUrls`, an explicit list of pages to visit after submission, using the same cookie jar and browser state. Each verification opens a fresh page. `storedExecutionObserved: true` means execution was observed during that follow-up visit; validate the actual storage and victim workflow manually.

Example stored/form flow:

```json
{
  "id": "own-profile-bio",
  "type": "browser-form",
  "url": "https://your-authorized-target.example/profile/edit",
  "field": "textarea[name=bio]",
  "submit": "button[type=submit]",
  "fields": { "input[name=displayName]": "Authorized test account" },
  "verifyUrls": ["https://your-authorized-target.example/profile/me"]
}
```

The real form flow keeps normal hidden fields and CSRF behavior. Raw POST cases require you to supply any necessary fields yourself; they do not extract fresh CSRF tokens. Selects, file uploads, nested JSON injection, multi-step dialogs, and arbitrary JavaScript actions are not automated by this version.

## Authentication and program headers

Save a test account's Playwright login state locally:

```powershell
New-Item -ItemType Directory -Force auth
npx playwright codegen --save-storage=auth/target.storage-state.json https://your-authorized-target.example/login
```

Log in manually and close the browser to save state. Add `"storageState": "../auth/target.storage-state.json"` to a config inside `examples/`. Relative paths resolve from the config's directory. Browser contexts start fresh for each payload. Saved cookies/local storage can be reused; browser session storage is not restored. In HTTP-only mode, only the cookie portion is useful.

Optional top-level or per-case `headers` can hold a program-required identification header or a test bearer token:

```json
"headers": { "X-Bug-Bounty": "your-handle" }
```

Per-case headers override global headers. Explicit headers are applied only to that case's original origin and are removed after cross-origin HTTP redirects. Cookie state follows normal browser cookie rules. Transport-managed headers, including `Cookie` and `Host`, are rejected; use `storageState` for cookies. Keep real tokens in an ignored `.local.json` file. Auth files, reports and local configs are ignored by Git. Reports may contain sensitive URLs, response excerpts, and transport errors; review them before sharing.

## Controls and reports

```powershell
node src/cli.js payloads
node src/cli.js scan --config examples/target.local.json --http-only
node src/cli.js scan --config examples/target.local.json --headed
node src/cli.js scan --config examples/target.local.json --fail-on-confirmed
```

`--http-only` needs no downloaded Chromium and never claims execution. Fragment and browser-form cases are skipped in that mode. `--dry-run` validates and shows coverage without network requests. `--out` selects the report directory; otherwise a timestamped directory is created. Reusing an output directory replaces its two report files.

`payloadIds` optionally selects built-in payload IDs, for example `["html-script", "html-svg"]`. List IDs with `payloads`. Templates live in `src/payloads.js`; each only produces an alert with a random marker. No credential access, external callback or data extraction is included.

| Default | Value | Meaning |
| --- | ---: | --- |
| `delayMs` | 750 | Minimum spacing between controlled HTTP/browser request starts, including page resources. |
| `timeoutMs` | 10000 | Per-request/navigation/action timeout. |
| `settleMs` | 500 | Observation windows around pending browser requests; increase for slow client rendering. |
| `maxProbes` | 100 | Maximum case × payload combinations attempted. |
| `maxRequests` | 500 | Total controlled request budget, including resources and redirect hops. |
| `maxResponseBytes` | 2000000 | Maximum response body inspected/fulfilled; transport buffers before this check. |
| `maxRedirects` | 5 | Maximum redirects followed by HTTP requests. |

Override values inside `defaults`. Requests are sequentially paced; probes use isolated contexts. HTTP 429 stops new requests. TLS verification stays on. The suite blocks browser redirects entirely, because redirect hops are not reliably intercepted by ordinary Playwright routing. Supply the final page URL, or use `verifyUrls` after a form POST redirects. HTTP-only/raw POST requests follow manually checked in-scope redirects.

| Result | Interpretation |
| --- | --- |
| `confirmed` | Exact per-probe marker executed in an allowed, non-opaque browser origin. Review impact and reproducibility. |
| `reflected` | Marker appeared in response text, which can include properly escaped HTML or JSON. This is not a vulnerability verdict. |
| `not_observed` | Neither execution nor server response reflection was observed in the configured window. This does not mean the endpoint is safe. |
| `inconclusive` | No stronger evidence, and requests were blocked or failed. |
| `skipped` | Required write opt-in or browser mode was absent. |

A reflected or confirmed result can still have errors or blocked requests; read those fields. Counts refer to payload observations, not distinct vulnerabilities. Reports include marker/payload, response context, CSP headers, frame origin, reproduction URL and verification URLs. Other body fields and headers are omitted from reproduction metadata. HTML reports escape all untrusted text and disable scripts.

Exit codes: `0` completed, `1` invalid config/runtime failure, `2` confirmed execution with `--fail-on-confirmed`, `3` partial coverage due to budgets, skipped cases, blocked requests or probe errors. Code `2` takes precedence over `3`. A local demo with a deliberately blocked form redirect can produce code `3` through the normal CLI while still confirming stored execution.

## Coverage limits and manual follow-up

This is a working starter suite, not an exhaustive scanner or a guarantee of bug bounty eligibility. It does not test every event, sanitizer behavior, browser, URL/path/header/cookie source, `postMessage` flow, or multi-user permission boundary. It does not provide blind-XSS collection. URL-prefix checks are application-level guards, not an OS network sandbox; use an isolated environment for untrusted applications.

Browser redirects, service workers and WebSockets are disabled. Third-party dependencies outside scope are blocked. Alert instrumentation, headless Chromium, resource limits and saved-session limitations may affect behavior. The response limit is checked after buffering and is not a hard streaming memory/download cap. A timeout or `not_observed` result does not rule out delayed or interaction-dependent XSS.

Use [the test checklist](docs/testing-checklist.md) to extend coverage and [the finding template](docs/finding-template.md) to prepare a manually verified report.

Implementation references: [OWASP XSS overview](https://community.owasp.org/attacks/xss/), [OWASP stored-XSS testing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting/), [Playwright network interception](https://playwright.dev/docs/network), and [Playwright API request context](https://playwright.dev/docs/api/class-apirequestcontext).
