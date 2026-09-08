<div align="center">

# 🛡️ Web Scanner

**A native macOS app that scans a website — and the host behind it — for security**
**weaknesses, exposed secrets, risky services, and performance problems, then**
**explains what each finding means, how it could be exploited, and how to fix it.**

![Platform](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple&logoColor=white)
![Swift](https://img.shields.io/badge/Swift-5.9-F05138?logo=swift&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)


</div>

---

> [!WARNING]
> **Authorized use only.** Only scan domains and hosts you own or have written
> permission to test. Scanning systems you do not control may be illegal where you
> live. This tool sends real HTTP requests and TCP probes to the target — you are
> responsible for how you use it.

## Highlights

- 🧭 **Ten focused scan modes** — from a quick read-only fingerprint to a complete
  Full Audit that runs every category against one host, back-to-back.
- 🔑 **Deep secret scan** — 120+ credential patterns (AWS, GCP, Stripe, GitHub,
  Slack, OpenAI, and many more), found across HTML, JS, CSS, config, and source maps.
- 📂 **Exposed-file hunt** — `.env`, `.git/config`, backups, SQL dumps, and blocked
  `.env` files recovered through side-doors the deny rule usually misses.
- 🗂️ **Content discovery** — wordlist-driven directory & file brute-forcing with
  directory discovery, recursion, extension fuzzing, open-directory + default-file
  detection, MIME-mismatch flags, and title scraping.
- 🧩 **URL-mask generator** — build and probe URLs from a template with wildcards
  ( `?` `*` `[a-z]` `{n,m}` `(a,b,c)` `$` ) — great for hostname/path sweeps.
- 🔌 **Port scan + service ID** — TCP sweep (Fast → Full 65,535) with banner
  grabbing, service fingerprinting, and a per-port hardening playbook.
- 🗄️ **Database exposure** — unauthenticated MySQL/PostgreSQL/MongoDB/Redis/
  Elasticsearch/…, web admin tools, leaked dumps, SQL errors, and injection surface.
- 🖥️ **Host / infrastructure profile** — resolved IPs, reverse DNS, hosting
  provider & ASN, geolocation, CDN/WAF detection, DNS/email records, TLS & SSH audit.
- ⚡ **Performance report** — TTFB, DNS/TCP/TLS setup, protocol & compression, page
  weight, render-blocking resources, and a 0–100 score with concrete fixes.
- 🕸️ **Active (but safe) probes** — open redirect, reflected XSS, CRLF, host-header
  injection, SSTI, SSRF, path traversal, and blind SQLi, all with benign markers.
- 👤 **User-View attacks** — what a signed-up user with DevTools can reach and tamper
  with: hidden/readonly fields, client-side validation, IDOR, mass assignment, and more.
- 📊 **Actionable reports** — every finding rated Critical → Info and exportable as
  Markdown or JSON, plus dedicated dashboards and a discovered-URL / open-port export.

<details>
<summary><b>See the full list of checks</b></summary>

<br>

| Category | Examples |
| --- | --- |
| Exposed secret files | `.env`, `.git/config`, `.aws/credentials`, `.npmrc`, SQL dumps, backups |
| Env hunt (any directory) | `.env`, `.env.prod`, `.env.staging` probed in every crawled directory and common app dir (`app/`, `backend/`, `public/`), plus config paths referenced inside the JS |
| Hidden/blocked `.env` recovery | Recovers a present-but-blocked `.env` via editor swap files (`.env.swp`), non-dotfile copies (`env.bak`), and path-normalization bypasses (`//.env`, `/%2eenv`, trailing dot) |
| Deep secret scan | 120+ credential patterns across cloud, payments, source control, messaging, and AI/dev services, plus JWTs, private keys, JDBC/Basic-auth creds, and `KEY=VALUE` env assignments |
| All files, not just `.env` | Secret-scans every first-party frontend file (HTML, JS, CSS, JSON, source maps, IaC, certs, logs), including bundles served from a CDN or sibling subdomain |
| Second-wave JS | Follows nested `.js` chunks referenced inside bundles and scans them too |
| Client-side risks (JS) | DOM-XSS sinks (`innerHTML`, `document.write`), `eval`/`new Function`, tokens in `localStorage`, `postMessage('*')`, insecure `http://` calls |
| Broken access control / auth | Unauthenticated admin endpoints, 401/403 bypasses via path-normalization and trusted-header spoofs, weak JWTs, IDOR indicators |
| Subdomain discovery + takeover | Probes common subdomains of the target's own domain, secret-scans each, and flags dangling-service takeover fingerprints |
| Open redirect | `?redirect=`, `?next=`, `?url=` params that bounce users off-site — tested with a canary that is never followed |
| Reflected input (XSS) | User input echoed back into HTML without output-encoding, detected with a harmless marker |
| Injection probes | Reflected XSS (with context), SSTI, command injection, SSRF, path traversal, and blind (boolean + time-based) SQLi, all with benign markers |
| CRLF injection / response splitting | Redirect params tested for CR/LF injection into response headers, using a benign marker header |
| Host header injection | Spoofed `Host` / `X-Forwarded-Host` reflected into redirects or absolute links |
| Risky HTTP methods | `TRACE`/`TRACK` and exposed write/WebDAV verbs, enumerated with a single safe `OPTIONS` |
| Verbose errors / debug mode | Framework stack traces and debug pages, surfaced with malformed-but-safe requests |
| Outdated JS libraries | Fingerprints jQuery, AngularJS, Bootstrap, Lodash, Moment.js, and more, and flags versions with public CVEs |
| Software version fingerprinting | Extracts product+version from response headers and service banners (SSH, FTP, SMTP …) and flags end-of-life or below-baseline builds |
| Subresource Integrity (SRI) | Third-party scripts/styles loaded without an `integrity` attribute |
| Mixed content | HTTPS pages loading active `http://` sub-resources |
| CSRF | State-changing (`POST`) forms with no anti-CSRF token |
| Security headers | HSTS, CSP (deep analysis), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and more |
| Transport / TLS | Invalid/expired/self-signed certs, weak keys & legacy signatures, TLS 1.0/1.1 still accepted, missing HTTPS, no HTTP-to-HTTPS redirect |
| SSH audit | Passively reads the SSH banner & `KEX_INIT` and flags weak key-exchange, host-key, cipher, MAC, and compression algorithms |
| Cookies | Missing `Secure`/`HttpOnly`/`SameSite`, `SameSite=None` without `Secure`, `__Host-` prefix violations |
| CORS | Reflected `Access-Control-Allow-Origin` with credentials |
| Open ports & services | TCP sweep with banner grabbing, service fingerprinting, and risky-exposure flags (databases, RDP, Telnet, Docker, Kubernetes, …) |
| Database exposure | Unauthenticated DB/cache/queue services, web admin tools (phpMyAdmin, Adminer …), leaked SQL dumps & SQLite files, SQL-error disclosure and injection surface |
| DDoS-reflection exposure | Checks whether the host answers UDP amplification probes (DNS, NTP, memcached, SSDP, SNMP, CLDAP, …) that could abuse it as an amplifier |
| Info disclosure | `Server`/`X-Powered-By` leaks, directory listing, Spring Actuator, phpinfo, WP user enumeration |

</details>

## Scan modes

Pick a mode at the top of the control panel. Each targets a different question.

### 🧨 Full Audit
Runs **every** category against one host at maximum depth, back-to-back — Info,
Performance, Host, Database, the full Site vulnerability assessment (deep crawl,
wide subdomain enum, blind SQLi, exhaustive `.env` hunt), Content Discovery, and a
complete sweep of all 65,535 TCP ports with banner grabbing — into one combined
report. The most exhaustive scan; very slow (20–40+ minutes) and noisy, so use it
only with explicit permission. (URL Mask is skipped — it needs a template, not a host.)

### 🛡️ Site Scan
The full web vulnerability assessment — headers, TLS, cookies, secrets, injection,
access control, subdomains, and a risky-port sweep — with a **Quick → Max**
intensity control:

| Intensity | What it adds |
| --- | --- |
| **Quick** | Homepage headers, TLS & top secret files only |
| **Standard** | Full sensitive-file probe + homepage secret scan |
| **Deep** | Crawls the site & scripts, source maps, robots/sitemap, forms, GraphQL/API docs, SRI, CRLF, HTTP TRACE, per-page cookie/caching hygiene, plus active injection probes (SQLi, SSTI, command injection, SSRF, path traversal, contextual XSS) |
| **Aggressive** | Deep + path brute-force, backup-name guessing, POST-form XSS, extra CORS origin-bypass checks, and subdomain discovery + takeover |
| **Max** | Everything cranked up: second-wave JS chunks, exhaustive `.env` hunt, wide subdomain enum, and blind (boolean + time-based) SQLi |

### 🗂️ Content Discovery
Wordlist-driven directory and file brute-forcing.

- **Wordlist** — paste words, pick a local file, or give one or more URLs
  (comma-separated). Leave it blank to use the built-in list. Point it at a large
  list (e.g. [SecLists](https://github.com/danielmiessler/SecLists)) for deep scans.
- **Discover directories** — pulls real directories from the page's links,
  `robots.txt`, and `sitemap.xml`, then scans the wordlist inside each.
- **Recursive** — follows directories discovered in responses and scans them too.
- **Extensions** — append a list like `php,bak,old,~` to every word.
- Flags **open directories**, **default files** (`index.php`, …), and
  **Content-Type ↔ extension mismatches**, scrapes each page's `<title>`, and
  secret-scans every non-HTML file it finds. Results land in a **Discovered** tab
  (code · kind · size · title) that exports to text.

### 🧩 URL Mask
Generate URLs from a template and probe each one:

| Wildcard | Meaning |
| --- | --- |
| `?` | one character from the domain alphabet |
| `*` | grow: 1…N such characters (bounded by max length) |
| `[a-z]` | one character from a range/set (e.g. `[a-z0-9]`) |
| `{n,m}` | repeat the preceding set n–m times |
| `(a,b,c)` | one alternative from the list |
| `[...]?` `(...)?` | the set/alternatives, or nothing (optional) |
| `$` | each word from the wordlist |

Examples: `https://base[0-9]{0,3}.(com,org,net)` · `https://[a-z]ou?ube.com` ·
`https://example.com/$`

### 🔌 Port Scan
Scan TCP ports on the host, identify the service on each open port, grab banners,
and flag risky exposures (databases, RDP, Telnet, Docker, …). Pick a profile:

| Profile | Coverage |
| --- | --- |
| **Fast** | ~20 ports that are almost always listening — a few seconds |
| **Top 100** | Nmap's most-common set |
| **Extended** | Well-known, registered, and service-catalog ports |
| **Full** | Every port 1–65535 — thorough but slow & noisy |
| **Custom** | Your own list, e.g. `22,80,443,8000-8100` |

Each open port comes with a hardening **playbook** — what the service is, how to
confirm it, and how to lock it down.

### 🗄️ Database
Hunt for data-store problems across three layers: exposed DB/cache/queue **services**
(MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, …), unauthenticated **access** to
HTTP-speaking stores, web **admin tools** (phpMyAdmin, Adminer, …), and leaked SQL
dumps & SQLite **files** — plus SQL-error disclosure and injection surface. A
dedicated dashboard summarizes exposure and gives a hardening checklist.

### 🖥️ Host
Profile the machine behind the site: resolved IP(s), reverse DNS, hosting provider
& ASN, datacenter-vs-residential and geolocation, CDN/WAF in front of the origin,
and the server/OS stack — plus TLS, SSH, software-version, and exposed-service
findings, and origin-reachable-by-IP exposure.

### ℹ️ Info
A quick, read-only overview: page title & technologies, server stack, resolved
IP(s), reverse DNS, hosting provider/ASN, CDN/WAF, DNS/email records, and a quick
check of common service ports — presented in a fingerprint dashboard. Raises no
active probes.

### ⚡ Performance
Measure load speed from a single instrumented request: server response time (TTFB),
DNS/TCP/TLS setup, HTTP protocol & TLS version, text compression, page weight,
image and caching hygiene, and render-blocking resources — scored 0–100 with a
grade and concrete ways to make it faster.

### 👤 User View
Attack the site the way a real signed-up user would — then actually try the
exploits, staying read-only and safe. **Passive:** open self-registration,
hidden/disabled/readonly fields (price, role, `isAdmin`, qty …) you can flip in
DevTools, client-side-only validation, role/feature flags and auth tokens the
browser can read & edit, JS-readable cookies, secrets & JWTs in the bundle, and the
browser-reachable API surface. **Active:** on visitor-controlled parameters and API
endpoints it fires reflected XSS, open redirect, SQL injection & error disclosure,
path traversal, confirmed IDOR (fetches an adjacent object and diffs),
mass-assignment / debug-parameter tampering, CORS credential-reflection, GraphQL
introspection, clickjacking, and access-control bypass against gated admin routes.

### 🎛️ Advanced request options (all modes)
Custom headers, cookie, HTTP basic auth, user-agent, a millisecond delay between
requests (a real global rate limit), and — for discovery/mask — ignore-codes,
only-codes, and not-in-title filters.

## Requirements

- macOS 13 or newer
- Xcode Command Line Tools (`xcode-select --install`), which provide `swift`

## Build

```bash
git clone https://github.com/kostis4563/web-scanner.git
cd web-scanner

./build.sh
./build.sh --run
```

Then double-click **WebScanner.app** or run `open WebScanner.app`.

## Usage

1. Confirm you are authorized to test the target (checkbox).
2. Choose a **mode** from the panel at the top.
3. Enter the target: a domain (e.g. `example.com`) or host for most modes, or a
   wildcard template for URL Mask.
4. Set mode options (Site Scan intensity, port profile, wordlist, extensions,
   template limits) and, if needed, **Advanced request options**.
5. Click **Scan**, then expand any finding for its exploit path and fix, or switch
   to the **Discovered** / **Ports** tab and the mode dashboards.
6. **Export** a Markdown / JSON report, or the discovered-URL / open-port list.

> **Depth & noise:** Quick modes (Info, Performance) touch the target lightly.
> Site Scan's Aggressive/Max intensities, Port Scan's Full profile, and especially
> **Full Audit** are slow and noisy — use them only with explicit permission.

## Add detections without Swift

Click the **crosshair button** beside the scan-settings button. Web Scanner opens
an editable JSON file at:

```text
~/Library/Application Support/WebScanner/detections.json
```

The file is created automatically from [`Resources/detections.json`](Resources/detections.json)
and contains disabled examples. Duplicate an example, give it a unique `id`, set
`enabled` to `true`, edit the plain-text values, and save. The file is reloaded
before every scan; rebuilding or restarting the app is not required. A malformed
rule is skipped and explained in the scan console instead of crashing the scan.

Two rule types are supported:

- `contentDetections` search downloaded HTML, JavaScript, JSON, CSS, maps, and
  other text. `matchType` can be `contains` or `regex`; matching is
  case-insensitive unless `caseSensitive` is `true`. Use `redactMatch: true` for
  credentials so the matched value follows the app's **Reveal secrets** setting.
- `pathDetections` request an extra relative path on the authorized host and
  confirm it using `bodyContainsAny` (any listed phrase matches) and/or
  `bodyRegex`. These run during Site Scan at Standard or deeper, and Full Audit.
  Set `scanForSecrets` to also run the built-in credential scanner on a confirmed
  response. For a binary or signature-free file, explicitly set
  `allowAnyBody: true`.

Only `id`, `title`, and `pattern` are required for a content rule. Path rules need
`id`, `title`, `path`, plus a content condition (or `allowAnyBody`). Severity may
be `critical`, `high`, `medium`, `low`, or `info`; omitted optional finding text
gets safe defaults. JSON backslashes must be doubled inside regex strings (for
example, `"\\d+"`). Advanced users can load another file by setting the
`WEBSCANNER_DETECTIONS_FILE` environment variable to its absolute path.

## How it works

The scanner is entirely client-side networking (`URLSession` for HTTP, the Network
framework for raw TCP/TLS/UDP) — nothing is uploaded anywhere, and all analysis
happens locally on your Mac. It:

- Fetches the homepage and inspects response headers, cookies, and TLS.
- Probes sensitive paths using content signatures and a soft-404 baseline to
  avoid false positives.
- Extracts and secret-scans script bundles, config files, and nested JS chunks.
- Hunts env/secret files in every directory it discovers, and recovers blocked
  `.env` files through side-doors — without breaking a correctly-enforced 403.
- Statically inspects the JavaScript for risky client-side patterns and outdated
  libraries with known CVEs.
- Sweeps TCP ports, grabs banners, fingerprints the service, and audits the TLS
  and SSH the host presents in the clear.
- Profiles the host — DNS, reverse DNS, ASN/geo, CDN/WAF — and measures load
  performance from instrumented request metrics.
- Runs safe active probes (open redirect, reflected input, CRLF, host header,
  SSTI, SSRF, path traversal, blind SQLi) using benign markers — never a working
  payload, never a state-changing request.

## Contributing

Issues and pull requests are welcome. If you add a new check, please include a
short note on what it detects and why it's safe to run.

## License

Released under the MIT License. See [`LICENSE`](LICENSE) for details.

## Disclaimer

This tool is for authorized security testing and education only. The authors are
not responsible for misuse or for any damage caused by scanning systems you do
not own or have permission to test.
