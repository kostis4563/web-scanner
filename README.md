<div align="center">

# 🛡️ Web Scanner

**A native macOS app that scans a website for security weaknesses, exposed secrets,**
**and hidden content — and explains what each finding means, how it could be exploited, and how to fix it.**

![Platform](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple&logoColor=white)
![Swift](https://img.shields.io/badge/Swift-5.9-F05138?logo=swift&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)


</div>

---

> [!WARNING]
> **Authorized use only.** Only scan domains you own or have written permission
> to test. Scanning systems you do not control may be illegal where you live.
> This tool sends real HTTP requests to the target — you are responsible for how
> you use it.

## Highlights

- 🔑 **Deep secret scan** — 65+ credential patterns (AWS, GCP, Stripe, GitHub,
  Slack, OpenAI, and many more), found across HTML, JS, CSS, config, and source maps.
- 📂 **Exposed-file hunt** — `.env`, `.git/config`, backups, SQL dumps, and blocked
  `.env` files recovered through side-doors the deny rule usually misses.
- 🗂️ **Content discovery** — wordlist-driven directory & file brute-forcing with
  directory discovery, recursion, extension fuzzing, open-directory + default-file
  detection, MIME-mismatch flags, and title scraping.
- 🧩 **URL-mask generator** — build and probe URLs from a template with wildcards
  ( `?` `*` `[a-z]` `{n,m}` `(a,b,c)` `$` ) — great for hostname/path sweeps.
- 🕸️ **Active (but safe) probes** — open redirect, reflected XSS, CRLF injection,
  and host-header injection, all with benign markers and no state-changing requests.
- 🔓 **Access control & auth** — unauthenticated admin endpoints, 401/403 bypasses,
  weak JWTs, and IDOR indicators.
- 🌐 **Subdomain discovery + takeover** — target-only enumeration with
  dangling-service takeover fingerprints.
- 🎛️ **Request control** — custom headers, cookie, basic auth, user-agent, a global
  request delay (rate limit), and status-code / title response filters.
- 📊 **Actionable reports** — every finding rated Critical → Info and exportable
  as Markdown or JSON, plus a discovered-URL list export.

<details>
<summary><b>See the full list of checks</b></summary>

<br>

| Category | Examples |
| --- | --- |
| Exposed secret files | `.env`, `.git/config`, `.aws/credentials`, `.npmrc`, SQL dumps, backups |
| Env hunt (any directory) | `.env`, `.env.prod`, `.env.staging` probed in every crawled directory and common app dir (`app/`, `backend/`, `public/`), plus config paths referenced inside the JS |
| Hidden/blocked `.env` recovery | Recovers a present-but-blocked `.env` via editor swap files (`.env.swp`), non-dotfile copies (`env.bak`), and path-normalization bypasses (`//.env`, `/%2eenv`, trailing dot) |
| Deep secret scan | 65+ credential patterns across cloud, payments, source control, messaging, and AI/dev services, plus JWTs, private keys, JDBC/Basic-auth creds, and `KEY=VALUE` env assignments |
| All files, not just `.env` | Secret-scans every first-party frontend file (HTML, JS, CSS, JSON, source maps, IaC, certs, logs), including bundles served from a CDN or sibling subdomain |
| Second-wave JS | Follows nested `.js` chunks referenced inside bundles and scans them too |
| Client-side risks (JS) | DOM-XSS sinks (`innerHTML`, `document.write`), `eval`/`new Function`, tokens in `localStorage`, `postMessage('*')`, insecure `http://` calls |
| Broken access control / auth | Unauthenticated admin endpoints, 401/403 bypasses via path-normalization and trusted-header spoofs, weak JWTs, IDOR indicators |
| Subdomain discovery + takeover | Probes common subdomains of the target's own domain, secret-scans each, and flags dangling-service takeover fingerprints |
| Open redirect | `?redirect=`, `?next=`, `?url=` params that bounce users off-site — tested with a canary that is never followed |
| Reflected input (XSS) | User input echoed back into HTML without output-encoding, detected with a harmless marker |
| CRLF injection / response splitting | Redirect params tested for CR/LF injection into response headers, using a benign marker header |
| Host header injection | Spoofed `Host` / `X-Forwarded-Host` reflected into redirects or absolute links |
| Risky HTTP methods | `TRACE`/`TRACK` and exposed write/WebDAV verbs, enumerated with a single safe `OPTIONS` |
| Verbose errors / debug mode | Framework stack traces and debug pages, surfaced with malformed-but-safe requests |
| Outdated JS libraries | Fingerprints jQuery, AngularJS, Bootstrap, Lodash, Moment.js, and more, and flags versions with public CVEs |
| Subresource Integrity (SRI) | Third-party scripts/styles loaded without an `integrity` attribute |
| Mixed content | HTTPS pages loading active `http://` sub-resources |
| CSRF | State-changing (`POST`) forms with no anti-CSRF token |
| Security headers | HSTS, CSP (deep analysis), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and more |
| Transport / TLS | Invalid/expired/self-signed certs, missing HTTPS, no HTTP-to-HTTPS redirect |
| Cookies | Missing `Secure`/`HttpOnly`/`SameSite`, `SameSite=None` without `Secure`, `__Host-` prefix violations |
| CORS | Reflected `Access-Control-Allow-Origin` with credentials |
| Info disclosure | `Server`/`X-Powered-By` leaks, directory listing, Spring Actuator, phpinfo, WP user enumeration |

</details>

## Scan modes

Pick a mode at the top of the control panel:

### 🛡️ Site Scan
The full vulnerability assessment described above — headers, TLS, cookies, secrets,
injection, access control, subdomains, and more — with a **Quick → Max** depth control.

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

./build.sh          # produces WebScanner.app in this folder
./build.sh --run    # build and launch
```

Then double-click **WebScanner.app** or run `open WebScanner.app`.

## Usage

1. Confirm you are authorized to test the target (checkbox).
2. Choose a **mode** — Site Scan, Content Discovery, or URL Mask.
3. Enter the target: a domain (e.g. `example.com`) for Site Scan / Content Discovery,
   or a wildcard template for URL Mask.
4. Set mode options (scan depth, wordlist, extensions, template limits) and, if
   needed, **Advanced request options**.
5. Click **Scan**, then expand any finding for its exploit path and fix, or open the
   **Discovered** tab for the reachable-URL list.
6. **Export** a Markdown / JSON report, or the discovered-URL list as text.

> **Scan depth (Site Scan):** Quick keeps to the homepage. Deep adds the crawl, JS
> analysis, access-control tests, and active probes. Max adds wide subdomain
> enumeration — it's the slowest and noisiest, so use it only with explicit permission.

## How it works

The scanner is entirely client-side networking (`URLSession`) — nothing is
uploaded anywhere, and all analysis happens locally on your Mac. It:

- Fetches the homepage and inspects response headers, cookies, and TLS.
- Probes sensitive paths using content signatures and a soft-404 baseline to
  avoid false positives.
- Extracts and secret-scans script bundles, config files, and nested JS chunks.
- Hunts env/secret files in every directory it discovers, and recovers blocked
  `.env` files through side-doors — without breaking a correctly-enforced 403.
- Statically inspects the JavaScript for risky client-side patterns and outdated
  libraries with known CVEs.
- Runs safe active probes (open redirect, reflected input, CRLF, host header)
  using benign markers — never a working payload, never a state-changing request.

## Contributing

Issues and pull requests are welcome. If you add a new check, please include a
short note on what it detects and why it's safe to run.

## License

Released under the MIT License. See [`LICENSE`](LICENSE) for details.

## Disclaimer

This tool is for authorized security testing and education only. The authors are
not responsible for misuse or for any damage caused by scanning systems you do
not own or have permission to test.
