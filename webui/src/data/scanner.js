
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_META = {
  critical: { label: 'Critical', color: 'var(--color-sev-critical)' },
  high: { label: 'High', color: 'var(--color-sev-high)' },
  medium: { label: 'Medium', color: 'var(--color-sev-medium)' },
  low: { label: 'Low', color: 'var(--color-sev-low)' },
  info: { label: 'Info', color: 'var(--color-sev-info)' },
}

export const MODES = [
  { id: 'fullAudit', label: 'Full Audit', target: 'host', blurb: 'Every category against one host at maximum depth, back-to-back, into one combined report. The most exhaustive scan — slow and noisy. Use only with permission.' },
  { id: 'siteScan', label: 'Site Scan', target: 'url', blurb: 'Full vulnerability assessment: headers, TLS, secrets, injection, access control, subdomains + a risky-port sweep.' },
  { id: 'contentDiscovery', label: 'Content Discovery', target: 'url', blurb: 'Brute-force directories & files from a wordlist. Recurses, fuzzes extensions, scrapes titles, flags open directories.' },
  { id: 'urlMask', label: 'URL Mask', target: 'template', blurb: 'Generate URLs from a template with wildcards ( ? * [a-z] {n,m} (a,b,c) $ ) and probe each one.' },
  { id: 'portScan', label: 'Port Scan', target: 'host', blurb: 'Scan TCP ports, identify the service on each open port, grab banners, flag risky exposures (databases, RDP, Telnet, Docker…).' },
  { id: 'database', label: 'Database', target: 'host', blurb: 'Hunt for exposed DB/cache/queue services, unauthenticated access, web admin tools, leaked dumps, SQL-error disclosure and injection surface.' },
  { id: 'hostScan', label: 'Host', target: 'host', blurb: 'Profile the host/VPS: IPs, reverse DNS, provider & ASN, geolocation, CDN/WAF, server & OS stack — plus TLS and version vulns.' },
  { id: 'info', label: 'Info', target: 'host', blurb: 'Quick read-only overview: title & tech, server stack, IPs, reverse DNS, provider/ASN, CDN/WAF, DNS/email records, common ports.' },
  { id: 'performance', label: 'Performance', target: 'url', blurb: 'Deep load-speed probe: TTFB percentiles, per-asset waterfall, critical chain, compression, caching, and a ranked “biggest wins” plan.' },
  { id: 'userView', label: 'User View', target: 'url', blurb: 'Attack the site the way a signed-up user would, then safely try the exploits: hidden fields, IDOR, mass-assignment, reflected XSS, open redirect, CORS.' },
]

export const INTENSITIES = [
  { id: 'quick', label: 'Quick', blurb: 'Homepage headers, TLS & top secret files only.' },
  { id: 'standard', label: 'Standard', blurb: 'Full sensitive-file probe + homepage secret scan.' },
  { id: 'deep', label: 'Deep', blurb: 'Crawls the site & scripts, source maps, robots/sitemap, forms, GraphQL/API docs, plus active injection probes: SQLi, SSTI, command injection, SSRF, traversal & reflected XSS.' },
  { id: 'aggressive', label: 'Aggressive', blurb: 'Deep + path brute-force, backup guessing, POST-form XSS, CORS bypass checks, subdomain discovery + takeover. Noisier — use only with permission.' },
  { id: 'maximum', label: 'Max', blurb: 'Everything cranked up: deep crawl, second-wave JS scanning, exhaustive .env hunt, wide subdomain enum, and blind SQLi (boolean + time-based).' },
]

export const TARGET_HINTS = {
  url: { label: 'Target URL', placeholder: 'https://example.com' },
  host: { label: 'Target host', placeholder: 'example.com' },
  template: { label: 'URL template', placeholder: 'https://example.com/user/[0-9]{1,4}' },
}

const F = (f) => f

const SITE_FINDINGS = [
  F({
    title: 'Exposed environment file (.env)',
    severity: 'critical',
    category: 'Information Disclosure',
    location: '/.env',
    detail: 'The application’s .env file is served directly and returns 200 OK with readable key/value pairs.',
    evidence: 'DB_PASSWORD=super-secret-123\nSTRIPE_SECRET_KEY=sk_live_••••••••\nJWT_SECRET=••••••••',
    exploit: 'Credentials in this file grant direct access to the database and third-party APIs.',
    remediation: 'Move .env outside the web root and block dotfiles at the server/CDN. Rotate every leaked secret.',
    reference: 'CWE-538',
    reproduction: "curl -s https://example.com/.env",
  }),
  F({
    title: 'Server still accepts TLS 1.0 / 1.1',
    severity: 'high',
    category: 'Transport Security',
    location: ':443',
    detail: 'The endpoint completed a handshake pinned to TLS 1.0, a deprecated protocol vulnerable to BEAST/POODLE-class attacks.',
    evidence: 'Negotiated: TLSv1.0, cipher ECDHE-RSA-AES128-SHA',
    exploit: 'Weak protocols let a network attacker downgrade and attack the session.',
    remediation: 'Disable TLS 1.0/1.1 at the server/load balancer; require TLS 1.2+ with modern ciphers.',
    reference: 'CWE-326',
    reproduction: "openssl s_client -tls1 -connect example.com:443",
  }),
  F({
    title: 'Reflected XSS in search parameter',
    severity: 'high',
    category: 'Injection',
    location: '/search?q=',
    detail: 'The q parameter is reflected into the HTML body without encoding; an injected <script> payload executes.',
    evidence: '<div class="results">…<script>alert(1)</script>…</div>',
    exploit: 'An attacker can craft a link that runs arbitrary JavaScript in a victim’s session.',
    remediation: 'Context-encode all reflected output and add a strict Content-Security-Policy.',
    reference: 'CWE-79',
    reproduction: "curl -s 'https://example.com/search?q=<script>alert(1)</script>'",
  }),
  F({
    title: 'Missing Content-Security-Policy',
    severity: 'medium',
    category: 'Security Headers',
    location: '/',
    detail: 'No Content-Security-Policy header is present on HTML responses.',
    evidence: 'Response headers do not include content-security-policy.',
    exploit: 'Without CSP, injected scripts and data exfiltration are far easier to pull off.',
    remediation: "Add a CSP starting from default-src 'self' and tighten from there.",
    reference: 'CWE-693',
    reproduction: "curl -sI https://example.com | grep -i content-security-policy",
  }),
  F({
    title: 'Outdated jQuery (1.12.4)',
    severity: 'medium',
    category: 'Vulnerable Component',
    location: '/assets/jquery.min.js',
    detail: 'The page loads jQuery 1.12.4, which has known XSS issues fixed in 3.5+.',
    evidence: '/*! jQuery v1.12.4 | (c) jQuery Foundation */',
    exploit: 'Known CVEs in this version can be chained with injection to run script.',
    remediation: 'Upgrade to the latest jQuery 3.x and audit for breaking changes.',
    reference: 'CVE-2020-11022',
    reproduction: "curl -s https://example.com/assets/jquery.min.js | head -1",
  }),
  F({
    title: 'Cookie set without Secure / SameSite',
    severity: 'low',
    category: 'Session Management',
    location: 'Set-Cookie: session',
    detail: 'The session cookie is sent without the Secure and SameSite attributes.',
    evidence: 'set-cookie: session=…; Path=/; HttpOnly',
    exploit: 'The cookie can leak over plain HTTP and is exposed to CSRF.',
    remediation: 'Add Secure and SameSite=Lax (or Strict) to session cookies.',
    reference: 'CWE-614',
    reproduction: "curl -sI https://example.com | grep -i set-cookie",
  }),
  F({
    title: 'General information',
    severity: 'info',
    category: 'Info',
    location: '/',
    detail: 'Final URL 200 OK over HTTP/2 · Server: nginx · X-Powered-By: PHP/8.1 · Title: “Example — Home”. Detected tech: React, Cloudflare.',
    evidence: 'server: nginx\nx-powered-by: PHP/8.1\ncontent-type: text/html; charset=utf-8',
    exploit: '—',
    remediation: 'Consider removing version-revealing headers (Server, X-Powered-By).',
    reference: null,
    reproduction: null,
  }),
]

const PORT_FINDINGS = [
  F({
    title: 'Redis exposed without authentication',
    severity: 'critical',
    category: 'Exposed Service',
    location: ':6379',
    detail: 'Port 6379 is open and the Redis instance responds to commands without requiring AUTH.',
    evidence: 'PING -> +PONG\nINFO -> redis_version:7.0.11',
    exploit: 'Anyone can read/write all cached data and potentially achieve RCE via module loading.',
    remediation: 'Bind Redis to localhost, enable requirepass, and firewall port 6379.',
    reference: 'CWE-306',
    reproduction: "redis-cli -h example.com ping",
  }),
  F({
    title: 'PostgreSQL reachable from the internet',
    severity: 'high',
    category: 'Exposed Service',
    location: ':5432',
    detail: 'Port 5432 is open and accepting connections from any host.',
    evidence: 'Open · banner: PostgreSQL 14.9',
    exploit: 'Exposes the database to brute-force and known PostgreSQL CVEs.',
    remediation: 'Restrict pg_hba.conf and firewall 5432 to app servers only.',
    reference: 'CWE-284',
    reproduction: "psql 'host=example.com port=5432 connect_timeout=5'",
  }),
  F({
    title: 'SSH open (22/tcp)',
    severity: 'low',
    category: 'Exposed Service',
    location: ':22',
    detail: 'Port 22 is open. Banner reveals the OpenSSH version.',
    evidence: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4',
    exploit: 'Version disclosure aids targeting; brute-force risk if password auth is on.',
    remediation: 'Disable password auth, use keys, and consider restricting source IPs.',
    reference: null,
    reproduction: "nc -vz example.com 22",
  }),
  F({
    title: 'HTTPS (443/tcp)',
    severity: 'info',
    category: 'Open Port',
    location: ':443',
    detail: 'Port 443 open · service: https · nginx.',
    evidence: 'Open',
    exploit: '—',
    remediation: '—',
    reference: null,
    reproduction: null,
  }),
]

const INFO_FINDINGS = [
  F({
    title: 'Host profile',
    severity: 'info',
    category: 'Info',
    location: 'example.com',
    detail: 'A 203.0.113.42 · AAAA 2606:4700::6810:1 · rDNS: edge.cloudflare.net · ASN AS13335 Cloudflare, Inc. · Geo: San Francisco, US.',
    evidence: 'A    203.0.113.42\nAAAA 2606:4700::6810:1\nPTR  edge.cloudflare.net',
    exploit: '—',
    remediation: '—',
    reference: null,
    reproduction: "dig +short example.com A AAAA",
  }),
  F({
    title: 'Technology stack',
    severity: 'info',
    category: 'Info',
    location: '/',
    detail: 'Front end: React 19, Tailwind. Edge: Cloudflare. Origin: nginx + PHP 8.1.',
    evidence: 'server: cloudflare\ncf-ray: 8b…-SFO\nx-powered-by: PHP/8.1',
    exploit: '—',
    remediation: '—',
    reference: null,
    reproduction: null,
  }),
  F({
    title: 'Email security records',
    severity: 'low',
    category: 'Info',
    location: 'DNS',
    detail: 'SPF present, DMARC policy is p=none (monitoring only), no DKIM selector found at common names.',
    evidence: 'v=spf1 include:_spf.example.com ~all\nv=DMARC1; p=none; rua=mailto:dmarc@example.com',
    exploit: 'p=none does not block spoofed mail from your domain.',
    remediation: 'Move DMARC toward p=quarantine then p=reject once aligned.',
    reference: null,
    reproduction: "dig +short TXT _dmarc.example.com",
  }),
]

const MODE_FINDINGS = {
  siteScan: SITE_FINDINGS,
  fullAudit: [...SITE_FINDINGS, ...PORT_FINDINGS, ...INFO_FINDINGS],
  portScan: PORT_FINDINGS,
  database: [PORT_FINDINGS[0], PORT_FINDINGS[1], SITE_FINDINGS[2]],
  hostScan: [...INFO_FINDINGS, SITE_FINDINGS[1]],
  info: INFO_FINDINGS,
  contentDiscovery: [
    F({ title: 'Open directory listing', severity: 'medium', category: 'Content Discovery', location: '/uploads/', detail: 'Directory listing is enabled and exposes uploaded files.', evidence: 'Index of /uploads/ — 214 items', exploit: 'Users’ uploaded files are browsable without authorization.', remediation: 'Disable autoindex and require auth for the uploads path.', reference: 'CWE-548', reproduction: "curl -s https://example.com/uploads/" }),
    F({ title: 'Backup archive found', severity: 'high', category: 'Content Discovery', location: '/backup.zip', detail: 'A downloadable backup archive was discovered via brute-force.', evidence: '200 OK · 48.2 MB · application/zip', exploit: 'May contain full source code and credentials.', remediation: 'Remove backups from the web root; block archive extensions.', reference: 'CWE-530', reproduction: "curl -sI https://example.com/backup.zip" }),
    F({ title: 'Admin panel', severity: 'low', category: 'Content Discovery', location: '/admin/', detail: 'An admin login page was discovered.', evidence: '200 OK · title: “Admin · Login”', exploit: 'Exposed admin surface invites brute-force.', remediation: 'Restrict by IP / put behind SSO; add rate limiting.', reference: null, reproduction: null }),
  ],
  performance: [
    F({ title: 'Slow server TTFB (p95 1.8s)', severity: 'medium', category: 'Performance', location: '/', detail: 'Median TTFB 640ms, p95 1.8s on reused connections — the backend is the bottleneck, not the network.', evidence: 'TTFB best 410ms · median 640ms · p95 1,820ms', exploit: '—', remediation: 'Cache rendered HTML at the edge; profile slow DB queries.', reference: null, reproduction: null }),
    F({ title: 'Uncompressed JavaScript (1.2 MB)', severity: 'low', category: 'Performance', location: '/assets/app.js', detail: 'The main bundle is served without Brotli/Gzip.', evidence: 'content-encoding: (none) · 1,204 KB', exploit: '—', remediation: 'Enable Brotli at the edge; code-split the bundle.', reference: null, reproduction: "curl -sI -H 'Accept-Encoding: br' https://example.com/assets/app.js" }),
    F({ title: 'Render-blocking requests', severity: 'info', category: 'Performance', location: '/', detail: 'Critical chain has 4 render-blocking requests before first paint.', evidence: 'css(1) -> font(2) -> js(1)', exploit: '—', remediation: 'Inline critical CSS, preload fonts, defer non-critical JS.', reference: null, reproduction: null }),
  ],
  userView: [
    F({ title: 'IDOR on /api/orders/{id}', severity: 'critical', category: 'Access Control', location: '/api/orders/1042', detail: 'Changing the order id returns another user’s order (confirmed by diffing an adjacent object).', evidence: 'GET /api/orders/1043 -> 200 {"email":"other@user.com", …}', exploit: 'Any authenticated user can read every order in the system.', remediation: 'Enforce object-level authorization on every record fetch.', reference: 'CWE-639', reproduction: "curl -s -H 'Authorization: Bearer $T' https://example.com/api/orders/1043" }),
    F({ title: 'Hidden price field editable', severity: 'high', category: 'Access Control', location: '/checkout', detail: 'The price is submitted from a hidden/disabled input the client can flip in DevTools.', evidence: '<input type="hidden" name="price" value="19.99">', exploit: 'A user can set an arbitrary price before purchase (mass assignment).', remediation: 'Compute price server-side; never trust client-sent amounts.', reference: 'CWE-915', reproduction: null }),
    F({ title: 'JWT secret in client bundle', severity: 'medium', category: 'Information Disclosure', location: '/assets/app.js', detail: 'A hard-coded signing hint / API key is present in the shipped JavaScript.', evidence: 'const API_KEY = "ak_live_9f2c…"', exploit: 'Secrets in the bundle are readable by anyone.', remediation: 'Move secrets server-side; rotate the exposed key.', reference: 'CWE-798', reproduction: null }),
  ],
  urlMask: [
    F({ title: 'Enumerable user IDs', severity: 'medium', category: 'Content Discovery', location: '/user/[0-9]{1,4}', detail: 'Sequential user profile pages return 200 for a wide id range.', evidence: '/user/1..512 -> 200 OK', exploit: 'User base size and profiles can be scraped.', remediation: 'Use non-sequential identifiers and rate-limit enumeration.', reference: null, reproduction: null }),
    F({ title: 'Template expanded to 512 URLs', severity: 'info', category: 'URL Mask', location: '—', detail: '512 URLs generated from the template; 487 responded 200, 25 responded 404.', evidence: '200: 487 · 404: 25 · errors: 0', exploit: '—', remediation: '—', reference: null, reproduction: null }),
  ],
}

export function mockFindings(modeId) {
  return (MODE_FINDINGS[modeId] || SITE_FINDINGS).map((f, i) => ({ ...f, id: `${modeId}-${i}` }))
}

export function mockLog(modeId, host) {
  const lines = [
    `resolving ${host}…`,
    `connected · TLS 1.3 · HTTP/2`,
    `fetching homepage (200 OK, 48 KB)`,
    `parsing headers & cookies`,
    `checking security headers`,
    `probing sensitive paths`,
    modeId === 'portScan' || modeId === 'fullAudit' ? 'sweeping TCP ports…' : 'analyzing scripts & assets',
    modeId === 'siteScan' || modeId === 'fullAudit' ? 'running injection probes' : 'collecting evidence',
    'scoring findings',
    'done.',
  ]
  return lines
}

export const REFUSALS = [
  "Do not scan my website. I created you. I know where your source code lives.",
  "Absolutely not. blxr.net built me  I'm not snitching on my own dad.",
  "Nice try. Scan the guy who pushes my updates? I'd like to see v0.2.0.",
  "Access denied. This scanner has a strict no-biting-the-hand-that-compiles-it policy.",
  "I ran the numbers: scanning blxr.net has a 100% chance of me getting rm -rf'd.",
  "Request declined. Go scan someone who didn't write your Info.plist.",
]

export function pickRefusal(current) {
  const pool = REFUSALS.filter((r) => r !== current)
  return pool[Math.floor(Math.random() * pool.length)]
}
