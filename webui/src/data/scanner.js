
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

const SECRET_FINDINGS = [
  F({
    title: 'Exposed .git directory',
    severity: 'critical',
    category: 'Information Disclosure',
    location: '/.git/config',
    detail: 'The .git directory is served to the public. /.git/config and /.git/HEAD return 200 OK, so the full repository history — including any secrets ever committed — can be reconstructed.',
    evidence: '[core]\n  repositoryformatversion = 0\n[remote "origin"]\n  url = https://•••••@github.com/acme/app.git',
    exploit: 'The entire source tree and every secret ever committed (even later "removed") can be pulled down.',
    remediation: 'Block /.git at the server/CDN, keep the deploy artifact separate from the repo, and rotate any credential that was ever committed.',
    reference: 'CWE-527',
    reproduction: "curl -s https://example.com/.git/config",
  }),
  F({
    title: 'Hard-coded credentials in JavaScript bundle',
    severity: 'high',
    category: 'Information Disclosure',
    location: '/assets/app.js',
    detail: 'The shipped bundle contains live-looking secret material (API key, signing hint). Anyone who views source can read it.',
    evidence: 'const STRIPE_KEY = "sk_live_••••••••";\nconst JWT_SECRET = "••••••••";',
    exploit: 'Secrets in client code are world-readable and can be used to call paid/privileged APIs as the app.',
    remediation: 'Move secrets server-side behind an API, scope keys to the minimum needed, and rotate anything exposed in a shipped build.',
    reference: 'CWE-798',
    reproduction: "curl -s https://example.com/assets/app.js | grep -iE 'sk_live|secret|api[_-]?key'",
  }),
  F({
    title: 'Cloud access key in HTTP response',
    severity: 'critical',
    category: 'Information Disclosure',
    location: '/config.js',
    detail: 'A response contains a string matching an AWS access-key-ID pattern alongside what looks like a secret key.',
    evidence: 'AWS_ACCESS_KEY_ID=AKIA••••••••••••\nAWS_SECRET_ACCESS_KEY=••••••••',
    exploit: 'Valid cloud keys can grant access to storage, compute, and billing in the account.',
    remediation: 'Rotate the key pair immediately, scope IAM policies tightly, and prefer short-lived role credentials over static keys.',
    reference: 'CWE-798',
    reproduction: "curl -s https://example.com/config.js | grep -iE 'AKIA[0-9A-Z]{16}'",
  }),
  F({
    title: 'Backup / dotfile with secrets',
    severity: 'high',
    category: 'Information Disclosure',
    location: '/.env.bak',
    detail: 'A sibling backup of a config file (.env.bak, config.php~, settings.py.save) is readable and contains key/value secrets.',
    evidence: 'DB_PASSWORD=••••••••\nMAIL_PASSWORD=••••••••',
    exploit: 'Editor/deploy backups often hold the same live credentials as the real config file.',
    remediation: 'Block backup/editor suffixes (~ .bak .old .save .swp) at the server and keep backups out of the web root. Rotate leaked secrets.',
    reference: 'CWE-530',
    reproduction: "curl -sI https://example.com/.env.bak",
  }),
  F({
    title: 'Private key served publicly',
    severity: 'critical',
    category: 'Information Disclosure',
    location: '/id_rsa',
    detail: 'A PEM-formatted private key is downloadable from the web root.',
    evidence: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA••••••••\n-----END RSA PRIVATE KEY-----',
    exploit: 'A leaked private key can impersonate the server/service or allow SSH access depending on its use.',
    remediation: 'Remove the key from the web root immediately, rotate the key pair, and audit anywhere it was authorized.',
    reference: 'CWE-312',
    reproduction: "curl -s https://example.com/id_rsa | head -1",
  }),
  F({
    title: 'Secret in HTML comment',
    severity: 'medium',
    category: 'Information Disclosure',
    location: '/',
    detail: 'An HTML comment left in the page contains what looks like a credential or internal note.',
    evidence: '<!-- TODO remove before prod: basic-auth staging:•••••••• -->',
    exploit: 'Comments ship to every visitor; leftover credentials or internal hosts help an attacker pivot.',
    remediation: 'Strip comments in the production build and never place secrets or internal hostnames in markup.',
    reference: 'CWE-615',
    reproduction: "curl -s https://example.com/ | grep -o '<!--.*-->'",
  }),
]

const ADMIN_FINDINGS = [
  F({
    title: 'Admin panel reachable without authentication',
    severity: 'critical',
    category: 'Access Control',
    location: '/admin/',
    detail: 'The admin path returns the dashboard itself (not a login) to an unauthenticated request — no session cookie or auth header was sent.',
    evidence: 'GET /admin/ -> 200 OK · title: “Dashboard” · contains "Users", "Settings" nav (no redirect to /login)',
    exploit: 'The administrative interface is usable by anyone who finds the URL.',
    remediation: 'Require authentication on every admin route server-side, redirect unauthenticated requests to login, and put the panel behind SSO/IP allow-listing.',
    reference: 'CWE-306',
    reproduction: "curl -s -o /dev/null -w '%{http_code}' https://example.com/admin/",
  }),
  F({
    title: 'Admin login accepts a known default credential',
    severity: 'critical',
    category: 'Access Control',
    location: '/admin/login',
    detail: 'The login form accepted a well-known default account (shipped-with-the-software pair) and returned an authenticated session instead of an error.',
    evidence: 'POST /admin/login (default vendor account) -> 302 /admin/ · Set-Cookie: session=•••••••• · no lockout after attempt',
    exploit: 'Default accounts that were never disabled give full admin access and are the first thing attackers try.',
    remediation: 'Delete or rename all default/seed accounts, force a strong password on first run, enable MFA, and add login rate-limiting + lockout.',
    reference: 'CWE-1392',
    reproduction: null,
  }),
  F({
    title: 'Admin API exposed without authorization',
    severity: 'high',
    category: 'Access Control',
    location: '/api/admin/users',
    detail: 'An admin API endpoint returns privileged data to a request with no token or an ordinary user token.',
    evidence: 'GET /api/admin/users -> 200 [{"email":"•••","role":"admin"}, …]',
    exploit: 'Admin-only data/actions are reachable without admin rights — a privilege-escalation path.',
    remediation: 'Enforce role checks on the server for every admin endpoint, not just by hiding the UI link.',
    reference: 'CWE-285',
    reproduction: "curl -s -o /dev/null -w '%{http_code}' https://example.com/api/admin/users",
  }),
  F({
    title: 'Admin login has no brute-force protection',
    severity: 'medium',
    category: 'Access Control',
    location: '/admin/login',
    detail: 'Repeated failed logins return the same error with no delay, lockout, or CAPTCHA — unlimited guessing is possible.',
    evidence: '20 rapid POST /admin/login -> all 200 "invalid" · no 429 · no Retry-After',
    exploit: 'Unlimited attempts make password guessing against admin accounts practical.',
    remediation: 'Add per-account and per-IP rate limiting, exponential backoff / temporary lockout, and MFA on admin accounts.',
    reference: 'CWE-307',
    reproduction: null,
  }),
  F({
    title: 'Admin panel discovered',
    severity: 'low',
    category: 'Content Discovery',
    location: '/admin/',
    detail: 'A login page for an administrative interface was found at a common path (also checked: /wp-admin, /administrator, /manage, /panel).',
    evidence: '200 OK · title: “Admin · Login”',
    exploit: 'An exposed admin surface invites credential brute-force and targeted attacks.',
    remediation: 'Restrict by IP / put behind SSO, rename off well-known paths, and add rate limiting.',
    reference: null,
    reproduction: "curl -sI https://example.com/admin/",
  }),
]

const HEADER_FINDINGS = [
  F({ title: 'Missing HSTS header', severity: 'medium', category: 'Security Headers', location: '/', detail: 'Responses over HTTPS do not set Strict-Transport-Security, so browsers may still try plain HTTP.', evidence: 'no strict-transport-security header', exploit: 'A network attacker can downgrade the first request to HTTP and intercept it.', remediation: 'Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload.', reference: 'CWE-319', reproduction: "curl -sI https://example.com | grep -i strict-transport-security" }),
  F({ title: 'Clickjacking: no frame protection', severity: 'medium', category: 'Security Headers', location: '/', detail: 'Neither X-Frame-Options nor a CSP frame-ancestors directive is set; the page can be framed by any site.', evidence: 'no x-frame-options · no frame-ancestors in CSP', exploit: 'The UI can be overlaid in a hidden iframe to trick users into clicks (clickjacking).', remediation: "Set X-Frame-Options: DENY or CSP frame-ancestors 'self'.", reference: 'CWE-1021', reproduction: "curl -sI https://example.com | grep -iE 'x-frame-options|frame-ancestors'" }),
  F({ title: 'Missing X-Content-Type-Options', severity: 'low', category: 'Security Headers', location: '/', detail: 'The nosniff header is absent, so browsers may MIME-sniff responses.', evidence: 'no x-content-type-options header', exploit: 'MIME sniffing can turn an uploaded file into executable script in the victim’s browser.', remediation: 'Add X-Content-Type-Options: nosniff on all responses.', reference: 'CWE-693', reproduction: "curl -sI https://example.com | grep -i x-content-type-options" }),
  F({ title: 'Missing Referrer-Policy', severity: 'low', category: 'Security Headers', location: '/', detail: 'No Referrer-Policy header; full URLs may leak to third parties via the Referer header.', evidence: 'no referrer-policy header', exploit: 'Sensitive path/query data can leak to external sites in the Referer.', remediation: 'Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).', reference: 'CWE-200', reproduction: "curl -sI https://example.com | grep -i referrer-policy" }),
  F({ title: 'Missing Permissions-Policy', severity: 'info', category: 'Security Headers', location: '/', detail: 'No Permissions-Policy header; powerful browser features are not restricted.', evidence: 'no permissions-policy header', exploit: 'Embedded/injected content can request camera, mic, geolocation, etc.', remediation: 'Add a Permissions-Policy that disables unused features, e.g. camera=(), microphone=(), geolocation=().', reference: 'CWE-693', reproduction: "curl -sI https://example.com | grep -i permissions-policy" }),
  F({ title: 'Sensitive page is cacheable', severity: 'low', category: 'Security Headers', location: '/account', detail: 'An authenticated page is returned without Cache-Control: no-store, so it may be stored by shared caches/proxies.', evidence: 'cache-control: public, max-age=3600 on /account', exploit: 'Private data can be served to the next user of a shared cache.', remediation: 'Send Cache-Control: no-store (and no caching headers) on authenticated responses.', reference: 'CWE-525', reproduction: "curl -sI https://example.com/account | grep -i cache-control" }),
]

const INJECTION_FINDINGS = [
  F({ title: 'SQL injection (error-based)', severity: 'critical', category: 'Injection', location: '/product?id=', detail: 'A single quote in the id parameter triggers a database error echoed into the response.', evidence: "id=1' -> 500 \"SQLSTATE[42000]: syntax error near ''1'''\"", exploit: 'The parameter is concatenated into SQL, allowing data theft or modification.', remediation: 'Use parameterised queries / prepared statements and a least-privilege DB account.', reference: 'CWE-89', reproduction: "curl -s \"https://example.com/product?id=1'\"" }),
  F({ title: 'Blind SQL injection (time-based)', severity: 'critical', category: 'Injection', location: '/search?q=', detail: 'A boolean/time payload measurably delays the response, indicating injectable SQL with no visible error.', evidence: "q=x';SELECT pg_sleep(5)-- -> response +5.0s vs ~0.3s baseline", exploit: 'Data can be exfiltrated bit by bit even without error output.', remediation: 'Parameterise all queries; add a WAF rule and query timeouts as defence in depth.', reference: 'CWE-89', reproduction: null }),
  F({ title: 'Server-side template injection (SSTI)', severity: 'critical', category: 'Injection', location: '/greet?name=', detail: 'A template expression in the name parameter is evaluated server-side.', evidence: 'name={{7*7}} -> page renders "49"', exploit: 'SSTI frequently escalates to remote code execution.', remediation: 'Never put user input into template source; use a sandboxed, logic-less template and pass data as context.', reference: 'CWE-1336', reproduction: "curl -s 'https://example.com/greet?name=%7B%7B7*7%7D%7D'" }),
  F({ title: 'OS command injection', severity: 'critical', category: 'Injection', location: '/tools/ping', detail: 'The host field appears to be passed to a shell; a chained command alters the output.', evidence: 'host=127.0.0.1;id -> output contains "uid=33(www-data)"', exploit: 'An attacker can run arbitrary OS commands on the server.', remediation: 'Avoid the shell; call binaries with an argument array and validate/allow-list input.', reference: 'CWE-78', reproduction: null }),
  F({ title: 'XML external entity (XXE)', severity: 'high', category: 'Injection', location: '/api/import', detail: 'The XML parser resolves external entities, letting a document read local files.', evidence: '<!ENTITY xxe SYSTEM "file:///etc/passwd"> -> response echoes "root:x:0:0"', exploit: 'Can read local files and trigger SSRF from the server.', remediation: 'Disable DTDs/external entity resolution in the XML parser.', reference: 'CWE-611', reproduction: null }),
  F({ title: 'NoSQL injection', severity: 'high', category: 'Injection', location: '/api/login', detail: 'A JSON operator payload bypasses the query filter on the login endpoint.', evidence: '{"user":"admin","pass":{"$ne":null}} -> 200 authenticated', exploit: 'Operator injection can bypass auth or dump documents.', remediation: 'Cast inputs to expected types, reject objects where scalars are expected, and use strict schemas.', reference: 'CWE-943', reproduction: null }),
  F({ title: 'CRLF / HTTP response splitting', severity: 'medium', category: 'Injection', location: '/redirect?url=', detail: 'Encoded CR/LF in a reflected parameter injects a new response header.', evidence: 'url=%0d%0aSet-Cookie:inj=1 -> response includes "Set-Cookie: inj=1"', exploit: 'Attackers can inject headers, set cookies, or poison caches.', remediation: 'Strip CR/LF from values placed in headers; use the framework’s header API.', reference: 'CWE-93', reproduction: null }),
  F({ title: 'LDAP injection', severity: 'high', category: 'Injection', location: '/directory?user=', detail: 'LDAP filter metacharacters in the user parameter alter the directory query.', evidence: 'user=*)(uid=* -> returns all directory entries', exploit: 'Can bypass filters and enumerate or authenticate against the directory.', remediation: 'Escape LDAP special characters and use parameterised filters.', reference: 'CWE-90', reproduction: null }),
]

const ACCESS_FINDINGS = [
  F({ title: 'CORS allows any origin with credentials', severity: 'high', category: 'Access Control', location: '/api/', detail: 'The API reflects the request Origin and sets Access-Control-Allow-Credentials: true.', evidence: 'Origin: https://evil.test -> ACAO: https://evil.test · ACAC: true', exploit: 'Any site can make authenticated cross-origin requests and read the responses.', remediation: 'Allow only a vetted origin allow-list; never reflect arbitrary origins with credentials.', reference: 'CWE-942', reproduction: "curl -s -I -H 'Origin: https://evil.test' https://example.com/api/ | grep -i access-control" }),
  F({ title: 'Open redirect', severity: 'medium', category: 'Access Control', location: '/out?url=', detail: 'The redirect target is taken from a parameter without validation.', evidence: 'url=https://evil.test -> 302 Location: https://evil.test', exploit: 'Used to make phishing links look like they come from your domain.', remediation: 'Redirect only to a relative path or an allow-listed host.', reference: 'CWE-601', reproduction: "curl -sI 'https://example.com/out?url=https://evil.test' | grep -i location" }),
  F({ title: 'Server-side request forgery (SSRF)', severity: 'high', category: 'Access Control', location: '/fetch?url=', detail: 'A server-side fetch follows an attacker-supplied URL, including internal addresses.', evidence: 'url=http://169.254.169.254/latest/meta-data/ -> cloud metadata returned', exploit: 'Can reach internal services and cloud metadata to steal credentials.', remediation: 'Allow-list destinations, block private/link-local ranges, and disable redirects on server fetches.', reference: 'CWE-918', reproduction: null }),
  F({ title: 'Path traversal / local file read', severity: 'high', category: 'Access Control', location: '/download?file=', detail: 'Dot-dot sequences in the file parameter escape the intended directory.', evidence: 'file=../../../../etc/passwd -> response contains "root:x:0:0"', exploit: 'Arbitrary files readable by the app user can be downloaded.', remediation: 'Resolve the path and confirm it stays within a base directory; reject .. and absolute paths.', reference: 'CWE-22', reproduction: "curl -s 'https://example.com/download?file=../../../../etc/passwd'" }),
  F({ title: 'Missing function-level authorization', severity: 'high', category: 'Access Control', location: '/api/reports/export', detail: 'A privileged action succeeds for a normal (non-admin) user session.', evidence: 'POST /api/reports/export as basic user -> 200 (admin-only action)', exploit: 'Users can invoke actions their role should not permit.', remediation: 'Check the required role/permission server-side on every sensitive action.', reference: 'CWE-862', reproduction: null }),
  F({ title: 'IDOR on user profile', severity: 'high', category: 'Access Control', location: '/api/users/{id}', detail: 'Swapping the id returns another user’s private profile.', evidence: 'GET /api/users/2001 as user 2000 -> 200 {"phone":"•••","address":"•••"}', exploit: 'Any user can read other users’ records by changing the id.', remediation: 'Enforce per-object ownership checks on every fetch.', reference: 'CWE-639', reproduction: null }),
  F({ title: 'Privilege escalation via role parameter', severity: 'high', category: 'Access Control', location: '/api/profile', detail: 'The profile update accepts a role/isAdmin field and trusts it.', evidence: 'PATCH /api/profile {"role":"admin"} -> 200, subsequent requests act as admin', exploit: 'A user can grant themselves admin by adding a field (mass assignment).', remediation: 'Whitelist updatable fields server-side; never accept role/privilege from the client.', reference: 'CWE-269', reproduction: null }),
  F({ title: 'Unauthenticated file upload', severity: 'high', category: 'Access Control', location: '/upload', detail: 'The upload endpoint accepts files without authentication and stores them in a web-served path.', evidence: 'POST /upload (no session) -> 200 {"url":"/uploads/x.html"}', exploit: 'Attackers can host arbitrary content, and script types may lead to stored XSS or worse.', remediation: 'Require auth, validate type/size, store outside the web root, and serve with a safe content type.', reference: 'CWE-434', reproduction: null }),
]

const DISCLOSURE_FINDINGS = [
  F({ title: 'Directory listing enabled', severity: 'medium', category: 'Information Disclosure', location: '/assets/', detail: 'Autoindex is on; the directory contents are browsable.', evidence: 'Index of /assets/ — 88 items', exploit: 'Exposes files not meant to be discoverable.', remediation: 'Disable autoindex/directory listing on the server.', reference: 'CWE-548', reproduction: "curl -s https://example.com/assets/ | grep -i 'index of'" }),
  F({ title: 'phpinfo() page exposed', severity: 'medium', category: 'Information Disclosure', location: '/phpinfo.php', detail: 'A phpinfo page reveals full server configuration, paths, and loaded modules.', evidence: '200 OK · "PHP Version 8.1.2" · DOCUMENT_ROOT, loaded extensions listed', exploit: 'Hands attackers a detailed map of the server environment.', remediation: 'Remove phpinfo/test pages from production.', reference: 'CWE-200', reproduction: "curl -sI https://example.com/phpinfo.php" }),
  F({ title: 'Verbose error / stack trace', severity: 'medium', category: 'Information Disclosure', location: '/', detail: 'An unhandled error returns a full stack trace with file paths and framework versions.', evidence: 'Traceback (most recent call last): File "/srv/app/views.py", line 42 …', exploit: 'Leaks internal structure, dependency versions, and sometimes secrets.', remediation: 'Disable debug mode in production; return a generic error page and log details server-side.', reference: 'CWE-209', reproduction: null }),
  F({ title: 'Apache server-status exposed', severity: 'medium', category: 'Information Disclosure', location: '/server-status', detail: 'mod_status is reachable publicly and lists active requests and client IPs.', evidence: '200 OK · "Apache Server Status" · current requests table', exploit: 'Reveals live traffic, internal URLs, and client addresses.', remediation: 'Restrict /server-status to localhost/trusted IPs or disable mod_status.', reference: 'CWE-200', reproduction: "curl -sI https://example.com/server-status" }),
  F({ title: 'JavaScript source map exposed', severity: 'low', category: 'Information Disclosure', location: '/assets/app.js.map', detail: 'A source map is published, reconstructing original source, comments, and paths.', evidence: '200 OK · application/json · "sources":["src/config.ts", …]', exploit: 'Exposes original code and any secrets/logic in it.', remediation: 'Do not deploy .map files to production, or restrict them to internal access.', reference: 'CWE-540', reproduction: "curl -sI https://example.com/assets/app.js.map" }),
  F({ title: 'API documentation exposed', severity: 'low', category: 'Information Disclosure', location: '/swagger.json', detail: 'A full OpenAPI/Swagger spec is publicly readable, mapping every endpoint and parameter.', evidence: '200 OK · "openapi":"3.0.0" · 140 paths', exploit: 'Gives attackers a complete map of the API surface.', remediation: 'Require auth for API docs in production or disable them.', reference: 'CWE-200', reproduction: "curl -sI https://example.com/swagger.json" }),
  F({ title: '.DS_Store file exposed', severity: 'low', category: 'Information Disclosure', location: '/.DS_Store', detail: 'A macOS .DS_Store file leaks directory and file names.', evidence: '200 OK · binary · references "backup", "old", "invoices"', exploit: 'Reveals otherwise-hidden filenames to target.', remediation: 'Block .DS_Store at the server and keep it out of deployments.', reference: 'CWE-527', reproduction: "curl -sI https://example.com/.DS_Store" }),
  F({ title: 'Application debug mode enabled', severity: 'high', category: 'Information Disclosure', location: '/', detail: 'The framework’s debug console/toolbar is active in production.', evidence: 'response contains "Werkzeug Debugger" / "Whoops" interactive console', exploit: 'Debug consoles can execute code and reveal environment variables.', remediation: 'Set DEBUG=false in production and remove debug toolbars.', reference: 'CWE-489', reproduction: null }),
  F({ title: 'WordPress user enumeration', severity: 'low', category: 'Information Disclosure', location: '/wp-json/wp/v2/users', detail: 'The REST API lists usernames/slugs for all authors.', evidence: '200 OK · [{"id":1,"slug":"admin"}, …]', exploit: 'Valid usernames make password attacks easier.', remediation: 'Restrict the users endpoint and disable author archives if unused.', reference: 'CWE-200', reproduction: "curl -s https://example.com/wp-json/wp/v2/users" }),
]

const AUTH_FINDINGS = [
  F({ title: 'Weak password policy', severity: 'medium', category: 'Session Management', location: '/register', detail: 'Registration accepts a 4-character password with no complexity or breach check.', evidence: 'password "1234" accepted -> 201 Created', exploit: 'Weak passwords are trivially guessed or credential-stuffed.', remediation: 'Require a minimum length (12+), check against known-breached lists, and allow passphrases.', reference: 'CWE-521', reproduction: null }),
  F({ title: 'Password field allows autocomplete/caching', severity: 'info', category: 'Session Management', location: '/login', detail: 'The password input does not set appropriate attributes to limit caching on shared devices.', evidence: '<input type="password" name="pass"> (no autocomplete guidance)', exploit: 'On shared machines, cached credentials can be recovered.', remediation: 'Use current-password/new-password autocomplete hints appropriately and avoid storing plaintext in the DOM.', reference: 'CWE-200', reproduction: null }),
  F({ title: 'Session fixation', severity: 'high', category: 'Session Management', location: '/login', detail: 'The session identifier is not regenerated after authentication.', evidence: 'pre-login session=ABC -> post-login session=ABC (unchanged)', exploit: 'An attacker who plants a session id can ride the victim’s authenticated session.', remediation: 'Regenerate the session id on login and on privilege changes.', reference: 'CWE-384', reproduction: null }),
  F({ title: 'Credentials submitted over HTTP', severity: 'high', category: 'Session Management', location: 'http://example.com/login', detail: 'The login form posts to an http:// (non-TLS) endpoint.', evidence: '<form action="http://example.com/login" method="post">', exploit: 'Credentials can be read by anyone on the network path.', remediation: 'Serve the whole site over HTTPS and post credentials only to https:// endpoints.', reference: 'CWE-319', reproduction: "curl -s https://example.com/login | grep -i 'action=\"http:'" }),
  F({ title: 'No multi-factor authentication option', severity: 'low', category: 'Session Management', location: '/account/security', detail: 'The account has no option to enable MFA/2FA.', evidence: 'no TOTP/WebAuthn/MFA settings present', exploit: 'Accounts rely on a password alone; one leak fully compromises them.', remediation: 'Offer TOTP and/or WebAuthn and encourage/enforce it for privileged roles.', reference: 'CWE-308', reproduction: null }),
  F({ title: 'Username enumeration via login error', severity: 'medium', category: 'Session Management', location: '/login', detail: 'The login response distinguishes “no such user” from “wrong password”.', evidence: 'unknown user -> "account not found" · valid user -> "incorrect password"', exploit: 'Lets attackers confirm which usernames exist before guessing passwords.', remediation: 'Return one generic failure message and keep response timing uniform.', reference: 'CWE-203', reproduction: null }),
]

const TLS_FINDINGS = [
  F({ title: 'Expired TLS certificate', severity: 'high', category: 'Transport Security', location: ':443', detail: 'The served certificate is past its notAfter date.', evidence: 'notAfter=Jan 2 2026 · now Oct 8 2026 (expired)', exploit: 'Browsers warn or block, and users click through into unverified connections.', remediation: 'Renew the certificate and automate renewal (e.g. ACME) with expiry monitoring.', reference: 'CWE-298', reproduction: "openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -dates" }),
  F({ title: 'Certificate hostname mismatch', severity: 'high', category: 'Transport Security', location: ':443', detail: 'The certificate CN/SAN does not cover the requested hostname.', evidence: 'requested example.com · cert SAN: *.other.net', exploit: 'Prevents real verification and enables man-in-the-middle.', remediation: 'Install a certificate whose SAN list includes the served hostname.', reference: 'CWE-297', reproduction: "openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName" }),
  F({ title: 'Weak TLS cipher suites offered', severity: 'medium', category: 'Transport Security', location: ':443', detail: 'The server negotiates legacy ciphers (3DES / RC4 / CBC-SHA1).', evidence: 'accepted: TLS_RSA_WITH_3DES_EDE_CBC_SHA', exploit: 'Weak ciphers are vulnerable to known cryptographic attacks.', remediation: 'Offer only modern AEAD suites (AES-GCM, ChaCha20) and disable legacy ciphers.', reference: 'CWE-327', reproduction: "openssl s_client -connect example.com:443 -cipher 'DES-CBC3-SHA' </dev/null" }),
  F({ title: 'HSTS not preloaded', severity: 'low', category: 'Transport Security', location: '/', detail: 'HSTS lacks includeSubDomains/preload, so first-visit and subdomains remain exposed.', evidence: 'strict-transport-security: max-age=300 (no includeSubDomains; no preload)', exploit: 'Short max-age and no preload leave a downgrade window.', remediation: 'Use a long max-age with includeSubDomains; preload and submit to the HSTS preload list.', reference: 'CWE-319', reproduction: "curl -sI https://example.com | grep -i strict-transport-security" }),
  F({ title: 'Certificate expiring soon', severity: 'info', category: 'Transport Security', location: ':443', detail: 'The certificate expires within 14 days.', evidence: 'notAfter in 11 days', exploit: '—', remediation: 'Renew ahead of expiry; verify auto-renewal is working.', reference: null, reproduction: "openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -enddate" }),
]

const DNS_FINDINGS = [
  F({ title: 'Possible subdomain takeover', severity: 'high', category: 'DNS', location: 'blog.example.com', detail: 'A subdomain’s CNAME points to a decommissioned third-party service that returns an unclaimed-resource page.', evidence: 'blog.example.com CNAME -> unused.herokuapp.com · "No such app"', exploit: 'An attacker can claim the dangling resource and serve content on your subdomain.', remediation: 'Remove dangling DNS records as soon as the backing resource is retired.', reference: 'CWE-350', reproduction: "dig +short CNAME blog.example.com" }),
  F({ title: 'DNS zone transfer allowed (AXFR)', severity: 'medium', category: 'DNS', location: 'ns1.example.com', detail: 'A nameserver answers AXFR requests, dumping the full zone.', evidence: 'AXFR -> 214 records returned', exploit: 'Exposes every host/subdomain, aiding mapping of the attack surface.', remediation: 'Restrict zone transfers to authorised secondaries only.', reference: 'CWE-200', reproduction: "dig AXFR example.com @ns1.example.com" }),
  F({ title: 'Wildcard DNS record', severity: 'info', category: 'DNS', location: '*.example.com', detail: 'A wildcard A/CNAME resolves arbitrary subdomains to one host.', evidence: 'random-1234.example.com -> 203.0.113.42', exploit: 'Can aid phishing and complicates subdomain monitoring.', remediation: 'Replace the wildcard with explicit records where feasible.', reference: null, reproduction: "dig +short random-$RANDOM.example.com" }),
  F({ title: 'No CAA record', severity: 'info', category: 'DNS', location: 'example.com', detail: 'No CAA record restricts which CAs may issue certificates for the domain.', evidence: 'dig CAA example.com -> (empty)', exploit: 'Any CA can issue a certificate, widening mis-issuance risk.', remediation: 'Publish a CAA record naming your authorised CA(s).', reference: null, reproduction: "dig +short CAA example.com" }),
]

const API_FINDINGS = [
  F({ title: 'GraphQL introspection enabled', severity: 'low', category: 'API', location: '/graphql', detail: 'The GraphQL endpoint answers introspection queries in production, exposing the full schema.', evidence: '__schema query -> full type list returned', exploit: 'Reveals every type, field, and mutation to probe for weaknesses.', remediation: 'Disable introspection in production and apply field-level authorization.', reference: 'CWE-200', reproduction: "curl -s -X POST https://example.com/graphql -H 'content-type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'" }),
  F({ title: 'API endpoint lacks rate limiting', severity: 'medium', category: 'API', location: '/api/login', detail: 'A sensitive endpoint returns no throttling signals under rapid requests.', evidence: '100 requests/10s -> all 200/401, no 429, no Retry-After', exploit: 'Enables brute-force, credential stuffing, and resource exhaustion.', remediation: 'Apply per-IP and per-account rate limits and return 429 with Retry-After.', reference: 'CWE-770', reproduction: null }),
  F({ title: 'Prometheus metrics exposed', severity: 'low', category: 'API', location: '/metrics', detail: 'A metrics endpoint is public, leaking internal routes, versions, and traffic volumes.', evidence: '200 OK · "http_requests_total{handler=\"/admin\"}" present', exploit: 'Reveals internal structure and can expose tokens embedded in labels.', remediation: 'Bind /metrics to an internal network or require authentication.', reference: 'CWE-200', reproduction: "curl -sI https://example.com/metrics" }),
  F({ title: 'Dangerous HTTP methods enabled', severity: 'medium', category: 'API', location: '/', detail: 'The server allows PUT/DELETE/TRACE on resources.', evidence: 'OPTIONS / -> Allow: GET,POST,PUT,DELETE,TRACE', exploit: 'PUT/DELETE may let attackers write/remove files; TRACE enables Cross-Site Tracing.', remediation: 'Disable unused methods; allow only those each route needs.', reference: 'CWE-650', reproduction: "curl -s -X OPTIONS -I https://example.com/ | grep -i allow" }),
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
  siteScan: [
    ...SITE_FINDINGS, ...SECRET_FINDINGS, ADMIN_FINDINGS[0], ADMIN_FINDINGS[4],
    ...HEADER_FINDINGS, ...INJECTION_FINDINGS, ...ACCESS_FINDINGS, ...DISCLOSURE_FINDINGS, ...AUTH_FINDINGS, ...TLS_FINDINGS,
  ],
  fullAudit: [
    ...SITE_FINDINGS, ...SECRET_FINDINGS, ...ADMIN_FINDINGS, ...HEADER_FINDINGS, ...INJECTION_FINDINGS,
    ...ACCESS_FINDINGS, ...DISCLOSURE_FINDINGS, ...AUTH_FINDINGS, ...TLS_FINDINGS, ...DNS_FINDINGS, ...API_FINDINGS,
    ...PORT_FINDINGS, ...INFO_FINDINGS,
  ],
  portScan: PORT_FINDINGS,
  database: [PORT_FINDINGS[0], PORT_FINDINGS[1], SITE_FINDINGS[2], INJECTION_FINDINGS[0], INJECTION_FINDINGS[1], INJECTION_FINDINGS[5]],
  hostScan: [...INFO_FINDINGS, SITE_FINDINGS[1], ...TLS_FINDINGS, ...DNS_FINDINGS],
  info: [...INFO_FINDINGS, ...DNS_FINDINGS],
  contentDiscovery: [
    F({ title: 'Open directory listing', severity: 'medium', category: 'Content Discovery', location: '/uploads/', detail: 'Directory listing is enabled and exposes uploaded files.', evidence: 'Index of /uploads/ — 214 items', exploit: 'Users’ uploaded files are browsable without authorization.', remediation: 'Disable autoindex and require auth for the uploads path.', reference: 'CWE-548', reproduction: "curl -s https://example.com/uploads/" }),
    F({ title: 'Backup archive found', severity: 'high', category: 'Content Discovery', location: '/backup.zip', detail: 'A downloadable backup archive was discovered via brute-force.', evidence: '200 OK · 48.2 MB · application/zip', exploit: 'May contain full source code and credentials.', remediation: 'Remove backups from the web root; block archive extensions.', reference: 'CWE-530', reproduction: "curl -sI https://example.com/backup.zip" }),
    ADMIN_FINDINGS[4],
    ADMIN_FINDINGS[0],
    DISCLOSURE_FINDINGS[0],
    DISCLOSURE_FINDINGS[6],
    DISCLOSURE_FINDINGS[5],
    API_FINDINGS[2],
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
    ADMIN_FINDINGS[2],
    ADMIN_FINDINGS[1],
    ACCESS_FINDINGS[0],
    ACCESS_FINDINGS[1],
    ACCESS_FINDINGS[2],
    ACCESS_FINDINGS[6],
    ACCESS_FINDINGS[7],
    AUTH_FINDINGS[2],
    AUTH_FINDINGS[5],
    API_FINDINGS[0],
    API_FINDINGS[1],
    API_FINDINGS[3],
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
