import Foundation

enum Checks {

    static func generalInfo(_ r: HTTPResponse) -> Finding {
        let loc = r.finalURL.absoluteString
        var lines: [String] = []

        lines.append("URL: \(loc)")
        if r.finalURL.absoluteString != r.requestedURL.absoluteString {
            lines.append("Redirected from: \(r.requestedURL.absoluteString)")
        }
        lines.append("HTTP status: \(r.status)")
        lines.append("Transport: \(r.finalURL.scheme == "https" ? "HTTPS (encrypted)" : "HTTP (plaintext)")")
        if let host = r.finalURL.host { lines.append("Host: \(host)\(r.finalURL.port.map { ":\($0)" } ?? "")") }
        if let title = HTMLHelpers.title(from: r.text) { lines.append("Page title: \(snippet(title, max: 120))") }
        if let server = r.header("server") { lines.append("Server: \(server)") }
        if let powered = r.header("x-powered-by") { lines.append("Powered by: \(powered)") }
        for (label, tech) in techHints(r) { lines.append("\(label): \(tech)") }
        let ct = r.contentType
        if !ct.isEmpty { lines.append("Content-Type: \(ct)") }
        lines.append("Response size: \(byteSize(r.body.count))")
        if !r.cookies.isEmpty {
            let names = r.cookies.map { $0.name }.prefix(6).joined(separator: ", ")
            lines.append("Cookies set: \(r.cookies.count) (\(names))")
        }

        return Finding(
            title: "General information",
            severity: .info,
            category: "Info",
            location: loc,
            detail: "General information observed about this target:\n" + lines.map { "• \($0)" }.joined(separator: "\n"),
            evidence: "Gathered from the homepage response headers and body.",
            exploit: "Informational only - this is the same public reconnaissance context an attacker collects first. No action is required.",
            remediation: "No fix needed. To reduce fingerprinting you can suppress version tokens (Server, X-Powered-By) and generator meta tags.",
            reference: nil)
    }

    private static func techHints(_ r: HTTPResponse) -> [(String, String)] {
        var out: [(String, String)] = []
        let html = r.text
        if let gen = regexCapture("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", in: html) {
            out.append(("Generator", snippet(gen, max: 80)))
        }
        var frameworks: [String] = []
        let lower = html.lowercased()
        let sniff: [(String, String)] = [
            ("WordPress", "/wp-content/"), ("WordPress", "/wp-includes/"),
            ("Drupal", "sites/all/"), ("Drupal", "drupal.settings"),
            ("Joomla", "/media/jui/"), ("Shopify", "cdn.shopify.com"),
            ("React", "data-reactroot"), ("React", "__next"), ("Next.js", "/_next/"),
            ("Vue.js", "data-v-"), ("Angular", "ng-version"), ("Nuxt", "__nuxt"),
            ("Svelte", "svelte-"), ("Gatsby", "___gatsby"), ("Webflow", "wf-"),
            ("Squarespace", "squarespace"), ("Wix", "wix.com"),
        ]
        for (name, marker) in sniff where lower.contains(marker) && !frameworks.contains(name) {
            frameworks.append(name)
        }
        if let via = r.header("via") { out.append(("Via", snippet(via, max: 80))) }
        if !frameworks.isEmpty { out.append(("Detected tech", frameworks.prefix(6).joined(separator: ", "))) }
        return out
    }

    private static func byteSize(_ n: Int) -> String {
        if n < 1024 { return "\(n) B" }
        if n < 1_048_576 { return String(format: "%.1f KB", Double(n) / 1024) }
        return String(format: "%.1f MB", Double(n) / 1_048_576)
    }

    private static func regexCapture(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let ns = text as NSString
        guard let m = re.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges > 1 else { return nil }
        return ns.substring(with: m.range(at: 1))
    }

    static func securityHeaders(_ r: HTTPResponse) -> [Finding] {
        var out: [Finding] = []
        let isHTTPS = r.finalURL.scheme == "https"
        let loc = r.finalURL.absoluteString

        if isHTTPS, let hsts = r.header("strict-transport-security") {

            let low = hsts.lowercased()
            var weaknesses: [String] = []
            let maxAge = hstsMaxAge(low)
            if let maxAge {
                if maxAge == 0 {
                    weaknesses.append("max-age=0 disables HSTS entirely")
                } else if maxAge < 15_552_000 {
                    weaknesses.append("max-age is only \(maxAge)s (~\(maxAge / 86_400)d); use at least 15552000 (180d)")
                }
            } else {
                weaknesses.append("no valid max-age directive")
            }
            if !low.contains("includesubdomains") {
                weaknesses.append("no includeSubDomains (subdomains are left unprotected)")
            }
            if !weaknesses.isEmpty {
                out.append(Finding(
                    title: "Weak HSTS configuration",
                    severity: .low, category: "Security Headers", location: loc,
                    detail: "Strict-Transport-Security is set but not strong:\n" + weaknesses.map { "• \($0)" }.joined(separator: "\n"),
                    evidence: "Strict-Transport-Security: \(snippet(hsts, max: 160))",
                    exploit: "A short max-age lets the HSTS pin expire between visits (re-opening the SSL-strip window), and omitting includeSubDomains leaves every subdomain exposed to HTTPS downgrade / cookie-scope attacks.",
                    remediation: "Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload - after confirming every subdomain supports HTTPS.",
                    reference: "OWASP Secure Headers Project"))
            }
        } else if isHTTPS {
            out.append(Finding(
                title: "Missing HSTS header",
                severity: .medium, category: "Security Headers", location: loc,
                detail: "Strict-Transport-Security is not set.",
                evidence: "No 'Strict-Transport-Security' response header.",
                exploit: "Without HSTS, an attacker on the network can strip HTTPS (SSL-strip) or use the first plaintext request to man-in-the-middle the user before the redirect.",
                remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload  (after confirming all subdomains support HTTPS).",
                reference: "OWASP Secure Headers Project",
                reproduction: "curl -sI \"\(loc)\" | grep -i strict-transport-security   # (no output = header missing)"))
        }

        let csp = r.header("content-security-policy")
        if csp == nil {
            out.append(Finding(
                title: "Missing Content-Security-Policy",
                severity: .medium, category: "Security Headers", location: loc,
                detail: "No Content-Security-Policy header is present.",
                evidence: "No 'Content-Security-Policy' response header.",
                exploit: "A CSP is the strongest defense against cross-site scripting (XSS). Without it, any injected script executes freely, enabling session theft and account takeover.",
                remediation: "Define a restrictive CSP, e.g. default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'. Avoid 'unsafe-inline'/'unsafe-eval'.",
                reference: "CWE-79 / MDN: Content-Security-Policy",
                reproduction: "curl -sI \"\(loc)\" | grep -i content-security-policy   # (no output = header missing)"))
        } else if let csp {
            let (weaknesses, severe) = cspWeaknesses(csp)
            if !weaknesses.isEmpty {
                out.append(Finding(
                    title: "Weak Content-Security-Policy",
                    severity: severe ? .medium : .low, category: "Security Headers", location: loc,
                    detail: "The CSP is present but has gaps that undermine its XSS protection:\n" + weaknesses.map { "• \($0)" }.joined(separator: "\n"),
                    evidence: snippet(csp, max: 200),
                    exploit: "Each gap gives injected scripts a way to still execute: 'unsafe-inline'/'unsafe-eval' and wildcard/data: script sources let attacker markup run, and a missing base-uri/object-src leaves base-tag and plugin vectors open - so the policy provides far less real XSS protection than it appears to.",
                    remediation: "Tighten to: script-src with nonces/hashes (no 'unsafe-inline'/'unsafe-eval', no '*'/data:), object-src 'none', base-uri 'none', and frame-ancestors 'none'. Set a default-src fallback.",
                    reference: "CWE-79 / MDN: Content-Security-Policy"))
            }
        }

        let xfo = r.header("x-frame-options")
        let cspFrameAncestors = (csp?.lowercased().contains("frame-ancestors")) ?? false
        if xfo == nil && !cspFrameAncestors {
            out.append(Finding(
                title: "Missing clickjacking protection",
                severity: .medium, category: "Security Headers", location: loc,
                detail: "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                evidence: "No 'X-Frame-Options' header and no 'frame-ancestors' in CSP.",
                exploit: "The page can be embedded in a hidden <iframe> on a malicious site and used for clickjacking - tricking users into clicking actions they can't see.",
                remediation: "Add X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP 'frame-ancestors 'none''.",
                reference: "CWE-1021: Improper Restriction of Rendered UI Layers"))
        }

        let xcto = r.header("x-content-type-options")?.lowercased()
        if xcto != "nosniff" {
            out.append(Finding(
                title: "Missing X-Content-Type-Options: nosniff",
                severity: .low, category: "Security Headers", location: loc,
                detail: "MIME-type sniffing is not disabled.",
                evidence: "X-Content-Type-Options is '\(r.header("x-content-type-options") ?? "absent")'.",
                exploit: "Browsers may guess (sniff) content types, allowing a benign-looking upload to be interpreted as executable script.",
                remediation: "Add: X-Content-Type-Options: nosniff",
                reference: "OWASP Secure Headers Project"))
        }

        if r.header("referrer-policy") == nil {
            out.append(Finding(
                title: "Missing Referrer-Policy",
                severity: .low, category: "Security Headers", location: loc,
                detail: "No Referrer-Policy header is set.",
                evidence: "No 'Referrer-Policy' response header.",
                exploit: "Full URLs (which may contain tokens or IDs) can leak to third-party sites via the Referer header.",
                remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
                reference: "MDN: Referrer-Policy"))
        }

        if r.header("permissions-policy") == nil {
            out.append(Finding(
                title: "Missing Permissions-Policy",
                severity: .info, category: "Security Headers", location: loc,
                detail: "No Permissions-Policy header is set.",
                evidence: "No 'Permissions-Policy' response header.",
                exploit: "Powerful browser features (camera, microphone, geolocation) are not explicitly restricted, widening the impact of an XSS.",
                remediation: "Add a Permissions-Policy that disables unused features, e.g. geolocation=(), camera=(), microphone=().",
                reference: "MDN: Permissions-Policy"))
        }

        if r.header("cross-origin-opener-policy") == nil {
            out.append(Finding(
                title: "Missing Cross-Origin-Opener-Policy",
                severity: .info, category: "Security Headers", location: loc,
                detail: "No Cross-Origin-Opener-Policy (COOP) header is set, so this page shares a browsing-context group with windows it opens or that open it.",
                evidence: "No 'Cross-Origin-Opener-Policy' response header.",
                exploit: "Without COOP, a cross-origin page you open (or that opens you) keeps a handle to your window, enabling cross-window scripting and cross-origin information leaks (XS-Leaks) that a same-origin isolation policy would block.",
                remediation: "Add: Cross-Origin-Opener-Policy: same-origin (and Cross-Origin-Embedder-Policy: require-corp if you need full cross-origin isolation).",
                reference: "MDN: Cross-Origin-Opener-Policy"))
        }

        if r.header("cross-origin-resource-policy") == nil {
            out.append(Finding(
                title: "Missing Cross-Origin-Resource-Policy",
                severity: .info, category: "Security Headers", location: loc,
                detail: "No Cross-Origin-Resource-Policy (CORP) header is set, so the browser applies no per-resource cross-origin read restriction.",
                evidence: "No 'Cross-Origin-Resource-Policy' response header.",
                exploit: "Without CORP, this resource can be embedded and read by other origins, widening the surface for speculative-execution (Spectre) side-channel reads and cross-origin resource inclusion in some contexts.",
                remediation: "Add Cross-Origin-Resource-Policy: same-origin (or same-site) on resources that should not be loaded by other origins.",
                reference: "MDN: Cross-Origin-Resource-Policy"))
        }

        if r.header("cross-origin-opener-policy") != nil && r.header("cross-origin-embedder-policy") == nil {
            out.append(Finding(
                title: "Cross-Origin-Embedder-Policy missing (COOP set without COEP)",
                severity: .info, category: "Security Headers", location: loc,
                detail: "Cross-Origin-Opener-Policy is set but Cross-Origin-Embedder-Policy (COEP) is not, so the document is not fully cross-origin isolated.",
                evidence: "Cross-Origin-Opener-Policy: \(r.header("cross-origin-opener-policy") ?? ""); no 'Cross-Origin-Embedder-Policy' header.",
                exploit: "Full cross-origin isolation - needed to safely use SharedArrayBuffer and high-resolution timers and to close several XS-Leak channels - only engages when COOP and COEP are both present. With COEP absent the page stays non-isolated and those protections never activate.",
                remediation: "Add Cross-Origin-Embedder-Policy: require-corp (or credentialless) alongside COOP: same-origin to reach crossOriginIsolated.",
                reference: "MDN: Cross-Origin-Embedder-Policy"))
        }

        if r.status == 200,
           r.contentType.lowercased().contains("text/html"),
           r.header("cache-control") == nil, r.header("expires") == nil, r.header("pragma") == nil {
            out.append(Finding(
                title: "No Cache-Control header on page response",
                severity: .low, category: "Security Headers", location: loc,
                detail: "This HTML page response sets no Cache-Control, Expires, or Pragma directive, leaving caching behavior to browser/proxy heuristics.",
                evidence: "HTTP \(r.status), Content-Type: \(snippet(r.contentType, max: 80)); no Cache-Control/Expires/Pragma header.",
                exploit: "With no explicit policy, shared proxies and the browser cache may apply heuristic caching and retain a page that is actually dynamic or user-specific, risking stale content or cross-user exposure on shared caches.",
                remediation: "Set an explicit policy: Cache-Control: no-store for sensitive/personalized pages, or a deliberate max-age with 'private'/'public' for genuinely static content.",
                reference: "MDN: Cache-Control"))
        }

        if let xxp = r.header("x-xss-protection"),
           xxp.lowercased().trimmingCharacters(in: .whitespaces).hasPrefix("1") {
            out.append(Finding(
                title: "Legacy X-XSS-Protection filter enabled",
                severity: .low, category: "Security Headers", location: loc,
                detail: "X-XSS-Protection is set to a non-zero legacy value ('\(snippet(xxp, max: 60))'). The browser XSS auditor it controls is deprecated and has been removed from modern browsers.",
                evidence: "X-XSS-Protection: \(snippet(xxp, max: 80))",
                exploit: "In legacy IE/Edge and old Chrome the auditor could itself be abused to introduce cross-site scripting or selectively disable page scripts, and '1; mode=block' enabled cross-site information-leak tricks - which is exactly why the header was deprecated. Keeping it enabled adds risk with no benefit.",
                remediation: "Set X-XSS-Protection: 0 to disable the legacy auditor, and rely on a strong Content-Security-Policy for XSS defense.",
                reference: "OWASP Secure Headers Project / MDN: X-XSS-Protection"))
        }

        if let acam = r.header("access-control-allow-methods"),
           acam.split(whereSeparator: { $0 == "," || $0 == " " }).contains("*") {
            out.append(Finding(
                title: "Access-Control-Allow-Methods: * (wildcard methods)",
                severity: .info, category: "Security Headers", location: loc,
                detail: "The CORS response advertises every HTTP method via Access-Control-Allow-Methods: *.",
                evidence: "Access-Control-Allow-Methods: \(snippet(acam, max: 80))",
                exploit: "A wildcard method list signals a permissive CORS configuration. The '*' is ignored for credentialed requests, but combined with a reflected or overly broad Access-Control-Allow-Origin it widens what a cross-origin caller may invoke - review it together with the Allow-Origin and Allow-Credentials headers.",
                remediation: "Return only the methods the endpoint actually supports (e.g. Access-Control-Allow-Methods: GET, POST) instead of '*'.",
                reference: "CWE-942 / MDN: Access-Control-Allow-Methods"))
        }

        if csp == nil, let cspRO = r.header("content-security-policy-report-only") {
            out.append(Finding(
                title: "Content-Security-Policy only in report-only mode",
                severity: .medium, category: "Security Headers", location: loc,
                detail: "A Content-Security-Policy-Report-Only header is present but no enforcing Content-Security-Policy header is set, so the policy is monitored but never enforced.",
                evidence: "Content-Security-Policy-Report-Only: \(snippet(cspRO, max: 180)); no enforcing 'Content-Security-Policy' header.",
                exploit: "Report-only mode logs violations without blocking anything, so injected scripts still execute. An attacker's XSS runs exactly as if there were no CSP at all - the policy provides zero runtime protection.",
                remediation: "Once the report-only policy is tuned and clean, deploy the same policy under the enforcing Content-Security-Policy header; keep report-only only for staging new rules.",
                reference: "CWE-79 / MDN: Content-Security-Policy-Report-Only"))
        }

        return out
    }

    private static func hstsMaxAge(_ lowerValue: String) -> Int? {
        guard let re = try? NSRegularExpression(pattern: "max-age\\s*=\\s*\"?([0-9]+)", options: []) else { return nil }
        let ns = lowerValue as NSString
        guard let m = re.firstMatch(in: lowerValue, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges > 1 else { return nil }
        return Int(ns.substring(with: m.range(at: 1)))
    }

    static func cspWeaknesses(_ csp: String) -> (weaknesses: [String], severe: Bool) {
        let lower = csp.lowercased()

        var directives: [String: String] = [:]
        for part in lower.split(separator: ";") {
            let toks = part.trimmingCharacters(in: .whitespaces).split(separator: " ", maxSplits: 1)
            guard let name = toks.first else { continue }
            directives[String(name)] = toks.count > 1 ? String(toks[1]) : ""
        }
        let scriptSrc = directives["script-src"] ?? directives["default-src"]

        var out: [String] = []
        var severe = false
        if lower.contains("unsafe-inline") { out.append("allows 'unsafe-inline' (inline injected scripts still run)") }
        if lower.contains("unsafe-eval") { out.append("allows 'unsafe-eval' (string-to-code execution stays possible)"); severe = true }
        if let s = scriptSrc {

            if s.split(whereSeparator: { $0 == " " }).contains("*") {
                out.append("script source allows '*' (any host can serve scripts)"); severe = true
            }
            if s.contains("data:") { out.append("script source allows 'data:' URIs (a known XSS vector)"); severe = true }
            if s.contains("http://") { out.append("script source allows plaintext http:// origins") }
        }
        if directives["object-src"] == nil && directives["default-src"] == nil {
            out.append("no 'object-src' (plugin/embed content is unrestricted)")
        }
        if directives["base-uri"] == nil {
            out.append("no 'base-uri' (a <base> tag injection can hijack relative URLs)")
        }
        if directives["form-action"] == nil {
            out.append("no 'form-action' (injected markup can point forms at an attacker origin to exfiltrate submitted data)")
        }
        if lower.contains("unsafe-inline"), lower.contains("nonce-") || lower.contains("'sha") {
            out.append("'unsafe-inline' is combined with a nonce/hash - CSP Level 2 browsers ignore the nonce and honour 'unsafe-inline', so the policy is only as strong as its weakest fallback")
        }
        if lower.contains("unsafe-hashes") {
            out.append("allows 'unsafe-hashes' (hashed inline event handlers and javascript: attribute values can execute - a broader allowance than plain script hashes)")
        }
        if let s = scriptSrc, regexMatches("(^|\\s)\\*\\.[a-z0-9.-]+", in: s) {
            out.append("script source includes a wildcard subdomain (e.g. '*.example.com') - any current or future host under that domain, including attacker-controlled or abandoned subdomains, can serve scripts")
        }
        if let s = scriptSrc, regexMatches("(^|\\s)https:(\\s|$)", in: s) {
            out.append("script source allows the scheme-wide 'https:' source (any host reachable over HTTPS can serve scripts, so the allow-list is effectively open)"); severe = true
        }
        if directives["frame-ancestors"] == nil {
            out.append("no 'frame-ancestors' (the CSP does not restrict who can frame the page, so clickjacking protection relies solely on X-Frame-Options)")
        }
        if lower.contains("strict-dynamic"), !lower.contains("nonce-"), !lower.contains("'sha") {
            out.append("'strict-dynamic' is used without any nonce or hash source - it neutralizes host/scheme allow-list entries but has nothing to trust in their place, breaking legitimate scripts while providing no real allow-list protection")
        }
        if directives["report-uri"] == nil, directives["report-to"] == nil {
            out.append("no 'report-uri'/'report-to' (CSP violations are not reported anywhere, so both real attacks and accidental breakage go unnoticed)")
        }
        return (out, severe)
    }

    static func infoDisclosure(_ r: HTTPResponse) -> [Finding] {
        var out: [Finding] = []
        let loc = r.finalURL.absoluteString

        func versionLeak(_ headerName: String, value: String) -> Bool {

            regexMatches("[0-9]+\\.[0-9]+", in: value)
        }

        if let server = r.header("server"), versionLeak("server", value: server) {
            out.append(Finding(
                title: "Server version disclosed",
                severity: .low, category: "Information Disclosure", location: loc,
                detail: "The Server header exposes software and version.",
                evidence: "Server: \(server)",
                exploit: "Knowing the exact server/version lets an attacker look up matching CVEs and target known exploits.",
                remediation: "Suppress version tokens (e.g. Apache ServerTokens Prod / nginx server_tokens off / hide X-Powered-By).",
                reference: "CWE-200"))
        }

        if let powered = r.header("x-powered-by") {
            out.append(Finding(
                title: "X-Powered-By disclosed",
                severity: .low, category: "Information Disclosure", location: loc,
                detail: "The X-Powered-By header reveals the backend technology.",
                evidence: "X-Powered-By: \(powered)",
                exploit: "Reveals framework/runtime (e.g. PHP, Express) and often its version, aiding targeted attacks.",
                remediation: "Remove the X-Powered-By header (e.g. Express: app.disable('x-powered-by'); PHP: expose_php Off).",
                reference: "CWE-200"))
        }

        for h in ["x-aspnet-version", "x-aspnetmvc-version", "x-generator"] {
            if let v = r.header(h) {
                out.append(Finding(
                    title: "Technology version disclosed (\(h))",
                    severity: .low, category: "Information Disclosure", location: loc,
                    detail: "The \(h) header reveals framework version details.",
                    evidence: "\(h): \(v)",
                    exploit: "Framework version disclosure helps attackers select known exploits.",
                    remediation: "Remove the \(h) header in your server/framework configuration.",
                    reference: "CWE-200"))
            }
        }

        let debugHeaders: [(String, String)] = [
            ("x-debug-token", "a Symfony debug profiler token - the /_profiler and /_wdt debug UI may be reachable"),
            ("x-debug-token-link", "a link to the Symfony debug profiler"),
            ("x-drupal-cache", "the Drupal page-cache state"),
            ("x-symfony-cache", "the Symfony HTTP-cache state"),
            ("x-runtime", "the backend request-processing time (a timing side-channel oracle)"),
            ("x-debug", "an application debug-mode indicator"),
        ]
        for (h, meaning) in debugHeaders {
            if let v = r.header(h) {
                out.append(Finding(
                    title: "Debug/diagnostic header exposed (\(h))",
                    severity: .low, category: "Information Disclosure", location: loc,
                    detail: "The response includes \(h), revealing \(meaning).",
                    evidence: "\(h): \(v)",
                    exploit: "Debug headers confirm the framework and can expose an interactive profiler (potential source/config/secret disclosure) or a timing oracle useful for side-channel attacks.",
                    remediation: "Disable debug mode and profiler middleware in production, and strip these headers at the app or reverse-proxy layer.",
                    reference: "CWE-200"))
            }
        }

        let fingerprintHeaders: [(String, String, Severity)] = [
            ("x-amz-cf-id", "an Amazon CloudFront edge request ID (the site is fronted by AWS CloudFront)", .info),
            ("x-amz-request-id", "an AWS request ID (an Amazon S3 / AWS service produced this response)", .info),
            ("x-cache", "the CDN/reverse-proxy cache result such as HIT/MISS (typical of Fastly, Varnish, CloudFront)", .info),
            ("x-served-by", "the cache/CDN node that served the response - often an internal Fastly/Varnish node hostname", .low),
            ("x-envoy-upstream-service-time", "the backend processing time behind an Envoy proxy - a timing side-channel and infrastructure fingerprint", .low),
            ("x-backend-server", "the internal backend server name that handled the request", .low),
            ("server-timing", "server-side timing metrics that can leak internal component names and act as a side-channel", .low),
            ("x-nextjs-cache", "the Next.js data-cache state (the application is built on Next.js)", .info),
            ("x-vercel-id", "a Vercel edge request ID with region codes (the site is hosted on Vercel)", .info),
            ("x-vercel-cache", "the Vercel edge cache state (the site is hosted on Vercel)", .info),
            ("x-turbo-charged-by", "the LiteSpeed / OpenLiteSpeed web-server banner", .info),
            ("x-litespeed-cache", "the LiteSpeed page-cache state (LiteSpeed web server / cache in use)", .info),
            ("liferay-portal", "the Liferay Portal edition and often its exact version", .low),
        ]
        for (h, meaning, sev) in fingerprintHeaders {
            if let v = r.header(h) {
                out.append(Finding(
                    title: "Infrastructure/fingerprint header exposed (\(h))",
                    severity: sev, category: "Information Disclosure", location: loc,
                    detail: "The response includes \(h), revealing \(meaning).",
                    evidence: "\(h): \(snippet(v, max: 120))",
                    exploit: "Infrastructure, CDN and internal-node headers let an attacker fingerprint the hosting stack (provider, cache layer, backend) and, where they carry internal hostnames or per-request timings, aid target selection and side-channel timing analysis.",
                    remediation: "Strip non-essential infrastructure headers at the edge/proxy before responses reach clients; keep only what the application actually needs.",
                    reference: "CWE-200"))
            }
        }

        for (name, value) in r.headers where name.hasPrefix("x-kubernetes") {
            out.append(Finding(
                title: "Kubernetes header exposed (\(name))",
                severity: .low, category: "Information Disclosure", location: loc,
                detail: "The response includes \(name), indicating a Kubernetes-based deployment and possibly internal orchestration identifiers.",
                evidence: "\(name): \(snippet(value, max: 120))",
                exploit: "A header that leaks the orchestration layer confirms the platform and can expose namespace/pod/service identifiers, helping an attacker map internal infrastructure after gaining a foothold.",
                remediation: "Remove Kubernetes/ingress debug headers at the ingress or reverse-proxy layer so they are never sent to clients.",
                reference: "CWE-200"))
        }

        return out
    }

    static func sensitiveCaching(_ r: HTTPResponse) -> Finding? {
        guard let raw = r.setCookieRaw?.lowercased() else { return nil }
        let looksAuth = ["sess", "auth", "token", "jwt", "sid", "login"].contains { raw.contains($0) }
        guard looksAuth else { return nil }
        let cc = (r.header("cache-control") ?? "").lowercased()
        let pragma = (r.header("pragma") ?? "").lowercased()
        let safe = cc.contains("no-store") || cc.contains("private")
            || cc.contains("no-cache") || pragma.contains("no-cache")
        guard !safe else { return nil }
        return Finding(
            title: "Sensitive response not protected from caching",
            severity: .low, category: "Security Headers", location: r.finalURL.absoluteString,
            detail: "This response sets a session/authentication cookie but does not send Cache-Control: no-store (or private / no-cache).",
            evidence: "Set-Cookie present; Cache-Control: \(r.header("cache-control") ?? "absent")",
            exploit: "Without no-store, a shared proxy or the browser back/forward cache may retain an authenticated page, letting the next user of a shared machine or cache read another user's private data.",
            remediation: "Send Cache-Control: no-store, no-cache, private (and Pragma: no-cache) on any authenticated or personalized response.",
            reference: "CWE-525: Information Exposure Through Browser Caching")
    }

    static func cookies(_ r: HTTPResponse) -> [Finding] {
        var out: [Finding] = []
        let isHTTPS = r.finalURL.scheme == "https"
        let loc = r.finalURL.absoluteString
        let cookieSegments = splitSetCookie((r.setCookieRaw ?? "").lowercased())

        for cookie in r.cookies {

            let name = cookie.name
            let lname = name.lowercased()
            var prefixIssues: [String] = []
            if lname.hasPrefix("__secure-"), !cookie.isSecure {
                prefixIssues.append("a __Secure- cookie must carry the Secure flag, but this one does not")
            }
            if lname.hasPrefix("__host-") {
                if !cookie.isSecure { prefixIssues.append("a __Host- cookie must be Secure") }
                if cookie.path != "/" { prefixIssues.append("a __Host- cookie must have Path=/ (found '\(cookie.path)')") }
            }
            if !prefixIssues.isEmpty {
                out.append(Finding(
                    title: "Cookie prefix contract violated: \(name)",
                    severity: .medium, category: "Cookies", location: loc,
                    detail: "Cookie '\(name)' uses a security prefix but breaks its rules: \(prefixIssues.joined(separator: "; ")).",
                    evidence: r.setCookieRaw.map { snippet($0, max: 160) } ?? "Set-Cookie: \(name)=...",
                    exploit: "Browsers only enforce __Secure-/__Host- guarantees when the flags are actually set. A mismatch means the cookie can be planted or read over insecure paths or scoped too broadly, defeating the protection the prefix implies.",
                    remediation: "Set __Secure- cookies with Secure, and __Host- cookies with Secure; Path=/ and no Domain attribute.",
                    reference: "CWE-614 / RFC 6265bis cookie prefixes"))
            }

            let ownSegment = cookieSegments.first { $0.trimmingCharacters(in: .whitespaces).hasPrefix(lname + "=") }
            if let seg = ownSegment, seg.contains("samesite=none"), !seg.contains("secure") {
                out.append(Finding(
                    title: "Cookie SameSite=None without Secure: \(name)",
                    severity: .low, category: "Cookies", location: loc,
                    detail: "Cookie '\(name)' is set with SameSite=None but without the Secure flag.",
                    evidence: r.setCookieRaw.map { snippet($0, max: 160) } ?? "Set-Cookie: \(name)=...; SameSite=None",
                    exploit: "SameSite=None opts the cookie into cross-site requests; without Secure it is also sent over plaintext HTTP where a network attacker can read it. Modern browsers reject this combination, so the cookie may also silently fail.",
                    remediation: "Always pair SameSite=None with Secure. If the cookie does not need to be sent cross-site, use SameSite=Lax or Strict instead.",
                    reference: "CWE-614 / MDN: SameSite cookies"))
            }

            var problems: [String] = []
            if isHTTPS && !cookie.isSecure { problems.append("no Secure flag") }
            if !cookie.isHTTPOnly { problems.append("no HttpOnly flag") }
            let sameSite = cookie.sameSitePolicy
            if sameSite == nil { problems.append("no SameSite attribute") }

            guard !problems.isEmpty else { continue }

            let looksSession = cookie.name.lowercased().contains("sess")
                || cookie.name.lowercased().contains("auth")
                || cookie.name.lowercased().contains("token")
                || cookie.name.lowercased().contains("id")
            let sev: Severity = (problems.count >= 2 && looksSession) ? .medium : .low

            out.append(Finding(
                title: "Insecure cookie: \(cookie.name)",
                severity: sev, category: "Cookies", location: loc,
                detail: "Cookie '\(cookie.name)' is missing hardening flags: \(problems.joined(separator: ", ")).",
                evidence: r.setCookieRaw.map { snippet($0, max: 160) } ?? "Set-Cookie: \(cookie.name)=...",
                exploit: "Missing HttpOnly lets XSS read the cookie (session theft); missing Secure lets it leak over plaintext HTTP; missing SameSite enables CSRF.",
                remediation: "Set the cookie with: Secure; HttpOnly; SameSite=Lax (or Strict) for session/auth cookies.",
                reference: "CWE-1004 / CWE-614"))
        }
        return out
    }

    private static func splitSetCookie(_ raw: String) -> [String] {
        guard !raw.isEmpty,
              let re = try? NSRegularExpression(pattern: ",\\s*(?=[a-z0-9!#$%&'*+._-]+=)", options: []) else {
            return raw.isEmpty ? [] : [raw]
        }
        let ns = raw as NSString
        var segments: [String] = []
        var last = 0
        for m in re.matches(in: raw, range: NSRange(location: 0, length: ns.length)) {
            segments.append(ns.substring(with: NSRange(location: last, length: m.range.location - last)))
            last = m.range.location + m.range.length
        }
        segments.append(ns.substring(from: last))
        return segments
    }

    static func isDirectoryListing(_ r: HTTPResponse) -> Bool {
        guard r.status == 200 else { return false }
        let t = r.text.lowercased()
        return t.contains("<title>index of /") || t.contains("<h1>index of /")
            || (t.contains("directory listing for") && t.contains("<pre"))
    }

    static func directoryListing(_ url: URL) -> Finding {
        Finding(
            title: "Directory listing enabled",
            severity: .medium, category: "Information Disclosure", location: url.absoluteString,
            detail: "The server returns an automatic index of directory contents.",
            evidence: "Response body contains an 'Index of /' listing.",
            exploit: "Attackers can browse all files in the directory - backups, configs, source, uploads - discovering sensitive files that aren't linked anywhere.",
            remediation: "Disable auto-indexing (Apache: Options -Indexes; nginx: autoindex off;) and add an index file.",
            reference: "CWE-548: Exposure Through Directory Listing",
            reproduction: "curl -s \"\(url.absoluteString)\"   # browse the auto-generated index")
    }

    static func invalidTLS(_ host: String) -> Finding {
        Finding(
            title: "Invalid TLS certificate",
            severity: .high, category: "Transport Security", location: "https://\(host)",
            detail: "The site's certificate failed standard validation (expired, self-signed, wrong host, or untrusted CA).",
            evidence: "Strict certificate validation rejected the connection to https://\(host).",
            exploit: "An invalid certificate trains users to click through warnings and can allow man-in-the-middle interception of all traffic, including credentials.",
            remediation: "Install a valid certificate from a trusted CA (e.g. free via Let's Encrypt) that matches the hostname, and keep it renewed.",
            reference: "CWE-295: Improper Certificate Validation")
    }

    static func noHTTPS(_ host: String) -> Finding {
        Finding(
            title: "Site not served over HTTPS",
            severity: .high, category: "Transport Security", location: "http://\(host)",
            detail: "The site is reachable only over plaintext HTTP.",
            evidence: "https:// was unreachable; http:// served content.",
            exploit: "All traffic - including passwords and cookies - travels in cleartext and can be read or modified by anyone on the network path.",
            remediation: "Obtain a TLS certificate, serve everything over HTTPS, and redirect HTTP → HTTPS.",
            reference: "CWE-319: Cleartext Transmission of Sensitive Information",
            reproduction: "curl -v http://\(host)/   # served over plaintext; sniffable with: tcpdump -A -s0 host \(host)")
    }

    static func noHTTPSRedirect(_ host: String) -> Finding {
        Finding(
            title: "No HTTP → HTTPS redirect",
            severity: .medium, category: "Transport Security", location: "http://\(host)",
            detail: "Requests to http:// are served directly instead of redirecting to https://.",
            evidence: "http://\(host)/ returned 200 without redirecting to https.",
            exploit: "Users (and links) that hit HTTP stay on plaintext, exposing their session to interception.",
            remediation: "Force a 301 redirect from all HTTP requests to HTTPS, and add HSTS.",
            reference: "CWE-319")
    }

    static func cors(_ r: HTTPResponse, reflectedOrigin: String) -> Finding? {
        let acao = r.header("access-control-allow-origin")
        let acac = r.header("access-control-allow-credentials")?.lowercased() == "true"
        guard let acao else { return nil }

        let reflects = acao == reflectedOrigin
        let wildcard = acao == "*"

        if reflects && acac {
            return Finding(
                title: "CORS misconfiguration (origin reflection + credentials)",
                severity: .high, category: "CORS", location: r.finalURL.absoluteString,
                detail: "The server reflects an arbitrary Origin and allows credentials.",
                evidence: "Access-Control-Allow-Origin: \(acao)\nAccess-Control-Allow-Credentials: true",
                exploit: "Any malicious website can make authenticated cross-origin requests to this site using the victim's cookies and read the responses - stealing private data.",
                remediation: "Never reflect the Origin with credentials. Allow only an explicit allow-list of trusted origins, or drop Access-Control-Allow-Credentials.",
                reference: "CWE-942: Overly Permissive CORS Policy",
                reproduction: "curl -sI \"\(r.finalURL.absoluteString)\" -H 'Origin: https://evil.example'   # ACAO reflects your Origin + ACAC: true")
        }
        if reflects {
            return Finding(
                title: "CORS reflects arbitrary Origin",
                severity: .medium, category: "CORS", location: r.finalURL.absoluteString,
                detail: "The server echoes any supplied Origin in Access-Control-Allow-Origin.",
                evidence: "Access-Control-Allow-Origin: \(acao)",
                exploit: "Reflecting arbitrary origins lets other sites read non-credentialed responses and is often a step toward data exposure.",
                remediation: "Return a fixed allow-list of trusted origins instead of reflecting the request Origin.",
                reference: "CWE-942")
        }
        if wildcard && acac {
            return Finding(
                title: "CORS wildcard with credentials",
                severity: .medium, category: "CORS", location: r.finalURL.absoluteString,
                detail: "Access-Control-Allow-Origin: * combined with credentials (browsers block this, but it signals misconfiguration).",
                evidence: "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                exploit: "Indicates an insecure CORS setup; adjacent endpoints may reflect specific origins with credentials.",
                remediation: "Do not combine '*' with credentials; use an explicit trusted-origin allow-list.",
                reference: "CWE-942")
        }
        return nil
    }

    static func corsNullOrigin(_ r: HTTPResponse) -> Finding? {
        guard r.header("access-control-allow-origin")?.lowercased() == "null" else { return nil }
        let acac = r.header("access-control-allow-credentials")?.lowercased() == "true"
        return Finding(
            title: acac ? "CORS trusts the 'null' origin with credentials" : "CORS trusts the 'null' origin",
            severity: acac ? .high : .medium, category: "CORS", location: r.finalURL.absoluteString,
            detail: "The server returned Access-Control-Allow-Origin: null in response to an Origin: null request.",
            evidence: "Access-Control-Allow-Origin: null" + (acac ? "\nAccess-Control-Allow-Credentials: true" : ""),
            exploit: "The 'null' origin is produced by sandboxed iframes, data:/file: documents and some redirects - all attacker-controllable. Trusting it lets a malicious page read \(acac ? "authenticated " : "")responses cross-origin.",
            remediation: "Never allow the literal 'null' origin. Validate against an explicit allow-list of exact trusted origins and drop Access-Control-Allow-Credentials unless strictly required.",
            reference: "CWE-942: Overly Permissive CORS Policy",
            reproduction: "curl -sI \"\(r.finalURL.absoluteString)\" -H 'Origin: null'   # look for Access-Control-Allow-Origin: null")
    }

    static func corsTrustBypass(_ r: HTTPResponse, sentOrigin: String, technique: String) -> Finding? {
        guard r.header("access-control-allow-origin") == sentOrigin else { return nil }
        let acac = r.header("access-control-allow-credentials")?.lowercased() == "true"
        return Finding(
            title: "CORS origin-validation bypass (\(technique))",
            severity: acac ? .high : .medium, category: "CORS", location: r.finalURL.absoluteString,
            detail: "The server reflected the attacker-controlled origin \(sentOrigin), which only \(technique) the real domain. That reveals a flawed substring/prefix/suffix origin check rather than exact-match validation.",
            evidence: "Sent Origin: \(sentOrigin)\nAccess-Control-Allow-Origin: \(r.header("access-control-allow-origin") ?? "")" + (acac ? "\nAccess-Control-Allow-Credentials: true" : ""),
            exploit: "A weak origin check (startsWith / endsWith / contains) lets an attacker register or craft a domain that passes validation and then reads \(acac ? "credentialed " : "")cross-origin responses - leaking user data.",
            remediation: "Validate the Origin against an exact allow-list (full-string equality on scheme + host + port); never use a substring, prefix, or suffix match.",
            reference: "CWE-942: Overly Permissive CORS Policy",
            reproduction: "curl -sI \"\(r.finalURL.absoluteString)\" -H 'Origin: \(sentOrigin)'   # ACAO reflects the crafted origin")
    }

    static func fromPath(_ p: SensitivePath, _ r: HTTPResponse) -> Finding {
        Finding(
            title: p.title,
            severity: p.severity,
            category: p.category,
            location: r.finalURL.absoluteString,
            detail: "A request to /\(p.path) returned readable, sensitive content (HTTP \(r.status)).",
            evidence: "URL: \(r.finalURL.absoluteString)\nHTTP \(r.status), \(r.body.count) bytes",
            exploit: p.exploit,
            remediation: p.remediation,
            reference: p.reference,
            reproduction: "curl -s \"\(r.finalURL.absoluteString)\"   # download the exposed file",
            capturedContent: capturedBody(r.text))
    }
}
