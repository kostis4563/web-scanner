import Foundation

enum Checks {

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
                reference: "OWASP Secure Headers Project"))
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
                reference: "CWE-79 / MDN: Content-Security-Policy"))
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

        return out
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
            reference: "CWE-548: Exposure Through Directory Listing")
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
            reference: "CWE-319: Cleartext Transmission of Sensitive Information")
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
                reference: "CWE-942: Overly Permissive CORS Policy")
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

    static func fromPath(_ p: SensitivePath, _ r: HTTPResponse) -> Finding {
        Finding(
            title: p.title,
            severity: p.severity,
            category: p.category,
            location: r.finalURL.absoluteString,
            detail: "A request to /\(p.path) returned readable, sensitive content (HTTP \(r.status)).",
            evidence: "URL: \(r.finalURL.absoluteString)\nHTTP \(r.status), \(r.body.count) bytes\nPreview: \(snippet(r.text, max: 160))",
            exploit: p.exploit,
            remediation: p.remediation,
            reference: p.reference)
    }
}
