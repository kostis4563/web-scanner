import Foundation

enum ExtraChecks {

    static func extractLinks(html: String, base: URL, sameHost: String) -> [URL] {
        matchAttr(pattern: "<a[^>]+href\\s*=\\s*[\"']([^\"'#]+)[\"']", in: html)
            .compactMap { resolve($0, base: base, sameHost: sameHost, htmlOnly: true) }
    }

    static func extractScriptSources(html: String, base: URL, sameHost: String) -> [URL] {
        matchAttr(pattern: "<script[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']", in: html)
            .compactMap { resolveFirstParty($0, base: base, baseHost: sameHost) }
    }

    private static let scannableAssetExts: Set<String> = [
        "css", "json", "json5", "jsonc", "jsonl", "map", "txt", "text", "xml",
        "yml", "yaml", "csv", "tsv", "ini", "conf", "config", "cfg", "properties",
        "env", "webmanifest", "manifest", "md", "mdx", "rst", "adoc", "toml",
        "tf", "tfvars", "tfstate", "hcl", "har", "sql", "dump", "log", "pem",
        "key", "crt", "pub", "asc", "ovpn", "netrc", "npmrc", "yarnrc", "pypirc",
        "pgpass", "s3cfg", "dockercfg", "htpasswd", "htaccess", "credentials",
        "gitconfig", "cnf", "plist", "prisma", "graphql", "proto", "lock",
        "gradle", "csproj", "ts", "tsx", "jsx", "mjs", "cjs", "vue", "svelte",
        "astro", "coffee", "scss", "sass", "less", "styl",
        "bak", "backup", "old", "orig", "save", "swp", "tmp", "inc",
        "dist", "sample", "example", "template", "tmpl",
    ]

    private static let configEndpointMarkers: [String] = [
        "config", "settings", "secret", "credential", "env", "manifest",
        "keys", "token", ".well-known",
    ]

    static func extractAssetURLs(html: String, base: URL, sameHost: String) -> [URL] {
        var out: [URL] = []
        var seen = Set<String>()
        for raw in matchAttr(pattern: "(?:href|src|data-src)\\s*=\\s*[\"']([^\"']+)[\"']", in: html) {
            let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !s.isEmpty,
                  !s.hasPrefix("mailto:"), !s.hasPrefix("tel:"),
                  !s.hasPrefix("javascript:"), !s.hasPrefix("data:"), !s.hasPrefix("#") else { continue }
            guard let u = URL(string: s, relativeTo: base)?.absoluteURL,
                  u.scheme == "http" || u.scheme == "https",
                  isFirstParty(u.host, base: sameHost) else { continue }
            let ext = u.pathExtension.lowercased()
            if ext == "js" { continue }   
            let path = u.path.lowercased()
            let keep = scannableAssetExts.contains(ext)
                || (ext.isEmpty && configEndpointMarkers.contains { path.contains($0) })
            guard keep else { continue }
            if seen.insert(u.absoluteString).inserted { out.append(u) }
            if out.count >= 250 { break }
        }
        return out
    }

    static func isFirstParty(_ host: String?, base: String) -> Bool {
        guard let host = host?.lowercased() else { return false }
        let b = base.lowercased()
        if host == b { return true }
        let rd = registrableDomain(b)
        guard !rd.isEmpty else { return false }
        return host == rd || host.hasSuffix("." + rd)
    }

    static func registrableDomain(_ host: String) -> String {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return host }
        let twoLevel: Set<String> = ["co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"]
        if labels.count >= 3, twoLevel.contains(labels[labels.count - 2]) {
            return labels.suffix(3).joined(separator: ".")
        }
        return labels.suffix(2).joined(separator: ".")
    }

    private static func resolveFirstParty(_ raw: String, base: URL, baseHost: String) -> URL? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty,
              !s.hasPrefix("mailto:"), !s.hasPrefix("tel:"),
              !s.hasPrefix("javascript:"), !s.hasPrefix("data:") else { return nil }
        guard let u = URL(string: s, relativeTo: base)?.absoluteURL,
              u.scheme == "http" || u.scheme == "https",
              isFirstParty(u.host, base: baseHost) else { return nil }
        return u
    }

    private static func matchAttr(pattern: String, in html: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = html as NSString
        var out: [String] = []
        for m in re.matches(in: html, range: NSRange(location: 0, length: ns.length)) {
            guard m.numberOfRanges > 1 else { continue }
            out.append(ns.substring(with: m.range(at: 1)))
        }
        return out
    }

    private static func resolve(_ raw: String, base: URL, sameHost: String, htmlOnly: Bool) -> URL? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty,
              !s.hasPrefix("mailto:"), !s.hasPrefix("tel:"),
              !s.hasPrefix("javascript:"), !s.hasPrefix("data:") else { return nil }
        guard let u = URL(string: s, relativeTo: base)?.absoluteURL,
              u.scheme == "http" || u.scheme == "https",
              u.host == sameHost else { return nil }
        if htmlOnly {

            let ext = u.pathExtension.lowercased()
            let skip: Set<String> = ["jpg","jpeg","png","gif","svg","webp","ico","css",
                                     "js","woff","woff2","ttf","eot","pdf","zip","mp4",
                                     "mp3","webm","avi","dmg","exe","xml","json"]
            if skip.contains(ext) { return nil }
        }
        return u
    }

    static func sourceMapCandidates(scriptURL: URL, body: String) -> [URL] {
        var urls: [URL] = []
        var seen = Set<String>()
        func add(_ u: URL?) {
            guard let u, seen.insert(u.absoluteString).inserted else { return }
            urls.append(u)
        }
        if let re = try? NSRegularExpression(pattern: "(?://|/\\*)[#@]\\s*sourceMappingURL\\s*=\\s*([^\\s'\"*]+)", options: []) {
            let ns = body as NSString
            for m in re.matches(in: body, range: NSRange(location: 0, length: ns.length)) where m.numberOfRanges > 1 {
                let ref = ns.substring(with: m.range(at: 1))
                if !ref.hasPrefix("data:") { add(URL(string: ref, relativeTo: scriptURL)?.absoluteURL) }
            }
        }
        add(URL(string: scriptURL.absoluteString + ".map"))
        return urls
    }

    static func analyzeSourceMap(mapURL: URL, body: Data) -> [Finding] {
        guard body.count < 8_000_000,
              let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              obj["version"] != nil || obj["sources"] != nil else { return [] }

        var findings: [Finding] = []
        findings.append(Finding(
            title: "Source map exposed",
            severity: .low,
            category: "Source Code Exposure",
            location: mapURL.absoluteString,
            detail: "A JavaScript source map is publicly readable, exposing the original (unminified) source code.",
            evidence: "URL: \(mapURL.absoluteString)\nSource files: \((obj["sources"] as? [Any])?.count ?? 0)",
            exploit: "Source maps reconstruct your original source - including comments, internal logic, and any hardcoded secrets - from minified bundles.",
            remediation: "Do not deploy .map files to production (or restrict them), and keep secrets out of frontend code.",
            reference: "CWE-540: Inclusion of Sensitive Information in Source Code"))

        if let contents = obj["sourcesContent"] as? [Any] {
            var combined = ""
            for case let s as String in contents {
                combined += "\n" + s
                if combined.count > 2_000_000 { break }
            }
            findings += SecretScanner.scan(combined, source: mapURL.absoluteString + " (original source)")
        }
        return findings
    }

    static func robotsDisallowPaths(_ body: String) -> [String] {
        var paths: [String] = []
        for line in body.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let l = line.trimmingCharacters(in: .whitespaces)
            let lower = l.lowercased()
            if lower.hasPrefix("disallow:") || lower.hasPrefix("allow:") {
                let value = l.drop(while: { $0 != ":" }).dropFirst().trimmingCharacters(in: .whitespaces)
                if !value.isEmpty && value != "/" {
                    paths.append(value.hasPrefix("/") ? String(value.dropFirst()) : value)
                }
            }
        }
        return Array(Set(paths))
    }

    static func sitemapLocations(_ body: String, sameHost: String) -> [URL] {
        matchAttr(pattern: "<loc>\\s*([^<\\s]+)\\s*</loc>", in: body)
            .compactMap { URL(string: $0)?.absoluteURL }
            .filter { ($0.scheme == "http" || $0.scheme == "https") && $0.host == sameHost }
    }

    static func robotsFinding(url: URL, disallow: [String]) -> Finding? {
        let sensitive = disallow.filter { p in
            let l = p.lowercased()
            return ["admin","backup","config","private","secret","api","internal","db","sql","login","panel","wp-"]
                .contains { l.contains($0) }
        }
        guard !sensitive.isEmpty else { return nil }
        return Finding(
            title: "robots.txt discloses sensitive paths",
            severity: .info,
            category: "Information Disclosure",
            location: url.absoluteString,
            detail: "robots.txt lists paths that appear sensitive. Attackers read robots.txt first to find hidden areas.",
            evidence: "Disallowed: \(sensitive.prefix(12).map { "/\($0)" }.joined(separator: ", "))",
            exploit: "robots.txt is public; listing admin/backup/api paths here effectively advertises them to attackers.",
            remediation: "Do not rely on robots.txt for security. Protect sensitive paths with authentication and access control instead of listing them.",
            reference: "CWE-200")
    }

    static func analyzeForms(html: String, pageURL: URL) -> [Finding] {
        var findings: [Finding] = []
        let isHTTPS = pageURL.scheme == "https"
        guard let re = try? NSRegularExpression(pattern: "<form\\b[\\s\\S]*?</form>", options: [.caseInsensitive]) else { return [] }
        let ns = html as NSString
        let forms = re.matches(in: html, range: NSRange(location: 0, length: ns.length))
        var flaggedHTTPPassword = false
        var flaggedExternal = false

        for m in forms.prefix(30) {
            let form = ns.substring(with: m.range).lowercased()
            let hasPassword = form.contains("type=\"password\"") || form.contains("type='password'") || form.contains("type=password")

            if hasPassword, !isHTTPS, !flaggedHTTPPassword {
                flaggedHTTPPassword = true
                findings.append(Finding(
                    title: "Password submitted over insecure HTTP",
                    severity: .high, category: "Transport Security", location: pageURL.absoluteString,
                    detail: "A form containing a password field is served on a non-HTTPS page.",
                    evidence: snippet(form, max: 160),
                    exploit: "Credentials entered here travel in cleartext and can be captured by anyone on the network path.",
                    remediation: "Serve all pages with login forms over HTTPS and post credentials only to https:// endpoints.",
                    reference: "CWE-319"))
            }

            if let am = firstMatch("action\\s*=\\s*[\"']([^\"']+)[\"']", in: form),
               let action = URL(string: am, relativeTo: pageURL)?.absoluteURL {
                let external = action.host != nil && action.host != pageURL.host
                let insecure = action.scheme == "http" && isHTTPS
                if hasPassword, (external || insecure), !flaggedExternal {
                    flaggedExternal = true
                    findings.append(Finding(
                        title: "Login form posts to insecure/external endpoint",
                        severity: .medium, category: "Forms", location: pageURL.absoluteString,
                        detail: "A login form's action targets \(insecure ? "an http:// endpoint" : "a different host") (\(action.host ?? "?")).",
                        evidence: "action = \(am)",
                        exploit: "Posting credentials to an external or plaintext endpoint can leak them or indicate a phishing/mixed-content issue.",
                        remediation: "Post credentials only to your own HTTPS endpoint; review any third-party form handlers.",
                        reference: "CWE-319"))
                }
            }
        }
        return findings
    }

    static func mixedContent(html: String, pageURL: URL) -> [Finding] {
        guard pageURL.scheme == "https" else { return [] }
        guard let re = try? NSRegularExpression(
            pattern: "<(script|iframe|link|object|embed|source|img|audio|video)\\b[^>]*?(?:src|href|data)\\s*=\\s*[\"'](http://[^\"']+)[\"']",
            options: [.caseInsensitive]) else { return [] }
        let ns = html as NSString
        var active: [String] = []
        var passive: [String] = []
        var seen = Set<String>()
        let activeTags: Set<String> = ["script", "iframe", "link", "object", "embed", "source"]
        for m in re.matches(in: html, range: NSRange(location: 0, length: ns.length)) where m.numberOfRanges > 2 {
            let tag = ns.substring(with: m.range(at: 1)).lowercased()
            let url = ns.substring(with: m.range(at: 2))
            guard seen.insert(url).inserted else { continue }
            if activeTags.contains(tag) { active.append(url) } else { passive.append(url) }
            if seen.count >= 60 { break }
        }
        guard !active.isEmpty || !passive.isEmpty else { return [] }

        let examples = (active + passive).prefix(6).joined(separator: "\n")
        return [Finding(
            title: active.isEmpty ? "Mixed content: passive resources over HTTP" : "Mixed content: active resources over HTTP",
            severity: active.isEmpty ? .low : .medium,
            category: "Transport Security",
            location: pageURL.absoluteString,
            detail: "An HTTPS page loads \(active.count) active and \(passive.count) passive sub-resource(s) over plaintext http://.",
            evidence: "Insecure sub-resources:\n\(examples)",
            exploit: active.isEmpty
                ? "Passive http:// resources (images/media) can be swapped by a network attacker to mislead users, and they leak the request over plaintext."
                : "An attacker on the network can modify http:// scripts/iframes/stylesheets in transit and inject code that runs in the secure page's origin - defeating HTTPS for this page.",
            remediation: "Load every sub-resource over https:// (or protocol-relative that resolves to https). Add the CSP directive 'upgrade-insecure-requests' to auto-upgrade legacy references.",
            reference: "CWE-311 / MDN: Mixed content")]
    }

    static func sriFindings(html: String, pageURL: URL, sameHost: String) -> [Finding] {
        let ns = html as NSString
        var offenders: [String] = []
        var seen = Set<String>()

        func scan(pattern: String, attr: String, requireStylesheet: Bool) {
            guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return }
            for m in re.matches(in: html, range: NSRange(location: 0, length: ns.length)) {
                let tag = ns.substring(with: m.range)
                let lower = tag.lowercased()
                if requireStylesheet, !lower.contains("stylesheet") { continue }
                guard let raw = firstMatch("\(attr)\\s*=\\s*[\"']([^\"']+)[\"']", in: tag),
                      let u = URL(string: raw, relativeTo: pageURL)?.absoluteURL,
                      u.scheme == "http" || u.scheme == "https" else { continue }
                if isFirstParty(u.host, base: sameHost) { continue }
                if lower.contains("integrity") { continue }              
                if seen.insert(u.absoluteString).inserted { offenders.append(u.absoluteString) }
                if offenders.count >= 40 { break }
            }
        }
        scan(pattern: "<script\\b[^>]*\\bsrc\\s*=\\s*[\"'][^\"']+[\"'][^>]*>", attr: "src", requireStylesheet: false)
        scan(pattern: "<link\\b[^>]*>", attr: "href", requireStylesheet: true)
        guard !offenders.isEmpty else { return [] }

        return [Finding(
            title: "Third-party resources without Subresource Integrity (SRI)",
            severity: .low,
            category: "Vulnerable Component",
            location: pageURL.absoluteString,
            detail: "\(offenders.count) cross-origin script/stylesheet(s) are loaded without an `integrity` attribute, so the browser cannot verify the file was not tampered with.",
            evidence: "Unprotected third-party resources:\n\(offenders.prefix(8).joined(separator: "\n"))",
            exploit: "If the third-party host is breached (a common supply-chain attack) or the resource is served over a compromised path, it can inject arbitrary JavaScript that runs with this page's full privileges - reading data, stealing sessions, and defacing the site - with nothing on your server changing.",
            remediation: "Add an integrity=\"sha384-...\" (and crossorigin) attribute to third-party <script>/<link> tags so the browser rejects modified files, or self-host the resource. Pin versions rather than loading 'latest'. (Note: files that change on every request, like some analytics loaders, cannot use SRI - self-host or sandbox them.)",
            reference: "CWE-494: Download of Code Without Integrity Check")]
    }

    private static let csrfTokenMarkers = [
        "csrf", "xsrf", "authenticity_token", "__requestverificationtoken",
        "_token", "csrfmiddlewaretoken", "anti-forgery", "antiforgery",
        "nonce", "_csrf", "requestverificationtoken",
    ]

    static func csrfFindings(html: String, pageURL: URL) -> [Finding] {
        guard let re = try? NSRegularExpression(pattern: "<form\\b[\\s\\S]*?</form>", options: [.caseInsensitive]) else { return [] }
        let ns = html as NSString
        var unprotected = 0
        var example = ""
        for m in re.matches(in: html, range: NSRange(location: 0, length: ns.length)).prefix(30) {
            let form = ns.substring(with: m.range)
            let lower = form.lowercased()

            guard lower.contains("method=\"post\"") || lower.contains("method='post'") || lower.contains("method=post") else { continue }

            if lower.contains("type=\"password\"") || lower.contains("type='password'") || lower.contains("type=password") { continue }

            if let am = firstMatch("action\\s*=\\s*[\"']([^\"']+)[\"']", in: form),
               let action = URL(string: am, relativeTo: pageURL)?.absoluteURL,
               let h = action.host, h != pageURL.host { continue }
            let hasToken = csrfTokenMarkers.contains { lower.contains($0) }
            if !hasToken {
                unprotected += 1
                if example.isEmpty { example = snippet(form, max: 160) }
            }
        }
        guard unprotected > 0 else { return [] }
        return [Finding(
            title: "Form without anti-CSRF token",
            severity: .low,
            category: "CSRF",
            location: pageURL.absoluteString,
            detail: "\(unprotected) POST form(s) on this page contain no recognizable anti-CSRF token field. If the endpoint also relies on cookies for auth and does not enforce SameSite, it may be vulnerable to cross-site request forgery.",
            evidence: "Example form (no token field found):\n\(example)",
            exploit: "An attacker hosts a page that auto-submits a hidden form to this endpoint. A logged-in victim who visits it performs the state-changing action (change email, transfer, etc.) unknowingly, using their own session.",
            remediation: "Add a per-session, per-request CSRF token to every state-changing form and verify it server-side. Set session cookies to SameSite=Lax or Strict as defense-in-depth. (Verify manually - a token delivered via header/meta or SameSite cookies may already protect this.)",
            reference: "CWE-352: Cross-Site Request Forgery")]
    }

    static func graphqlIntrospection(_ r: HTTPResponse) -> Finding? {
        let t = r.text.lowercased()
        guard r.status == 200,
              t.contains("__schema") || (t.contains("\"querytype\"") && t.contains("\"data\"")) else { return nil }
        return Finding(
            title: "GraphQL introspection enabled",
            severity: .medium, category: "API Surface", location: r.finalURL.absoluteString,
            detail: "The GraphQL endpoint answered an introspection query, exposing its full schema.",
            evidence: "URL: \(r.finalURL.absoluteString)\n\(snippet(r.text, max: 160))",
            exploit: "Introspection hands an attacker the complete API schema - every type, query, and mutation - dramatically easing the discovery of sensitive operations and injection points.",
            remediation: "Disable introspection in production, require authentication, and add query depth/complexity limits and rate limiting.",
            reference: "CWE-200")
    }

    private static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let ns = text as NSString
        guard let m = re.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges > 1 else { return nil }
        return ns.substring(with: m.range(at: 1))
    }
}
