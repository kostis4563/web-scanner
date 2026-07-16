import Foundation

enum JSAnalysis {

    private static let interestingExts: Set<String> = [
        "env", "json", "yml", "yaml", "config", "conf", "ini", "properties",
        "sql", "bak", "old", "pem", "key", "cfg", "tfstate", "php",
    ]
    private static let interestingNames: [String] = [
        ".env", "config", "secret", "credential", "settings", "database",
        "backup", "dump", ".git/", "id_rsa", "private",
    ]

    private static let stringLiteralRegex = try! NSRegularExpression(
        pattern: "[\"'`]([^\"'`\\s{}$]{2,180})[\"'`]", options: [])

    static func interestingPaths(from text: String, base: URL, sameHost: String) -> [URL] {
        let ns = text as NSString
        var out: [URL] = []
        var seen = Set<String>()

        for m in stringLiteralRegex.matches(in: text, range: NSRange(location: 0, length: ns.length))
        where m.numberOfRanges > 1 {
            let raw = ns.substring(with: m.range(at: 1))
            guard raw.contains("/") || raw.contains(".") else { continue }
            let low = raw.lowercased()

            let ext = (raw as NSString).pathExtension.lowercased()
            let looksInteresting = low.contains(".env")
                || interestingExts.contains(ext)
                || interestingNames.contains { low.contains($0) }
            guard looksInteresting else { continue }

            if low.hasPrefix("data:") || low.hasPrefix("mailto:") { continue }
            if ["png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "woff", "woff2", "ttf"]
                .contains(ext) { continue }

            guard let u = URL(string: raw, relativeTo: base)?.absoluteURL,
                  u.scheme == "http" || u.scheme == "https",
                  u.host == sameHost,
                  seen.insert(u.absoluteString).inserted else { continue }
            out.append(u)
            if out.count >= 60 { break }
        }
        return out
    }

    private static let scriptURLRegex = try! NSRegularExpression(
        pattern: "[\"'`]([A-Za-z0-9_\\-./]+\\.js(?:\\?[^\"'`\\s]*)?)[\"'`]", options: [])

    static func scriptURLs(from text: String, base: URL, sameHost: String) -> [URL] {
        let ns = text as NSString
        var out: [URL] = []
        var seen = Set<String>()
        for m in scriptURLRegex.matches(in: text, range: NSRange(location: 0, length: ns.length))
        where m.numberOfRanges > 1 {
            let raw = ns.substring(with: m.range(at: 1))
            guard let u = URL(string: raw, relativeTo: base)?.absoluteURL,
                  u.scheme == "http" || u.scheme == "https",
                  u.host == sameHost,
                  seen.insert(u.absoluteString).inserted else { continue }
            out.append(u)
            if out.count >= 120 { break }
        }
        return out
    }

    struct SinkHit {
        let name: String
        let severity: Severity
        let category: String
        let detail: String
        let exploit: String
        let remediation: String
        let reference: String
        let sample: String
        let source: String
    }

    private struct Rule {
        let name: String
        let severity: Severity
        let category: String
        let regex: NSRegularExpression
        let detail: String
        let exploit: String
        let remediation: String
        let reference: String

        init(_ name: String, _ severity: Severity, _ pattern: String, detail: String,
             exploit: String, remediation: String, reference: String,
             category: String = "Client-Side (DOM)") {
            self.name = name
            self.severity = severity
            self.category = category
            self.regex = try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
            self.detail = detail
            self.exploit = exploit
            self.remediation = remediation
            self.reference = reference
        }
    }

    private static let rules: [Rule] = [
        Rule("Unsanitized innerHTML/outerHTML assignment", .info,
             "\\.(?:inner|outer)HTML\\s*(?:\\+?=)[^=]",
             detail: "Client code assigns to innerHTML/outerHTML. If the assigned value contains untrusted input, it is a DOM-based XSS sink.",
             exploit: "If any part of the assigned string comes from the URL, postMessage, storage, or an API response, an attacker can inject <script>/<img onerror> markup that runs in the victim's session.",
             remediation: "Set textContent instead of innerHTML, or sanitize with a vetted library (e.g. DOMPurify) before insertion.",
             reference: "CWE-79: DOM-based Cross-Site Scripting"),

        Rule("document.write() sink", .info,
             "document\\.write(?:ln)?\\s*\\(",
             detail: "document.write() is used, which writes raw HTML into the page.",
             exploit: "If the written content is influenced by user input (URL params, referrer, storage), it enables DOM XSS.",
             remediation: "Avoid document.write(); build DOM nodes with createElement/textContent or sanitize inputs.",
             reference: "CWE-79"),

        Rule("insertAdjacentHTML sink", .info,
             "\\.insertAdjacentHTML\\s*\\(",
             detail: "insertAdjacentHTML() parses and inserts raw HTML.",
             exploit: "Untrusted input passed here executes injected markup - a DOM XSS vector.",
             remediation: "Insert text nodes, or sanitize the HTML before calling insertAdjacentHTML.",
             reference: "CWE-79"),

        Rule("React dangerouslySetInnerHTML", .low,
             "dangerouslySetInnerHTML",
             detail: "React's dangerouslySetInnerHTML bypasses React's built-in XSS protection.",
             exploit: "Rendering unsanitized HTML here lets attacker-controlled content execute scripts in users' browsers.",
             remediation: "Avoid it; if unavoidable, sanitize the HTML (DOMPurify) immediately before rendering.",
             reference: "CWE-79"),

        Rule("Dynamic code execution (eval / new Function)", .low,
             "\\beval\\s*\\(|\\bnew\\s+Function\\s*\\(",
             detail: "eval() or new Function() executes strings as code. (Note: some bundlers emit eval for dev source maps - verify it is not a build artifact.)",
             exploit: "If the executed string is attacker-influenced, it yields arbitrary JavaScript execution (and full DOM/session access).",
             remediation: "Remove eval/new Function; use JSON.parse for data and explicit function references for logic.",
             reference: "CWE-95: Eval Injection"),

        Rule("Secret/token written to web storage", .info,
             "(?:local|session)Storage\\.setItem\\s*\\(\\s*[\"'][^\"']*(?:token|auth|jwt|secret|password|api[_-]?key|session)",
             detail: "An authentication token/secret appears to be stored in localStorage/sessionStorage.",
             exploit: "Web storage is readable by any JavaScript on the page, so a single XSS flaw exfiltrates the token. Unlike HttpOnly cookies, storage offers no protection.",
             remediation: "Keep session tokens in HttpOnly, Secure cookies. Do not persist long-lived secrets in web storage.",
             reference: "CWE-522: Insufficiently Protected Credentials"),

        Rule("postMessage to wildcard target origin", .low,
             "postMessage\\s*\\([^;\\)]*,\\s*[\"']\\*[\"']",
             detail: "postMessage is called with a target origin of \"*\".",
             exploit: "Broadcasting to \"*\" can leak the message (often containing tokens or user data) to any window/iframe, and paired listeners that don't verify event.origin can be abused.",
             remediation: "Specify an explicit target origin instead of \"*\", and validate event.origin in every message handler.",
             reference: "CWE-345: Insufficient Verification of Data Authenticity"),

        Rule("Insecure http:// request in JavaScript", .low,
             "(?:fetch|axios(?:\\.[a-z]+)?|\\.open|url\\s*[:=])\\s*\\(?\\s*[\"']http://[a-z0-9.\\-]",
             detail: "Client code issues a request to a plaintext http:// URL.",
             exploit: "On an HTTPS page this is mixed content: the request (and any credentials/data in it) travels in cleartext and can be intercepted or tampered with.",
             remediation: "Use https:// for all API/resource requests and enable HSTS.",
             reference: "CWE-319: Cleartext Transmission of Sensitive Information",
             category: "Transport Security"),
    ]

    static func sinkHits(in text: String, source: String) -> [SinkHit] {
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)
        var hits: [SinkHit] = []
        for rule in rules {
            let matches = rule.regex.matches(in: text, range: full)
            guard let first = matches.first else { continue }
            let sample = sampleAround(first.range, in: ns)

            for _ in matches.prefix(1) {
                hits.append(SinkHit(
                    name: rule.name, severity: rule.severity, category: rule.category,
                    detail: rule.detail, exploit: rule.exploit,
                    remediation: rule.remediation, reference: rule.reference,
                    sample: sample, source: source))
            }
        }
        return hits
    }

    static func makeSinkFindings(_ hits: [SinkHit]) -> [Finding] {
        guard !hits.isEmpty else { return [] }
        var byName: [String: [SinkHit]] = [:]
        for h in hits { byName[h.name, default: []].append(h) }

        var out: [Finding] = []
        for (name, group) in byName {
            let first = group[0]
            let sources = Array(Set(group.map { $0.source })).sorted()
            let evidence = """
            Occurrences: \(group.count) hit(s) across \(sources.count) file(s)
            Example: \(snippet(first.sample, max: 140))
            Files: \(sources.prefix(3).joined(separator: ", "))\(sources.count > 3 ? " ..." : "")
            """
            out.append(Finding(
                title: "Potential client-side risk: \(name)",
                severity: first.severity,
                category: first.category,
                location: sources.first ?? "JavaScript",
                detail: first.detail,
                evidence: evidence,
                exploit: first.exploit,
                remediation: first.remediation,
                reference: first.reference))
        }
        return out.sorted { $0.severity < $1.severity }
    }

    private static func sampleAround(_ range: NSRange, in ns: NSString) -> String {
        let start = max(0, range.location - 30)
        let len = min(ns.length - start, range.length + 90)
        guard len > 0 else { return "" }
        return ns.substring(with: NSRange(location: start, length: len))
    }
}
