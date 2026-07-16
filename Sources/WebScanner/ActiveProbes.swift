import Foundation

enum ActiveProbes {

    static let redirectParams: [String] = [
        "url", "redirect", "redirect_uri", "redirect_url", "redirecturl",
        "return", "returnurl", "return_url", "returnto", "return_to",
        "next", "goto", "dest", "destination", "continue", "forward",
        "to", "out", "link", "target", "redir", "callback", "u", "r",
    ]

    static let redirectCanaryHost = "redirect-probe.example.org"
    static var redirectCanaryURL: String { "https://\(redirectCanaryHost)/ws" }

    static func isOpenRedirect(_ r: HTTPResponse) -> Bool {
        guard (300...399).contains(r.status), let loc = r.header("location") else { return false }
        let l = loc.lowercased()

        return l.hasPrefix("https://\(redirectCanaryHost)")
            || l.hasPrefix("http://\(redirectCanaryHost)")
            || l.hasPrefix("//\(redirectCanaryHost)")
            || l.contains("://\(redirectCanaryHost)")
    }

    static func openRedirectFinding(pageURL: URL, params: [String], location: String) -> Finding {
        Finding(
            title: "Open redirect",
            severity: .high,
            category: "Open Redirect",
            location: pageURL.absoluteString,
            detail: "The page redirects to an attacker-supplied external URL passed in a request parameter, without validating the destination.",
            evidence: "Request: \(pageURL.absoluteString)\nParameter(s): \(params.joined(separator: ", "))\nServer responded: Location: \(snippet(location, max: 160))",
            exploit: "An attacker crafts a link on your trusted domain that silently forwards victims to a phishing or malware site - the URL looks legitimate. It is also frequently chained to steal OAuth tokens/authorization codes via the redirect_uri.",
            remediation: "Never redirect to a raw user-supplied URL. Allow-list permitted destinations, or only accept relative paths (reject anything containing '://', '//', or a host). Validate after URL-decoding.",
            reference: "CWE-601: URL Redirection to Untrusted Site (Open Redirect)")
    }

    static let reflectionParams: [String] = [
        "q", "s", "search", "query", "keyword", "term", "name", "id",
        "message", "msg", "error", "lang", "page", "ref", "callback", "redirect",
    ]

    struct ReflectionCanary {
        let token: String
        let injected: String
        let needle: String

        init() {
            let hex = UUID().uuidString.replacingOccurrences(of: "-", with: "")
            token = "ws" + String(hex.prefix(10))
            needle = "<\(token)>"                 
            injected = "\"'\(needle)"
        }
    }

    static func isReflectedUnencoded(_ r: HTTPResponse, canary: ReflectionCanary) -> Bool {
        let ct = r.contentType.lowercased()
        guard ct.contains("html") || ct.isEmpty else { return false }

        return r.text.contains(canary.needle)
    }

    static func reflectedInputFinding(pageURL: URL, params: [String]) -> Finding {
        Finding(
            title: "Reflected input without output-encoding (possible XSS)",
            severity: .high,
            category: "Cross-Site Scripting",
            location: pageURL.absoluteString,
            detail: "A value supplied in the request was reflected back into the HTML response with its < > \" characters intact (not entity-encoded). That is the core precondition for reflected cross-site scripting.",
            evidence: "Request: \(pageURL.absoluteString)\nParameter(s): \(params.joined(separator: ", "))\nA benign marker containing <, >, \" was returned verbatim in the HTML (no working payload was sent).",
            exploit: "If the reflection is in an HTML/attribute/script context, an attacker replaces the marker with real script that runs in the victim's browser - stealing sessions, keystrokes, or performing actions as the user. Verify the exact context to confirm exploitability.",
            remediation: "Context-sensitively encode all user input on output (HTML-entity-encode for body/attributes, JS-encode for scripts). Prefer a framework that auto-escapes, and add a strict Content-Security-Policy as defense-in-depth.",
            reference: "CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)")
    }

    static let crlfHeaderName = "x-ws-crlf"
    static let crlfHeaderValue = "ws-injected"

    static var crlfPayload: String {

        "ws%0d%0a\(crlfHeaderName):%20\(crlfHeaderValue)%0d%0aset-cookie:%20wscrlf=1"
    }

    static func crlfInjected(_ r: HTTPResponse) -> Bool {
        if let v = r.header(crlfHeaderName), v.contains(crlfHeaderValue) { return true }
        if let sc = r.header("set-cookie")?.lowercased(), sc.contains("wscrlf=1") { return true }
        return false
    }

    static func crlfInjectionFinding(pageURL: URL, param: String, evidence: String) -> Finding {
        Finding(
            title: "CRLF injection / HTTP response splitting",
            severity: .high,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "A value supplied in the '\(param)' parameter was reflected into a response header with its carriage-return/line-feed characters intact, letting the request split a new header into the response.",
            evidence: "Request: \(pageURL.absoluteString)\nParameter: \(param)\nInjected header observed in the response:\n\(snippet(evidence, max: 180))",
            exploit: "Injecting raw CR/LF into a response header lets an attacker add arbitrary headers (e.g. Set-Cookie to fix a session), split the response to inject a body (reflected XSS that bypasses some filters), or poison a shared cache for every visitor.",
            remediation: "Never place unvalidated input into response headers (Location, Set-Cookie, custom headers). Strip or reject CR (%0d) and LF (%0a) before echoing input; use framework APIs that encode header values. Prefer allow-listed, relative redirect targets.",
            reference: "CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers")
    }

    static let hostCanary = "ws-hostinj.example.org"

    static func hostReflected(_ r: HTTPResponse) -> Bool {
        if let loc = r.header("location")?.lowercased(), loc.contains(hostCanary) { return true }

        return r.text.contains("://\(hostCanary)") || r.text.contains("//\(hostCanary)")
    }

    static func hostHeaderFinding(pageURL: URL, via: String, evidence: String) -> Finding {
        Finding(
            title: "Host header injection",
            severity: .medium,
            category: "Host Header Injection",
            location: pageURL.absoluteString,
            detail: "The application trusts a client-supplied host (\(via)) and reflects it into a redirect target or an absolute URL in the response.",
            evidence: "Request to \(pageURL.absoluteString) with a spoofed host.\n\(snippet(evidence, max: 200))",
            exploit: "An attacker sets the host to a site they control. Reflected into password-reset links it poisons the reset email (account takeover); reflected into cached pages it enables web-cache poisoning against all visitors.",
            remediation: "Never build URLs from the request Host/X-Forwarded-Host. Validate Host against an allow-list of expected domains and configure an absolute canonical/base URL server-side. Reject requests with an unexpected Host.",
            reference: "CWE-644: Improper Neutralization of HTTP Headers / Host header attacks")
    }

    static func httpMethodsFinding(_ r: HTTPResponse) -> Finding? {
        let raw = (r.header("allow") ?? "") + "," + (r.header("access-control-allow-methods") ?? "")
        let methods = Set(raw.uppercased()
            .split(whereSeparator: { $0 == "," || $0 == " " })
            .map(String.init)
            .filter { !$0.isEmpty })
        guard !methods.isEmpty else { return nil }

        let trace = methods.contains("TRACE") || methods.contains("TRACK")
        let write = methods.intersection(["PUT", "DELETE", "PATCH", "CONNECT",
                                          "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"])
        guard trace || !write.isEmpty else { return nil }

        var problems: [String] = []
        if trace { problems.append("TRACE/TRACK (Cross-Site Tracing)") }
        if !write.isEmpty { problems.append("write/WebDAV methods: \(write.sorted().joined(separator: ", "))") }

        return Finding(
            title: "Risky HTTP methods enabled",
            severity: trace ? .medium : .low,
            category: "Attack Surface",
            location: r.finalURL.absoluteString,
            detail: "The server advertises methods beyond safe read verbs: \(problems.joined(separator: "; ")).",
            evidence: "Allow: \(methods.sorted().joined(separator: ", "))",
            exploit: trace
                ? "TRACE echoes the full request (including cookies/auth headers) and can be abused for Cross-Site Tracing to read HttpOnly cookies. Exposed write/WebDAV methods may allow uploading or deleting files."
                : "Write/WebDAV methods (PUT/DELETE/PROPFIND...) exposed to the internet can allow uploading, overwriting, or deleting resources if authorization is weak.",
            remediation: "Disable TRACE/TRACK. Restrict the endpoint to the methods it actually needs (typically GET/HEAD/POST) and require authentication + authorization for any write method.",
            reference: "CWE-16 / CWE-650: Trusting HTTP Permission Methods on the Server Side")
    }

    private struct ErrorSig { let label: String; let regex: NSRegularExpression }
    private static func sig(_ label: String, _ pattern: String) -> ErrorSig {
        ErrorSig(label: label, regex: try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive]))
    }

    private static let errorSignatures: [ErrorSig] = [
        sig("Python/Django traceback", "Traceback \\(most recent call last\\)|django\\.|werkzeug|DEBUG = True"),
        sig("Flask/Werkzeug interactive debugger", "Werkzeug Debugger|__debugger__|traceback\\.js"),
        sig("Ruby on Rails error", "ActionController::|ActiveRecord::|rails\\.|app/controllers/"),
        sig("PHP error/warning", "(?:Fatal error|Parse error|Warning|Notice):.*(?:in|on line).*\\.php"),
        sig("Laravel/Symfony (Whoops)", "Whoops\\\\|Symfony\\\\Component|Stack trace:|vendor/laravel"),
        sig("ASP.NET stack trace", "Server Error in '/' Application|System\\.(?:Web|Data|Null)|Microsoft\\.AspNet|\\.aspx:line"),
        sig("Java/Spring stack trace", "javax?\\.[a-z]+\\.[A-Za-z]+Exception|\\bat (?:org|com|java)\\.[a-z0-9_.]+\\([A-Za-z0-9_]+\\.java:[0-9]+\\)|org\\.springframework"),
        sig("Node.js stack trace", "at (?:Object\\.)?<anonymous>|at Module\\._compile|node_modules|/node:internal"),
        sig("Absolute server file path leak", "(?:/var/www/|/home/[a-z0-9_]+/|/usr/local/|/app/src/|[A-Z]:\\\\(?:inetpub|xampp|wwwroot|Users)\\\\)"),
    ]

    static func errorSignature(in text: String) -> (label: String, sample: String)? {
        let ns = text as NSString
        let range = NSRange(location: 0, length: min(ns.length, 200_000))
        for s in errorSignatures {
            if let m = s.regex.firstMatch(in: text, range: range) {
                let start = max(0, m.range.location - 20)
                let len = min(ns.length - start, m.range.length + 120)
                return (s.label, ns.substring(with: NSRange(location: start, length: len)))
            }
        }
        return nil
    }

    static func errorDisclosureFinding(url: URL, label: String, sample: String) -> Finding {
        Finding(
            title: "Verbose error / debug output exposed (\(label))",
            severity: .medium,
            category: "Information Disclosure",
            location: url.absoluteString,
            detail: "The server returned a detailed stack trace or debug page instead of a generic error. These pages leak framework versions, absolute file paths, SQL, and sometimes environment variables or source code.",
            evidence: "URL: \(url.absoluteString)\nSignature: \(label)\nExcerpt: \(snippet(sample, max: 200))",
            exploit: "Stack traces map your internal structure (paths, components, versions) for an attacker and occasionally leak secrets directly. A left-on debug mode (e.g. Django DEBUG, Flask/Werkzeug console, Rails) can even permit remote code execution.",
            remediation: "Disable debug mode in production and return generic error pages. Log full details server-side only. Ensure DEBUG/development flags are off in the deployed configuration.",
            reference: "CWE-209: Generation of Error Message Containing Sensitive Information")
    }
}
