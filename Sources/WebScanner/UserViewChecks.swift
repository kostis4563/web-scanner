import Foundation

enum UserViewChecks {

    private static func regex(_ pattern: String) -> NSRegularExpression? {
        try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
    }

    private static func matches(_ pattern: String, in text: String) -> [[String]] {
        guard let re = regex(pattern) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { m in
            (0..<m.numberOfRanges).map { i in
                let r = m.range(at: i)
                return r.location == NSNotFound ? "" : ns.substring(with: r)
            }
        }
    }

    private static func formBlocks(_ html: String) -> [String] {
        matches("<form\\b[\\s\\S]*?</form>", in: html).map { $0[0] }
    }

    private static func tagAttr(_ attr: String, in tag: String) -> String? {
        matches("\\b\(attr)\\s*=\\s*[\"']([^\"']*)[\"']", in: tag).first?[1]
    }

    static func registrationSurface(html: String, pageURL: URL) -> [Finding] {
        let loc = pageURL.absoluteString
        var out: [Finding] = []
        let joinWords = ["register", "sign up", "signup", "sign-up", "create account",
                         "create an account", "join", "get started", "new account"]

        for form in formBlocks(html) {
            let low = form.lowercased()
            let hasPassword = low.contains("type=\"password\"") || low.contains("type='password'") || low.contains("type=password")
            guard hasPassword else { continue }
            let looksLikeJoin = joinWords.contains { low.contains($0) }
                || (low.contains("email") && (low.contains("confirm") || low.contains("repeat")) )
            guard looksLikeJoin else { continue }

            let action = tagAttr("action", in: form) ?? "(same page)"
            let mentionsVerify = low.contains("verify") || low.contains("verification")
                || low.contains("captcha") || low.contains("recaptcha") || low.contains("hcaptcha")
            var detail = "A self-service registration form lets any anonymous visitor create an account."
            if !mentionsVerify {
                detail += " No CAPTCHA or email-verification hint is visible in the form markup, so account creation may be fully automatable."
            }
            out.append(Finding(
                title: "Open self-registration form",
                severity: mentionsVerify ? .info : .low,
                category: "User View",
                location: loc,
                detail: detail,
                evidence: "action = \(action)\n" + snippet(form, max: 200),
                exploit: "Anyone can register and reach the authenticated user surface. Without a CAPTCHA or verified email, the endpoint can be scripted to mass-create accounts (spam, credential-stuffing staging, abuse of free tiers).",
                remediation: "If open sign-up is intended, gate it with email verification and a bot challenge (CAPTCHA / rate limit) and enforce that server-side. If it is not intended for the public, require an invite.",
                reference: "OWASP: Improper Restriction of Excessive Authentication Attempts / abuse of functionality"))
            break
        }
        return out
    }

    private static let trustSensitiveNames: [String] = [
        "price", "amount", "total", "subtotal", "cost", "fee", "discount", "coupon",
        "qty", "quantity", "count", "credit", "credits", "balance", "points",
        "role", "roles", "is_admin", "isadmin", "admin", "is_staff", "user_id",
        "userid", "uid", "account_id", "accountid", "customer_id", "is_paid",
        "paid", "plan", "tier", "level", "permission", "permissions", "grant",
        "approved", "status", "verified", "premium", "vip",
    ]

    static func tamperableFormControls(html: String, pageURL: URL) -> [Finding] {
        let loc = pageURL.absoluteString
        var hits: [(name: String, kind: String, value: String, tag: String)] = []
        var seen = Set<String>()

        for input in matches("<input\\b[^>]*>", in: html).map({ $0[0] }) {
            let low = input.lowercased()
            let name = tagAttr("name", in: input) ?? tagAttr("id", in: input) ?? ""
            guard !name.isEmpty else { continue }
            let nlow = name.lowercased()
            guard trustSensitiveNames.contains(where: { nlow == $0 || nlow.contains($0) }) else { continue }

            var kind: String?
            let type = (tagAttr("type", in: input) ?? "").lowercased()
            if type == "hidden" { kind = "hidden" }
            else if low.contains(" disabled") || low.contains("disabled=") || low.contains("disabled ") || low.contains("disabled>") { kind = "disabled" }
            else if low.contains("readonly") { kind = "readonly" }
            guard let k = kind, seen.insert("\(nlow)|\(k)").inserted else { continue }
            let value = tagAttr("value", in: input) ?? ""
            hits.append((name, k, value, input))
        }

        guard !hits.isEmpty else { return [] }
        let money = hits.contains { n in
            ["price", "amount", "total", "cost", "discount", "credit", "balance", "qty", "quantity"].contains { n.name.lowercased().contains($0) }
        }
        let priv = hits.contains { n in
            ["role", "admin", "is_staff", "permission", "grant", "plan", "tier", "premium", "verified"].contains { n.name.lowercased().contains($0) }
        }
        let severity: Severity = priv ? .high : (money ? .medium : .low)
        let list = hits.map { "• \($0.name) [\($0.kind)]" + ($0.value.isEmpty ? "" : " = \($0.value)") }
            .joined(separator: "\n")
        let evidence = list + "\n\n" + snippet(hits.first!.tag, max: 200)

        return [Finding(
            title: "Trust-bearing form fields tamperable in the browser",
            severity: severity,
            category: "User View",
            location: loc,
            detail: "The page ships \(hits.count) hidden/disabled/readonly form field(s) whose name implies a security- or money-relevant value:\n\(list)\n\n`hidden`, `disabled` and `readonly` are cosmetic - the user can delete the attribute or set any value from DevTools before submitting.",
            evidence: evidence,
            exploit: "A user opens DevTools, edits the field (e.g. price to 0, quantity to a negative number, role to admin, user_id to someone else's) and submits. If the server trusts the posted value, this becomes price manipulation, privilege escalation, or IDOR.",
            remediation: "Never trust client-supplied values for trust or pricing decisions. Look prices/roles/ownership up server-side from the authenticated session; treat every field in the request as attacker-controlled and re-validate/authorize it.",
            reference: "CWE-472: External Control of Assumed-Immutable Web Parameter")]
    }

    static func clientSideValidationOnly(html: String, pageURL: URL) -> [Finding] {
        let loc = pageURL.absoluteString
        var out: [Finding] = []
        for form in formBlocks(html) {
            let low = form.lowercased()

            let method = (tagAttr("method", in: form) ?? "get").lowercased()
            let jsGate = low.contains("onsubmit") && (low.contains("return false") || low.contains("validate") || low.contains("return checkform") || low.contains("return "))
            let htmlConstraints = matches("\\b(required|pattern|maxlength|minlength|min|max)\\s*=", in: form).count
            guard method == "post" else { continue }
            guard jsGate || htmlConstraints >= 2 else { continue }

            var basis: [String] = []
            if jsGate { basis.append("an onsubmit JavaScript handler") }
            if htmlConstraints > 0 { basis.append("\(htmlConstraints) HTML validation attribute(s) (required/pattern/min/max/maxlength)") }
            out.append(Finding(
                title: "Form relies on client-side validation",
                severity: .low,
                category: "User View",
                location: loc,
                detail: "A POST form gates its input with \(basis.joined(separator: " and ")). Browser-side validation is a UX convenience only - a user can strip the attributes, cancel the onsubmit handler, or skip the page entirely and POST arbitrary values directly.",
                evidence: snippet(form, max: 220),
                exploit: "The user disables the JS handler / edits the `pattern`,`maxlength`,`required` attributes in DevTools, or replays the request with curl, sending values the form claimed to forbid (over-long input, wrong format, missing required fields, out-of-range numbers).",
                remediation: "Re-validate every field server-side with the same rules. Treat HTML/JS validation purely as UX; never assume the received request obeyed it.",
                reference: "CWE-602: Client-Side Enforcement of Server-Side Security"))
            if out.count >= 3 { break }
        }
        return out
    }

    static func clientSideTrustFlags(js: String, source: String) -> [Finding] {
        var hits: [String] = []
        var seen = Set<String>()
        let patterns = [
            "([\"']?(?:is)?[_ ]?admin[\"']?)\\s*[:=]\\s*(true|1|[\"']admin[\"'])",
            "([\"']?is[_ ]?(?:staff|superuser|premium|pro|vip|paid|authenticated|loggedin|logged_in)[\"']?)\\s*[:=]\\s*(true|1)",
            "([\"']?(?:user)?[_ ]?role[\"']?)\\s*[:=]\\s*[\"'](admin|superadmin|staff|owner|root|manager)[\"']",
            "([\"']?can[_ ]?(?:edit|delete|manage|admin|access)[\"']?)\\s*[:=]\\s*(true|1)",
            "([\"']?(?:feature[_ ]?flags?|features)[\"']?)\\s*[:=]\\s*\\{",
            "([\"']?debug[\"']?)\\s*[:=]\\s*(true|1)",
        ]
        for p in patterns {
            for m in matches(p, in: js) {
                let frag = snippet(m[0], max: 100)
                guard seen.insert(frag.lowercased()).inserted else { continue }
                hits.append(frag)
                if hits.count >= 12 { break }
            }
        }
        guard !hits.isEmpty else { return [] }
        return [Finding(
            title: "Privilege / feature decisions made in client-side JavaScript",
            severity: .medium,
            category: "User View",
            location: source,
            detail: "Client JavaScript sets role, privilege, feature-flag or debug values that appear to gate what the UI shows or allows:\n" + hits.map { "• \($0)" }.joined(separator: "\n") + "\n\nAnything the browser evaluates, the user controls - these values can be overwritten from the console.",
            evidence: hits.prefix(8).joined(separator: "\n"),
            exploit: "The user opens the console, sets the flag (e.g. `user.isAdmin = true`, `window.featureFlags.betaPanel = true`) and the gated admin/premium/beta UI unlocks. If the backing endpoints trust that the UI would only call them for privileged users, the user now reaches privileged functionality.",
            remediation: "Use client-side role/feature flags only to *hint* the UI. Authorize every privileged action on the server against the authenticated session; never let a client-set value be the access decision.",
            reference: "CWE-602 / CWE-639: Authorization Bypass Through User-Controlled Key")]
    }

    static func browserStorageAuth(js: String, source: String) -> [Finding] {
        var hits: [String] = []
        var seen = Set<String>()
        let pattern = "(local|session)Storage\\s*(?:\\.setItem\\s*\\(\\s*[\"']([^\"']*)[\"']|\\.([A-Za-z_][A-Za-z0-9_]*)\\s*=)"
        for m in matches(pattern, in: js) {
            let store = m[1].lowercased() + "Storage"
            let key = (m.count > 2 && !m[2].isEmpty) ? m[2] : (m.count > 3 ? m[3] : "")
            let klow = key.lowercased()
            let sensitive = ["token", "jwt", "auth", "session", "secret", "role",
                             "admin", "apikey", "api_key", "access", "refresh",
                             "credential", "password", "user", "account"]
            guard sensitive.contains(where: { klow.contains($0) }) else { continue }
            let frag = "\(store)[\"\(key)\"]"
            guard seen.insert(frag.lowercased()).inserted else { continue }
            hits.append(frag)
            if hits.count >= 12 { break }
        }
        guard !hits.isEmpty else { return [] }
        return [Finding(
            title: "Auth material stored in browser localStorage/sessionStorage",
            severity: .medium,
            category: "User View",
            location: source,
            detail: "Client JS keeps authentication/identity material in Web Storage:\n" + hits.map { "• \($0)" }.joined(separator: "\n") + "\n\nWeb Storage is plain-text, has no HttpOnly equivalent, and is fully readable and writable from the page's own JavaScript.",
            evidence: hits.prefix(8).joined(separator: "\n"),
            exploit: "The user reads the token straight from `localStorage` in the console (and can edit it to impersonate a role/user if the server trusts its contents). More importantly, any XSS on the site can exfiltrate it instantly - unlike an HttpOnly cookie, script can read it.",
            remediation: "Keep session tokens in Secure, HttpOnly, SameSite cookies the page's JS cannot read. If a token must live client-side, keep it in memory only, keep it short-lived, and never trust client-editable identity claims server-side.",
            reference: "CWE-522 / OWASP: HTML5 Web Storage security")]
    }

    static func jsReadableSessionCookies(_ r: HTTPResponse) -> [Finding] {
        guard let raw = r.setCookieRaw else { return [] }
        let loc = r.finalURL.absoluteString
        var flagged: [String] = []
        let sessionNames = ["session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf", "remember"]
        for line in raw.components(separatedBy: "\n") {
            let low = line.lowercased()
            guard let name = line.split(separator: "=").first.map({ String($0).trimmingCharacters(in: .whitespaces) }) else { continue }
            let nlow = name.lowercased()
            let looksSession = sessionNames.contains { nlow.contains($0) }
            guard looksSession, !low.contains("httponly") else { continue }
            flagged.append(name)
        }
        guard !flagged.isEmpty else { return [] }
        return [Finding(
            title: "Session cookie readable by the user's own JavaScript",
            severity: .medium,
            category: "User View",
            location: loc,
            detail: "Cookie(s) that look session/identity-related are set without the HttpOnly flag: \(flagged.joined(separator: ", ")). Any JavaScript running in the page - including code the user types in the console - can read and overwrite them via document.cookie.",
            evidence: snippet(r.setCookieRaw ?? "", max: 200),
            exploit: "The user (or any injected script) reads the cookie with `document.cookie`, copies another value in, or replays it elsewhere. Without HttpOnly a single XSS is enough to hijack the session; with it, the cookie stays out of script's reach.",
            remediation: "Set session/auth cookies with HttpOnly (plus Secure and SameSite). Reserve non-HttpOnly cookies for values that are genuinely safe for client scripts to read.",
            reference: "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag")]
    }

    static func clientSideRedirectGate(js: String, source: String) -> [Finding] {
        let pattern = "if\\s*\\([^)]*(?:!\\s*(?:isloggedin|loggedin|authenticated|user|token|auth|session)|(?:isloggedin|loggedin|authenticated)\\s*==?\\s*false)[^)]*\\)\\s*\\{?[^}]*(?:window\\.)?location(?:\\.href)?\\s*=\\s*[\"'][^\"']*(?:login|signin|sign-in)"
        let hits = matches(pattern, in: js)
        guard !hits.isEmpty else { return [] }
        return [Finding(
            title: "Access gated by a client-side redirect",
            severity: .medium,
            category: "User View",
            location: source,
            detail: "Client JS redirects unauthenticated users to a login page (e.g. `if (!loggedIn) location = '/login'`). By the time this runs, the protected page and its data have already been sent to the browser.",
            evidence: snippet(hits.first?[0] ?? "", max: 200),
            exploit: "The user disables JS, sets a breakpoint, or just reads the already-loaded DOM/network response before the redirect fires - seeing content the redirect was meant to hide. Any data the 'protected' page fetched is fully visible.",
            remediation: "Enforce authentication server-side: return 401/redirect from the server for unauthenticated requests and never send protected data in the first place. A client-side redirect is UX, not access control.",
            reference: "CWE-602: Client-Side Enforcement of Server-Side Security")]
    }

    static func privilegedClientPaths(html: String, js: String, base: URL, sameHost: String) -> [String] {
        let combined = html + "\n" + js
        var found = Set<String>()
        let markers = ["admin", "dashboard", "manage", "console", "backend", "backoffice",
                       "internal", "private", "debug", "settings/", "config", "moderator",
                       "staff", "control", "superuser", "/api/admin", "/api/internal"]

        let pathPatterns = [
            "[\"'](/[A-Za-z0-9_\\-./]+)[\"']",
            "(?:href|src|action|url)\\s*=\\s*[\"']([^\"'#?]+)[\"']",
        ]
        for p in pathPatterns {
            for m in matches(p, in: combined) {
                guard m.count > 1 else { continue }
                let raw = m[1]
                let low = raw.lowercased()
                guard markers.contains(where: { low.contains($0) }) else { continue }

                guard let u = URL(string: raw, relativeTo: base)?.absoluteURL else { continue }
                if let h = u.host, h != sameHost { continue }
                var path = u.path
                if path.hasPrefix("/") { path = String(path.dropFirst()) }
                guard !path.isEmpty, path.count < 120 else { continue }

                let ext = (path as NSString).pathExtension.lowercased()
                if ["css", "js", "png", "jpg", "jpeg", "gif", "svg", "woff", "woff2", "ico", "map"].contains(ext) { continue }
                found.insert(path)
                if found.count >= 20 { break }
            }
        }
        return Array(found).sorted()
    }

    static func formInventory(html: String, pageURL: URL) -> [Finding] {
        let loc = pageURL.absoluteString
        let forms = formBlocks(html)
        guard !forms.isEmpty else { return [] }
        var out: [Finding] = []
        var lines: [String] = []

        for (i, form) in forms.prefix(20).enumerated() {
            let low = form.lowercased()
            let method = (tagAttr("method", in: form) ?? "get").uppercased()
            let action = tagAttr("action", in: form) ?? "(same page)"
            var fieldNames: [String] = []
            for input in matches("<(?:input|textarea|select)\\b[^>]*>", in: form).map({ $0[0] }) {
                let t = (tagAttr("type", in: input) ?? "").lowercased()
                if t == "submit" || t == "button" || t == "hidden" { continue }
                if let n = tagAttr("name", in: input) ?? tagAttr("id", in: input), !n.isEmpty {
                    fieldNames.append(n)
                }
            }
            let kind: String
            if low.contains("password") { kind = low.contains("confirm") || low.contains("register") || low.contains("sign up") || low.contains("signup") ? "register/login" : "login" }
            else if low.contains("search") || (method == "GET" && fieldNames.contains(where: { $0.lowercased().contains("q") || $0.lowercased().contains("search") })) { kind = "search" }
            else if low.contains("upload") || low.contains("type=\"file\"") || low.contains("type=file") { kind = "upload" }
            else if low.contains("email") || low.contains("message") || low.contains("comment") || low.contains("contact") { kind = "contact/comment" }
            else { kind = "form" }
            let fields = fieldNames.isEmpty ? "no named fields" : fieldNames.prefix(8).joined(separator: ", ")
            lines.append("\(i + 1). \(kind) · \(method) → \(action)  [\(fields)]")
        }

        out.append(Finding(
            title: "Forms a user can submit",
            severity: .info,
            category: "User View",
            location: loc,
            detail: "The page exposes \(forms.count) form(s) a visitor can fill in and submit:\n" + lines.joined(separator: "\n"),
            evidence: lines.joined(separator: "\n"),
            exploit: "Each form is an entry point a user (or a script acting as them) drives directly. Review whether every field is re-validated and authorized server-side - the client can send any value to any of these actions, regardless of what the form UI allows.",
            remediation: "Treat every listed action as attacker-reachable: validate and authorize server-side, add anti-CSRF tokens to state-changing (POST) forms, and rate-limit sensitive ones (login, register, contact).",
            reference: "OWASP: Attack Surface Analysis"))

        for form in forms {
            let low = form.lowercased()
            if (low.contains("type=\"file\"") || low.contains("type=file")) {
                out.append(Finding(
                    title: "User-reachable file upload",
                    severity: .low, category: "User View", location: loc,
                    detail: "A form on the page accepts a file upload from the visitor.",
                    evidence: snippet(form, max: 200),
                    exploit: "A user can send arbitrary files here. Without strict server-side type/size checks and safe storage, this is a path to malware upload, XSS via SVG/HTML, or web-shell placement.",
                    remediation: "Validate type and size server-side, store uploads outside the web root or on a separate origin, randomize names, and never trust the client-supplied Content-Type or extension.",
                    reference: "CWE-434: Unrestricted Upload of File with Dangerous Type"))
                break
            }
        }
        return out
    }

    static func externalResources(html: String, pageURL: URL, sameHost: String) -> [Finding] {
        var hosts = Set<String>()
        var examples: [String] = []
        let patterns = [
            "<script\\b[^>]*\\bsrc\\s*=\\s*[\"'](https?://[^\"']+)[\"']",
            "<iframe\\b[^>]*\\bsrc\\s*=\\s*[\"'](https?://[^\"']+)[\"']",
        ]
        for p in patterns {
            for m in matches(p, in: html) where m.count > 1 {
                guard let u = URL(string: m[1]), let h = u.host else { continue }
                let bare = h.hasPrefix("www.") ? String(h.dropFirst(4)) : h
                let base = sameHost.hasPrefix("www.") ? String(sameHost.dropFirst(4)) : sameHost
                guard bare != base, !bare.hasSuffix("." + base) else { continue }
                if hosts.insert(h).inserted { examples.append(m[1]) }
            }
        }
        guard hosts.count >= 1 else { return [] }
        return [Finding(
            title: "Third-party code runs in the user's browser",
            severity: hosts.count >= 6 ? .low : .info,
            category: "User View",
            location: pageURL.absoluteString,
            detail: "The page loads scripts/frames from \(hosts.count) external origin(s):\n" + hosts.sorted().prefix(12).map { "• \($0)" }.joined(separator: "\n") + "\n\nEach runs in the user's browser with access to the page (DOM, cookies the script can read, forms).",
            evidence: examples.prefix(8).joined(separator: "\n"),
            exploit: "Every third-party script is trusted to run as the site. If any is compromised or swapped (supply-chain / Magecart), it can read what the user types, steal tokens, or inject content - all from the user's own browser session.",
            remediation: "Minimize third-party scripts; pin them with Subresource Integrity (integrity=...), scope them with a strict CSP, and load them from as few origins as possible.",
            reference: "OWASP: Third-Party JavaScript Management")]
    }

    static func browserReachableEndpoints(_ paths: [URL], source: String) -> [Finding] {
        guard !paths.isEmpty else { return [] }
        let list = paths.prefix(25).map { "• \($0.path)\($0.query.map { "?\($0)" } ?? "")" }
        return [Finding(
            title: "API / internal endpoints reachable from the browser",
            severity: .info,
            category: "User View",
            location: source,
            detail: "Client code references \(paths.count) endpoint(s) a user can call directly (they show up in the Network tab / can be replayed from the console):\n" + list.joined(separator: "\n"),
            evidence: list.joined(separator: "\n"),
            exploit: "A user enumerates these from the shipped JS and calls each one with their own session - or unauthenticated - probing for endpoints that return data or accept actions the UI never exposed (hidden parameters, other users' IDs, admin-only calls).",
            remediation: "Every endpoint must authenticate and authorize independently of the UI. Assume the full list is public (it is - it's in the bundle) and that users will call each with arbitrary parameters.",
            reference: "OWASP API Security: Broken Object/Function Level Authorization")]
    }

    static func clickjacking(_ r: HTTPResponse) -> Finding? {

        guard r.contentType.lowercased().contains("html") else { return nil }
        let xfo = (r.header("x-frame-options") ?? "").lowercased()
        let csp = (r.header("content-security-policy") ?? "").lowercased()
        let hasXFO = xfo.contains("deny") || xfo.contains("sameorigin")
        let hasFA = csp.contains("frame-ancestors")
        guard !hasXFO, !hasFA else { return nil }
        return Finding(
            title: "Page can be framed (clickjacking / UI-redress)",
            severity: .low,
            category: "User View",
            location: r.finalURL.absoluteString,
            detail: "The page sets neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive, so any site can load it inside an invisible <iframe>.",
            evidence: "X-Frame-Options: \(r.header("x-frame-options") ?? "(none)")\nCSP frame-ancestors: \(hasFA ? "present" : "(none)")",
            exploit: "An attacker frames this page transparently over decoy content. The logged-in user thinks they are clicking the attacker's page but are really clicking buttons here - confirming actions, changing settings, or approving requests with their own session (clickjacking).",
            remediation: "Send `X-Frame-Options: DENY` (or SAMEORIGIN) and/or a CSP `frame-ancestors 'none'` (or 'self') on every HTML response, especially authenticated and state-changing pages.",
            reference: "CWE-1021: Improper Restriction of Rendered UI Layers (Clickjacking)")
    }

    static func sensitiveDataKeys(in body: String) -> [String] {
        let low = body.lowercased()

        guard low.contains("{") || low.contains("[") else { return [] }
        let keys = ["password", "passwd", "email", "e-mail", "ssn", "social_security",
                    "phone", "mobile", "address", "credit_card", "creditcard", "card_number",
                    "cvv", "iban", "api_key", "apikey", "secret", "token", "access_token",
                    "private_key", "auth", "session", "date_of_birth", "dob", "first_name",
                    "last_name", "full_name", "username", "user_id", "national_id", "passport"]
        var hits: [String] = []
        for k in keys where low.contains("\"\(k)\"") || low.contains("'\(k)'") {
            hits.append(k)
            if hits.count >= 12 { break }
        }
        return hits
    }

    static func unauthApiExposureFinding(endpoint: URL, keys: [String], response r: HTTPResponse) -> Finding {
        Finding(
            title: "Browser-called API returns user data without authentication: \(endpoint.path)",
            severity: .high,
            category: "User View",
            location: r.finalURL.absoluteString,
            detail: "An API endpoint the client JavaScript calls answered an anonymous request (HTTP \(r.status)) with a data payload containing sensitive field(s): \(keys.joined(separator: ", ")).",
            evidence: "URL: \(r.finalURL.absoluteString)\nHTTP \(r.status), \(r.body.count) bytes\nSensitive keys: \(keys.joined(separator: ", "))\nPreview: \(snippet(r.text, max: 220))",
            exploit: "A user (or anyone) reads the endpoint straight from the shipped JS and calls it with no credentials, pulling back personal data / secrets. This is broken object- or function-level authorization - the API trusts that only the UI would call it.",
            remediation: "Authenticate and authorize every API endpoint independently of the UI. Return only data the caller is entitled to, and treat the full endpoint list as public (it ships in the bundle).",
            reference: "OWASP API1/API2: Broken Object & Function Level Authorization")
    }

    static func confirmedIDORFinding(original: URL, neighbor: URL, response r: HTTPResponse) -> Finding {
        Finding(
            title: "Confirmed IDOR: adjacent object accessible: \(neighbor.path)\(neighbor.query.map { "?\($0)" } ?? "")",
            severity: .high,
            category: "User View",
            location: r.finalURL.absoluteString,
            detail: "The object reference was changed to an adjacent identifier and the server returned a different, valid record (HTTP \(r.status), \(r.body.count) bytes) instead of denying access. Original: \(original.absoluteString)",
            evidence: "Original:  \(original.absoluteString)\nTampered:  \(neighbor.absoluteString)\nHTTP \(r.status), \(r.body.count) bytes\nPreview: \(snippet(r.text, max: 200))",
            exploit: "A user simply increments/decrements the identifier and reads records belonging to other users or accounts - no authorization is enforced on the object. Iterating the ID enumerates the whole dataset.",
            remediation: "Enforce per-object authorization server-side on every request: verify the referenced object belongs to the authenticated user's account/tenant before returning it. Unguessable IDs help but are not sufficient alone.",
            reference: "CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)")
    }

    static func debugParamFinding(original: URL, tampered: URL, param: String, response r: HTTPResponse) -> Finding {
        Finding(
            title: "Response changes when the user adds &\(param)=",
            severity: .medium,
            category: "User View",
            location: r.finalURL.absoluteString,
            detail: "Adding the parameter `\(param)` to the request produced a materially different response (HTTP \(r.status), \(r.body.count) bytes), suggesting the server honours a client-supplied debug/privilege/mass-assignment parameter.",
            evidence: "Original:  \(original.absoluteString)\nWith param: \(tampered.absoluteString)\nHTTP \(r.status), \(r.body.count) bytes\nPreview: \(snippet(r.text, max: 200))",
            exploit: "A user appends the parameter (e.g. ?debug=true, ?admin=true, ?role=admin) and the server exposes extra data, debug internals, or grants elevated behaviour - a mass-assignment / hidden-parameter flaw the UI never advertised.",
            remediation: "Ignore unexpected request parameters. Never let client-supplied fields toggle debug output or privilege; bind request data to an explicit allow-list of fields and authorize server-side.",
            reference: "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes")
    }

    static func reachableRouteFinding(path: String, response r: HTTPResponse) -> Finding {
        Finding(
            title: "Privileged-looking route answers an anonymous user: /\(path)",
            severity: .low,
            category: "User View",
            location: r.finalURL.absoluteString,
            detail: "A route referenced in the client code and named like a privileged area (/\(path)) returned HTTP \(r.status), \(r.body.count) bytes to a logged-out request without redirecting to a login.",
            evidence: "URL: \(r.finalURL.absoluteString)\nHTTP \(r.status), \(r.body.count) bytes\nPreview: \(snippet(r.text, max: 180))",
            exploit: "If this route is meant for staff/authenticated users, a visitor reaches it (or the data/actions behind it) with no credentials. Confirm what it exposes - it may be an access-control gap or just a public page that happens to be named this way.",
            remediation: "Confirm the route's intended audience. If it is privileged, require authentication and authorization server-side; don't rely on the link being hidden from the UI.",
            reference: "CWE-425: Direct Request ('Forced Browsing')")
    }
}
