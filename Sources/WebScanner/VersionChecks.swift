import Foundation

enum VersionChecks {

    struct Ident: Equatable {
        var product: String
        var display: String
        var version: String?
    }

    static func idents(from raw: String) -> [Ident] {
        var out: [Ident] = []
        var seen = Set<String>()
        func add(_ display: String, _ version: String?) {
            let key = display.lowercased()
            let dedupe = "\(key)|\(version ?? "")"
            guard seen.insert(dedupe).inserted else { return }
            out.append(Ident(product: normalize(key), display: display, version: version))
        }

        if let m = firstMatch("OpenSSH[_/]([0-9][0-9A-Za-z._-]*)", in: raw) {
            add("OpenSSH", cleanVersion(m))
        }

        if let m = firstMatch("Jetty[ /(]([0-9][0-9A-Za-z._-]*)", in: raw) {
            add("Jetty", cleanVersion(m))
        }

        if let m = firstMatch("redis_version:([0-9][0-9A-Za-z._-]*)", in: raw) {
            add("Redis", cleanVersion(m))
        }

        for (name, ver) in matches("([A-Za-z][A-Za-z0-9._+-]{1,30})/([0-9][0-9A-Za-z._-]*)", in: raw) {
            add(name, cleanVersion(ver))
        }

        for (name, ver) in matches("\\b(ProFTPD|Pure-FTPd|vsFTPd|Exim|Postfix|Sendmail|MariaDB|MySQL|Microsoft-IIS|PHP|Jetty|WordPress|Drupal|Joomla|OpenSSL)[ /]([0-9][0-9A-Za-z._-]*)", in: raw) {
            add(name, cleanVersion(ver))
        }

        let lowered = raw.lowercased()
        if lowered.contains("mysql") || lowered.contains("mariadb")
            || firstMatch("[0-9]+\\.[0-9]+\\.[0-9]+-(?:log|mariadb|ubuntu|community|debian|el[0-9]|focal|jammy)", in: raw) != nil {
            if let m = firstMatch("([345678]\\.[0-9]+\\.[0-9]+)", in: raw), out.isEmpty {
                add(lowered.contains("mariadb") ? "MariaDB" : "MySQL", cleanVersion(m))
            }
        }

        return out
    }

    private static func normalize(_ product: String) -> String {
        let p = product.lowercased()
        if p.contains("iis") { return "iis" }
        if p == "apache" || p == "httpd" || p.hasPrefix("apache") { return "apache" }
        if p.contains("openssh") { return "openssh" }
        return p
    }

    static func fromHeaders(_ r: HTTPResponse) -> [Finding] {
        var out: [Finding] = []
        let loc = r.finalURL.absoluteString
        for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"] {
            guard let value = r.header(h) else { continue }
            for id in idents(from: value) {
                if let f = issueFinding(id, source: "\(h): \(value)", location: loc) {
                    out.append(f)
                }
            }
        }

        if let jv = r.header("x-jenkins") {
            let id = Ident(product: "jenkins", display: "Jenkins", version: cleanVersion(jv))
            if let f = issueFinding(id, source: "X-Jenkins: \(jv)", location: loc) {
                out.append(f)
            }
        }
        return out
    }

    static func fromHTML(_ html: String, location: String) -> [Finding] {
        let content = firstMatch("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", in: html)
            ?? firstMatch("<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator[\"']", in: html)
        guard let content else { return [] }
        var out: [Finding] = []
        for id in idents(from: content) {
            if let f = issueFinding(id, source: "<meta name=\"generator\">: \(snippet(content, max: 120))", location: location) {
                out.append(f)
            }
        }
        return out
    }

    static func fromBanner(_ banner: String, service: String, location: String) -> [Finding] {
        var out: [Finding] = []
        for id in idents(from: banner) {
            if let f = issueFinding(id, source: "Banner: \(snippet(banner, max: 160))", location: location) {
                out.append(f)
            }
        }
        return out
    }

    private struct Baseline {
        let display: String

        let eolBelow: String?

        let outdatedBelow: String?
        let note: String
        let reference: String
    }

    private static let baselines: [String: Baseline] = [
        "nginx": Baseline(display: "nginx", eolBelow: "1.24", outdatedBelow: "1.28",
            note: "Older nginx builds carry disclosed CVEs (request smuggling, resolver overflows, HTTP/2 rapid-reset, mp4-module CVE-2024-7347). The current stable branch is 1.28.",
            reference: "nginx security advisories"),
        "apache": Baseline(display: "Apache httpd", eolBelow: "2.4.0", outdatedBelow: "2.4.63",
            note: "The 2.2.x line is end-of-life; 2.4.x before recent patch releases is affected by the 2024 mod_proxy/mod_rewrite CVEs (CVE-2024-38473 et al., fixed in 2.4.60) and later fixes. Current release is 2.4.63+.",
            reference: "Apache httpd security reports"),
        "openssh": Baseline(display: "OpenSSH", eolBelow: "8.0", outdatedBelow: "9.9",
            note: "Older OpenSSH is affected by disclosed CVEs: CVE-2023-38408 (ssh-agent PKCS#11 RCE, fixed 9.3p2), CVE-2024-6387 'regreSSHion' (fixed 9.8p1), and CVE-2025-26465 (client MitM, fixed 9.9p2). Current release is 10.0p1.",
            reference: "OpenSSH release notes"),
        "openssl": Baseline(display: "OpenSSL", eolBelow: "3.0.0", outdatedBelow: "3.2",
            note: "OpenSSL 1.1.1 (EOL Sept 2023) and 1.0.2 are end-of-life and unpatched; the 3.0 LTS branch reaches EOL in Sept 2026. Prefer the 3.5 LTS series and apply fixes such as CVE-2024-6119.",
            reference: "OpenSSL security policy"),
        "php": Baseline(display: "PHP", eolBelow: "8.2", outdatedBelow: "8.3",
            note: "PHP 8.1 and earlier are end-of-life (8.1 ended Dec 2025) and receive no security fixes; 8.2 is in security-only support. Current active branches are 8.3/8.4.",
            reference: "php.net supported versions"),
        "iis": Baseline(display: "Microsoft IIS", eolBelow: "10.0", outdatedBelow: nil,
            note: "IIS below 10.0 ships only on end-of-life Windows Server releases (Server 2012 / 2012 R2 reached EOL in Oct 2023). IIS 10.0 covers Server 2016 through 2025.",
            reference: "Microsoft lifecycle"),
        "mysql": Baseline(display: "MySQL", eolBelow: "8.0", outdatedBelow: "8.4",
            note: "MySQL 5.7 and earlier are end-of-life (5.7 ended Oct 2023). The 8.0 series is superseded by the 8.4 LTS; migrate and keep patched.",
            reference: "Oracle MySQL lifecycle"),
        "mariadb": Baseline(display: "MariaDB", eolBelow: "10.6", outdatedBelow: "11.4",
            note: "MariaDB branches below 10.6 are end-of-life (10.5 ended June 2025); 11.4 is the current LTS series.",
            reference: "MariaDB maintenance policy"),
        "exim": Baseline(display: "Exim", eolBelow: "4.94", outdatedBelow: "4.98",
            note: "Older Exim is affected by critical CVEs: CVE-2019-10149 'Return of the WIZard' (fixed 4.92) and the 2023 ZDI chain (CVE-2023-42115 et al., fixed 4.96.1/4.97). Current release is 4.98.",
            reference: "Exim security"),
        "proftpd": Baseline(display: "ProFTPD", eolBelow: "1.3.6", outdatedBelow: "1.3.8",
            note: "ProFTPD before 1.3.6/1.3.8 has disclosed RCE / copy-module CVEs.",
            reference: "ProFTPD advisories"),
        "vsftpd": Baseline(display: "vsftpd", eolBelow: "2.3.5", outdatedBelow: "3.0.5",
            note: "vsftpd 2.3.4 famously shipped a backdoor; verify the build.",
            reference: "vsftpd changelog"),
        "wordpress": Baseline(display: "WordPress", eolBelow: "6.0", outdatedBelow: "6.7",
            note: "Outdated WordPress core is a leading breach vector; keep core and plugins current. Recent releases are in the 6.7/6.8 range.",
            reference: "WordPress releases"),
        "drupal": Baseline(display: "Drupal", eolBelow: "10.0", outdatedBelow: "10.3",
            note: "Drupal 7 (EOL Jan 2025), 8 and 9 (EOL Nov 2023) are end-of-life; unpatched core is a frequent breach vector (the 'Drupalgeddon' SA-CORE RCE CVEs). Current branches are 10.x/11.x.",
            reference: "Drupal security advisories"),
        "joomla": Baseline(display: "Joomla", eolBelow: "5.0", outdatedBelow: "5.2",
            note: "Joomla 3.x (EOL Aug 2023) and 4.x (EOL Oct 2024) are end-of-life; older cores carry disclosed SQLi/RCE CVEs (e.g. CVE-2023-23752). Current branch is 5.x.",
            reference: "Joomla security centre"),
        "tomcat": Baseline(display: "Apache Tomcat", eolBelow: "9.0", outdatedBelow: "10.1",
            note: "Tomcat 7/8 are end-of-life (8.5 ended March 2024); older builds carry disclosed CVEs (AJP 'Ghostcat' CVE-2020-1938, partial-PUT RCE CVE-2025-24813). Current branches are 10.1/11.0.",
            reference: "Apache Tomcat security"),
        "lighttpd": Baseline(display: "lighttpd", eolBelow: "1.4.60", outdatedBelow: "1.4.76",
            note: "Older lighttpd builds have disclosed CVEs; keep to a current 1.4.x release.",
            reference: "lighttpd advisories"),
        "openresty": Baseline(display: "OpenResty", eolBelow: "1.21.4", outdatedBelow: "1.25.3",
            note: "OpenResty bundles a fixed nginx core plus LuaJIT; older bundles ship the nginx CVEs of their era (request smuggling, resolver overflows, HTTP/2 issues). Current bundles track nginx 1.27.x.",
            reference: "OpenResty release notes"),
        "gunicorn": Baseline(display: "Gunicorn", eolBelow: "20.0", outdatedBelow: "22.0",
            note: "Gunicorn before 22.0.0 is affected by CVE-2024-1135 (improper Transfer-Encoding handling enabling HTTP request smuggling). A version in the Server header also confirms the WSGI backend.",
            reference: "Gunicorn security advisories"),
        "miniserv": Baseline(display: "Webmin (MiniServ)", eolBelow: "1.930", outdatedBelow: "2.100",
            note: "Webmin's MiniServ server reports the Webmin version in the Server header; builds below 1.930 are affected by CVE-2019-15107 (unauthenticated RCE in password_change.cgi), and below 1.990 by CVE-2022-0824 (post-auth RCE).",
            reference: "Webmin security advisories"),
        "werkzeug": Baseline(display: "Werkzeug", eolBelow: "2.0", outdatedBelow: "3.0.3",
            note: "A Werkzeug version in the Server header means a Flask/Werkzeug app, often the built-in development server, which must not face production. Builds below 3.0.3 are affected by CVE-2024-34069 (debugger PIN RCE when debug mode is on) and earlier multipart-DoS CVEs.",
            reference: "Werkzeug/Pallets security advisories"),
        "jetty": Baseline(display: "Eclipse Jetty", eolBelow: "10.0", outdatedBelow: "12.0",
            note: "Jetty 9.x is end-of-life (community support ended June 2022); older builds carry disclosed CVEs (HTTP/2 rapid reset CVE-2023-44487, HPACK integer overflow CVE-2023-36478). Current branch is 12.0.",
            reference: "Eclipse Jetty security advisories"),
        "jenkins": Baseline(display: "Jenkins", eolBelow: "2.400", outdatedBelow: "2.462",
            note: "Jenkins exposes its version in the X-Jenkins response header. Builds below LTS 2.426.3 are affected by CVE-2024-23897 (unauthenticated arbitrary file read via the CLI), commonly chained to RCE. Keep to a current LTS line.",
            reference: "Jenkins security advisories"),
        "redis": Baseline(display: "Redis", eolBelow: "6.2", outdatedBelow: "7.2",
            note: "Older Redis carries disclosed CVEs, including Lua-based RCE/DoS (CVE-2022-24834 cjson heap overflow, CVE-2024-31449 bit-library stack overflow). An exposed, versioned Redis compounds the critical no-auth exposure already flagged on port 6379.",
            reference: "Redis security advisories"),
    ]

    private static func issueFinding(_ id: Ident, source: String, location: String) -> Finding? {
        guard let version = id.version,
              let baseline = baselines[id.product] else { return nil }

        let parsed = parseVersion(version)
        guard !parsed.isEmpty else { return nil }

        var severity: Severity?
        var status = ""
        if let eol = baseline.eolBelow, compareVersion(parsed, parseVersion(eol)) < 0 {
            severity = .medium
            status = "end-of-life"
        } else if let old = baseline.outdatedBelow, compareVersion(parsed, parseVersion(old)) < 0 {
            severity = .low
            status = "outdated"
        }
        guard let sev = severity else { return nil }

        return Finding(
            title: "\(status.capitalized) \(baseline.display) \(version)",
            severity: sev,
            category: "Outdated Software",
            location: location,
            detail: "The target appears to run \(baseline.display) \(version), which is \(status). \(baseline.note)",
            evidence: source,
            exploit: "Attackers map the disclosed version to public CVEs and exploit code for that release. Running \(status) software means known, documented vulnerabilities may be exploitable without any custom research.",
            remediation: "Upgrade \(baseline.display) to a current, supported release and apply security updates promptly. If the version banner is inaccurate (back-ported patches), suppress it to avoid handing attackers a target list.",
            reference: baseline.reference,
            reproduction: "searchsploit \(baseline.display) \(version)   # list public exploits for this version")
    }

    private static func parseVersion(_ v: String) -> [Int] {
        v.split(whereSeparator: { $0 == "." || $0 == "-" || $0 == "p" || $0 == "_" })
            .prefix(4)
            .compactMap { Int($0.prefix(while: { $0.isNumber })) }
    }

    private static func compareVersion(_ a: [Int], _ b: [Int]) -> Int {
        let n = Swift.max(a.count, b.count)
        for i in 0..<n {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x < y ? -1 : 1 }
        }
        return 0
    }

    private static func cleanVersion(_ v: String) -> String? {
        let trimmed = v.trimmingCharacters(in: CharacterSet(charactersIn: " \t\r\n"))
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let ns = text as NSString
        guard let m = re.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges > 1 else { return nil }
        return ns.substring(with: m.range(at: 1))
    }

    private static func matches(_ pattern: String, in text: String) -> [(String, String)] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        var out: [(String, String)] = []
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) where m.numberOfRanges > 2 {
            out.append((ns.substring(with: m.range(at: 1)), ns.substring(with: m.range(at: 2))))
        }
        return out
    }
}
