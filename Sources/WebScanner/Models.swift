import Foundation

enum Severity: String, CaseIterable, Codable, Comparable {
    case critical
    case high
    case medium
    case low
    case info

    var rank: Int {
        switch self {
        case .critical: return 0
        case .high:     return 1
        case .medium:   return 2
        case .low:      return 3
        case .info:     return 4
        }
    }

    var label: String { rawValue.capitalized }

    var symbol: String {
        switch self {
        case .critical: return "exclamationmark.octagon.fill"
        case .high:     return "exclamationmark.triangle.fill"
        case .medium:   return "exclamationmark.circle.fill"
        case .low:      return "info.circle.fill"
        case .info:     return "checkmark.circle"
        }
    }

    static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

struct Finding: Identifiable, Codable, Equatable {
    var id = UUID()
    var title: String
    var severity: Severity
    var category: String

    var location: String

    var detail: String

    var evidence: String

    var exploit: String

    var remediation: String

    var reference: String?

    var reproduction: String? = nil

    var capturedContent: String? = nil

    var dedupeKey: String { "\(title)::\(location)" }

    static func == (lhs: Finding, rhs: Finding) -> Bool { lhs.dedupeKey == rhs.dedupeKey }
}

enum ScanIntensity: String, CaseIterable, Identifiable, Codable {
    case quick
    case standard
    case deep
    case aggressive
    case maximum

    var id: String { rawValue }

    var label: String {
        switch self {
        case .quick:      return "Quick"
        case .standard:   return "Standard"
        case .deep:       return "Deep"
        case .aggressive: return "Aggressive"
        case .maximum:    return "Max"
        }
    }

    var blurb: String {
        switch self {
        case .quick:      return "Homepage headers, TLS & top secret files only."
        case .standard:   return "Full sensitive-file probe + homepage secret scan."
        case .deep:       return "Crawls the site & scripts, source maps, robots/sitemap, forms, GraphQL/API docs, SRI, CRLF, HTTP TRACE, per-page cookie/caching hygiene, plus active injection probes over both link and search-form parameters: SQLi, SSTI, command injection, SSRF, path traversal & reflected XSS (with context)."
        case .aggressive: return "Deep + path brute-force, backup-name guessing, POST-form XSS on search forms, extra CORS origin-bypass checks, and subdomain discovery + takeover. Noisier - use only with permission."
        case .maximum:    return "Everything, cranked up: deep crawl, second-wave JS chunk scanning, exhaustive .env hunt, wide subdomain enumeration + takeover, and blind SQLi (boolean + time-based). Slowest & noisiest - explicit permission only."
        }
    }

    var maxPages: Int {
        switch self {
        case .quick, .standard: return 1
        case .deep:             return 60
        case .aggressive:       return 90
        case .maximum:          return 200
        }
    }

    var maxDepth: Int {
        switch self {
        case .quick, .standard: return 0
        case .deep:             return 2
        case .aggressive:       return 3
        case .maximum:          return 4
        }
    }

    var maxScripts: Int {
        switch self {
        case .quick:      return 5
        case .standard:   return 25
        case .deep:       return 100
        case .aggressive: return 140
        case .maximum:    return 300
        }
    }

    var maxEnvDirs: Int {
        switch self {
        case .maximum:    return 120
        case .aggressive: return 60
        default:          return 30
        }
    }
    var maxEnvProbes: Int {
        switch self {
        case .maximum:    return 900
        case .aggressive: return 400
        default:          return 220
        }
    }

    var maxJSPathProbes: Int {
        switch self {
        case .maximum:    return 120
        case .aggressive: return 60
        default:          return 30
        }
    }

    var scanAllAssets: Bool { self != .quick }

    var maxAssets: Int {
        switch self {
        case .quick:      return 0
        case .standard:   return 20
        case .deep:       return 120
        case .aggressive: return 160
        case .maximum:    return 400
        }
    }

    var followJSChunks: Bool { self == .deep || self == .aggressive || self == .maximum }
    var maxSecondWaveScripts: Int {
        switch self {
        case .maximum:    return 200
        case .aggressive: return 90
        case .deep:       return 60
        default:          return 0
        }
    }

    var probeSensitiveFiles: Bool { self != .quick }
    var crawlSite: Bool { self == .deep || self == .aggressive || self == .maximum }

    var testAccessControl: Bool { self == .deep || self == .aggressive || self == .maximum }

    var maxAuthCandidates: Int {
        switch self {
        case .maximum:    return 40
        case .aggressive: return 26
        default:          return 14
        }
    }
    var fetchSourceMaps: Bool { self == .deep || self == .aggressive || self == .maximum }
    var analyzeForms: Bool { self == .deep || self == .aggressive || self == .maximum }
    var probeApiSurface: Bool { self == .deep || self == .aggressive || self == .maximum }
    var parseRobotsSitemap: Bool { self != .quick }
    var bruteForcePaths: Bool { self == .aggressive || self == .maximum }
    var guessBackupNames: Bool { self == .aggressive || self == .maximum }

    var probeHTTPMethods: Bool { self != .quick }

    var detectServerErrors: Bool { self != .quick }

    var testInjection: Bool { self == .deep || self == .aggressive || self == .maximum }

    var maxInjectionTargets: Int {
        switch self {
        case .maximum:    return 40
        case .aggressive: return 20
        default:          return 14
        }
    }

    var checkSRI: Bool { self == .deep || self == .aggressive || self == .maximum }

    var testCRLF: Bool { self == .deep || self == .aggressive || self == .maximum }

    var enumerateSubdomains: Bool { self == .aggressive || self == .maximum }
    var maxSubdomains: Int {
        switch self {
        case .maximum:    return 160
        case .aggressive: return 70
        default:          return 0
        }
    }

    var checkTLSVersions: Bool { self != .quick }

    var sweepPorts: Bool { self == .aggressive || self == .maximum }
}

enum ScanMode: String, CaseIterable, Identifiable, Codable {

    case fullAudit

    case siteScan

    case contentDiscovery

    case urlMask

    case portScan

    case database

    case hostScan

    case info

    case performance

    case userView

    var id: String { rawValue }

    var label: String {
        switch self {
        case .fullAudit:        return "Full Audit"
        case .siteScan:         return "Site Scan"
        case .contentDiscovery: return "Content Discovery"
        case .urlMask:          return "URL Mask"
        case .portScan:         return "Port Scan"
        case .database:         return "Database"
        case .hostScan:         return "Host"
        case .info:             return "Info"
        case .performance:      return "Performance"
        case .userView:         return "User View"
        }
    }

    var blurb: String {
        switch self {
        case .fullAudit:
            return "Runs every category against one host at MAXIMUM depth, back-to-back - Info, Performance, Host, Database, the full Site vulnerability assessment (deep crawl, wide subdomain enum, blind SQLi, exhaustive .env hunt), Content Discovery, and a complete sweep of all 65,535 TCP ports with banner grabbing - producing one combined report. The most exhaustive scan; very slow (can take 20-40+ minutes) and noisy, so use only with permission. (URL Mask is skipped - it needs a URL template, not a host.)"
        case .siteScan:
            return "Full vulnerability assessment: headers, TLS, secrets, injection, access control, subdomains + a risky-port sweep."
        case .contentDiscovery:
            return "Brute-force directories & files from a wordlist. Discovers directories, recurses, fuzzes extensions, scrapes titles, and flags open directories."
        case .urlMask:
            return "Generate URLs from a template with wildcards ( ? * [a-z] {n,m} (a,b,c) $ ) and probe each one."
        case .portScan:
            return "Scan TCP ports on the host, identify the service on each open port, grab banners, and flag risky exposures (databases, RDP, Telnet, Docker, …)."
        case .database:
            return "Hunt for database problems: exposed DB/cache/queue services (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch …), unauthenticated data access, web admin tools (phpMyAdmin, Adminer …), leaked SQL dumps & SQLite files, plus SQL-error disclosure and injection surface."
        case .hostScan:
            return "Profile the host / VPS: resolved IP(s), reverse DNS, hosting provider & ASN, geolocation, CDN/WAF, server & OS stack — plus TLS, software-version and exposed-service vulnerabilities."
        case .info:
            return "Quick read-only overview: page title & technologies, server stack, resolved IP(s), reverse DNS, hosting provider/ASN, CDN/WAF, DNS/email records, plus a quick check of common service ports (MySQL, PostgreSQL, SSH, RDP, …)."
        case .performance:
            return "Measure load speed: server response time (TTFB), DNS/TCP/TLS setup, HTTP protocol & TLS version, text compression, page weight and render-blocking resources - with concrete ways to make it faster."
        case .userView:
            return "Attack the site the way a real signed-up user would - then actually try the exploits. Passive: open self-registration, hidden/disabled/readonly fields (price, role, isAdmin, qty…) you can flip in DevTools, client-side-only validation, role/feature flags and auth tokens the browser can read & edit, JS-readable cookies, secrets & JWTs in the bundle, and the browser-reachable API surface. Active (read-only/​safe): on the parameters and API endpoints a visitor controls it fires reflected XSS, open redirect, SQL-injection & error disclosure, path traversal, confirmed IDOR (fetches an adjacent object and diffs), mass-assignment / debug-parameter tampering, CORS credential-reflection, GraphQL introspection, clickjacking, access-control bypass (path/header tricks) against gated admin routes, and hits the browser-called APIs anonymously to catch ones that hand back user data without auth. Everything a user could do with DevTools and the Network tab - no server break-in."
        }
    }
}

enum PortProfile: String, CaseIterable, Identifiable, Codable {
    case fast
    case top100
    case extended
    case full
    case custom

    var id: String { rawValue }

    var label: String {
        switch self {
        case .fast:     return "Fast"
        case .top100:   return "Top 100"
        case .extended: return "Extended"
        case .full:     return "Full"
        case .custom:   return "Custom"
        }
    }

    var blurb: String {
        switch self {
        case .fast:     return "\(PortCatalog.fast.count) ports that are almost always listening - a few seconds."
        case .top100:   return "Nmap's most-common set - \(PortCatalog.top100.count) ports."
        case .extended: return "\(PortCatalog.extended.count) well-known, registered and service-catalog ports."
        case .full:     return "Every port 1-65535 - thorough but slow & noisy."
        case .custom:   return "Your own list, e.g. 22,80,443,8000-8100."
        }
    }
}

struct DiscoveredURL: Identifiable, Codable, Equatable {
    var id = UUID()
    var url: String
    var status: Int
    var length: Int
    var contentType: String
    var title: String?
    var kind: Kind

    var notable: Bool = false

    enum Kind: String, Codable {
        case page
        case directory
        case openDirectory
        case file
        case mismatch
        case defaultFile

        var label: String {
            switch self {
            case .page:          return "PAGE"
            case .directory:     return "DIR"
            case .openDirectory: return "OPEN DIR"
            case .file:          return "FILE"
            case .mismatch:      return "MISMATCH"
            case .defaultFile:   return "DEFAULT"
            }
        }
    }

    static func == (lhs: DiscoveredURL, rhs: DiscoveredURL) -> Bool { lhs.url == rhs.url }
}

struct ScanReport: Codable {
    var target: String
    var finalURL: String
    var startedAt: Date
    var finishedAt: Date
    var findings: [Finding]

    var counts: [Severity: Int] {
        var c: [Severity: Int] = [:]
        for f in findings { c[f.severity, default: 0] += 1 }
        return c
    }

    var grade: String {
        let c = counts
        if (c[.critical] ?? 0) > 0 { return "F" }
        if (c[.high] ?? 0) >= 2    { return "D" }
        if (c[.high] ?? 0) == 1    { return "C" }
        if (c[.medium] ?? 0) >= 3  { return "C" }
        if (c[.medium] ?? 0) >= 1  { return "B" }
        if (c[.low] ?? 0) >= 1      { return "A-" }
        return "A"
    }
}
