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
        case .deep:       return "Crawls the site: every page & script, source maps, robots/sitemap, forms, GraphQL & API docs, SRI, CRLF & injection probes."
        case .aggressive: return "Deep + path brute-force, backup-name guessing, and subdomain discovery + takeover checks. Noisier - use only with permission."
        case .maximum:    return "Everything, cranked up: deep crawl, second-wave JS chunk scanning, exhaustive .env hunt, and wide subdomain enumeration + takeover. Slowest & noisiest - explicit permission only."
        }
    }

    var maxPages: Int {
        switch self {
        case .quick, .standard: return 1
        case .deep:             return 40
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
        case .deep:       return 70
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
        case .deep:       return 80
        case .aggressive: return 160
        case .maximum:    return 400
        }
    }

    var followJSChunks: Bool { self == .deep || self == .aggressive || self == .maximum }
    var maxSecondWaveScripts: Int {
        switch self {
        case .maximum:    return 200
        case .aggressive: return 90
        case .deep:       return 40
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
        default:          return 10
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
}

/// What the scanner does when you press Scan.
enum ScanMode: String, CaseIterable, Identifiable, Codable {
    /// The full vulnerability assessment (the app's original behavior).
    case siteScan
    /// Wordlist-driven directory/file brute-forcing (port of `scaner.py`).
    case contentDiscovery
    /// URL-mask generation + probing (port of `scanurls.py`).
    case urlMask

    var id: String { rawValue }

    var label: String {
        switch self {
        case .siteScan:         return "Site Scan"
        case .contentDiscovery: return "Content Discovery"
        case .urlMask:          return "URL Mask"
        }
    }

    var blurb: String {
        switch self {
        case .siteScan:
            return "Full vulnerability assessment: headers, TLS, secrets, injection, access control, subdomains."
        case .contentDiscovery:
            return "Brute-force directories & files from a wordlist. Discovers directories, recurses, fuzzes extensions, scrapes titles, and flags open directories."
        case .urlMask:
            return "Generate URLs from a template with wildcards ( ? * [a-z] {n,m} (a,b,c) $ ) and probe each one."
        }
    }
}

/// One reachable URL found during content discovery or URL-mask scanning.
/// This is the raw "hit list" (like the Python scanner's console output),
/// separate from security Findings.
struct DiscoveredURL: Identifiable, Codable, Equatable {
    var id = UUID()
    var url: String
    var status: Int
    var length: Int
    var contentType: String
    var title: String?
    var kind: Kind
    /// Whether this hit is notable (open directory, MIME mismatch, or secret-bearing).
    var notable: Bool = false

    enum Kind: String, Codable {
        case page          // an HTML page
        case directory     // a reachable directory
        case openDirectory // directory with auto-index enabled
        case file          // a non-HTML file
        case mismatch      // Content-Type disagrees with the file extension
        case defaultFile   // index.html / index.php / default.aspx inside a dir

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
