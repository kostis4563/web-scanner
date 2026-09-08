import Foundation

enum CustomDetections {
    struct LoadReport {
        let url: URL
        let created: Bool
        let contentCount: Int
        let pathCount: Int
        let warnings: [String]
    }

    private enum MatchType {
        case contains
        case regex
    }

    private struct ContentRule {
        let id: String
        let title: String
        let severity: Severity
        let category: String
        let matchType: MatchType
        let pattern: String
        let caseSensitive: Bool
        let regex: NSRegularExpression?
        let redactMatch: Bool
        let detail: String
        let exploit: String
        let remediation: String
        let reference: String?
    }

    private struct ParsedConfig {
        let contentRules: [ContentRule]
        let pathRules: [SensitivePath]
        let warnings: [String]
    }

    private struct ConfigFile: Decodable {
        let version: Int
        var contentDetections: [Lossy<ContentEntry>]?
        var pathDetections: [Lossy<PathEntry>]?
    }

    private struct Lossy<Value: Decodable>: Decodable {
        let value: Value?

        init(from decoder: Decoder) throws {
            value = try? Value(from: decoder)
        }
    }

    private struct ContentEntry: Decodable {
        var id: String?
        var enabled: Bool?
        var title: String?
        var severity: String?
        var category: String?
        var matchType: String?
        var pattern: String?
        var caseSensitive: Bool?
        var redactMatch: Bool?
        var detail: String?
        var exploit: String?
        var remediation: String?
        var reference: String?
    }

    private struct PathEntry: Decodable {
        var id: String?
        var enabled: Bool?
        var path: String?
        var title: String?
        var severity: String?
        var category: String?
        var bodyContainsAny: [String]?
        var bodyRegex: String?
        var bodyMustNotContain: [String]?
        var allowAnyBody: Bool?
        var scanForSecrets: Bool?
        var exploit: String?
        var remediation: String?
        var reference: String?
    }

    enum ConfigError: LocalizedError {
        case unsupportedVersion(Int)
        case unreadable(String)

        var errorDescription: String? {
            switch self {
            case .unsupportedVersion(let version):
                return "Unsupported detections.json version \(version); this app supports version 1."
            case .unreadable(let message):
                return message
            }
        }
    }

    private(set) static var pathRules: [SensitivePath] = []
    private static var contentRules: [ContentRule] = []

    static var configURL: URL {
        if let override = ProcessInfo.processInfo.environment["WEBSCANNER_DETECTIONS_FILE"]?
            .trimmingCharacters(in: .whitespacesAndNewlines), !override.isEmpty {
            return URL(fileURLWithPath: override).standardizedFileURL
        }
        let root = FileManager.default.urls(for: .applicationSupportDirectory,
                                             in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support", isDirectory: true)
        return root.appendingPathComponent("WebScanner", isDirectory: true)
            .appendingPathComponent("detections.json")
    }

    @discardableResult
    static func ensureConfigFile() throws -> (url: URL, created: Bool) {
        let url = configURL
        if FileManager.default.fileExists(atPath: url.path) { return (url, false) }

        if ProcessInfo.processInfo.environment["WEBSCANNER_DETECTIONS_FILE"] != nil {
            throw ConfigError.unreadable("WEBSCANNER_DETECTIONS_FILE does not exist: \(url.path)")
        }

        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try starterData().write(to: url, options: .atomic)
        return (url, true)
    }

    static func reload() -> LoadReport {
        contentRules = []
        pathRules = []
        let url = configURL
        do {
            let ensured = try ensureConfigFile()
            let parsed = try parse(Data(contentsOf: ensured.url))
            contentRules = parsed.contentRules
            pathRules = parsed.pathRules
            return LoadReport(url: ensured.url, created: ensured.created,
                              contentCount: contentRules.count, pathCount: pathRules.count,
                              warnings: parsed.warnings)
        } catch {
            return LoadReport(url: url, created: false, contentCount: 0, pathCount: 0,
                              warnings: [error.localizedDescription])
        }
    }

    private static func parse(_ data: Data) throws -> ParsedConfig {
        let file: ConfigFile
        do {
            file = try JSONDecoder().decode(ConfigFile.self, from: data)
        } catch {
            throw ConfigError.unreadable("Could not read detections.json: \(error.localizedDescription)")
        }
        guard file.version == 1 else { throw ConfigError.unsupportedVersion(file.version) }

        var content: [ContentRule] = []
        var paths: [SensitivePath] = []
        var warnings: [String] = []
        var seenIDs = Set<String>()

        for (index, wrapped) in (file.contentDetections ?? []).prefix(500).enumerated() {
            guard let entry = wrapped.value else {
                warnings.append("contentDetections[\(index)] was skipped: expected a JSON object with correctly typed fields.")
                continue
            }
            guard entry.enabled ?? true else { continue }
            let label = "contentDetections[\(index)]"
            guard let id = nonEmpty(entry.id) else {
                warnings.append("\(label) was skipped: missing id.")
                continue
            }
            guard seenIDs.insert(id.lowercased()).inserted else {
                warnings.append("\(label) was skipped: duplicate id '\(id)'.")
                continue
            }
            guard let title = nonEmpty(entry.title), let pattern = nonEmpty(entry.pattern) else {
                warnings.append("\(label) ('\(id)') was skipped: title and pattern are required.")
                continue
            }
            guard pattern.count <= 10_000 else {
                warnings.append("\(label) ('\(id)') was skipped: pattern is longer than 10,000 characters.")
                continue
            }
            guard let severity = severity(entry.severity, label: label, warnings: &warnings) else { continue }

            let kind: MatchType
            let compiled: NSRegularExpression?
            switch (entry.matchType ?? "contains").lowercased() {
            case "contains":
                kind = .contains
                compiled = nil
            case "regex":
                kind = .regex
                do {
                    compiled = try NSRegularExpression(
                        pattern: pattern,
                        options: (entry.caseSensitive ?? false) ? [] : [.caseInsensitive])
                } catch {
                    warnings.append("\(label) ('\(id)') was skipped: invalid regex (\(error.localizedDescription)).")
                    continue
                }
            default:
                warnings.append("\(label) ('\(id)') was skipped: matchType must be 'contains' or 'regex'.")
                continue
            }

            content.append(ContentRule(
                id: id,
                title: title,
                severity: severity,
                category: nonEmpty(entry.category) ?? "Custom Detection",
                matchType: kind,
                pattern: pattern,
                caseSensitive: entry.caseSensitive ?? false,
                regex: compiled,
                redactMatch: entry.redactMatch ?? false,
                detail: nonEmpty(entry.detail) ?? "A user-configured content rule ('\(id)') matched this response.",
                exploit: nonEmpty(entry.exploit) ?? "Review the matched content and determine whether it exposes information or behavior an attacker could use.",
                remediation: nonEmpty(entry.remediation) ?? "Remove or protect the matched content if it should not be publicly reachable.",
                reference: nonEmpty(entry.reference)))
        }
        if (file.contentDetections?.count ?? 0) > 500 {
            warnings.append("Only the first 500 content detections were loaded.")
        }

        for (index, wrapped) in (file.pathDetections ?? []).prefix(500).enumerated() {
            guard let entry = wrapped.value else {
                warnings.append("pathDetections[\(index)] was skipped: expected a JSON object with correctly typed fields.")
                continue
            }
            guard entry.enabled ?? true else { continue }
            let label = "pathDetections[\(index)]"
            guard let id = nonEmpty(entry.id) else {
                warnings.append("\(label) was skipped: missing id.")
                continue
            }
            guard seenIDs.insert(id.lowercased()).inserted else {
                warnings.append("\(label) was skipped: duplicate id '\(id)'.")
                continue
            }
            guard var path = nonEmpty(entry.path), let title = nonEmpty(entry.title) else {
                warnings.append("\(label) ('\(id)') was skipped: path and title are required.")
                continue
            }
            while path.hasPrefix("/") { path.removeFirst() }
            guard !path.isEmpty, !path.contains("://"), !path.contains("#"),
                  !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                warnings.append("\(label) ('\(id)') was skipped: path must be a relative URL path on the scanned host.")
                continue
            }
            guard let severity = severity(entry.severity, label: label, warnings: &warnings) else { continue }

            let contains = (entry.bodyContainsAny ?? [])
                .compactMap(nonEmpty)
            let bodyRegex = nonEmpty(entry.bodyRegex)
            let allowAny = entry.allowAnyBody ?? false
            if contains.isEmpty && bodyRegex == nil && !allowAny {
                warnings.append("\(label) ('\(id)') was skipped: add bodyContainsAny/bodyRegex, or set allowAnyBody to true.")
                continue
            }
            if let bodyRegex {
                do {
                    _ = try NSRegularExpression(pattern: bodyRegex)
                } catch {
                    warnings.append("\(label) ('\(id)') was skipped: invalid bodyRegex (\(error.localizedDescription)).")
                    continue
                }
            }

            paths.append(SensitivePath(
                path, title, severity,
                category: nonEmpty(entry.category) ?? "Custom Detection",
                mustContain: contains,
                regex: bodyRegex,
                mustNotContain: entry.bodyMustNotContain ?? ["<!doctype html", "<html"],
                scanForSecrets: entry.scanForSecrets ?? false,
                exploit: nonEmpty(entry.exploit) ?? "The configured path returned content matching a user-defined sensitive signature.",
                remediation: nonEmpty(entry.remediation) ?? "Remove this file or endpoint from public access, or require appropriate authentication.",
                reference: nonEmpty(entry.reference)))
        }
        if (file.pathDetections?.count ?? 0) > 500 {
            warnings.append("Only the first 500 path detections were loaded.")
        }

        return ParsedConfig(contentRules: content, pathRules: paths, warnings: warnings)
    }

    static func scanContent(_ text: String, source: String) -> [Finding] {
        guard !contentRules.isEmpty, !text.isEmpty else { return [] }
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)
        var out: [Finding] = []

        for rule in contentRules {
            let range: NSRange?
            switch rule.matchType {
            case .contains:
                let options: NSString.CompareOptions = rule.caseSensitive ? [] : [.caseInsensitive]
                let found = ns.range(of: rule.pattern, options: options, range: full)
                range = found.location == NSNotFound ? nil : found
            case .regex:
                range = rule.regex?.firstMatch(in: text, range: full)?.range
            }
            guard let range, range.location != NSNotFound,
                  range.location + range.length <= ns.length else { continue }

            let matched = ns.substring(with: range)
            let evidence: String
            if rule.redactMatch && !SecretScanner.revealSecrets {
                evidence = "Configured rule: \(rule.id)\nMatched value: \(redact(matched))"
            } else {
                let start = max(0, range.location - 40)
                let length = min(ns.length - start, range.length + 80)
                let context = length > 0 ? ns.substring(with: NSRange(location: start, length: length)) : matched
                evidence = "Configured rule: \(rule.id)\nContext: ...\(snippet(context, max: 220))..."
            }

            out.append(Finding(
                title: rule.title,
                severity: rule.severity,
                category: rule.category,
                location: source,
                detail: rule.detail,
                evidence: evidence,
                exploit: rule.exploit,
                remediation: rule.remediation,
                reference: rule.reference))
        }
        return out
    }

    private static func severity(_ raw: String?, label: String,
                                 warnings: inout [String]) -> Severity? {
        let value = (nonEmpty(raw) ?? "medium").lowercased()
        guard let result = Severity(rawValue: value) else {
            warnings.append("\(label) was skipped: severity must be critical, high, medium, low, or info.")
            return nil
        }
        return result
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else { return nil }
        return trimmed
    }

    private static func starterData() throws -> Data {
        let candidates: [URL?] = [
            Bundle.main.url(forResource: "detections", withExtension: "json"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("Resources/detections.json"),
        ]
        for candidate in candidates.compactMap({ $0 })
            where FileManager.default.fileExists(atPath: candidate.path) {
            return try Data(contentsOf: candidate)
        }
        guard let data = fallbackStarter.data(using: .utf8) else {
            throw ConfigError.unreadable("Could not create the starter detections.json file.")
        }
        return data
    }

    private static let fallbackStarter = """
    {
      "version": 1,
      "contentDetections": [],
      "pathDetections": []
    }
    """
}
