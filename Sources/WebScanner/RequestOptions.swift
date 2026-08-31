import Foundation

struct RequestOptions: Equatable {
    var extraHeaders: [String: String] = [:]
    var cookie: String? = nil

    var basicAuth: String? = nil
    var userAgent: String? = nil

    var delayMs: Int = 0

    static let none = RequestOptions()

    var isEmpty: Bool {
        extraHeaders.isEmpty && (cookie?.isEmpty ?? true)
            && (basicAuth?.isEmpty ?? true) && (userAgent?.isEmpty ?? true) && delayMs <= 0
    }

    func resolvedHeaders() -> [String: String] {
        var h = extraHeaders
        if let cookie, !cookie.isEmpty { h["Cookie"] = cookie }
        if let userAgent, !userAgent.isEmpty { h["User-Agent"] = userAgent }
        if let basicAuth, basicAuth.contains(":"),
           let data = basicAuth.data(using: .utf8) {
            h["Authorization"] = "Basic " + data.base64EncodedString()
        }
        return h
    }

    static func parseHeaderLine(_ line: String) -> (String, String)? {
        guard let idx = line.firstIndex(of: ":") else { return nil }
        let key = line[..<idx].trimmingCharacters(in: .whitespaces)
        let value = line[line.index(after: idx)...].trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { return nil }
        return (key, value)
    }

    static func parseHeaderBlock(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        for raw in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, let (k, v) = parseHeaderLine(line) else { continue }
            out[k] = v
        }
        return out
    }
}

struct DiscoveryFilters: Equatable {

    var excludeCodes: Set<Int> = []

    var onlyCodes: Set<Int> = []

    var notInTitle: String? = nil

    var excludePrefix: String? = nil

    static let none = DiscoveryFilters()

    func passesCode(_ code: Int) -> Bool {
        if excludeCodes.contains(code) { return false }
        if !onlyCodes.isEmpty { return onlyCodes.contains(code) }
        return true
    }

    func passesTitle(_ title: String?) -> Bool {
        guard let notInTitle, !notInTitle.isEmpty, let title else { return true }
        return !title.localizedCaseInsensitiveContains(notInTitle)
    }

    func passesPath(_ path: String) -> Bool {
        guard let excludePrefix, !excludePrefix.isEmpty else { return true }
        return !path.hasPrefix(excludePrefix)
    }

    static func parseCodes(_ s: String) -> Set<Int> {
        Set(s.split(whereSeparator: { $0 == "," || $0 == " " })
            .compactMap { Int($0.trimmingCharacters(in: .whitespaces)) })
    }
}

enum MimeTypes {
    static let byExtension: [String: String] = [
        "html": "text/html", "htm": "text/html", "xhtml": "application/xhtml+xml",
        "php": "text/html", "asp": "text/html", "aspx": "text/html",
        "jsp": "text/html", "cfm": "text/html", "shtml": "text/html",
        "css": "text/css",
        "js": "application/javascript", "mjs": "application/javascript",
        "json": "application/json", "map": "application/json",
        "xml": "application/xml", "rss": "application/rss+xml",
        "txt": "text/plain", "text": "text/plain", "md": "text/plain",
        "ini": "text/plain", "log": "text/plain", "conf": "text/plain",
        "cfg": "text/plain", "csv": "text/csv", "tsv": "text/tab-separated-values",
        "pdf": "application/pdf",
        "zip": "application/zip", "gz": "application/gzip", "tar": "application/x-tar",
        "rar": "application/vnd.rar", "7z": "application/x-7z-compressed",
        "sql": "application/sql", "sqlite": "application/x-sqlite3",
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
        "gif": "image/gif", "svg": "image/svg+xml", "webp": "image/webp",
        "ico": "image/x-icon", "bmp": "image/bmp",
        "woff": "font/woff", "woff2": "font/woff2", "ttf": "font/ttf",
        "mp4": "video/mp4", "webm": "video/webm", "mp3": "audio/mpeg",
        "yaml": "text/plain", "yml": "text/plain", "toml": "text/plain",
        "env": "text/plain", "properties": "text/plain",
    ]

    static func expected(forPath path: String) -> String? {
        let ext = (path as NSString).pathExtension.lowercased()
        guard !ext.isEmpty else { return nil }
        return byExtension[ext]
    }

    static func baseType(of contentType: String) -> String {
        contentType.split(separator: ";").first.map {
            $0.trimmingCharacters(in: .whitespaces).lowercased()
        } ?? contentType.lowercased()
    }

    static func mismatch(path: String, contentType: String) -> Bool {
        guard let want = expected(forPath: path), !contentType.isEmpty else { return false }
        let got = baseType(of: contentType)
        if got.isEmpty { return false }
        return got != want.lowercased()
    }
}

enum HTMLHelpers {

    static func title(from html: String) -> String? {
        guard let re = try? NSRegularExpression(
            pattern: "<title[^>]*>([^<]+)</title>", options: [.caseInsensitive]) else { return nil }
        let ns = html as NSString
        guard let m = re.firstMatch(in: html, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges > 1 else { return nil }
        let raw = ns.substring(with: m.range(at: 1))
        let collapsed = raw
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return collapsed.isEmpty ? nil : collapsed
    }

    static func looksLikeHTML(_ text: String) -> Bool {
        let lead = text.prefix(256).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return lead.hasPrefix("<!doctype html") || lead.hasPrefix("<html")
            || lead.contains("<head") || lead.contains("<body")
    }

    static func isOpenDirectory(_ text: String) -> Bool {
        let t = text.lowercased()
        return t.contains("index of /") || t.contains("directory listing for")
    }
}
