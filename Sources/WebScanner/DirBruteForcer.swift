import Foundation

@MainActor
protocol DiscoveryReporter: AnyObject {
    func discoveryFinding(_ f: Finding)
    func discoveryURL(_ d: DiscoveredURL)
    func discoveryProgress(done: Int, total: Int, status: String)
    func discoveryLog(_ s: String)
}

final class DirBruteForcer {

    struct Config {
        var origin: String
        var host: String
        var extensions: [String] = []
        var scanDirectories: Bool = false
        var recursive: Bool = false
        var probeDefaultFiles: Bool = true
        var runSecretScan: Bool = true
        var concurrency: Int = 12
        var maxRequests: Int = 4000
        var maxDirs: Int = 60
        var filters: DiscoveryFilters = .none
    }

    private let http: HTTPClient
    private let cfg: Config
    private weak var reporter: DiscoveryReporter?

    private var sentURLs = Set<String>()
    private var knownDirs: [String] = []
    private var knownDirSet = Set<String>()
    private var probedDefaultDirs = Set<String>()
    private var requestCount = 0
    private var total = 1
    private var soft = Soft404Baseline(is200ForEverything: false, bodyLength: 0, bodyHash: 0)

    private let defaultFiles = ["index.html", "index.php", "index.htm", "default.aspx", "default.asp"]

    init(http: HTTPClient, config: Config, reporter: DiscoveryReporter) {
        self.http = http
        self.cfg = config
        self.reporter = reporter
    }

    func run(words: [String], soft: Soft404Baseline) async {
        self.soft = soft
        let words = words.filter { cfg.filters.passesPath($0) }
        guard !words.isEmpty else {
            await reporter?.discoveryLog("• Wordlist is empty — nothing to scan.")
            return
        }

        addDir("")
        if cfg.scanDirectories {
            await reporter?.discoveryProgress(done: 0, total: 1, status: "Discovering directories…")
            for d in await discoverDirectories() { addDir(d) }
            await reporter?.discoveryLog("• Directory discovery found \(knownDirs.count) directory(ies)")
        }

        let perDir = words.count * (cfg.extensions.count + 1)
        total = min(cfg.maxRequests, max(1, knownDirs.count * perDir))

        var dirIndex = 0
        while dirIndex < knownDirs.count, requestCount < cfg.maxRequests {
            let dir = knownDirs[dirIndex]
            dirIndex += 1
            if cfg.scanDirectories {
                await reporter?.discoveryProgress(
                    done: requestCount, total: total,
                    status: "Scanning /\(dir) — \(requestCount)/\(total)")
            }
            if cfg.probeDefaultFiles { await probeDefaults(inDir: dir) }
            await scanWordlist(words, inDir: dir)

            total = min(cfg.maxRequests, max(total, knownDirs.count * perDir))
        }

        await reporter?.discoveryProgress(done: total, total: total, status: "Content discovery complete")
    }

    private func scanWordlist(_ words: [String], inDir dir: String) async {
        var newDirs: [String] = []
        for batch in words.chunked(into: cfg.concurrency) {
            guard requestCount < cfg.maxRequests else { break }
            var targets: [(path: String, url: URL)] = []
            for word in batch {
                for path in candidatePaths(dir: dir, word: word) {
                    guard let url = URL(string: "\(cfg.origin)/\(path)") else { continue }
                    targets.append((path, url))
                }
            }
            let client = http
            await withTaskGroup(of: (String, HTTPResponse?).self) { group in
                for t in targets {
                    group.addTask { (t.path, await client.fetch(t.url)) }
                }
                for await (path, resp) in group {
                    requestCount += 1
                    guard let resp else { continue }
                    if let d = await classifyAndReport(path: path, resp: resp) {
                        if cfg.recursive, d.kind == .page || d.kind == .directory || d.kind == .openDirectory {
                            for nd in directoriesFrom(html: resp.text, base: resp.finalURL) {
                                newDirs.append(nd)
                            }
                        }
                    }
                }
            }
            await reporter?.discoveryProgress(
                done: requestCount, total: total,
                status: "Scanning /\(dir) — \(min(requestCount, total))/\(total)")
        }
        if cfg.recursive {
            for nd in newDirs { addDir(nd) }
        }
    }

    private func candidatePaths(dir: String, word: String) -> [String] {
        var out = ["\(dir)\(word)"]
        if !cfg.extensions.isEmpty, !word.hasSuffix("/") {
            for ext in cfg.extensions { out.append("\(dir)\(word)\(ext)") }
        }
        return out
    }

    private func probeDefaults(inDir dir: String) async {
        guard probedDefaultDirs.insert(dir).inserted else { return }
        let client = http
        await withTaskGroup(of: (String, HTTPResponse?).self) { group in
            for name in defaultFiles {
                let path = "\(dir)\(name)"
                guard let url = URL(string: "\(cfg.origin)/\(path)") else { continue }
                group.addTask { (path, await client.fetch(url)) }
            }
            for await (path, resp) in group {
                requestCount += 1
                guard let resp, resp.status == 200 else { continue }
                await report(path: path, resp: resp, kind: .defaultFile, notable: false)
            }
        }
    }

    @discardableResult
    private func classifyAndReport(path: String, resp: HTTPResponse) async -> DiscoveredURL? {
        let code = resp.status
        guard cfg.filters.passesCode(code) else { return nil }

        let isDirPath = path.hasSuffix("/")
        if code == 404 { return nil }
        if code >= 500 { return nil }
        if !isDirPath, resp.body.isEmpty { return nil }

        let text = resp.text

        if soft.looksLikeThis(resp) || looksLikeNotFound(text) { return nil }

        let title = HTMLHelpers.title(from: text)
        guard cfg.filters.passesTitle(title) else { return nil }

        let ct = MimeTypes.baseType(of: resp.contentType)
        let isHTML = ct.contains("html") || HTMLHelpers.looksLikeHTML(text)

        var kind: DiscoveredURL.Kind
        var notable = false

        if HTMLHelpers.isOpenDirectory(text) {
            kind = .openDirectory
            notable = true
            await reporter?.discoveryFinding(Checks.directoryListing(resp.finalURL))
        } else if isDirPath, code == 200 || code == 301 || code == 403 {
            kind = .directory
        } else if !isHTML {

            if MimeTypes.mismatch(path: path, contentType: resp.contentType) {
                kind = .mismatch
                notable = true
            } else {
                kind = .file
            }
        } else {
            kind = .page
        }

        if cfg.runSecretScan, !isHTML, code == 200 || code == 206 {
            let hits = SecretScanner.scan(text, source: resp.finalURL.absoluteString)
            if !hits.isEmpty {
                notable = true
                for f in hits { await reporter?.discoveryFinding(f) }
            }
        }
        if sensitiveName(path), !isHTML, code == 200 {
            notable = true
            await reporter?.discoveryFinding(reachableSensitiveFinding(path: path, resp: resp))
        }

        return await report(path: path, resp: resp, kind: kind, notable: notable, title: title)
    }

    @discardableResult
    private func report(path: String, resp: HTTPResponse, kind: DiscoveredURL.Kind,
                        notable: Bool, title: String? = nil) async -> DiscoveredURL? {
        let key = resp.finalURL.absoluteString
        guard sentURLs.insert(key).inserted else { return nil }
        let d = DiscoveredURL(
            url: key,
            status: resp.status,
            length: resp.body.count,
            contentType: MimeTypes.baseType(of: resp.contentType),
            title: title ?? HTMLHelpers.title(from: resp.text),
            kind: kind,
            notable: notable)
        await reporter?.discoveryURL(d)
        let marker = notable ? "‼︎" : "+"
        await reporter?.discoveryLog("\(marker) [\(resp.status)] /\(path) (\(resp.body.count) B)\(d.title.map { " — \($0)" } ?? "")")
        return d
    }

    private func discoverDirectories() async -> [String] {
        var dirs = Set<String>()
        guard let home = URL(string: "\(cfg.origin)/"), let r = await http.fetch(home) else { return [] }
        for d in directoriesFrom(html: r.text, base: r.finalURL) { dirs.insert(d) }

        if let u = URL(string: "\(cfg.origin)/robots.txt"), let rr = await http.fetch(u), rr.status == 200 {
            for p in ExtraChecks.robotsDisallowPaths(rr.text) {
                let dir = directoryComponent(of: p)
                if !dir.isEmpty { dirs.insert(dir) }
            }
        }
        if let u = URL(string: "\(cfg.origin)/sitemap.xml"), let rs = await http.fetch(u),
           rs.status == 200, rs.text.contains("<loc") {
            for loc in ExtraChecks.sitemapLocations(rs.text, sameHost: cfg.host) {
                let dir = directoryComponent(of: loc.path)
                if !dir.isEmpty { dirs.insert(dir) }
            }
        }

        var expanded = Set<String>()
        for d in dirs {
            expanded.insert(d)
            for parent in parentDirs(of: d) { expanded.insert(parent) }
        }
        return Array(expanded).sorted()
    }

    private func directoriesFrom(html: String, base: URL) -> [String] {
        var out = Set<String>()
        for link in ExtraChecks.extractLinks(html: html, base: base, sameHost: cfg.host) {
            let dir = directoryComponent(of: link.path)
            if !dir.isEmpty { out.insert(dir) }
        }
        return Array(out)
    }

    private func directoryComponent(of path: String) -> String {
        var p = path
        if let q = p.firstIndex(of: "?") { p = String(p[..<q]) }

        if !p.hasSuffix("/") {
            let last = p.split(separator: "/").last.map(String.init) ?? ""
            if last.contains(".") {
                if let slash = p.lastIndex(of: "/") { p = String(p[...slash]) } else { p = "/" }
            } else if !p.isEmpty {
                p += "/"
            }
        }
        while p.hasPrefix("/") { p.removeFirst() }
        return p
    }

    private func parentDirs(of dir: String) -> [String] {
        var out: [String] = []
        var comps = dir.split(separator: "/").map(String.init)
        while comps.count > 1 {
            comps.removeLast()
            out.append(comps.joined(separator: "/") + "/")
        }
        return out
    }

    private func addDir(_ dir: String) {
        guard knownDirs.count < cfg.maxDirs || dir.isEmpty else { return }
        if knownDirSet.insert(dir).inserted { knownDirs.append(dir) }
    }

    private func looksLikeNotFound(_ text: String) -> Bool {
        let l = text.prefix(4000).lowercased()
        guard l.contains("404") else { return false }
        return l.contains("not found") || l.contains("page not found")
            || l.contains("doesn't exist") || l.contains("does not exist")
            || l.contains("cannot be found")
    }

    private func sensitiveName(_ path: String) -> Bool {
        let l = path.lowercased()
        let markers = [".env", ".git/", ".svn/", "config", "secret", "credential", "backup",
                       "dump", ".sql", ".bak", ".old", "id_rsa", ".key", ".pem", "wp-config",
                       ".htpasswd", ".npmrc", "docker-compose", ".aws", "settings"]
        return markers.contains { l.contains($0) }
    }

    private func reachableSensitiveFinding(path: String, resp: HTTPResponse) -> Finding {
        Finding(
            title: "Reachable sensitive file: /\(path)",
            severity: .medium,
            category: "Information Disclosure",
            location: resp.finalURL.absoluteString,
            detail: "Content discovery reached /\(path) (HTTP \(resp.status), \(resp.body.count) bytes) and it returned non-HTML content. Sensitive-looking files in the web root often leak configuration or credentials.",
            evidence: "URL: \(resp.finalURL.absoluteString)\nContent-Type: \(resp.contentType)\nPreview: \(snippet(resp.text, max: 160))",
            exploit: "Config, backup, VCS, and key files exposed in the web root frequently hand an attacker internal paths, versions, or working credentials.",
            remediation: "Remove the file from the web root if it should not be public, or deny access to it at the web server. Rotate any secrets it may contain.",
            reference: "CWE-200: Exposure of Sensitive Information")
    }
}
