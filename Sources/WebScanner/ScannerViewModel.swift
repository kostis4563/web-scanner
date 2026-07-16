import Foundation
import Combine

struct Soft404Baseline {
    let is200ForEverything: Bool
    let bodyLength: Int
    let bodyHash: Int

    func looksLikeThis(_ r: HTTPResponse) -> Bool {
        guard is200ForEverything, r.status == 200 else { return false }
        if abs(r.body.count - bodyLength) <= 48 { return true }
        return String(r.text.prefix(2000)).hashValue == bodyHash
    }
}

@MainActor
final class ScannerViewModel: ObservableObject {

    @Published var target: String = ""
    @Published var authorized: Bool = false
    @Published var deepSecretScan: Bool = true
    @Published var revealSecrets: Bool = true
    @Published var intensity: ScanIntensity = .deep
    @Published var mode: ScanMode = .siteScan

    // Content-discovery options (port of scaner.py flags)
    @Published var wordlistText: String = ""       // words pasted directly
    @Published var wordlistSource: String = ""     // file path(s)/URL(s), comma-separated (-d)
    @Published var extensionsText: String = ""     // e.g. "php,bak,old" (-X)
    @Published var scanDirectories: Bool = true    // discover directories (-s)
    @Published var recursive: Bool = false         // recurse into found dirs (-r)
    @Published var maxRequests: Int = 3000         // safety cap on total requests

    // URL-mask options (port of scanurls.py)
    @Published var maskMaxLength: Int = 44         // max URL length for * growth (-l)
    @Published var maskLimit: Int = 2000           // cap on generated URLs

    // Request options applied to every request, all modes
    @Published var customHeaders: String = ""      // "Key: Value" lines (-H)
    @Published var cookie: String = ""             // cookie string (-c)
    @Published var basicAuth: String = ""          // user:password (-u)
    @Published var userAgentOverride: String = ""  // custom UA (-a)
    @Published var requestDelayMs: Int = 0         // delay between requests (-z)

    // Response filters (content discovery / URL mask)
    @Published var excludeCodesText: String = "404"  // ignore these codes (-N)
    @Published var onlyCodesText: String = ""        // only these codes (-S)
    @Published var notInTitle: String = ""           // skip if in title (--not)

    @Published private(set) var findings: [Finding] = []
    @Published private(set) var discovered: [DiscoveredURL] = []

    @Published var isScanning: Bool = false
    @Published var progress: Double = 0
    @Published var statusText: String = "Idle"
    @Published var logLines: [String] = []

    @Published var scannedURL: URL?
    @Published var startedAt: Date?
    @Published var finishedAt: Date?

    private let http = HTTPClient()
    private var findingKeys = Set<String>()
    private var discoveredKeys = Set<String>()
    private var seenJWTs = Set<String>()

    var sortedFindings: [Finding] {
        findings.sorted {
            if $0.severity != $1.severity { return $0.severity < $1.severity }
            return $0.category < $1.category
        }
    }

    var counts: [Severity: Int] {
        var c: [Severity: Int] = [:]
        for f in findings { c[f.severity, default: 0] += 1 }
        return c
    }

    var report: ScanReport? {
        guard let start = startedAt, let url = scannedURL else { return nil }
        return ScanReport(
            target: target,
            finalURL: url.absoluteString,
            startedAt: start,
            finishedAt: finishedAt ?? start,
            findings: sortedFindings
        )
    }

    func startScan() {
        guard !isScanning else { return }
        guard authorized else {
            log("⚠️ Confirm you are authorized to test this target before scanning.")
            return
        }

        // Per-mode validation.
        var base: URL?
        if mode == .siteScan || mode == .contentDiscovery {
            guard let b = normalizeTarget(target) else {
                log("❌ Enter a valid domain, e.g. example.com")
                return
            }
            base = b
        } else {
            guard !target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                log("❌ Enter a URL template, e.g. https://[a-z]{1,3}.example.com")
                return
            }
        }

        http.options = buildRequestOptions()
        SecretScanner.revealSecrets = revealSecrets
        resetState()
        isScanning = true
        startedAt = Date()
        finishedAt = nil

        switch mode {
        case .siteScan:
            scannedURL = base
            Task { await runScan(base!) }
        case .contentDiscovery:
            scannedURL = base
            Task { await runContentDiscoveryScan(base!) }
        case .urlMask:
            Task { await runURLMask(target.trimmingCharacters(in: .whitespacesAndNewlines)) }
        }
    }

    private func resetState() {
        findings = []
        findingKeys = []
        discovered = []
        discoveredKeys = []
        seenJWTs = []
        logLines = []
        progress = 0
    }

    private func buildRequestOptions() -> RequestOptions {
        var o = RequestOptions()
        o.extraHeaders = RequestOptions.parseHeaderBlock(customHeaders)
        o.cookie = cookie.isEmpty ? nil : cookie
        o.basicAuth = basicAuth.isEmpty ? nil : basicAuth
        o.userAgent = userAgentOverride.isEmpty ? nil : userAgentOverride
        o.delayMs = max(0, requestDelayMs)
        return o
    }

    private func buildFilters() -> DiscoveryFilters {
        var f = DiscoveryFilters()
        f.excludeCodes = DiscoveryFilters.parseCodes(excludeCodesText)
        f.onlyCodes = DiscoveryFilters.parseCodes(onlyCodesText)
        f.notInTitle = notInTitle.isEmpty ? nil : notInTitle
        return f
    }

    /// Assemble the effective word list from pasted text and/or file/URL sources,
    /// falling back to the built-in default list.
    private func loadWords() async -> [String] {
        var seen = Set<String>()
        var words: [String] = []
        func add(_ list: [String]) { for w in list where seen.insert(w).inserted { words.append(w) } }

        if !wordlistText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            add(Wordlist.parse(wordlistText))
        }
        let src = wordlistSource.trimmingCharacters(in: .whitespacesAndNewlines)
        if !src.isEmpty {
            add(await Wordlist.load(spec: src, http: http))
        }
        if words.isEmpty { add(Wordlist.defaultPaths) }
        return words
    }

    // MARK: - Content discovery (scaner.py)

    private func runContentDiscoveryScan(_ base: URL) async {
        let host0 = base.host ?? base.absoluteString
        log("▶︎ Content discovery on \(host0)")
        setStatus("Connecting...")
        guard let home = await http.fetch(base) else {
            log("❌ Could not reach \(host0). Scan aborted.")
            finishScan()
            return
        }
        scannedURL = home.finalURL
        let origin = originString(of: home.finalURL)
        let host = home.finalURL.host ?? host0
        log("✓ Connected - HTTP \(home.status) at \(home.finalURL.absoluteString)")
        progress = 0.04

        setStatus("Calibrating soft-404 baseline...")
        let soft = await computeSoft404(origin: origin)

        setStatus("Loading wordlist...")
        let words = await loadWords()
        log("• Wordlist: \(words.count) entries" + (extensionsText.isEmpty ? "" : ", extensions: \(extensionsText)"))

        var cfg = DirBruteForcer.Config(origin: origin, host: host)
        cfg.extensions = Wordlist.parseExtensions(extensionsText)
        cfg.scanDirectories = scanDirectories
        cfg.recursive = recursive
        cfg.runSecretScan = deepSecretScan
        cfg.maxRequests = max(50, maxRequests)
        cfg.filters = buildFilters()

        let forcer = DirBruteForcer(http: http, config: cfg, reporter: self)
        await forcer.run(words: words, soft: soft)

        progress = 1.0
        finishScan()
    }

    // MARK: - URL mask (scanurls.py)

    private func runURLMask(_ template: String) async {
        log("▶︎ URL mask: \(template)")
        setStatus("Expanding template...")

        let dict = template.contains("$") ? await loadWords() : []
        let urls = URLTemplate.expand(template, dictionary: dict,
                                      maxLength: maskMaxLength, limit: max(1, maskLimit))
        guard !urls.isEmpty else {
            log("❌ Template produced no URLs.")
            finishScan()
            return
        }
        log("• Generated \(urls.count) candidate URL(s)")

        let filters = buildFilters()
        let candidates = urls.compactMap { URL(string: $0) }
        let client = http
        let total = max(candidates.count, 1)
        var done = 0
        for batch in candidates.chunked(into: 12) {
            await withTaskGroup(of: (URL, HTTPResponse?).self) { group in
                for u in batch { group.addTask { (u, await client.fetch(u)) } }
                for await (u, resp) in group {
                    done += 1
                    guard let resp, resp.status != 404,
                          filters.passesCode(resp.status) else { continue }
                    let title = HTMLHelpers.title(from: resp.text)
                    guard filters.passesTitle(title) else { continue }
                    recordMaskHit(url: u, resp: resp, title: title)
                }
            }
            progress = min(0.99, Double(min(done, total)) / Double(total))
            setStatus("Probing URLs... \(min(done, total))/\(total) — \(discovered.count) live")
        }
        progress = 1.0
        finishScan()
    }

    private func recordMaskHit(url: URL, resp: HTTPResponse, title: String?) {
        let ct = MimeTypes.baseType(of: resp.contentType)
        let isHTML = ct.contains("html") || HTMLHelpers.looksLikeHTML(resp.text)
        var notable = false
        var kind: DiscoveredURL.Kind = isHTML ? .page : .file
        if HTMLHelpers.isOpenDirectory(resp.text) { kind = .openDirectory; notable = true }

        if deepSecretScan, !isHTML, resp.status == 200, resp.body.count > 0 {
            let hits = SecretScanner.scan(resp.text, source: resp.finalURL.absoluteString)
            if !hits.isEmpty { notable = true; addFindings(hits) }
        }
        let d = DiscoveredURL(url: resp.finalURL.absoluteString, status: resp.status,
                              length: resp.body.count, contentType: ct, title: title,
                              kind: kind, notable: notable)
        discoveryURL(d)
        log("\(notable ? "‼︎" : "+") [\(resp.status)] \(resp.finalURL.absoluteString)\(title.map { " — \($0)" } ?? "")")
    }

    private func runScan(_ base: URL) async {
        let host0 = base.host ?? base.absoluteString
        log("▶︎ Starting \(intensity.label) scan of \(host0)")

        if base.scheme == "https" {
            setStatus("Checking TLS certificate...")
            if await http.tlsValid(host: host0) == false {
                addFinding(Checks.invalidTLS(host0))
                log("• TLS certificate is invalid/untrusted")
            }
        }
        progress = 0.04

        setStatus("Fetching homepage...")
        var homepage = await http.fetch(base)
        if homepage == nil, base.scheme == "https", let u = URL(string: "http://\(host0)/") {
            homepage = await http.fetch(u)
            if homepage != nil { addFinding(Checks.noHTTPS(host0)) }
        }
        guard let home = homepage else {
            log("❌ Could not reach \(host0). Scan aborted.")
            finishScan()
            return
        }
        scannedURL = home.finalURL
        let origin = originString(of: home.finalURL)
        let host = home.finalURL.host ?? host0
        log("✓ Connected - HTTP \(home.status) at \(home.finalURL.absoluteString)")
        progress = 0.08

        setStatus("Checking HTTP → HTTPS redirect...")
        if let u = URL(string: "http://\(host)/"),
           let r = await http.fetch(u), r.finalURL.scheme != "https", r.status == 200 {
            addFinding(Checks.noHTTPSRedirect(host))
        }

        setStatus("Analyzing security headers & cookies...")
        addFindings(Checks.securityHeaders(home))
        addFindings(Checks.infoDisclosure(home))
        addFindings(Checks.cookies(home))
        addFindings(ExtraChecks.mixedContent(html: home.text, pageURL: home.finalURL))
        addFindings(ExtraChecks.csrfFindings(html: home.text, pageURL: home.finalURL))
        if intensity.checkSRI { addFindings(ExtraChecks.sriFindings(html: home.text, pageURL: home.finalURL, sameHost: host)) }
        if Checks.isDirectoryListing(home) { addFinding(Checks.directoryListing(home.finalURL)) }

        setStatus("Testing CORS policy...")
        let evilOrigin = "https://scanner-cors-probe.example.com"
        if let r = await http.fetch(home.finalURL, extraHeaders: ["Origin": evilOrigin]),
           let cors = Checks.cors(r, reflectedOrigin: evilOrigin) {
            addFinding(cors)
        }
        progress = 0.12

        let soft = await computeSoft404(origin: origin)

        var sitemapURLs: [URL] = []
        if intensity.parseRobotsSitemap {
            setStatus("Reading robots.txt & sitemap.xml...")
            sitemapURLs = await processRobotsSitemap(origin: origin, host: host)
        }
        progress = 0.16

        var pages: [HTTPResponse] = [home]
        var scripts: [URL] = []
        if intensity.crawlSite {
            setStatus("Crawling site...")
            let (p, s) = await crawlSite(seed: home, host: host)
            pages = p
            scripts = s
            log("• Crawled \(pages.count) pages, found \(scripts.count) scripts")
        } else {
            scripts = ExtraChecks.extractScriptSources(html: home.text, base: home.finalURL, sameHost: host)
        }
        progress = 0.45

        if intensity.probeSensitiveFiles {
            setStatus("Probing sensitive files...")
            await probeCurated(origin: origin, soft: soft)
        }
        progress = 0.60

        if intensity.crawlSite {
            setStatus("Hunting .env across directories...")
            await huntEnvFiles(origin: origin, pages: pages, scripts: scripts, soft: soft)
        }
        progress = max(progress, 0.62)

        if intensity.bruteForcePaths {
            setStatus("Brute-forcing admin & config paths...")
            await probeStrings(Wordlists.adminPaths, kind: .admin, origin: origin, soft: soft, band: (0.62, 0.66))
            await probeStrings(Wordlists.extraFiles, kind: .extra, origin: origin, soft: soft, band: (0.66, 0.70))
        }
        if intensity.guessBackupNames {
            setStatus("Guessing backup archive names...")
            await probeStrings(Wordlists.backupNames(forHost: host), kind: .backup, origin: origin, soft: soft, band: (0.70, 0.74))
        }
        progress = max(progress, 0.74)

        if intensity.probeApiSurface {
            setStatus("Probing GraphQL introspection...")
            await probeGraphQL(origin: origin)
        }
        progress = 0.76

        if intensity.testAccessControl {
            setStatus("Testing authentication & access control...")
            await probeAccessControl(origin: origin, host: host, soft: soft)
            checkIDOR(pages: pages, host: host)
        }
        progress = 0.77

        if intensity.probeHTTPMethods {
            setStatus("Checking allowed HTTP methods...")
            if let r = await http.fetch(home.finalURL, method: "OPTIONS"),
               let f = ActiveProbes.httpMethodsFinding(r) { addFinding(f) }
        }

        if intensity.detectServerErrors {
            setStatus("Probing for verbose errors / debug output...")
            await probeServerErrors(origin: origin, home: home)
        }

        if intensity.testInjection {
            setStatus("Testing open redirect, reflected input & host header...")
            await probeInjection(home: home, pages: pages, host: host, origin: origin)
        }
        progress = 0.78

        if intensity.enumerateSubdomains {
            setStatus("Enumerating subdomains...")
            await enumerateSubdomains(host: host)
        }
        progress = max(progress, 0.78)

        if deepSecretScan {
            setStatus("Deep secret scan...")
            var sinkHits: [JSAnalysis.SinkHit] = []
            var libHits: [LibraryChecks.Hit] = []
            var jsDiscoveredPaths = Set<String>()
            var jsChunkURLs = Set<String>()
            for pg in pages {
                addFindings(SecretScanner.scan(pg.text, source: pg.finalURL.absoluteString))
                if intensity.testAccessControl { scanJWTs(text: pg.text, source: pg.finalURL.absoluteString) }
                sinkHits += JSAnalysis.sinkHits(in: pg.text, source: pg.finalURL.absoluteString)
                libHits += LibraryChecks.scanDocument(url: pg.finalURL, text: pg.text)
                if intensity.analyzeForms {
                    addFindings(ExtraChecks.analyzeForms(html: pg.text, pageURL: pg.finalURL))
                    addFindings(ExtraChecks.mixedContent(html: pg.text, pageURL: pg.finalURL))
                    addFindings(ExtraChecks.csrfFindings(html: pg.text, pageURL: pg.finalURL))
                }
                if intensity.checkSRI {
                    addFindings(ExtraChecks.sriFindings(html: pg.text, pageURL: pg.finalURL, sameHost: host))
                }
            }

            let crawledKeys = Set(pages.map { $0.finalURL.absoluteString })
            for u in sitemapURLs.prefix(20) where !crawledKeys.contains(u.absoluteString) {
                if let r = await http.fetch(u), r.status == 200 {
                    addFindings(SecretScanner.scan(r.text, source: r.finalURL.absoluteString))
                    if intensity.analyzeForms {
                        addFindings(ExtraChecks.analyzeForms(html: r.text, pageURL: r.finalURL))
                    }
                }
            }

            let capped = Array(scripts.prefix(intensity.maxScripts))
            if scripts.count > capped.count {
                log("• \(scripts.count) scripts found; scanning first \(capped.count)")
            }
            var i = 0
            for u in capped {
                i += 1
                setStatus("Deep secret scan... script \(i)/\(capped.count)")
                if let r = await http.fetch(u), r.status == 200 {
                    let js = r.text
                    addFindings(SecretScanner.scan(js, source: u.absoluteString))
                    if intensity.testAccessControl { scanJWTs(text: js, source: u.absoluteString) }
                    sinkHits += JSAnalysis.sinkHits(in: js, source: u.absoluteString)
                    libHits += LibraryChecks.scanDocument(url: u, text: js)
                    for p in JSAnalysis.interestingPaths(from: js, base: u, sameHost: host) {
                        jsDiscoveredPaths.insert(p.absoluteString)
                    }
                    if intensity.followJSChunks {
                        for c in JSAnalysis.scriptURLs(from: js, base: u, sameHost: host) {
                            jsChunkURLs.insert(c.absoluteString)
                        }
                    }
                    if intensity.fetchSourceMaps {
                        for mapURL in ExtraChecks.sourceMapCandidates(scriptURL: u, body: js).prefix(2) {
                            if let mr = await http.fetch(mapURL), mr.status == 200, mr.body.count > 0 {
                                addFindings(ExtraChecks.analyzeSourceMap(mapURL: mr.finalURL, body: mr.body))
                            }
                        }
                    }
                }
                progress = 0.78 + 0.14 * Double(i) / Double(max(capped.count, 1))
            }

            if intensity.followJSChunks, intensity.maxSecondWaveScripts > 0 {
                let firstWave = Set(capped.map { $0.absoluteString })
                let nested = Array(jsChunkURLs.subtracting(firstWave))
                    .compactMap { URL(string: $0) }
                    .prefix(intensity.maxSecondWaveScripts)
                if !nested.isEmpty {
                    log("• Second-wave JS: scanning \(nested.count) nested chunk(s)")
                    var j = 0
                    for u in nested {
                        j += 1
                        setStatus("Deep secret scan... nested chunk \(j)/\(nested.count)")
                        if let r = await http.fetch(u), r.status == 200 {
                            let js = r.text
                            addFindings(SecretScanner.scan(js, source: u.absoluteString))
                            sinkHits += JSAnalysis.sinkHits(in: js, source: u.absoluteString)
                            libHits += LibraryChecks.scanDocument(url: u, text: js)
                            for p in JSAnalysis.interestingPaths(from: js, base: u, sameHost: host) {
                                jsDiscoveredPaths.insert(p.absoluteString)
                            }
                        }
                        progress = 0.92 + 0.04 * Double(j) / Double(nested.count)
                    }
                }
            }

            let alreadyFetched = Set(pages.map { $0.finalURL.absoluteString })
                .union(scripts.map { $0.absoluteString })
                .union(jsChunkURLs)
            await probeDiscoveredPaths(jsDiscoveredPaths, alreadySeen: alreadyFetched, soft: soft)

            if intensity.scanAllAssets {
                setStatus("Scanning all frontend files for secrets...")
                await scanFrontendAssets(pages: pages, host: host,
                                         alreadyScanned: alreadyFetched.union(jsDiscoveredPaths))
            }

            addFindings(JSAnalysis.makeSinkFindings(sinkHits))

            addFindings(LibraryChecks.makeFindings(libHits))
        }

        progress = 1.0
        finishScan()
    }

    private func scanFrontendAssets(pages: [HTTPResponse], host: String,
                                    alreadyScanned: Set<String>) async {
        var assetSet = Set<String>()
        for pg in pages {
            for a in ExtraChecks.extractAssetURLs(html: pg.text, base: pg.finalURL, sameHost: host) {
                assetSet.insert(a.absoluteString)
            }
        }

        let targets = assetSet.subtracting(alreadyScanned)
            .compactMap { URL(string: $0) }
            .map { (url: $0, rank: assetPriority($0)) }
            .sorted { $0.rank != $1.rank ? $0.rank < $1.rank : $0.url.absoluteString < $1.url.absoluteString }
            .map { $0.url }
        guard !targets.isEmpty else { return }
        let capped = Array(targets.prefix(intensity.maxAssets))
        if targets.count > capped.count {
            log("• \(targets.count) frontend files found; scanning the \(capped.count) most secret-likely")
        }
        log("• Scanning \(capped.count) other frontend file(s) for secrets (config/JSON/CSS/text)")
        let client = http
        let total = max(capped.count, 1)
        let startP = progress
        var done = 0
        for batch in capped.chunked(into: 8) {
            await withTaskGroup(of: HTTPResponse?.self) { group in
                for u in batch { group.addTask { await client.fetch(u) } }
                for await resp in group {
                    guard let resp, resp.status == 200 || resp.status == 206,
                          resp.body.count > 0 else { continue }

                    if resp.contentType.lowercased().contains("text/html") { continue }
                    let lead = resp.text.prefix(256).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    if lead.hasPrefix("<!doctype html") || lead.hasPrefix("<html") { continue }
                    let hits = SecretScanner.scan(resp.text, source: resp.finalURL.absoluteString)
                    if !hits.isEmpty {
                        addFindings(hits)
                        log("‼︎ Secret(s) in frontend file: \(resp.finalURL.path)")
                    }
                }
            }
            done += batch.count
            progress = min(0.99, startP + (0.99 - startP) * Double(min(done, total)) / Double(total))
            setStatus("Scanning frontend files... \(min(done, total))/\(total)")
        }
    }

    private func assetPriority(_ url: URL) -> Int {
        let ext = url.pathExtension.lowercased()
        let p = url.path.lowercased()
        let highValue: Set<String> = [
            "env", "pem", "key", "crt", "credentials", "pgpass", "npmrc", "yarnrc",
            "pypirc", "s3cfg", "dockercfg", "htpasswd", "tfstate", "tfvars", "tf",
            "hcl", "sql", "dump", "log", "har", "json", "json5", "jsonc", "yml",
            "yaml", "toml", "properties", "ini", "conf", "cfg", "config", "plist",
            "bak", "backup", "old", "orig", "save", "swp",
        ]
        if highValue.contains(ext) { return 0 }
        if ext.isEmpty, ["config", "secret", "credential", "env", "key", "token"].contains(where: { p.contains($0) }) { return 0 }
        if ["map", "xml", "csv", "tsv", "graphql", "proto"].contains(ext) { return 1 }
        return 2
    }

    private func crawlSite(seed: HTTPResponse, host: String) async -> (pages: [HTTPResponse], scripts: [URL]) {
        let client = http
        func canon(_ u: URL) -> String {
            var p = u.path.lowercased()
            if p.count > 1 && p.hasSuffix("/") { p = String(p.dropLast()) }
            if p.isEmpty { p = "/" }
            return (u.host ?? "") + p
        }

        var visited = Set<String>()
        var pages: [HTTPResponse] = [seed]
        var scriptSet = Set<String>()
        var scripts: [URL] = []
        visited.insert(canon(seed.finalURL))

        for s in ExtraChecks.extractScriptSources(html: seed.text, base: seed.finalURL, sameHost: host) {
            if scriptSet.insert(s.absoluteString).inserted { scripts.append(s) }
        }

        var frontier: [URL] = []
        if intensity.maxDepth >= 1 {
            for link in ExtraChecks.extractLinks(html: seed.text, base: seed.finalURL, sameHost: host) {
                if visited.insert(canon(link)).inserted { frontier.append(link) }
            }
        }

        var depth = 1
        while depth <= intensity.maxDepth && !frontier.isEmpty && pages.count < intensity.maxPages {
            let remaining = intensity.maxPages - pages.count
            let level = Array(frontier.prefix(remaining))
            frontier = []
            var responses: [HTTPResponse] = []
            for chunk in level.chunked(into: 6) {
                await withTaskGroup(of: HTTPResponse?.self) { group in
                    for u in chunk { group.addTask { await client.fetch(u) } }
                    for await r in group { if let r { responses.append(r) } }
                }
                setStatus("Crawling... \(min(pages.count + responses.count, intensity.maxPages))/\(intensity.maxPages) pages")
            }
            for r in responses {
                guard pages.count < intensity.maxPages else { break }
                let ct = r.contentType.lowercased()
                guard r.status == 200, ct.contains("html") || ct.isEmpty else { continue }
                pages.append(r)
                for s in ExtraChecks.extractScriptSources(html: r.text, base: r.finalURL, sameHost: host) {
                    if scriptSet.insert(s.absoluteString).inserted { scripts.append(s) }
                }
                if depth < intensity.maxDepth {
                    for link in ExtraChecks.extractLinks(html: r.text, base: r.finalURL, sameHost: host) {
                        if visited.count < intensity.maxPages * 4, visited.insert(canon(link)).inserted {
                            frontier.append(link)
                        }
                    }
                }
            }
            depth += 1
            progress = min(0.45, 0.16 + 0.29 * Double(pages.count) / Double(max(intensity.maxPages, 1)))
        }
        return (pages, scripts)
    }

    private func probeCurated(origin: String, soft: Soft404Baseline) async {
        let allPaths = SensitivePath.all
        let client = http
        var done = 0
        for batch in allPaths.chunked(into: 8) {
            await withTaskGroup(of: (SensitivePath, HTTPResponse?).self) { group in
                for p in batch {
                    let url = URL(string: "\(origin)/\(p.path)")
                    group.addTask {
                        guard let url else { return (p, nil) }
                        return (p, await client.fetch(url))
                    }
                }
                for await (p, resp) in group {
                    guard let resp else { continue }
                    if isConfirmed(p, resp, soft: soft) {
                        addFinding(Checks.fromPath(p, resp))
                        log("‼︎ Exposed: /\(p.path)")
                        if p.scanForSecrets {
                            addFindings(SecretScanner.scan(resp.text, source: resp.finalURL.absoluteString))
                        }
                    }
                }
            }
            done += batch.count
            progress = 0.45 + 0.17 * Double(min(done, allPaths.count)) / Double(max(allPaths.count, 1))
            setStatus("Probing sensitive files... \(min(done, allPaths.count))/\(allPaths.count)")
        }
    }

    private enum ProbeKind { case admin, extra, backup }

    private func probeStrings(_ paths: [String], kind: ProbeKind, origin: String,
                             soft: Soft404Baseline, band: (Double, Double)) async {
        let client = http
        let total = max(paths.count, 1)
        var done = 0
        for batch in paths.chunked(into: 10) {
            await withTaskGroup(of: (String, HTTPResponse?).self) { group in
                for p in batch {
                    let url = URL(string: "\(origin)/\(p)")
                    group.addTask {
                        guard let url else { return (p, nil) }
                        return (p, await client.fetch(url))
                    }
                }
                for await (p, resp) in group {
                    guard let resp, resp.status == 200,
                          !soft.looksLikeThis(resp), !looksLikeNotFound(resp) else { continue }
                    switch kind {
                    case .admin:
                        let l = resp.text.lowercased()
                        if Wordlists.adminSignatures.contains(where: { l.contains($0) }) {
                            addFinding(Wordlists.adminFinding(path: p, response: resp))
                            log("• Reachable admin endpoint: /\(p)")
                        }
                    case .extra:
                        let ct = resp.contentType.lowercased()
                        let looksHTMLPage = resp.text.lowercased().contains("<!doctype html")
                        if !looksHTMLPage || ct.contains("json") || ct.contains("text/plain") {
                            addFinding(Wordlists.extraFileFinding(path: p, response: resp))
                            addFindings(SecretScanner.scan(resp.text, source: resp.finalURL.absoluteString))
                        }
                    case .backup:
                        let ct = resp.contentType.lowercased()
                        let looksBinary = ["zip", "octet", "gzip", "tar", "x-rar", "compressed"].contains { ct.contains($0) }
                        if (looksBinary || !resp.text.lowercased().contains("<html")), resp.body.count > 0 {
                            addFinding(backupFinding(path: p, response: resp))
                            log("‼︎ Possible backup archive: /\(p)")
                        }
                    }
                }
            }
            done += batch.count
            progress = band.0 + (band.1 - band.0) * Double(min(done, total)) / Double(total)
            setStatus("Probing... \(min(done, total))/\(total)")
        }
    }

    private func probeGraphQL(origin: String) async {
        let body = "{\"query\":\"query{__schema{queryType{name} types{name}}}\"}".data(using: .utf8)
        for p in ["graphql", "api/graphql", "v1/graphql", "graphql/console", "query"] {
            guard let url = URL(string: "\(origin)/\(p)") else { continue }
            if let r = await http.fetch(url, method: "POST",
                                        extraHeaders: ["Content-Type": "application/json", "Accept": "application/json"],
                                        body: body),
               let f = ExtraChecks.graphqlIntrospection(r) {
                addFinding(f)
                log("• GraphQL introspection enabled at /\(p)")
                break
            }
        }
    }

    private func probeServerErrors(origin: String, home: HTTPResponse) async {
        var reported = Set<String>()
        func consider(_ url: URL, _ text: String) {
            guard let (label, sample) = ActiveProbes.errorSignature(in: text),
                  reported.insert(label).inserted else { return }
            addFinding(ActiveProbes.errorDisclosureFinding(url: url, label: label, sample: sample))
            log("‼︎ Verbose error/debug output: \(label) at \(url.path)")
        }
        consider(home.finalURL, home.text)

        let probes = ["'", "%ef%bf%be", "%c0%ae", "?ws%5B%5D=1", "?id=%27%22%3C"]
        for p in probes {
            guard reported.count < 3, let u = URL(string: "\(origin)/\(p)") else { continue }
            if let r = await http.fetch(u) { consider(r.finalURL, r.text) }
        }
    }

    private func probeInjection(home: HTTPResponse, pages: [HTTPResponse],
                                host: String, origin: String) async {

        var paramURLs: [URL] = []
        var seen = Set<String>()
        func consider(_ u: URL) {
            guard u.host == host,
                  let comps = URLComponents(url: u, resolvingAgainstBaseURL: false),
                  let items = comps.queryItems, !items.isEmpty else { return }
            let key = u.path + "?" + items.map { $0.name.lowercased() }.sorted().joined(separator: ",")
            if seen.insert(key).inserted { paramURLs.append(u) }
        }
        for pg in pages {
            consider(pg.finalURL)
            for l in ExtraChecks.extractLinks(html: pg.text, base: pg.finalURL, sameHost: host) { consider(l) }
            if paramURLs.count >= intensity.maxInjectionTargets * 3 { break }
        }
        let targets = Array(paramURLs.prefix(intensity.maxInjectionTargets))

        await probeOpenRedirect(homeURL: home.finalURL, targets: targets)
        await probeReflected(homeURL: home.finalURL, targets: targets)
        await probeHostHeader(url: home.finalURL)
        if intensity.testCRLF { await probeCRLF(homeURL: home.finalURL, targets: targets) }
    }

    private func probeCRLF(homeURL: URL, targets: [URL]) async {
        let client = http
        let payload = ActiveProbes.crlfPayload

        let params = Array(ActiveProbes.redirectParams.prefix(10))
        for batch in params.chunked(into: 5) {
            await withTaskGroup(of: (String, HTTPResponse?).self) { group in
                for p in batch {
                    guard let u = crlfTestURL(base: homeURL, param: p, payload: payload) else { continue }
                    group.addTask { (p, await client.fetch(u, followRedirects: false)) }
                }
                for await (p, r) in group {
                    guard let r, ActiveProbes.crlfInjected(r) else { continue }
                    let ev = "\(ActiveProbes.crlfHeaderName): \(r.header(ActiveProbes.crlfHeaderName) ?? "")\nSet-Cookie: \(r.header("set-cookie") ?? "(none)")"
                    addFinding(ActiveProbes.crlfInjectionFinding(pageURL: homeURL, param: p, evidence: ev))
                    log("‼︎ CRLF injection via ?\(p)=")
                }
            }
        }

        for u in targets.prefix(10) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems else { continue }
            let names = items.map { $0.name }.filter { ActiveProbes.redirectParams.contains($0.lowercased()) }
            guard let name = names.first, let test = crlfTestURL(base: u, param: name, payload: payload) else { continue }
            if let r = await http.fetch(test, followRedirects: false), ActiveProbes.crlfInjected(r) {
                let ev = "\(ActiveProbes.crlfHeaderName): \(r.header(ActiveProbes.crlfHeaderName) ?? "")"
                addFinding(ActiveProbes.crlfInjectionFinding(pageURL: u, param: name, evidence: ev))
                log("‼︎ CRLF injection at \(u.path)")
            }
        }
    }

    private func crlfTestURL(base: URL, param: String, payload: String) -> URL? {
        var s = base.absoluteString
        if let hash = s.firstIndex(of: "#") { s = String(s[..<hash]) }
        s += (s.contains("?") ? "&" : "?") + param + "=" + payload
        return URL(string: s)
    }

    private func probeOpenRedirect(homeURL: URL, targets: [URL]) async {
        let client = http
        let canary = ActiveProbes.redirectCanaryURL

        let homeParams = Array(ActiveProbes.redirectParams.prefix(12))
        for batch in homeParams.chunked(into: 6) {
            await withTaskGroup(of: (String, HTTPResponse?).self) { group in
                for p in batch {
                    guard let u = urlBySetting([p], to: canary, on: homeURL) else { continue }
                    group.addTask { (p, await client.fetch(u, followRedirects: false)) }
                }
                for await (p, r) in group {
                    guard let r, ActiveProbes.isOpenRedirect(r) else { continue }
                    addFinding(ActiveProbes.openRedirectFinding(
                        pageURL: homeURL, params: [p], location: r.header("location") ?? ""))
                    log("‼︎ Open redirect via ?\(p)=")
                }
            }
        }

        for u in targets {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems else { continue }
            let names = items.map { $0.name }.filter { ActiveProbes.redirectParams.contains($0.lowercased()) }
            guard !names.isEmpty, let test = urlBySetting(names, to: canary, on: u) else { continue }
            if let r = await http.fetch(test, followRedirects: false), ActiveProbes.isOpenRedirect(r) {
                addFinding(ActiveProbes.openRedirectFinding(
                    pageURL: u, params: names, location: r.header("location") ?? ""))
                log("‼︎ Open redirect at \(u.path)")
            }
        }
    }

    private func probeReflected(homeURL: URL, targets: [URL]) async {
        let canary = ActiveProbes.ReflectionCanary()

        if let u = urlByReplacingAllParams(ActiveProbes.reflectionParams, to: canary.injected, on: homeURL),
           let r = await http.fetch(u), ActiveProbes.isReflectedUnencoded(r, canary: canary) {
            addFinding(ActiveProbes.reflectedInputFinding(pageURL: homeURL, params: ActiveProbes.reflectionParams))
            log("‼︎ Reflected input without encoding (homepage)")
        }

        for u in targets {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty,
                  let test = urlBySetting(items.map { $0.name }, to: canary.injected, on: u) else { continue }
            if let r = await http.fetch(test), ActiveProbes.isReflectedUnencoded(r, canary: canary) {
                addFinding(ActiveProbes.reflectedInputFinding(pageURL: u, params: items.map { $0.name }))
                log("‼︎ Reflected input without encoding at \(u.path)")
            }
        }
    }

    private func probeHostHeader(url: URL) async {
        let canary = ActiveProbes.hostCanary

        for (name, label) in [("X-Forwarded-Host", "X-Forwarded-Host"), ("Host", "Host header")] {
            if let r = await http.fetch(url, extraHeaders: [name: canary], followRedirects: false),
               ActiveProbes.hostReflected(r) {
                let ev = "\(name): \(canary)\nLocation: \(r.header("location") ?? "(reflected in body)")"
                addFinding(ActiveProbes.hostHeaderFinding(pageURL: url, via: label, evidence: ev))
                log("‼︎ Host header injection via \(label)")
                return
            }
        }
    }

    private func urlBySetting(_ names: [String], to value: String, on url: URL) -> URL? {
        guard var comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let set = Set(names.map { $0.lowercased() })
        var items = comps.queryItems ?? []
        var present = Set<String>()
        items = items.map { item in
            guard set.contains(item.name.lowercased()) else { return item }
            present.insert(item.name.lowercased())
            return URLQueryItem(name: item.name, value: value)
        }
        for n in names where !present.contains(n.lowercased()) {
            items.append(URLQueryItem(name: n, value: value))
        }
        comps.queryItems = items
        return comps.url
    }

    private func urlByReplacingAllParams(_ names: [String], to value: String, on url: URL) -> URL? {
        guard var comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        comps.queryItems = names.map { URLQueryItem(name: $0, value: value) }
        return comps.url
    }

    private func enumerateSubdomains(host: String) async {

        guard host.contains(where: { $0.isLetter }) else { return }
        let base = ExtraChecks.registrableDomain(host)
        guard base.contains(".") else { return }

        let hosts = SubdomainScan.candidateHosts(base: base, limit: intensity.maxSubdomains)
            .filter { $0 != host }
        guard !hosts.isEmpty else { return }

        let client = http
        var live: [String] = []
        let total = max(hosts.count, 1)
        var done = 0
        for batch in hosts.chunked(into: 12) {
            await withTaskGroup(of: (String, HTTPResponse?).self) { group in
                for h in batch {
                    group.addTask {
                        if let u = URL(string: "https://\(h)/"), let r = await client.fetch(u) { return (h, r) }
                        if let u = URL(string: "http://\(h)/"), let r = await client.fetch(u) { return (h, r) }
                        return (h, nil)
                    }
                }
                for await (h, resp) in group {
                    guard let resp else { continue }
                    live.append(h)
                    if let svc = SubdomainScan.takeoverService(body: resp.text) {
                        addFinding(SubdomainScan.takeoverFinding(subdomain: h, service: svc, response: resp))
                        log("‼︎ Possible subdomain takeover: \(h) (\(svc))")
                    }
                    if deepSecretScan {
                        let ct = resp.contentType.lowercased()
                        if resp.status == 200, resp.body.count > 0, !ct.contains("image/"), !ct.contains("video/") {
                            addFindings(SecretScanner.scan(resp.text, source: resp.finalURL.absoluteString))
                        }
                    }
                }
            }
            done += batch.count
            setStatus("Enumerating subdomains... \(min(done, total))/\(total)")
        }
        if !live.isEmpty {
            addFinding(SubdomainScan.discoveredFinding(host: host, subdomains: live))
            log("• Discovered \(live.count) additional subdomain(s)")
        }
    }

    private func probeAccessControl(origin: String, host: String, soft: Soft404Baseline) async {
        let candidates = AccessControl.candidatePaths(max: intensity.maxAuthCandidates)
        let client = http
        var tested = 0
        for p in candidates {
            tested += 1
            setStatus("Testing access control... \(tested)/\(candidates.count)")
            guard let baseURL = URL(string: "\(origin)/\(p)"),
                  let base = await client.fetch(baseURL) else { continue }

            if (base.status == 200 || base.status == 206),
               !soft.looksLikeThis(base), !looksLikeNotFound(base),
               AccessControl.looksSensitive(base.text), !AccessControl.looksLikeLogin(base.text) {
                addFinding(AccessControl.missingAuthFinding(path: p, response: base))
                log("‼︎ Unauthenticated access to protected area: /\(p)")
                continue
            }

            guard base.status == 401 || base.status == 403 else { continue }
            let variants = AccessControl.bypassVariants(
                for: p, origin: origin, includeExtendedHeaders: intensity != .deep)
            let blockedLen = base.body.count
            var reported = false
            for batch in variants.chunked(into: 8) {
                if reported { break }
                await withTaskGroup(of: (AccessControl.BypassVariant, HTTPResponse?).self) { group in
                    for v in batch {
                        guard let u = URL(string: v.url) else { continue }
                        let headers = v.headers
                        group.addTask { (v, await client.fetch(u, extraHeaders: headers)) }
                    }
                    for await (v, resp) in group {
                        guard !reported, let resp,
                              resp.status == 200 || resp.status == 206,
                              !soft.looksLikeThis(resp), !looksLikeNotFound(resp),
                              !AccessControl.looksLikeLogin(resp.text),
                              resp.body.count > 0 else { continue }
                        let confident = AccessControl.looksSensitive(resp.text)

                        guard confident || resp.body.count > blockedLen + 512 else { continue }
                        addFinding(AccessControl.bypassFinding(
                            path: p, technique: v.label, response: resp, confident: confident))
                        log("‼︎ Access-control bypass on /\(p) via \(v.label)")
                        reported = true
                    }
                }
            }
        }
    }

    private func checkIDOR(pages: [HTTPResponse], host: String) {
        var urls: [URL] = []
        var seen = Set<String>()
        for pg in pages {
            if seen.insert(pg.finalURL.absoluteString).inserted { urls.append(pg.finalURL) }
            for l in ExtraChecks.extractLinks(html: pg.text, base: pg.finalURL, sameHost: host) {
                if seen.insert(l.absoluteString).inserted { urls.append(l) }
            }
        }
        let candidates = AccessControl.idorCandidates(in: urls)
        guard !candidates.isEmpty else { return }
        addFinding(AccessControl.idorFinding(candidates))
        log("• \(candidates.count) possible IDOR reference(s) - verify server-side authorization")
    }

    private func scanJWTs(text: String, source: String) {
        for token in AccessControl.extractJWTs(text) {
            guard seenJWTs.insert(token).inserted else { continue }
            let hits = AccessControl.jwtFindings(token: token, source: source)
            if !hits.isEmpty {
                addFindings(hits)
                log("‼︎ Weak JWT detected in \(source)")
            }
        }
    }

    private func processRobotsSitemap(origin: String, host: String) async -> [URL] {
        if let u = URL(string: "\(origin)/robots.txt"), let r = await http.fetch(u), r.status == 200 {
            let lower = r.text.lowercased()
            if lower.contains("disallow") || lower.contains("allow") {
                let dis = ExtraChecks.robotsDisallowPaths(r.text)
                if let f = ExtraChecks.robotsFinding(url: r.finalURL, disallow: dis) { addFinding(f) }
            }
        }
        if let u = URL(string: "\(origin)/sitemap.xml"), let r = await http.fetch(u),
           r.status == 200, r.text.contains("<loc") {
            let locs = ExtraChecks.sitemapLocations(r.text, sameHost: host)
            if !locs.isEmpty { log("• sitemap.xml lists \(locs.count) URLs") }
            return Array(locs.prefix(30))
        }
        return []
    }

    private func backupFinding(path: String, response: HTTPResponse) -> Finding {
        Finding(
            title: "Possible exposed backup/archive: /\(path)",
            severity: .high,
            category: "Data Exposure",
            location: response.finalURL.absoluteString,
            detail: "A request to /\(path) returned downloadable non-HTML content (HTTP \(response.status), \(response.body.count) bytes), consistent with a backup or database archive.",
            evidence: "URL: \(response.finalURL.absoluteString)\nContent-Type: \(response.contentType)\nSize: \(response.body.count) bytes",
            exploit: "Backup archives and database dumps typically contain source code, configs, and full datasets (including password hashes) - a complete compromise if downloaded.",
            remediation: "Remove backups/dumps from the web root immediately and store them in private, access-controlled storage. Rotate any credentials they may contain.",
            reference: "CWE-530: Exposure of Backup File")
    }

    private func dirPrefixes(of url: URL) -> [String] {
        var comps = url.path.split(separator: "/").map(String.init)
        if !url.path.hasSuffix("/"), !comps.isEmpty { comps.removeLast() }   
        var acc: [String] = []
        var cur = ""
        for c in comps {
            cur += c + "/"
            acc.append(cur)
        }
        return acc
    }

    private func directoryOf(_ rel: String) -> String {
        guard let idx = rel.lastIndex(of: "/") else { return "" }
        return String(rel[...idx])
    }

    private struct DotfileDeny { let deniesAll: Bool; let status: Int }
    private func dotfileDenyBaseline(origin: String) async -> DotfileDeny {
        guard let u = URL(string: "\(origin)/.ws_absent_\(UUID().uuidString)"),
              let r = await http.fetch(u) else { return DotfileDeny(deniesAll: false, status: 0) }
        return DotfileDeny(deniesAll: r.status == 401 || r.status == 403, status: r.status)
    }

    private func huntEnvFiles(origin: String, pages: [HTTPResponse], scripts: [URL],
                              soft: Soft404Baseline) async {
        var dirs = Set(Wordlists.commonDirs)
        var realDirs: Set<String> = [""]                        
        for p in pages { for d in dirPrefixes(of: p.finalURL) { dirs.insert(d); realDirs.insert(d) } }
        for s in scripts { for d in dirPrefixes(of: s) { dirs.insert(d); realDirs.insert(d) } }
        let dirList = Array(dirs).sorted().prefix(intensity.maxEnvDirs)

        let curated = Set(SensitivePath.all.map { $0.path })
        var candidates: [String] = []
        var seen = Set<String>()
        for d in dirList {
            for name in Wordlists.envFileNames {
                let rel = d + name
                if curated.contains(rel) { continue }
                if seen.insert(rel).inserted { candidates.append(rel) }
            }
        }
        let (openDirs, blockedDirs) = await probeEnv(
            Array(candidates.prefix(intensity.maxEnvProbes)), origin: origin, soft: soft)

        let baseline = await dotfileDenyBaseline(origin: origin)

        let blockedPromising = baseline.deniesAll ? blockedDirs.intersection(realDirs) : blockedDirs
        for dir in blockedPromising.sorted() {
            addFinding(hiddenEnvFinding(dir: dir, origin: origin, baseline: baseline))
        }

        let promising = openDirs.union(blockedPromising)
        if !promising.isEmpty {
            setStatus("Recovering hidden .env contents...")
            await huntEnvLeakVectors(dirs: promising, origin: origin, soft: soft)
        }
    }

    private func probeEnv(_ relPaths: [String], origin: String,
                          soft: Soft404Baseline) async -> (open: Set<String>, blocked: Set<String>) {
        let client = http
        let total = max(relPaths.count, 1)
        var done = 0
        var openDirs = Set<String>()
        var blockedDirs = Set<String>()
        for batch in relPaths.chunked(into: 12) {
            await withTaskGroup(of: (String, HTTPResponse?).self) { group in
                for rel in batch {
                    let url = URL(string: "\(origin)/\(rel)")
                    group.addTask {
                        guard let url else { return (rel, nil) }
                        return (rel, await client.fetch(url))
                    }
                }
                for await (rel, resp) in group {
                    guard let resp else { continue }
                    if (resp.status == 200 || resp.status == 206),
                       !soft.looksLikeThis(resp), !looksLikeNotFound(resp), looksLikeEnv(resp) {
                        addFinding(envFinding(rel: rel, response: resp))
                        log("‼︎ Exposed env file: /\(rel)")
                        addFindings(SecretScanner.scan(resp.text, source: resp.finalURL.absoluteString))
                        openDirs.insert(directoryOf(rel))
                    } else if resp.status == 401 || resp.status == 403 {
                        blockedDirs.insert(directoryOf(rel))
                    }
                }
            }
            done += batch.count
            setStatus("Hunting .env... \(min(done, total))/\(total)")
        }
        return (openDirs, blockedDirs)
    }

    private func huntEnvLeakVectors(dirs: Set<String>, origin: String, soft: Soft404Baseline) async {
        let client = http
        let dirList = Array(dirs).sorted().prefix(intensity == .maximum ? 20 : 12)
        for dir in dirList {

            var jobs: [(String, Bool, String)] = []
            for name in Wordlists.envLeakSiblings { jobs.append((dir + name, false, "sibling")) }
            for u in bypassVariants(dir: dir, origin: origin) { jobs.append((u, true, "bypass")) }

            for batch in jobs.chunked(into: 12) {
                await withTaskGroup(of: (String, String, HTTPResponse?).self) { group in
                    for (target, isAbs, kind) in batch {
                        let url = isAbs ? URL(string: target) : URL(string: "\(origin)/\(target)")
                        group.addTask {
                            guard let url else { return (target, kind, nil) }
                            return (target, kind, await client.fetch(url))
                        }
                    }
                    for await (target, kind, resp) in group {
                        guard let resp, resp.status == 200 || resp.status == 206,
                              !soft.looksLikeThis(resp), !looksLikeNotFound(resp),
                              resp.body.count > 0 else { continue }
                        classifyLeak(target: target, kind: kind, resp: resp)
                    }
                }
            }
        }
    }

    private func bypassVariants(dir: String, origin: String) -> [String] {
        let b = "\(dir).env"
        return [
            "\(origin)//\(b)",         
            "\(origin)/./\(b)",        
            "\(origin)/\(b).",         
            "\(origin)/\(b)%20",       
            "\(origin)/\(dir)%2eenv",  
            "\(origin)/\(b)?",         
        ]
    }

    private func classifyLeak(target: String, kind: String, resp: HTTPResponse) {
        let url = resp.finalURL.absoluteString
        let isSwap = resp.text.contains("b0VIM") || target.hasSuffix(".swp")
            || target.hasSuffix(".swo") || target.hasSuffix(".un~")

        if kind == "bypass", looksLikeEnv(resp) {
            addFinding(bypassFinding(response: resp))
            log("‼︎ .env deny bypassed → \(url)")
            addFindings(SecretScanner.scan(resp.text, source: url))
        } else if isSwap, resp.text.contains("b0VIM") {
            addFinding(swapFinding(response: resp))
            log("‼︎ Editor swap of .env exposed → \(url)")
            addFindings(SecretScanner.scan(resp.text, source: url))
        } else if looksLikeEnv(resp) {
            addFinding(envLeakFinding(response: resp))
            log("‼︎ .env contents leaked via copy → \(url)")
            addFindings(SecretScanner.scan(resp.text, source: url))
        } else {

            let lower = resp.text.lowercased()
            if !lower.contains("<html"), !lower.contains("<!doctype html") {
                let hits = SecretScanner.scan(resp.text, source: url)
                if !hits.isEmpty { addFindings(hits) }
            }
        }
    }

    private func hiddenEnvFinding(dir: String, origin: String, baseline: DotfileDeny) -> Finding {
        let path = "/\(dir).env"
        let specific = !baseline.deniesAll
        return Finding(
            title: "Hidden .env present but access-restricted: \(path)",
            severity: specific ? .medium : .low,
            category: "Exposed Secret File",
            location: "\(origin)\(path)",
            detail: specific
                ? "A request to \(path) returned HTTP 403/401 while unrelated dotfiles return 404 - the file is present but specifically protected."
                : "A request to \(path) returned HTTP \(baseline.status). The server blanket-denies dotfiles, so existence is unconfirmed, but an .env here is plausible.",
            evidence: "URL: \(origin)\(path)\nStatus: 401/403 (blocked)\nDotfile-deny baseline: \(baseline.deniesAll ? "yes (blanket)" : "no (\(baseline.status))")",
            exploit: "The file itself is blocked, but its contents commonly leak via editor swap files (.env.swp), non-dotfile copies (env.bak), or path-normalization bypasses - all checked automatically. If any succeeds, the credentials are fully recoverable.",
            remediation: "Keep env files out of the web root entirely (not just deny them). Also deny swap/backup extensions (.swp, .bak, ~, .save) and non-dotfile copies. Normalize paths to prevent deny-rule bypasses.",
            reference: "CWE-538: File and Directory Information Exposure")
    }

    private func bypassFinding(response: HTTPResponse) -> Finding {
        Finding(
            title: "Access-control bypass: .env served via path trick",
            severity: .critical,
            category: "Exposed Secret File",
            location: response.finalURL.absoluteString,
            detail: "A path-normalization variant of a blocked .env returned the file contents (HTTP \(response.status)), bypassing the server's deny rule.",
            evidence: "Working URL: \(response.finalURL.absoluteString)\nHTTP \(response.status), \(response.body.count) bytes\nPreview: \(snippet(response.text, max: 160))",
            exploit: "The .env deny rule is bypassable, so an attacker downloads the full environment file - database passwords, API keys, and app secrets - despite the block.",
            remediation: "Do not rely on a location/deny rule; move env files outside the web root. Normalize request paths (collapse //, /./, trailing dots, %2e) before applying access rules. Rotate every value in the file.",
            reference: "CWE-22 / CWE-538")
    }

    private func swapFinding(response: HTTPResponse) -> Finding {
        Finding(
            title: "Editor swap file of .env exposed (contents recoverable)",
            severity: .high,
            category: "Exposed Secret File",
            location: response.finalURL.absoluteString,
            detail: "A Vim swap/undo file for the env file is downloadable. Swap files embed the buffer's contents and are usually not covered by a .env deny rule.",
            evidence: "URL: \(response.finalURL.absoluteString)\nHTTP \(response.status), \(response.body.count) bytes (Vim swap: 'b0VIM' signature present)",
            exploit: "The swap file contains the .env's text; an attacker recovers it with `vim -r` (or by reading the strings), obtaining the same credentials the .env holds.",
            remediation: "Delete stray .swp/.swo/.un~ files from the server, deny those extensions at the web server, and rotate any secrets they contained.",
            reference: "CWE-530: Exposure of Backup File")
    }

    private func envLeakFinding(response: HTTPResponse) -> Finding {
        Finding(
            title: "Hidden .env contents leaked via readable copy",
            severity: .critical,
            category: "Exposed Secret File",
            location: response.finalURL.absoluteString,
            detail: "A backup/non-dotfile copy of the env file is world-readable (HTTP \(response.status)) and slips past the .env deny rule, exposing the same contents.",
            evidence: "URL: \(response.finalURL.absoluteString)\nHTTP \(response.status), \(response.body.count) bytes\nPreview: \(snippet(response.text, max: 160))",
            exploit: "The copy holds the live environment secrets (DB passwords, API keys) in plaintext, downloadable directly even though /.env itself is blocked.",
            remediation: "Remove backup/copy files (env.bak, env, *.save) from the web root, deny those names/extensions, and rotate every value - assume compromise.",
            reference: "CWE-530")
    }

    private func probeDiscoveredPaths(_ urls: Set<String>, alreadySeen: Set<String>,
                                      soft: Soft404Baseline) async {
        let targets = urls.subtracting(alreadySeen).compactMap { URL(string: $0) }
        guard !targets.isEmpty else { return }
        let client = http
        let capped = Array(targets.prefix(intensity.maxJSPathProbes))
        log("• Probing \(capped.count) config/secret path(s) referenced in JS")
        for batch in capped.chunked(into: 10) {
            await withTaskGroup(of: HTTPResponse?.self) { group in
                for u in batch { group.addTask { await client.fetch(u) } }
                for await resp in group {
                    guard let resp, resp.status == 200 || resp.status == 206,
                          !soft.looksLikeThis(resp), !looksLikeNotFound(resp) else { continue }
                    let lower = resp.text.lowercased()
                    let isHTML = lower.contains("<html") || lower.contains("<!doctype html")
                    if looksLikeEnv(resp) {
                        addFinding(envFinding(rel: relativePath(of: resp.finalURL), response: resp))
                        log("‼︎ Exposed env file (via JS): \(resp.finalURL.path)")
                    }
                    if !isHTML {
                        addFindings(SecretScanner.scan(resp.text, source: resp.finalURL.absoluteString))
                    }
                }
            }
        }
    }

    private func looksLikeEnv(_ r: HTTPResponse) -> Bool {
        let text = r.text
        let lower = text.lowercased()
        if lower.contains("<html") || lower.contains("<!doctype html") { return false }
        return regexMatches("(?m)^\\s*[A-Za-z_][A-Za-z0-9_]{1,}\\s*=", in: text)
    }

    private func relativePath(of url: URL) -> String {
        let p = url.path.hasPrefix("/") ? String(url.path.dropFirst()) : url.path
        return p.isEmpty ? url.absoluteString : p
    }

    private func envFinding(rel: String, response: HTTPResponse) -> Finding {
        Finding(
            title: "Exposed environment file: /\(rel)",
            severity: .critical,
            category: "Exposed Secret File",
            location: response.finalURL.absoluteString,
            detail: "A request to /\(rel) returned a readable environment file (HTTP \(response.status)). Env files hold credentials in plaintext.",
            evidence: "URL: \(response.finalURL.absoluteString)\nHTTP \(response.status), \(response.body.count) bytes\nPreview: \(snippet(response.text, max: 160))",
            exploit: "Environment files typically contain database passwords, API keys, and app secrets. An attacker downloads this directly and gains credentials to your backend, database, and third-party services.",
            remediation: "Never place env files inside the web root. Deny dotfiles at the web server and keep secrets in a secrets manager. Rotate every value in the file immediately - assume it is compromised.",
            reference: "CWE-538: File and Directory Information Exposure")
    }

    private func isConfirmed(_ p: SensitivePath, _ r: HTTPResponse, soft: Soft404Baseline) -> Bool {
        guard r.status == 200 || r.status == 206 else { return false }
        if soft.looksLikeThis(r) { return false }
        let text = r.text
        let lower = text.lowercased()
        for bad in p.mustNotContain where lower.contains(bad.lowercased()) { return false }
        var ok = true
        if let rx = p.mustContainRegex { ok = ok && regexMatches(rx, in: text) }
        if !p.mustContain.isEmpty { ok = ok && p.mustContain.contains { lower.contains($0.lowercased()) } }
        return ok
    }

    private func looksLikeNotFound(_ r: HTTPResponse) -> Bool {
        let l = r.text.prefix(4000).lowercased()
        guard l.contains("404") else { return false }
        return l.contains("not found") || l.contains("page not found")
            || l.contains("doesn't exist") || l.contains("does not exist")
            || l.contains("cannot be found")
    }

    private func computeSoft404(origin: String) async -> Soft404Baseline {
        let probe = "\(origin)/zz_ws_nonexistent_\(UUID().uuidString).probe"
        if let u = URL(string: probe), let r = await http.fetch(u) {
            return Soft404Baseline(
                is200ForEverything: r.status == 200,
                bodyLength: r.body.count,
                bodyHash: String(r.text.prefix(2000)).hashValue)
        }
        return Soft404Baseline(is200ForEverything: false, bodyLength: 0, bodyHash: 0)
    }

    private func normalizeTarget(_ raw: String) -> URL? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if !s.contains("://") { s = "https://" + s }
        guard let url = URL(string: s), url.host != nil else { return nil }
        return url
    }

    private func originString(of url: URL) -> String {
        let scheme = url.scheme ?? "https"
        let host = url.host ?? ""
        if let port = url.port { return "\(scheme)://\(host):\(port)" }
        return "\(scheme)://\(host)"
    }

    private func addFinding(_ f: Finding) {
        guard findingKeys.insert(f.dedupeKey).inserted else { return }
        findings.append(f)
    }

    private func addFindings(_ list: [Finding]) {
        for f in list { addFinding(f) }
    }

    private func setStatus(_ s: String) { statusText = s }

    private func log(_ s: String) { logLines.append(s) }

    private func finishScan() {
        finishedAt = Date()
        isScanning = false
        let disc = discovered.isEmpty ? "" : " · \(discovered.count) URLs"
        statusText = "Done - \(findings.count) findings\(disc)"
        let c = counts
        log("■ Scan complete: \(c[.critical] ?? 0) critical, \(c[.high] ?? 0) high, \(c[.medium] ?? 0) medium, \(c[.low] ?? 0) low, \(c[.info] ?? 0) info."
            + (discovered.isEmpty ? "" : " Discovered \(discovered.count) reachable URL(s)."))
    }

    /// Plain-text export of the discovered-URL hit list.
    var discoveredText: String {
        var out = "# Discovered URLs (\(discovered.count))\n"
        out += "# code\tbytes\tkind\turl\ttitle\n"
        for d in discovered.sorted(by: { $0.url < $1.url }) {
            out += "\(d.status)\t\(d.length)\t\(d.kind.label)\t\(d.url)\t\(d.title ?? "")\n"
        }
        return out
    }
}

// MARK: - DiscoveryReporter

extension ScannerViewModel: DiscoveryReporter {
    func discoveryFinding(_ f: Finding) { addFinding(f) }

    func discoveryURL(_ d: DiscoveredURL) {
        guard discoveredKeys.insert(d.url).inserted else { return }
        discovered.append(d)
    }

    func discoveryProgress(done: Int, total: Int, status: String) {
        if total > 0 { progress = min(0.99, 0.05 + 0.94 * Double(done) / Double(total)) }
        statusText = status
    }

    func discoveryLog(_ s: String) { log(s) }
}
