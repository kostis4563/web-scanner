import Foundation
import Combine

struct Soft404Baseline {
    let is200ForEverything: Bool
    let bodyLength: Int
    let bodyHash: Int

    var lengthTolerance: Int = 48

    var altHash: Int = 0

    func looksLikeThis(_ r: HTTPResponse) -> Bool {
        guard is200ForEverything, r.status == 200 else { return false }
        if abs(r.body.count - bodyLength) <= lengthTolerance { return true }
        let h = String(r.text.prefix(2000)).hashValue
        return h == bodyHash || (altHash != 0 && h == altHash)
    }
}

@MainActor
final class ScannerViewModel: ObservableObject {

    @Published var target: String = ""
    @Published var authorized: Bool = true
    @Published var deepSecretScan: Bool = true
    @Published var revealSecrets: Bool = true
    @Published var intensity: ScanIntensity = .deep
    @Published var mode: ScanMode = .siteScan

    @Published var wordlistText: String = ""
    @Published var wordlistSource: String = ""
    @Published var extensionsText: String = ""
    @Published var scanDirectories: Bool = true
    @Published var recursive: Bool = false
    @Published var maxRequests: Int = 3000

    @Published var maskMaxLength: Int = 44
    @Published var maskLimit: Int = 2000

    @Published var portProfile: PortProfile = .top100
    @Published var customPorts: String = ""
    @Published var grabBanners: Bool = true
    @Published var portTimeoutMs: Int = 1200
    @Published var portConcurrency: Int = 256
    @Published var portRetryFiltered: Bool = true
    @Published var portAdaptiveTimeout: Bool = true
    @Published var portProbeTLS: Bool = true
    @Published var showFilteredPorts: Bool = false
    @Published var portSearch: String = ""

    @Published var dbExtraPorts: String = ""
    @Published var dbTestAuth: Bool = true

    @Published var customHeaders: String = ""
    @Published var cookie: String = ""
    @Published var basicAuth: String = ""
    @Published var userAgentOverride: String = ""
    @Published var requestDelayMs: Int = 0

    @Published var excludeCodesText: String = "404"
    @Published var onlyCodesText: String = ""
    @Published var notInTitle: String = ""

    @Published private(set) var findings: [Finding] = []
    @Published private(set) var discovered: [DiscoveredURL] = []
    @Published private(set) var openPorts: [OpenPort] = []

    @Published private(set) var scanHost: String = ""
    @Published private(set) var perfReport: PerformanceReport?
    @Published private(set) var infoReport: InfoReport?
    @Published private(set) var dbReport: DatabaseReport?

    @Published var isScanning: Bool = false

    @Published var progress: Double = 0 { didSet { recomputeDisplayProgress() } }

    @Published var displayProgress: Double = 0
    @Published var statusText: String = "Idle"
    @Published var logLines: [String] = []

    @Published var scannedURL: URL?
    @Published var startedAt: Date?
    @Published var finishedAt: Date?

    private var progressWindow: (Double, Double)? = nil

    private var isOrchestrating = false

    private func recomputeDisplayProgress() {
        if let w = progressWindow {
            displayProgress = w.0 + (w.1 - w.0) * max(0, min(1, progress))
        } else {
            displayProgress = progress
        }
    }

    private let http = HTTPClient()
    private var findingKeys = Set<String>()
    private var discoveredKeys = Set<String>()
    private var openPortKeys = Set<Int>()
    private var seenJWTs = Set<String>()

    private var seenPassiveTitles = Set<String>()

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

    private var activeScanTask: Task<Void, Never>?

    var canStop: Bool { isScanning && activeScanTask != nil }

    func stopScan() {
        guard let task = activeScanTask else { return }
        log("■ Cancelling scan - finishing work already in flight...")
        setStatus("Cancelling scan...")
        task.cancel()
    }

    func startScan() {
        guard !isScanning else { return }
        guard authorized else {
            log("⚠️ Confirm you are authorized to test this target before scanning.")
            return
        }

        var base: URL?
        if mode == .fullAudit || mode == .siteScan || mode == .contentDiscovery || mode == .portScan || mode == .database || mode == .hostScan || mode == .info || mode == .performance || mode == .userView {
            guard let b = normalizeTarget(target) else {
                log("❌ Enter a valid host, e.g. example.com or 93.184.216.34")
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
        scanHost = base?.host ?? target.trimmingCharacters(in: .whitespacesAndNewlines)

        switch mode {
        case .fullAudit:
            scannedURL = base
            let host = base?.host ?? target.trimmingCharacters(in: .whitespacesAndNewlines)
            activeScanTask = Task { await runFullAudit(host: host, base: base!) }
        case .siteScan:
            scannedURL = base
            activeScanTask = Task { await runScan(base!) }
        case .contentDiscovery:
            scannedURL = base
            activeScanTask = Task { await runContentDiscoveryScan(base!) }
        case .urlMask:
            activeScanTask = Task { await runURLMask(target.trimmingCharacters(in: .whitespacesAndNewlines)) }
        case .portScan:
            scannedURL = base
            let host = base?.host ?? target.trimmingCharacters(in: .whitespacesAndNewlines)
            activeScanTask = Task { await runPortScan(host: host, base: base!) }
        case .database:
            scannedURL = base
            let host = base?.host ?? target.trimmingCharacters(in: .whitespacesAndNewlines)
            activeScanTask = Task { await runDatabaseScan(host: host, base: base!) }
        case .hostScan:
            scannedURL = base
            let host = base?.host ?? target.trimmingCharacters(in: .whitespacesAndNewlines)
            activeScanTask = Task { await runHostScan(host: host, base: base!) }
        case .info:
            scannedURL = base
            let host = base?.host ?? target.trimmingCharacters(in: .whitespacesAndNewlines)
            activeScanTask = Task { await runInfoScan(host: host, base: base!) }
        case .performance:
            scannedURL = base
            let host = base?.host ?? target.trimmingCharacters(in: .whitespacesAndNewlines)
            activeScanTask = Task { await runPerformanceScan(host: host, base: base!) }
        case .userView:
            scannedURL = base
            let host = base?.host ?? target.trimmingCharacters(in: .whitespacesAndNewlines)
            activeScanTask = Task { await runUserViewScan(host: host, base: base!) }
        }
    }

    private func resetState() {
        findings = []
        findingKeys = []
        discovered = []
        discoveredKeys = []
        openPorts = []
        openPortKeys = []
        scanHost = ""
        perfReport = nil
        infoReport = nil
        dbReport = nil
        seenJWTs = []
        seenPassiveTitles = []
        logLines = []
        progressWindow = nil
        isOrchestrating = false
        progress = 0
        displayProgress = 0
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

    private func runPortScan(host: String, base: URL) async {
        log("▶︎ Port scan on \(host)")
        let ports = portsForScan()
        guard !ports.isEmpty else {
            log("❌ No ports to scan - check the custom port list.")
            finishScan()
            return
        }
        if portProfile == .full {
            log("⚠️ Full 1-65535 scan can take several minutes and is noisy.")
        }

        var cfg = PortScanner.Config()
        cfg.timeoutMs = max(200, portTimeoutMs)
        cfg.grabBanners = grabBanners
        cfg.concurrency = PortScanner.usableConcurrency(max(8, portConcurrency))
        cfg.retryFiltered = portRetryFiltered
        cfg.adaptiveTimeout = portAdaptiveTimeout
        cfg.probeTLS = portProbeTLS

        var opts: [String] = ["\(cfg.concurrency) in flight", "\(cfg.timeoutMs) ms timeout"]
        if cfg.adaptiveTimeout { opts.append("adaptive") }
        if cfg.grabBanners { opts.append("banners") }
        if cfg.probeTLS { opts.append("TLS detect") }
        if cfg.retryFiltered { opts.append("retry") }
        log("• Scanning \(ports.count) TCP port(s) - \(opts.joined(separator: ", "))")
        if cfg.concurrency < portConcurrency {
            log("• Concurrency clamped to \(cfg.concurrency) by this process's file-descriptor limit.")
        }
        setStatus("Scanning ports...")

        await performPortScan(host: host, ports: ports, config: cfg, band: (0.02, 0.98))
        progress = 1.0
        finishScan()
    }

    private func runDatabaseScan(host: String, base: URL) async {
        log("▶︎ Database scan on \(host)")

        setStatus("Connecting...")
        var home = await http.fetch(base)
        if home == nil, base.scheme == "https", let u = URL(string: "http://\(host)/") {
            home = await http.fetch(u)
        }
        var origin = originString(of: base)
        if let home {
            scannedURL = home.finalURL
            origin = originString(of: home.finalURL)
            log("✓ Web server responded - HTTP \(home.status) at \(home.finalURL.absoluteString)")

            addFindings(SecretScanner.scan(home.text, source: home.finalURL.absoluteString))
        } else {
            log("• No web server on 80/443 - continuing with network-level database checks.")
        }
        progress = 0.10

        let sweepPorts = databasePorts()
        let extra = PortCatalog.parseSpec(dbExtraPorts).filter { !PortCatalog.databaseSweep.contains($0) }
        if !extra.isEmpty { log("• Including \(extra.count) custom port(s): \(extra.map(String.init).joined(separator: ", "))") }
        setStatus("Sweeping database & cache ports...")
        var cfg = PortScanner.Config()
        cfg.timeoutMs = 900
        cfg.grabBanners = true
        cfg.concurrency = 60
        let summary = await performPortScan(host: host, ports: sweepPorts,
                                            config: cfg, band: (0.10, 0.46),
                                            confirmBlanketServices: false)

        let openPorts = summary.ports.filter { $0.state == .open }

        if dbTestAuth {

            let candidatePorts: [Int] = summary.blanketOpen
                ? databasePorts()
                : openPorts.map { $0.port }
            if summary.blanketOpen {
                log("• Host accepts every connection - confirming each database port directly at the protocol layer.")
            }
            setStatus("Testing for unauthenticated database access...")
            await probeUnauthDatabases(host: host, ports: candidatePorts)

            await probeDatabaseProtocols(host: host, ports: candidatePorts)
        }
        progress = 0.56

        guard let home else {
            let hostUp = summary.openCount > 0 || summary.closedCount > 0
            dbReport = DatabaseChecks.buildReport(host: host, hostReachable: hostUp,
                                                  webReachable: false, summary: summary, findings: findings)
            progress = 1.0
            log("✓ Database scan complete (no web server for admin-tool / dump checks).")
            finishScan()
            return
        }
        let webHost = home.finalURL.host ?? host
        let soft = await computeSoft404(origin: origin)

        setStatus("Probing web database admin tools...")
        await probeDatabaseWebPaths(DatabaseChecks.adminTools, origin: origin, soft: soft, band: (0.52, 0.63))

        setStatus("Hunting leaked database credentials...")
        await probeDatabaseWebPaths(DatabaseChecks.configFiles, origin: origin, soft: soft, band: (0.63, 0.74))

        setStatus("Hunting exposed dumps & database files...")
        await probeDatabaseWebPaths(DatabaseChecks.exposedFiles, origin: origin, soft: soft, band: (0.74, 0.84))

        setStatus("Testing SQL error & injection surface...")
        await probeDatabaseErrors(origin: origin, home: home)
        if intensity.testInjection {

            var pages: [HTTPResponse] = [home]
            let client = http
            let links = Array(ExtraChecks.extractLinks(html: home.text, base: home.finalURL, sameHost: webHost).prefix(12))
            if !links.isEmpty {
                setStatus("Discovering parameterized URLs...")
                await withTaskGroup(of: HTTPResponse?.self) { group in
                    for l in links { group.addTask { await client.fetch(l) } }
                    for await r in group where r != nil { pages.append(r!) }
                }
            }
            let targets = injectionTargets(pages: pages, host: webHost, limit: intensity.maxInjectionTargets)
            if targets.isEmpty {
                log("• No query-parameter URLs found - testing headers & forms only.")
            } else {
                log("• Testing \(targets.count) parameterized URL(s) for SQL/NoSQL injection")
                setStatus("Testing for SQL injection (error & boolean-based)...")
                await probeSQLInjection(targets: targets, forceBlind: true)
                setStatus("Testing for time-based blind SQL injection...")
                await probeTimeSQLi(targets: targets)
                setStatus("Testing for NoSQL injection...")
                await probeNoSQLInjection(targets: targets, forceBlind: true)
            }

            setStatus("Testing request headers for SQL injection...")
            await probeHeaderSQLi(targets: targets.isEmpty ? [home.finalURL] : targets)
            setStatus("Testing form fields for SQL injection...")
            await probeFormSQLi(pages: pages, host: webHost)
        }

        dbReport = DatabaseChecks.buildReport(host: webHost, hostReachable: true,
                                              webReachable: true, summary: summary, findings: findings)
        progress = 1.0
        log("✓ Database scan complete · posture: \(dbReport?.posture.label ?? "-")")
        finishScan()
    }

    private func databasePorts() -> [Int] {
        var set = Set(PortCatalog.databaseSweep)
        for p in PortCatalog.parseSpec(dbExtraPorts) { set.insert(p) }
        return set.sorted()
    }

    private func probeDatabaseProtocols(host: String, ports: [Int]) async {
        let targets = Set(ports).sorted()
        await withTaskGroup(of: DatabaseProbe.Result?.self) { group in
            for port in targets {
                group.addTask { await DatabaseProbe.probe(host: host, port: port, timeoutMs: 2500) }
            }
            for await res in group {
                guard let res, res.unauthenticated else { continue }
                addFinding(DatabaseChecks.protocolUnauthFinding(res, host: host))
                log("‼︎ Unauthenticated \(res.service) access on port \(res.port) (no credentials required)")
            }
        }
    }

    private static let blanketDBProtocolPorts: Set<Int> = [6379, 6380, 11211, 5432, 5433, 27017, 27018, 27019]

    private func confirmBlanketDatabases(host: String, scannedPorts: [Int],
                                         emitFindings: Bool) async -> [OpenPort] {
        let candidates = Set(scannedPorts).intersection(Self.blanketDBProtocolPorts)
        guard !candidates.isEmpty else { return [] }
        var rows: [OpenPort] = []
        await withTaskGroup(of: DatabaseProbe.Result?.self) { group in
            for port in candidates.sorted() {
                group.addTask { await DatabaseProbe.probe(host: host, port: port, timeoutMs: 2500) }
            }
            for await res in group {
                guard let res, res.unauthenticated else { continue }
                var op = OpenPort(port: res.port, state: .open, service: res.service,
                                  banner: res.evidence.isEmpty ? nil : res.evidence, risk: .critical)
                op.product = res.service
                op.version = res.version
                rows.append(op)
                log("‼︎ Confirmed unauthenticated \(res.service) on port \(res.port) (verified at the protocol layer)")
                if emitFindings { addFinding(DatabaseChecks.protocolUnauthFinding(res, host: host)) }
            }
        }
        return rows.sorted { $0.port < $1.port }
    }

    private func probeUnauthDatabases(host: String, ports: [Int]) async {
        let portSet = Set(ports)
        for svc in DatabaseChecks.httpServices {
            for port in svc.ports where portSet.contains(port) {
                let root = "\(svc.scheme)://\(host):\(port)/"
                guard let url = URL(string: root + svc.probePath) else { continue }
                if let r = await http.fetch(url), DatabaseChecks.confirms(svc, r) {
                    addFinding(DatabaseChecks.httpServiceFinding(svc, host: host, port: port, r: r))
                    log("‼︎ Unauthenticated \(svc.name) access on port \(port)")
                }
            }
        }
    }

    private func probeDatabaseWebPaths(_ paths: [DatabaseChecks.WebPath], origin: String,
                                       soft: Soft404Baseline, band: (Double, Double)) async {
        let client = http
        let total = max(paths.count, 1)
        var done = 0
        for batch in paths.chunked(into: 8) {
            await withTaskGroup(of: (DatabaseChecks.WebPath, HTTPResponse?).self) { group in
                for p in batch {
                    let url = URL(string: "\(origin)/\(p.path)")
                    group.addTask {
                        guard let url else { return (p, nil) }
                        return (p, await client.fetch(url))
                    }
                }
                for await (p, resp) in group {
                    guard let resp, !soft.looksLikeThis(resp), !looksLikeNotFound(resp),
                          p.confirmed(resp) else { continue }
                    let captured = p.scanForSecrets ? capturedBody(resp.text) : nil
                    if p.category == "Database Credential Exposure" {
                        let leak = DatabaseChecks.credentialLeak(in: resp.text)
                        addFinding(DatabaseChecks.credentialFinding(p, resp, leak: leak, capturedContent: captured))
                    } else {
                        addFinding(DatabaseChecks.finding(p, resp, capturedContent: captured))
                    }
                    log("‼︎ \(p.title): /\(p.path)")
                    if p.scanForSecrets {
                        addFindings(SecretScanner.scan(resp.text, source: resp.finalURL.absoluteString))
                    }
                }
            }
            done += batch.count
            progress = band.0 + (band.1 - band.0) * Double(min(done, total)) / Double(total)
            setStatus("Probing database paths... \(min(done, total))/\(total)")
        }
    }

    private func probeDatabaseErrors(origin: String, home: HTTPResponse) async {
        var reported = Set<String>()
        func consider(_ url: URL, _ text: String) {
            guard let (dbms, sample) = ActiveProbes.sqlErrorDetail(in: text),
                  reported.insert(dbms).inserted else { return }
            addFinding(DatabaseChecks.dbmsErrorFinding(url: url, dbms: dbms, sample: sample))
            log("‼︎ Database error message exposed (\(dbms)) at \(url.path)")
        }
        consider(home.finalURL, home.text)
        let probes = ["'", "%27", "?id=1%27", "?q=%27%22"]
        for p in probes where reported.count < 2 {
            guard let u = URL(string: "\(origin)/\(p)") else { continue }
            if let r = await http.fetch(u) { consider(r.finalURL, r.text) }
        }
    }

    private func injectionTargets(pages: [HTTPResponse], host: String, limit: Int = 20) -> [URL] {
        var urls: [URL] = []
        var seen = Set<String>()
        func consider(_ u: URL) {
            guard u.host == host,
                  let comps = URLComponents(url: u, resolvingAgainstBaseURL: false),
                  let items = comps.queryItems, !items.isEmpty else { return }
            let key = u.path + "?" + items.map { $0.name.lowercased() }.sorted().joined(separator: ",")
            if seen.insert(key).inserted { urls.append(u) }
        }
        for pg in pages {
            consider(pg.finalURL)
            for l in ExtraChecks.extractLinks(html: pg.text, base: pg.finalURL, sameHost: host) { consider(l) }
            for f in ExtraChecks.getFormTargets(html: pg.text, pageURL: pg.finalURL, sameHost: host) { consider(f) }
            if urls.count >= limit { break }
        }
        return Array(urls.prefix(limit))
    }

    private func runInfoScan(host: String, base: URL) async {
        log("▶︎ Gathering general info on \(host)")
        setStatus("Fetching homepage...")

        var home = await http.fetch(base)
        if home == nil, base.scheme == "https", let u = URL(string: "http://\(host)/") {
            home = await http.fetch(u)
        }
        if let home {
            scannedURL = home.finalURL
            log("✓ Web server responded - HTTP \(home.status) at \(home.finalURL.absoluteString)")
            addFinding(Checks.generalInfo(home))
            addFindings(VersionChecks.fromHeaders(home))
            addFindings(VersionChecks.fromHTML(home.text, location: home.finalURL.absoluteString))
        } else {
            log("• No web server on 80/443 - continuing with host-level info only.")
        }
        progress = 0.3

        setStatus("Profiling host & infrastructure...")
        let (profile, hostFindings) = await HostRecon.inspect(host: host, home: home, http: http,
                                                              lookupIPInfo: true, probeDirectIP: false,
                                                              enumerateDNS: true)
        addFindings(hostFindings)
        progress = 0.5

        setStatus("Mapping backend / database / service ports...")
        var cfg = PortScanner.Config()
        cfg.timeoutMs = 700
        cfg.grabBanners = true
        cfg.concurrency = 60
        let summary = await performPortScan(host: host, ports: PortCatalog.infoServicePorts.map { $0.port },
                                            config: cfg, band: (0.5, 0.95), emitFindings: false,
                                            confirmBlanketServices: false)
        let services = InfoChecks.discoveredServices(from: summary)
        log(services.isEmpty
            ? "• No open service ports detected"
            : "• Discovered services: " + services.map { "\($0.name) → \($0.port)" }.joined(separator: ", "))

        infoReport = InfoChecks.build(home: home, profile: profile, services: services)
        progress = 1.0
        log("✓ Info overview complete")
        finishScan()
    }

    private func runPerformanceScan(host: String, base: URL) async {
        log("▶︎ Measuring performance of \(host)")
        setStatus("Measuring server response time...")

        var samples = await http.timedFetches(base, count: 4)
        if samples.isEmpty, base.scheme == "https", let u = URL(string: "http://\(host)/") {
            log("• HTTPS request failed - retrying over HTTP.")
            samples = await http.timedFetches(u, count: 4)
        }
        guard let home = samples.first?.response else {
            log("❌ Could not reach \(host). Scan aborted.")
            finishScan()
            return
        }
        scannedURL = home.finalURL
        log("✓ Connected - HTTP \(home.status) at \(home.finalURL.absoluteString)")
        if let best = samples.compactMap({ $0.timing.ttfbMs }).min() {
            let proto = samples.compactMap { $0.timing.networkProtocol }.first ?? "?"
            log(String(format: "• TTFB best %.0f ms · %@", best, proto))
        }
        progress = 0.45

        setStatus("Discovering page assets...")
        let discoveredAssets = PerformanceChecks.assetURLs(html: home.text, base: home.finalURL,
                                                           limit: PerformanceChecks.discoverCap)
        let toFetch = Array(discoveredAssets.prefix(PerformanceChecks.fetchCap))
        log("• \(discoveredAssets.count) asset(s) referenced; measuring \(toFetch.count)")
        setStatus("Measuring \(toFetch.count) page asset(s)...")
        let assets = await http.timedAssetFetches(toFetch)
        progress = 0.9

        setStatus("Scoring & analyzing...")
        let report = PerformanceChecks.report(home: home,
                                              samples: samples.map { $0.timing },
                                              discoveredAssetCount: discoveredAssets.count,
                                              assets: assets)
        perfReport = report
        addFindings(report.findings)

        progress = 1.0
        log("✓ Performance score: \(report.score)/100 (\(report.grade)) · page \(PerformanceChecks.kb(report.totalWireBytes)) over \(report.requestCount) request(s)")
        finishScan()
    }

    private func runUserViewScan(host: String, base: URL) async {
        log("▶︎ User-view assessment of \(host)")
        setStatus("Loading the page as a user would...")

        var home = await http.fetch(base)
        if home == nil, base.scheme == "https", let u = URL(string: "http://\(host)/") {
            home = await http.fetch(u)
        }
        guard let home else {
            log("❌ Could not reach \(host). Scan aborted.")
            finishScan()
            return
        }
        scannedURL = home.finalURL
        let sameHost = home.finalURL.host ?? host
        let origin = originString(of: home.finalURL)
        log("✓ Loaded HTTP \(home.status) at \(home.finalURL.absoluteString)")
        progress = 0.1

        setStatus("Following the pages a user would click through...")
        var pages: [HTTPResponse] = [home]
        var seenPages = Set([home.finalURL.absoluteString])
        let links = ExtraChecks.extractLinks(html: home.text, base: home.finalURL, sameHost: sameHost)
        let prioritized = links.sorted { a, b in
            userViewRelevance(a.absoluteString) > userViewRelevance(b.absoluteString)
        }
        for link in prioritized.prefix(8) {
            guard seenPages.insert(link.absoluteString).inserted else { continue }
            if let r = await http.fetch(link) { pages.append(r) }
        }
        log("• Reviewed \(pages.count) page(s) as a signed-out user")
        progress = 0.35

        setStatus("Reading the JavaScript the browser runs...")
        var scriptText = ""
        var scriptURLs: [URL] = []
        var seenScripts = Set<String>()
        for page in pages {
            for s in ExtraChecks.extractScriptSources(html: page.text, base: page.finalURL, sameHost: sameHost) {
                if seenScripts.insert(s.absoluteString).inserted { scriptURLs.append(s) }
            }

            scriptText += "\n" + page.text
        }
        for s in scriptURLs.prefix(14) {
            if let r = await http.fetch(s) { scriptText += "\n" + r.text }
        }
        log("• Read \(min(scriptURLs.count, 14)) script file(s) + inline scripts")
        progress = 0.6

        setStatus("Checking what a user can see, change and bypass...")
        var interestingPaths = Set<String>()
        for page in pages {
            addFindings(UserViewChecks.registrationSurface(html: page.text, pageURL: page.finalURL))
            addFindings(UserViewChecks.tamperableFormControls(html: page.text, pageURL: page.finalURL))
            addFindings(UserViewChecks.clientSideValidationOnly(html: page.text, pageURL: page.finalURL))
            addFindings(UserViewChecks.formInventory(html: page.text, pageURL: page.finalURL))
            addFindings(UserViewChecks.externalResources(html: page.text, pageURL: page.finalURL, sameHost: sameHost))
            addFindings(ExtraChecks.csrfFindings(html: page.text, pageURL: page.finalURL))
            addFindings(ExtraChecks.mixedContent(html: page.text, pageURL: page.finalURL))
            addFindings(ExtraChecks.htmlCommentLeaks(html: page.text, pageURL: page.finalURL))
            for f in UserViewChecks.jsReadableSessionCookies(page) where seenPassiveTitles.insert(f.title).inserted {
                addFinding(f)
            }
            if let cj = UserViewChecks.clickjacking(page), seenPassiveTitles.insert(cj.title).inserted {
                addFinding(cj)
            }

            for u in JSAnalysis.interestingPaths(from: page.text, base: page.finalURL, sameHost: sameHost) {
                interestingPaths.insert(u.absoluteString)
            }
        }

        let jsSource = home.finalURL.absoluteString
        addFindings(UserViewChecks.clientSideTrustFlags(js: scriptText, source: jsSource))
        addFindings(UserViewChecks.browserStorageAuth(js: scriptText, source: jsSource))
        addFindings(UserViewChecks.clientSideRedirectGate(js: scriptText, source: jsSource))
        addFindings(SecretScanner.scan(scriptText, source: jsSource))
        addFindings(JSAnalysis.makeSinkFindings(JSAnalysis.sinkHits(in: scriptText, source: jsSource)))
        var seenJWT = Set<String>()
        for token in AccessControl.extractJWTs(scriptText) where seenJWT.insert(token).inserted {
            addFindings(AccessControl.jwtFindings(token: token, source: jsSource))
            if seenJWT.count >= 6 { break }
        }

        for u in JSAnalysis.interestingPaths(from: scriptText, base: home.finalURL, sameHost: sameHost) {
            interestingPaths.insert(u.absoluteString)
        }
        let reachable = interestingPaths.compactMap { URL(string: $0) }.sorted { $0.absoluteString < $1.absoluteString }
        addFindings(UserViewChecks.browserReachableEndpoints(Array(reachable.prefix(40)), source: jsSource))
        progress = 0.5

        setStatus("Actively testing what a user could exploit...")
        var targets: [URL] = []
        var seenTarget = Set<String>()
        func addTarget(_ u: URL) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty else { return }
            if seenTarget.insert(u.absoluteString).inserted { targets.append(u) }
        }
        for page in pages {
            for l in ExtraChecks.extractLinks(html: page.text, base: page.finalURL, sameHost: sameHost) { addTarget(l) }
            for g in ExtraChecks.getFormTargets(html: page.text, pageURL: page.finalURL, sameHost: sameHost) { addTarget(g) }
        }
        for u in reachable { addTarget(u) }
        log("• \(targets.count) user-controllable request target(s) with parameters")

        await probeReflected(homeURL: home.finalURL, targets: targets)
        await probeOpenRedirect(homeURL: home.finalURL, targets: targets)
        await probeSQLInjection(targets: targets)
        await probeTraversal(targets: targets)
        checkIDOR(pages: pages, host: sameHost)

        await probeActiveIDOR(pages: pages, host: sameHost)

        await probeDebugParams(targets: targets)
        progress = 0.62

        setStatus("Fetching browser-called APIs as an anonymous user...")
        await probeAPIDataExposure(endpoints: reachable)
        progress = 0.68

        setStatus("Testing CORS on browser-called API endpoints...")
        await probeUserViewCORS(endpoints: [home.finalURL] + reachable)

        setStatus("Checking for exposed GraphQL introspection...")
        await probeGraphQL(origin: origin, endpoints: reachable)
        progress = 0.78

        setStatus("Trying privileged routes as an anonymous user...")
        var candidates = UserViewChecks.privilegedClientPaths(
            html: pages.map { $0.text }.joined(separator: "\n"),
            js: scriptText, base: home.finalURL, sameHost: sameHost)
        if candidates.isEmpty {
            candidates = AccessControl.candidatePaths(max: 12)
        }
        candidates = Array(candidates.prefix(15))
        log("• Probing \(candidates.count) privileged route(s) anonymously")
        var reached = 0
        var softGuesses = 0
        for path in candidates {
            guard let u = URL(string: "\(origin)/\(path)") else { continue }
            guard let r = await http.fetch(u) else { continue }
            if r.status == 200 {
                let body = r.text
                if AccessControl.looksLikeLogin(body) { continue }
                if AccessControl.looksSensitive(body) {

                    addFinding(AccessControl.missingAuthFinding(path: path, response: r))
                    log("‼︎ Unauthenticated access to /\(path)")
                    reached += 1
                } else if body.count > 512, softGuesses < 8 {

                    addFinding(UserViewChecks.reachableRouteFinding(path: path, response: r))
                    softGuesses += 1
                }
            } else if r.status == 401 || r.status == 403 {

                await probeRouteBypass(path: path, origin: origin, blockedLen: r.body.count)
            }
        }
        if reached > 0 { log("• \(reached) privileged route(s) answered without a login") }
        progress = 1.0
        log("✓ User-view assessment complete")
        finishScan()
    }

    private func probeRouteBypass(path: String, origin: String, blockedLen: Int) async {
        let client = http
        let variants = AccessControl.bypassVariants(for: path, origin: origin, includeExtendedHeaders: true)
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
                          !AccessControl.looksLikeLogin(resp.text), resp.body.count > 0 else { continue }
                    let confident = AccessControl.looksSensitive(resp.text)
                    guard confident || resp.body.count > blockedLen + 512 else { continue }
                    addFinding(AccessControl.bypassFinding(path: path, technique: v.label,
                                                           response: resp, confident: confident))
                    log("‼︎ Access-control bypass on /\(path) via \(v.label)")
                    reported = true
                }
            }
        }
    }

    private func probeUserViewCORS(endpoints: [URL]) async {
        let evilOrigin = "https://scanner-cors-probe.example.com"
        var seenPath = Set<String>()
        var reflectedTitles = Set<String>()
        var count = 0
        for ep in endpoints {
            guard count < 20, seenPath.insert(ep.path).inserted else { continue }
            count += 1
            guard let r = await http.fetch(ep, extraHeaders: ["Origin": evilOrigin]) else { continue }
            let reflectsArbitrary = r.header("access-control-allow-origin") == evilOrigin
            if let cors = Checks.cors(r, reflectedOrigin: evilOrigin), reflectedTitles.insert(cors.title).inserted {
                addFinding(cors)
                log("‼︎ CORS: \(cors.title) at \(ep.path)")
            }
            guard !reflectsArbitrary else { continue }
            if let r2 = await http.fetch(ep, extraHeaders: ["Origin": "null"]),
               let f = Checks.corsNullOrigin(r2), reflectedTitles.insert(f.title).inserted {
                addFinding(f)
            }
            let host = ep.host ?? ""
            let bypasses: [(String, String)] = [
                ("https://\(host).cors-probe.example.com", "prefixes (startsWith match)"),
                ("https://cors-probe-\(host)", "suffixes (endsWith match)"),
            ]
            for b in bypasses {
                if let r3 = await http.fetch(ep, extraHeaders: ["Origin": b.0]),
                   let f = Checks.corsTrustBypass(r3, sentOrigin: b.0, technique: b.1),
                   reflectedTitles.insert(f.title + b.1).inserted {
                    addFinding(f)
                    log("‼︎ CORS origin-validation bypass (\(b.1)) at \(ep.path)")
                }
            }
        }
    }

    private func probeGraphQL(origin: String, endpoints: [URL]) async {
        var paths = Set<String>()
        for ep in endpoints {
            let p = ep.path.lowercased()
            if p.contains("graphql") || p.contains("graphiql") || p.contains("/gql") { paths.insert(ep.path) }
        }

        for common in ["/graphql", "/api/graphql", "/v1/graphql", "/query"] { paths.insert(common) }
        let query = #"{"query":"{__schema{queryType{name} types{name}}}"}"#.data(using: .utf8)
        var tested = 0
        for path in paths {
            guard tested < 8, let u = URL(string: path, relativeTo: URL(string: origin))?.absoluteURL else { continue }
            tested += 1
            guard let r = await http.fetch(u, method: "POST",
                                           extraHeaders: ["Content-Type": "application/json"],
                                           body: query) else { continue }
            if let f = ExtraChecks.graphqlIntrospection(r) {
                addFinding(f)
                log("‼︎ GraphQL introspection enabled at \(path)")
            }
        }
    }

    private func probeActiveIDOR(pages: [HTTPResponse], host: String) async {
        var urls: [URL] = []
        var seen = Set<String>()
        for pg in pages {
            if seen.insert(pg.finalURL.absoluteString).inserted { urls.append(pg.finalURL) }
            for l in ExtraChecks.extractLinks(html: pg.text, base: pg.finalURL, sameHost: host) {
                if seen.insert(l.absoluteString).inserted { urls.append(l) }
            }
        }
        let candidates = AccessControl.idorCandidates(in: urls)
        var confirmed = 0
        for c in candidates.prefix(10) {
            guard confirmed < 4, let original = URL(string: c.url) else { continue }
            guard let baseResp = await http.fetch(original), baseResp.status == 200,
                  baseResp.body.count > 80, !AccessControl.looksLikeLogin(baseResp.text) else { continue }
            for neighbor in idorNeighbors(of: original) {
                guard let r = await http.fetch(neighbor), r.status == 200,
                      r.body.count > 80, !AccessControl.looksLikeLogin(r.text) else { continue }

                let a = baseResp.body.count, b = r.body.count
                let similarSize = Double(min(a, b)) / Double(max(a, b)) > 0.3
                guard r.text != baseResp.text, similarSize else { continue }
                addFinding(UserViewChecks.confirmedIDORFinding(original: original, neighbor: neighbor, response: r))
                log("‼︎ Confirmed IDOR: \(neighbor.path)\(neighbor.query.map { "?\($0)" } ?? "")")
                confirmed += 1
                break
            }
        }
    }

    private func idorNeighbors(of url: URL) -> [URL] {
        var out: [URL] = []

        if var comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let items = comps.queryItems {
            for (i, it) in items.enumerated() {
                guard let v = it.value, let n = Int(v), n >= 1, v.count <= 12 else { continue }
                for delta in [-1, 1] {
                    let nv = n + delta
                    guard nv >= 0 else { continue }
                    var copy = items
                    copy[i].value = String(nv)
                    comps.queryItems = copy
                    if let u = comps.url { out.append(u) }
                }
                break
            }
        }

        if out.isEmpty {
            let segs = url.pathComponents
            if let last = segs.last, let n = Int(last), n >= 1, last.count <= 12 {
                for delta in [-1, 1] {
                    let nv = n + delta
                    guard nv >= 0 else { continue }
                    var comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
                    var newSegs = segs
                    newSegs[newSegs.count - 1] = String(nv)
                    comps?.path = newSegs.joined(separator: "/").replacingOccurrences(of: "//", with: "/")
                    if let u = comps?.url { out.append(u) }
                }
            }
        }
        return Array(out.prefix(2))
    }

    private func probeDebugParams(targets: [URL]) async {
        let inject = ["debug", "admin", "test", "is_admin", "role", "show_all", "verbose"]
        var reported = 0

        for u in targets.prefix(intensity.maxInjectionTargets) {
            guard reported < 5 else { break }
            guard let base = await http.fetch(u), base.status == 200 else { continue }
            let baseLen = base.body.count
            guard baseLen > 0 else { continue }
            for p in inject {
                let value = (p == "role") ? "admin" : "true"
                guard let test = injectedURL(u, param: p, payload: value, append: false),
                      test.absoluteString != u.absoluteString,
                      let r = await http.fetch(test), r.status == 200 else { continue }

                let grew = r.body.count > baseLen + max(200, baseLen / 4)
                guard grew, r.text != base.text else { continue }
                addFinding(UserViewChecks.debugParamFinding(original: u, tampered: test, param: p, response: r))
                log("‼︎ Response changed when adding &\(p)= at \(u.path)")
                reported += 1
                break
            }
        }
    }

    private func probeAPIDataExposure(endpoints: [URL]) async {
        var seen = Set<String>()
        var flagged = 0
        for ep in endpoints {
            guard flagged < 8, seen.insert(ep.path).inserted else { continue }

            let p = ep.path.lowercased()
            let apiish = p.contains("/api/") || p.contains("/v1/") || p.contains("/v2/")
                || p.contains("/rest/") || p.contains(".json") || p.contains("/graphql")
            guard apiish else { continue }
            guard let r = await http.fetch(ep), r.status == 200, r.body.count > 20 else { continue }
            let ct = r.contentType.lowercased()
            guard ct.contains("json") || ct.contains("javascript") || ct.contains("text/plain") || r.text.hasPrefix("{") || r.text.hasPrefix("[") else { continue }
            let keys = UserViewChecks.sensitiveDataKeys(in: r.text)
            guard keys.count >= 2 else { continue }
            addFinding(UserViewChecks.unauthApiExposureFinding(endpoint: ep, keys: keys, response: r))
            log("‼︎ Unauthenticated API data at \(ep.path): \(keys.prefix(4).joined(separator: ", "))")
            flagged += 1
        }
    }

    private func userViewRelevance(_ url: String) -> Int {
        let l = url.lowercased()
        let strong = ["register", "signup", "sign-up", "join", "account", "checkout",
                      "cart", "profile", "settings", "dashboard", "login", "order"]
        return strong.reduce(0) { $0 + (l.contains($1) ? 1 : 0) }
    }

    private func runHostScan(host: String, base: URL) async {
        log("▶︎ Host scan on \(host)")
        setStatus("Connecting...")

        var home = await http.fetch(base)
        if home == nil, base.scheme == "https", let u = URL(string: "http://\(host)/") {
            home = await http.fetch(u)
        }
        if let home {
            scannedURL = home.finalURL
            log("✓ Web server responded - HTTP \(home.status) at \(home.finalURL.absoluteString)")
        } else {
            log("• No web server on 80/443 - continuing with host-level checks only.")
        }
        progress = 0.10

        setStatus("Profiling host & infrastructure...")
        addFindings(await HostRecon.profile(host: host, home: home, http: http,
                                            lookupIPInfo: true, probeDirectIP: true,
                                            enumerateDNS: true))
        progress = 0.35

        setStatus("Checking TLS certificate & protocol versions...")
        if await http.tlsValid(host: host) == false {
            addFinding(Checks.invalidTLS(host))
            log("• TLS certificate is invalid/untrusted")
        }
        let tlsPort = UInt16(home?.finalURL.port ?? base.port ?? 443)
        addFindings(await TLSChecks.legacyProtocols(host: host, port: tlsPort))
        addFindings(await CertChecks.inspect(host: host, port: tlsPort))
        progress = 0.50

        if let home {
            addFinding(Checks.generalInfo(home))
            addFindings(Checks.infoDisclosure(home))
            addFindings(VersionChecks.fromHeaders(home))
            addFindings(VersionChecks.fromHTML(home.text, location: home.finalURL.absoluteString))
        }
        progress = 0.55

        setStatus("Sweeping risky TCP ports...")
        var cfg = PortScanner.Config()
        cfg.timeoutMs = 900
        cfg.grabBanners = true
        cfg.concurrency = 80
        await performPortScan(host: host, ports: PortCatalog.siteSweep, config: cfg, band: (0.55, 0.90))

        setStatus("Assessing DDoS amplification exposure...")
        let ips = await HostRecon.resolveHost(host)
        if let ip = ips.v4.first ?? ips.v6.first, !HostRecon.isPrivateOrReserved(ip) {
            let openTCP = openPorts.filter { $0.state == .open }.map { $0.port }
            addFindings(await DDoSExposure.assess(host: host, ip: ip, openTCPPorts: openTCP))
        } else {
            log("• Skipping DDoS exposure (no public IP resolved).")
        }
        progress = 1.0
        finishScan()
    }

    private func portsForScan() -> [Int] {
        PortCatalog.ports(for: portProfile, custom: customPorts)
    }

    @discardableResult
    private func performPortScan(host: String, ports: [Int], config: PortScanner.Config,
                                 band: (Double, Double), emitFindings: Bool = true,
                                 confirmBlanketServices: Bool = true) async -> PortScanSummary {
        let scanner = PortScanner()
        var summary = await scanner.scan(host: host, ports: ports, config: config) { [weak self] done, total, found in
            Task { @MainActor in
                guard let self else { return }
                self.appendPorts(found)
                let frac = total > 0 ? Double(done) / Double(total) : 1
                self.progress = min(band.1, band.0 + (band.1 - band.0) * frac)
                let openCount = self.openPorts.filter { $0.state == .open }.count
                self.setStatus("Scanning ports... \(done)/\(total) - \(openCount) open")
            }
        }

        appendPorts(summary.ports)
        for op in summary.ports where op.state == .open {
            var line = "+ \(op.port)/tcp open - \(op.service)"
            if let v = op.version { line += " (\(op.product ?? op.service) \(v))" }
            if let tls = op.tlsInfo { line += " [\(tls)]" }
            if op.unexpectedService == true {
                line += "  ⟵ not the service this port normally runs"
            }
            log(line)
            guard emitFindings else { continue }
            if let f = PortCatalog.exposureFinding(hostLabel: host, port: op) {
                addFinding(f)
                log("‼︎ \(f.title)")
            }
            if let banner = op.banner {
                addFindings(VersionChecks.fromBanner(banner, service: op.service,
                                                     location: "\(host):\(op.port)"))
            }

            let looksSSH = op.port == 22 || op.service == "SSH" || (op.banner?.hasPrefix("SSH-") ?? false)
            if looksSSH, let res = await SSHAudit.audit(host: host, port: op.port,
                                                        timeoutMs: max(2000, config.timeoutMs * 2)) {
                let sshFindings = SSHAudit.findings(host: host, port: op.port, result: res)
                addFindings(sshFindings)
                for f in sshFindings { log("‼︎ \(f.title)") }

                if let b = res.banner, !b.isEmpty {
                    addFindings(VersionChecks.fromBanner(b, service: "SSH", location: "\(host):\(op.port)"))
                }
            }
        }

        if summary.blanketOpen, confirmBlanketServices {
            setStatus("Verifying real services behind the blanket-open host...")
            let already = Set(summary.ports.map { $0.port })
            let confirmed = await confirmBlanketDatabases(host: host, scannedPorts: ports,
                                                          emitFindings: emitFindings)
                .filter { !already.contains($0.port) }
            if !confirmed.isEmpty {
                appendPorts(confirmed)
                summary.ports.append(contentsOf: confirmed)
                summary.ports.sort { $0.port < $1.port }
                log("• Confirmed \(confirmed.count) real service(s) at the protocol layer despite the blanket-open host.")
            }
        }

        if summary.blanketOpen {
            log("⚠️ Host answered OPEN on \(summary.blanketOpenCount) port(s) with nothing behind them - it accepts every connection (firewall / load-balancer / tarpit). Those bogus \"unknown\" ports were dropped; only \(summary.shownOpenCount) positively-identified service(s) are listed.")
            if emitFindings {
                addFinding(blanketOpenFinding(host: host, count: summary.blanketOpenCount, scanned: summary.scanned))
            }
        }
        let openLabel = summary.blanketOpen ? summary.shownOpenCount : summary.openCount
        var tail = "• Ports: \(openLabel) open, \(summary.closedCount) closed, \(summary.filteredCount) filtered (of \(summary.scanned))"
        if summary.blanketOpen { tail += " · \(summary.blanketOpenCount) bogus opens suppressed" }
        if summary.elapsed > 0 {
            tail += String(format: " in %.1fs — %.0f ports/s", summary.elapsed, summary.rate)
        }
        log(tail)
        if summary.recovered > 0 {
            log("• Retry pass recovered \(summary.recovered) port(s) that timed out on the first probe.")
        }
        if summary.cancelled {
            log("■ Stopped early - \(summary.probed) of \(summary.scanned) port(s) were probed; the rest were never tested.")
        }
        if summary.filteredHidden > 0 {
            log("• \(summary.filteredHidden) further filtered port(s) not listed - the host drops these silently.")
        }
        if summary.effectiveTimeoutMs > 0, summary.effectiveTimeoutMs < config.timeoutMs {
            log("• Timeout tightened to \(summary.effectiveTimeoutMs) ms from the measured round-trip.")
        }
        if !summary.hostResponsive && summary.scanned > 0 {
            log("⚠️ No port answered at all - the host is down, or a firewall is dropping every probe. Results are inconclusive, not \"all closed\".")
        }
        return summary
    }

    private func blanketOpenFinding(host: String, count: Int, scanned: Int) -> Finding {
        Finding(
            title: "Host accepts connections on all ports (port scan unreliable)",
            severity: .info,
            category: "Network",
            location: host,
            detail: "The host completed the TCP handshake on \(count) of \(scanned) probed port(s) without any service responding behind them. A real host does not run that many services - this is the signature of a device that accepts every SYN: a firewall/IPS in a \"reject-by-drop, accept-by-open\" mode, a load balancer or reverse proxy, a port-knocking tarpit, or a cloud security layer. Because every port appears open, a TCP connect scan cannot tell which ports host real services.",
            evidence: "\(count) port(s) opened with no banner and no TLS handshake.",
            exploit: "None directly. The value is diagnostic: results from a plain connect scan against this host are not trustworthy for enumerating services.",
            remediation: "To enumerate real services here, use techniques that see past a blanket-accept layer: probe each candidate port at the application layer (send an HTTP request, TLS ClientHello, or service-specific handshake) and keep only ports that answer correctly; or scan from a network position behind the firewall/LB. Only the positively-identified services (with a banner or TLS) are listed above.",
            reference: nil
        )
    }

    private func appendPorts(_ ports: [OpenPort]) {
        var changed = false
        for op in ports {
            if openPortKeys.insert(op.port).inserted {
                openPorts.append(op)
                changed = true
            } else if let i = openPorts.firstIndex(where: { $0.port == op.port }),
                      openPorts[i].state != op.state || openPorts[i].banner != op.banner {
                var updated = op
                updated.id = openPorts[i].id
                openPorts[i] = updated
            }
        }
        if changed { openPorts.sort { $0.port < $1.port } }
    }

    private func runFullAudit(host: String, base: URL) async {
        isOrchestrating = true

        let previousIntensity = intensity
        intensity = .maximum
        log("▶︎ Full Audit on \(host) - running every category at MAXIMUM depth + all 65,535 ports")
        log("• The most exhaustive scan: deep crawl, wide subdomain enum, blind SQLi, exhaustive .env hunt,")
        log("  every frontend file scanned, and a full 1-65535 TCP port sweep with banner grabbing.")
        log("• Very slow (can run 20-40+ minutes) and noisy. Eight phases will run back-to-back.")

        struct Phase { let name: String; let band: (Double, Double); let run: () async -> Void }
        let phases: [Phase] = [
            Phase(name: "Info",              band: (0.00, 0.06)) { await self.runInfoScan(host: host, base: base) },
            Phase(name: "Performance",       band: (0.06, 0.12)) { await self.runPerformanceScan(host: host, base: base) },
            Phase(name: "Host",              band: (0.12, 0.20)) { await self.runHostScan(host: host, base: base) },
            Phase(name: "Database",          band: (0.20, 0.32)) { await self.runDatabaseScan(host: host, base: base) },
            Phase(name: "Site vulnerabilities", band: (0.32, 0.58)) { await self.runScan(base) },
            Phase(name: "User View",         band: (0.58, 0.64)) { await self.runUserViewScan(host: host, base: base) },
            Phase(name: "Content discovery", band: (0.64, 0.74)) { await self.runContentDiscoveryScan(base) },
            Phase(name: "Port scan (all 65535)", band: (0.74, 1.00)) { await self.runAllPortsPhase(host: host) },
        ]

        for (i, phase) in phases.enumerated() {
            guard !Task.isCancelled else { break }
            progressWindow = phase.band
            progress = 0
            log("── Phase \(i + 1)/\(phases.count): \(phase.name) ──")
            setStatus("Full Audit \(i + 1)/\(phases.count) · \(phase.name)…")
            await phase.run()
            guard !Task.isCancelled else { break }
            progress = 1
        }

        progressWindow = nil
        isOrchestrating = false
        intensity = previousIntensity
        guard !Task.isCancelled else {
            finishCancelledScan()
            return
        }
        progress = 1.0
        finishScan()
    }

    private func runAllPortsPhase(host: String) async {
        let ports = PortCatalog.ports(for: .full)
        log("• Scanning all \(ports.count) TCP ports (1-65535) with banners - the slow part; please wait.")
        var cfg = PortScanner.Config()
        cfg.timeoutMs = max(1500, portTimeoutMs)
        cfg.grabBanners = true
        cfg.concurrency = PortScanner.usableConcurrency(max(8, portConcurrency))
        cfg.retryFiltered = true
        cfg.adaptiveTimeout = portAdaptiveTimeout
        cfg.probeTLS = true
        setStatus("Scanning all 65,535 ports…")
        await performPortScan(host: host, ports: ports, config: cfg, band: (0.0, 1.0))
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
            let certFindings = await CertChecks.inspect(host: host0, port: UInt16(base.port ?? 443))
            if !certFindings.isEmpty { log("• Certificate health: \(certFindings.count) issue(s)") }
            addFindings(certFindings)
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
        addFinding(Checks.generalInfo(home))
        addFindings(Checks.securityHeaders(home))
        addFindings(Checks.infoDisclosure(home))
        addFindings(VersionChecks.fromHeaders(home))
        addFindings(VersionChecks.fromHTML(home.text, location: home.finalURL.absoluteString))
        recordPassiveCookies(home)
        addFindings(ExtraChecks.mixedContent(html: home.text, pageURL: home.finalURL))
        addFindings(ExtraChecks.csrfFindings(html: home.text, pageURL: home.finalURL))
        if intensity != .quick {
            addFindings(ExtraChecks.htmlCommentLeaks(html: home.text, pageURL: home.finalURL))
            addFindings(ExtraChecks.internalAddressLeaks(text: home.text, pageURL: home.finalURL))
        }
        if intensity.checkSRI { addFindings(ExtraChecks.sriFindings(html: home.text, pageURL: home.finalURL, sameHost: host)) }
        if Checks.isDirectoryListing(home) { addFinding(Checks.directoryListing(home.finalURL)) }

        setStatus("Profiling host & infrastructure...")
        addFindings(await HostRecon.profile(host: host, home: home, http: http,
                                            lookupIPInfo: true,
                                            probeDirectIP: intensity != .quick,
                                            enumerateDNS: intensity != .quick))

        setStatus("Testing CORS policy...")
        let evilOrigin = "https://scanner-cors-probe.example.com"
        var corsReflectsArbitrary = false
        if let r = await http.fetch(home.finalURL, extraHeaders: ["Origin": evilOrigin]) {
            corsReflectsArbitrary = r.header("access-control-allow-origin") == evilOrigin
            if let cors = Checks.cors(r, reflectedOrigin: evilOrigin) { addFinding(cors) }
        }

        if intensity != .quick && !corsReflectsArbitrary {

            if let r = await http.fetch(home.finalURL, extraHeaders: ["Origin": "null"]),
               let f = Checks.corsNullOrigin(r) { addFinding(f) }

            let bypasses: [(origin: String, technique: String)] = [
                ("https://\(host).cors-probe.example.com", "prefixes (startsWith match)"),
                ("https://cors-probe-\(host)", "suffixes (endsWith match)"),
            ]
            for b in bypasses {
                if let r = await http.fetch(home.finalURL, extraHeaders: ["Origin": b.origin]),
                   let f = Checks.corsTrustBypass(r, sentOrigin: b.origin, technique: b.technique) {
                    addFinding(f)
                    log("‼︎ CORS origin-validation bypass (\(b.technique))")
                }
            }
        }

        if home.finalURL.scheme == "https", intensity.checkTLSVersions {
            setStatus("Checking TLS protocol versions...")
            let tlsPort = UInt16(home.finalURL.port ?? 443)
            let tlsFindings = await TLSChecks.legacyProtocols(host: host, port: tlsPort)
            if !tlsFindings.isEmpty { log("• Legacy TLS (1.0/1.1) still accepted") }
            addFindings(tlsFindings)
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

        if intensity.crawlSite {
            for pg in pages where pg.finalURL.absoluteString != home.finalURL.absoluteString {
                recordPassiveCookies(pg)
            }
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

            let traceCanary = "wsxst" + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(10)
            if let r = await http.fetch(home.finalURL, method: "TRACE",
                                        extraHeaders: [ActiveProbes.traceCanaryHeader: String(traceCanary)]),
               ActiveProbes.traceEchoed(r, canaryValue: String(traceCanary)) {
                addFinding(ActiveProbes.traceFinding(pageURL: home.finalURL))
                log("‼︎ HTTP TRACE enabled (Cross-Site Tracing)")
            }
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

        if intensity.sweepPorts {
            setStatus("Sweeping risky TCP ports...")
            var cfg = PortScanner.Config()
            cfg.timeoutMs = 800
            cfg.grabBanners = true
            cfg.concurrency = 80
            await performPortScan(host: host, ports: PortCatalog.siteSweep, config: cfg, band: (0.78, 0.80))
        }
        progress = max(progress, 0.80)

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
                    addFindings(ExtraChecks.htmlCommentLeaks(html: pg.text, pageURL: pg.finalURL))
                    addFindings(ExtraChecks.internalAddressLeaks(text: pg.text, pageURL: pg.finalURL))
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

            for f in ExtraChecks.getFormTargets(html: pg.text, pageURL: pg.finalURL, sameHost: host) { consider(f) }
            if paramURLs.count >= intensity.maxInjectionTargets * 3 { break }
        }
        let targets = Array(paramURLs.prefix(intensity.maxInjectionTargets))

        await probeOpenRedirect(homeURL: home.finalURL, targets: targets)
        await probeReflected(homeURL: home.finalURL, targets: targets)
        await probeReflectedForms(home: home, pages: pages)
        await probeHostHeader(url: home.finalURL)
        await probeSQLInjection(targets: targets)
        await probeNoSQLInjection(targets: targets)
        await probeSSTI(targets: targets)
        await probeCommandInjection(targets: targets)
        await probeSSRF(homeURL: home.finalURL, targets: targets)
        await probeTraversal(targets: targets)
        if intensity == .maximum { await probeTimeSQLi(targets: targets) }
        if intensity.testCRLF { await probeCRLF(homeURL: home.finalURL, targets: targets) }
    }

    private func injectedURL(_ url: URL, param: String, payload: String, append: Bool) -> URL? {
        guard var comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        var items = comps.queryItems ?? []
        if let i = items.firstIndex(where: { $0.name.lowercased() == param.lowercased() }) {
            let cur = items[i].value ?? ""
            items[i].value = append ? cur + payload : payload
        } else {
            items.append(URLQueryItem(name: param, value: payload))
        }
        comps.queryItems = items
        return comps.url
    }

    private func fileParamRank(_ name: String) -> Int {
        let n = name.lowercased()
        let strong = ["file", "path", "filepath", "template", "include", "page",
                      "doc", "document", "view", "load", "download", "dir",
                      "folder", "img", "image", "read", "cat", "url", "src", "name"]
        if strong.contains(where: { n == $0 || n.contains($0) }) { return 0 }
        return 1
    }

    private func probeSQLInjection(targets: [URL], forceBlind: Bool = false) async {
        let runBoolean = intensity == .maximum || forceBlind
        for u in targets.prefix(intensity.maxInjectionTargets) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty else { continue }

            guard let base = await http.fetch(u),
                  ActiveProbes.sqlErrorSignature(in: base.text) == nil else { continue }
            let baseLen = base.body.count
            var reported = false
            for name in items.map({ $0.name }).prefix(4) where !reported {

                for payload in ActiveProbes.sqliPayloads {
                    guard let test = injectedURL(u, param: name, payload: payload, append: true),
                          let r = await http.fetch(test),
                          let dbms = ActiveProbes.sqlErrorSignature(in: r.text) else { continue }
                    addFinding(ActiveProbes.sqlInjectionFinding(pageURL: u, param: name, dbms: dbms, poc: test))
                    log("‼︎ SQL injection (\(dbms)) via ?\(name)=")
                    reported = true
                    break
                }
                if reported { break }

                if runBoolean, await booleanSQLi(u, param: name, baseLen: baseLen) {
                    addFinding(ActiveProbes.sqlInjectionBooleanFinding(pageURL: u, param: name))
                    log("‼︎ SQL injection (boolean-based) via ?\(name)=")
                    reported = true
                }
            }
        }
    }

    private func booleanSQLi(_ u: URL, param: String, baseLen: Int) async -> Bool {
        func len(_ payload: String) async -> Int? {
            guard let url = injectedURL(u, param: param, payload: payload, append: true),
                  let r = await http.fetch(url), r.status == 200,
                  ActiveProbes.sqlErrorSignature(in: r.text) == nil else { return nil }
            return r.body.count
        }
        guard let t1 = await len("' AND '1'='1"), let f1 = await len("' AND '1'='2"),
              let t2 = await len("' AND '1'='1"), let f2 = await len("' AND '1'='2") else { return false }
        let trueStable  = abs(t1 - t2) <= max(32, t1 / 40)
        let falseStable = abs(f1 - f2) <= max(32, f1 / 40)
        let trueNearBase = abs(t1 - baseLen) <= max(64, baseLen / 20)
        let falseDiffers = abs(f1 - t1) > max(128, t1 / 8)
        return trueStable && falseStable && trueNearBase && falseDiffers
    }

    private func probeNoSQLInjection(targets: [URL], forceBlind: Bool = false) async {
        let runOperatorDiff = intensity == .maximum || forceBlind
        for u in targets.prefix(min(intensity.maxInjectionTargets, 10)) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty else { continue }

            guard let base = await http.fetch(u),
                  ActiveProbes.nosqlErrorSignature(in: base.text) == nil else { continue }
            let baseLen = base.body.count
            var reported = false
            for name in items.map({ $0.name }).prefix(3) where !reported {

                for payload in ActiveProbes.nosqlErrorPayloads {
                    guard let test = injectedURL(u, param: name, payload: payload, append: false),
                          let r = await http.fetch(test),
                          ActiveProbes.nosqlErrorSignature(in: r.text) != nil else { continue }
                    addFinding(ActiveProbes.nosqlInjectionFinding(
                        pageURL: u, param: name,
                        evidence: "A MongoDB driver error appeared only after injecting NoSQL syntax; the baseline response had none.",
                        poc: test, errorBased: true))
                    log("‼︎ NoSQL injection (MongoDB) via ?\(name)=")
                    reported = true
                    break
                }
                if reported { break }

                if runOperatorDiff,
                   let (poc, ev) = await nosqlOperatorDiff(u, param: name, baseLen: baseLen) {
                    addFinding(ActiveProbes.nosqlInjectionFinding(
                        pageURL: u, param: name, evidence: ev, poc: poc, errorBased: false))
                    log("‼︎ NoSQL injection (MongoDB operator) via ?\(name)[$ne]=")
                    reported = true
                }
            }
        }
    }

    private func nosqlOperatorURL(_ url: URL, param: String, op: String, value: String) -> URL? {
        guard var comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        var items = (comps.queryItems ?? []).filter { $0.name.lowercased() != param.lowercased() }
        items.append(URLQueryItem(name: "\(param)[\(op)]", value: value))
        comps.queryItems = items
        return comps.url
    }

    private func nosqlOperatorDiff(_ u: URL, param: String, baseLen: Int) async -> (URL, String)? {
        func len(_ url: URL?) async -> Int? {
            guard let url, let r = await http.fetch(url), r.status == 200,
                  ActiveProbes.nosqlErrorSignature(in: r.text) == nil else { return nil }
            return r.body.count
        }
        guard let neURL = nosqlOperatorURL(u, param: param, op: "$ne", value: "ws_nomatch"),
              let plainURL = injectedURL(u, param: param, payload: "ws_nomatch", append: false),
              let ne1 = await len(neURL), let p1 = await len(plainURL),
              let ne2 = await len(neURL), let p2 = await len(plainURL) else { return nil }
        let neStable = abs(ne1 - ne2) <= max(32, ne1 / 40)
        let plainStable = abs(p1 - p2) <= max(32, p1 / 40)
        let differs = abs(ne1 - p1) > max(256, ne1 / 6)
        guard neStable && plainStable && differs else { return nil }
        let ev = "`\(param)[$ne]=ws_nomatch` returned ~\(ne1) bytes (matches all rows) while `\(param)=ws_nomatch` returned ~\(p1) bytes (matches none) - a stable, large difference consistent with operator injection."
        return (neURL, ev)
    }

    private func probeHeaderSQLi(targets: [URL]) async {
        for u in targets.prefix(min(intensity.maxInjectionTargets, 4)) {

            guard let base = await http.fetch(u),
                  ActiveProbes.sqlErrorSignature(in: base.text) == nil else { continue }
            var reported = false
            for header in ActiveProbes.sqliHeaders where !reported {

                let value = header.lowercased().contains("ip") || header == "X-Forwarded-For"
                    ? "127.0.0.1'" : "Mozilla/5.0 sqltest'"
                guard let r = await http.fetch(u, extraHeaders: [header: value]),
                      let dbms = ActiveProbes.sqlErrorSignature(in: r.text) else { continue }

                if let clean = await http.fetch(u, extraHeaders: [header: "127.0.0.1"]),
                   ActiveProbes.sqlErrorSignature(in: clean.text) != nil { continue }
                addFinding(ActiveProbes.sqlInjectionHeaderFinding(pageURL: u, header: header, dbms: dbms))
                log("‼︎ SQL injection via '\(header)' header (\(dbms))")
                reported = true
            }
        }
    }

    private func probeFormSQLi(pages: [HTTPResponse], host: String) async {
        var tested = Set<String>()
        var count = 0
        let cap = min(intensity.maxInjectionTargets, 12)
        for pg in pages {
            for form in ActiveProbes.sqliCandidateForms(html: pg.text, pageURL: pg.finalURL, sameHost: host) {
                guard count < cap else { return }
                let key = form.method + " " + form.action.absoluteString + "?" + form.textFields.sorted().joined(separator: ",")
                guard tested.insert(key).inserted else { continue }
                count += 1

                let token = "ws\(Int.random(in: 1000...9999))"
                func submit(_ fields: [(String, String)]) async -> HTTPResponse? {
                    if form.method == "POST" {
                        var comps = URLComponents()
                        comps.queryItems = fields.map { URLQueryItem(name: $0.0, value: $0.1) }
                        let data = (comps.percentEncodedQuery ?? "").data(using: .utf8)
                        return await http.fetch(form.action, method: "POST",
                                                extraHeaders: ["Content-Type": "application/x-www-form-urlencoded"],
                                                body: data)
                    } else {
                        guard var comps = URLComponents(url: form.action, resolvingAgainstBaseURL: false) else { return nil }
                        comps.queryItems = fields.map { URLQueryItem(name: $0.0, value: $0.1) }
                        guard let url = comps.url else { return nil }
                        return await http.fetch(url)
                    }
                }
                let baseFields = form.hidden + form.textFields.map { ($0, token) }
                guard let base = await submit(baseFields),
                      ActiveProbes.sqlErrorSignature(in: base.text) == nil else { continue }

                for field in form.textFields {
                    let injFields = form.hidden + form.textFields.map { ($0, $0 == field ? token + "'" : token) }
                    guard let r = await submit(injFields),
                          let dbms = ActiveProbes.sqlErrorSignature(in: r.text) else { continue }
                    addFinding(ActiveProbes.sqlInjectionFormFinding(
                        pageURL: pg.finalURL, action: form.action, field: field, method: form.method, dbms: dbms))
                    log("‼︎ SQL injection in \(form.isLogin ? "login " : "")form field '\(field)' (\(dbms)) at \(form.action.path)")
                    break
                }
            }
        }
    }

    private func probeSSTI(targets: [URL]) async {
        for u in targets.prefix(min(intensity.maxInjectionTargets, 12)) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty else { continue }

            if let base = await http.fetch(u), base.text.contains(ActiveProbes.sstiProductString) { continue }
            var reported = false
            for name in items.map({ $0.name }).prefix(3) where !reported {
                for payload in ActiveProbes.sstiPayloads {
                    guard let test = injectedURL(u, param: name, payload: payload, append: false),
                          let r = await http.fetch(test),
                          ActiveProbes.sstiEvaluated(in: r.text) else { continue }
                    addFinding(ActiveProbes.sstiFinding(pageURL: u, param: name, payload: payload, poc: test))
                    log("‼︎ Server-Side Template Injection via ?\(name)=")
                    reported = true
                    break
                }
            }
        }
    }

    private func probeCommandInjection(targets: [URL]) async {
        for u in targets.prefix(min(intensity.maxInjectionTargets, 12)) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty else { continue }
            var reported = false
            for name in items.map({ $0.name }).prefix(3) where !reported {
                let canary = ActiveProbes.CommandCanary()
                for payload in canary.payloads {
                    guard let test = injectedURL(u, param: name, payload: payload, append: false),
                          let r = await http.fetch(test),
                          ActiveProbes.commandInjected(r.text, canary: canary) else { continue }
                    addFinding(ActiveProbes.commandInjectionFinding(pageURL: u, param: name, payload: payload, poc: test))
                    log("‼︎ OS command injection via ?\(name)=")
                    reported = true
                    break
                }
            }
        }
    }

    private func probeSSRF(homeURL: URL, targets: [URL]) async {

        let ssrfDepth = intensity == .maximum ? 9 : (intensity == .aggressive ? 6 : 3)
        let payloads = Array(ActiveProbes.ssrfPayloads.prefix(ssrfDepth))

        let names = Array(ActiveProbes.ssrfParams.prefix(intensity == .maximum ? 16 : 12))
        homepage: for p in names {
            for mp in payloads {
                guard let u = injectedURL(homeURL, param: p, payload: mp, append: false),
                      let r = await http.fetch(u), let leak = ActiveProbes.ssrfLeak(in: r.text) else { continue }
                addFinding(ActiveProbes.ssrfFinding(pageURL: homeURL, param: p, leaked: leak, poc: u))
                log("‼︎ SSRF via ?\(p)= → \(leak)")
                break homepage
            }
        }

        for u in targets.prefix(intensity.maxInjectionTargets) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems else { continue }
            let ssrfNames = items.map { $0.name }.filter { ActiveProbes.ssrfParams.contains($0.lowercased()) }
            var reported = false
            for name in ssrfNames.prefix(3) where !reported {
                for mp in payloads {
                    guard let test = injectedURL(u, param: name, payload: mp, append: false),
                          let r = await http.fetch(test), let leak = ActiveProbes.ssrfLeak(in: r.text) else { continue }
                    addFinding(ActiveProbes.ssrfFinding(pageURL: u, param: name, leaked: leak, poc: test))
                    log("‼︎ SSRF via ?\(name)= at \(u.path)")
                    reported = true
                    break
                }
            }
        }
    }

    private func probeTimeSQLi(targets: [URL]) async {
        func timed(_ url: URL) async -> Double? {
            let start = Date()
            guard await http.fetch(url) != nil else { return nil }
            return Date().timeIntervalSince(start)
        }
        for u in targets.prefix(min(intensity.maxInjectionTargets, 6)) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty,
                  let b1 = await timed(u), let b2 = await timed(u) else { continue }
            let baseline = min(b1, b2)
            guard baseline < 4.0 else { continue }
            var reported = false
            for name in items.map({ $0.name }).prefix(2) where !reported {
                for (inject, control) in ActiveProbes.sqliTimePayloads {
                    guard let injURL = injectedURL(u, param: name, payload: inject, append: true),
                          let injTime = await timed(injURL), injTime - baseline >= 4.0,
                          let ctlURL = injectedURL(u, param: name, payload: control, append: true),
                          let ctlTime = await timed(ctlURL), ctlTime - baseline < 2.0,
                          let confirm = await timed(injURL), confirm - baseline >= 4.0 else { continue }
                    let delay = min(injTime, confirm) - baseline
                    addFinding(ActiveProbes.sqlInjectionTimeFinding(pageURL: u, param: name, payload: inject, delay: delay, poc: injURL))
                    log("‼︎ Time-based blind SQLi via ?\(name)= (~\(String(format: "%.1f", delay))s)")
                    reported = true
                    break
                }
            }
        }
    }

    private func probeReflectedForms(home: HTTPResponse, pages: [HTTPResponse]) async {
        guard intensity == .aggressive || intensity == .maximum else { return }
        let canary = ActiveProbes.ReflectionCanary()
        var tested = Set<String>()
        var count = 0
        for pg in ([home] + pages) {
            guard count < intensity.maxInjectionTargets else { return }
            for form in ActiveProbes.safeSearchPostForms(html: pg.text, pageURL: pg.finalURL) {
                let key = form.action.absoluteString + "|" + form.fields.sorted().joined(separator: ",")
                guard tested.insert(key).inserted else { continue }
                count += 1
                var body = URLComponents()
                body.queryItems = form.fields.map { URLQueryItem(name: $0, value: canary.injected) }
                let data = (body.percentEncodedQuery ?? "").data(using: .utf8)
                if let r = await http.fetch(form.action, method: "POST",
                                            extraHeaders: ["Content-Type": "application/x-www-form-urlencoded"],
                                            body: data),
                   ActiveProbes.isReflectedUnencoded(r, canary: canary) {
                    let ctx = ActiveProbes.reflectionContextLabel(r, canary: canary)
                    addFinding(ActiveProbes.reflectedFormFinding(
                        pageURL: pg.finalURL, action: form.action, fields: form.fields, context: ctx))
                    log("‼︎ Reflected input (POST form) at \(form.action.path)")
                }
                if count >= intensity.maxInjectionTargets { return }
            }
        }
    }

    private func probeTraversal(targets: [URL]) async {
        let payloads = Array(ActiveProbes.traversalPayloads.prefix(intensity == .maximum ? 5 : 3))
        for u in targets.prefix(intensity.maxInjectionTargets) {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty else { continue }
            let ordered = items.map { $0.name }.sorted { fileParamRank($0) < fileParamRank($1) }
            var reported = false
            for name in ordered.prefix(4) where !reported {
                for payload in payloads {
                    guard let test = injectedURL(u, param: name, payload: payload, append: false),
                          let r = await http.fetch(test),
                          r.status == 200 || r.status == 500,
                          let file = ActiveProbes.traversalLeak(in: r.text) else { continue }
                    addFinding(ActiveProbes.pathTraversalFinding(pageURL: u, param: name, file: file, poc: test))
                    log("‼︎ Path traversal via ?\(name)= → \(file)")
                    reported = true
                    break
                }
            }
        }
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
            let ctx = ActiveProbes.reflectionContextLabel(r, canary: canary)
            addFinding(ActiveProbes.reflectedInputFinding(pageURL: homeURL, params: ActiveProbes.reflectionParams, context: ctx))
            log("‼︎ Reflected input without encoding (homepage)")
        }

        for u in targets {
            guard let items = URLComponents(url: u, resolvingAgainstBaseURL: false)?.queryItems,
                  !items.isEmpty,
                  let test = urlBySetting(items.map { $0.name }, to: canary.injected, on: u) else { continue }
            if let r = await http.fetch(test), ActiveProbes.isReflectedUnencoded(r, canary: canary) {
                let ctx = ActiveProbes.reflectionContextLabel(r, canary: canary)
                addFinding(ActiveProbes.reflectedInputFinding(pageURL: u, params: items.map { $0.name }, context: ctx))
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
            reference: "CWE-530: Exposure of Backup File",
            reproduction: "curl -sO \"\(response.finalURL.absoluteString)\"   # downloads the archive")
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
            evidence: "Working URL: \(response.finalURL.absoluteString)\nHTTP \(response.status), \(response.body.count) bytes",
            exploit: "The .env deny rule is bypassable, so an attacker downloads the full environment file - database passwords, API keys, and app secrets - despite the block.",
            remediation: "Do not rely on a location/deny rule; move env files outside the web root. Normalize request paths (collapse //, /./, trailing dots, %2e) before applying access rules. Rotate every value in the file.",
            reference: "CWE-22 / CWE-538",
            reproduction: "curl -s \"\(response.finalURL.absoluteString)\"   # deny rule bypassed, .env served",
            capturedContent: capturedBody(response.text))
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
            reference: "CWE-530: Exposure of Backup File",
            reproduction: "curl -s \"\(response.finalURL.absoluteString)\" -o .env.swp && vim -r .env.swp   # recovers the buffer",
            capturedContent: recoveredEnvLines(response.text))
    }

    private func envLeakFinding(response: HTTPResponse) -> Finding {
        Finding(
            title: "Hidden .env contents leaked via readable copy",
            severity: .critical,
            category: "Exposed Secret File",
            location: response.finalURL.absoluteString,
            detail: "A backup/non-dotfile copy of the env file is world-readable (HTTP \(response.status)) and slips past the .env deny rule, exposing the same contents.",
            evidence: "URL: \(response.finalURL.absoluteString)\nHTTP \(response.status), \(response.body.count) bytes",
            exploit: "The copy holds the live environment secrets (DB passwords, API keys) in plaintext, downloadable directly even though /.env itself is blocked.",
            remediation: "Remove backup/copy files (env.bak, env, *.save) from the web root, deny those names/extensions, and rotate every value - assume compromise.",
            reference: "CWE-530",
            reproduction: "curl -s \"\(response.finalURL.absoluteString)\"   # readable copy of the blocked .env",
            capturedContent: capturedBody(response.text))
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
            evidence: "URL: \(response.finalURL.absoluteString)\nHTTP \(response.status), \(response.body.count) bytes",
            exploit: "Environment files typically contain database passwords, API keys, and app secrets. An attacker downloads this directly and gains credentials to your backend, database, and third-party services.",
            remediation: "Never place env files inside the web root. Deny dotfiles at the web server and keep secrets in a secrets manager. Rotate every value in the file immediately - assume it is compromised.",
            reference: "CWE-538: File and Directory Information Exposure",
            reproduction: "curl -s \"\(response.finalURL.absoluteString)\"   # dumps credentials in plaintext",
            capturedContent: capturedBody(response.text))
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
        func probe() async -> HTTPResponse? {
            guard let u = URL(string: "\(origin)/zz_ws_nonexistent_\(UUID().uuidString).probe") else { return nil }
            return await http.fetch(u)
        }
        guard let r1 = await probe() else {
            return Soft404Baseline(is200ForEverything: false, bodyLength: 0, bodyHash: 0)
        }
        let is200 = r1.status == 200
        let len1 = r1.body.count
        let hash1 = String(r1.text.prefix(2000)).hashValue

        var tolerance = 48
        var altHash = 0
        if is200, let r2 = await probe(), r2.status == 200 {
            let delta = abs(r2.body.count - len1)
            tolerance = min(8192, max(48, delta + delta / 4 + 64))
            altHash = String(r2.text.prefix(2000)).hashValue
        }
        return Soft404Baseline(is200ForEverything: is200, bodyLength: len1,
                               bodyHash: hash1, lengthTolerance: tolerance, altHash: altHash)
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

    private func recordPassiveCookies(_ r: HTTPResponse) {
        for f in Checks.cookies(r) where seenPassiveTitles.insert(f.title).inserted {
            addFinding(f)
        }
        if let cache = Checks.sensitiveCaching(r), seenPassiveTitles.insert(cache.title).inserted {
            addFinding(cache)
        }
    }

    private func setStatus(_ s: String) { statusText = s }

    private func log(_ s: String) { logLines.append(s) }

    private func finishScan() {
        if Task.isCancelled {
            finishCancelledScan()
            return
        }
        guard !isOrchestrating else { return }
        finishedAt = Date()
        isScanning = false
        activeScanTask = nil
        let disc = discovered.isEmpty ? "" : " · \(discovered.count) URLs"
        let openCount = openPorts.filter { $0.state == .open }.count
        let portsPart = openCount == 0 ? "" : " · \(openCount) open ports"
        statusText = "Done - \(findings.count) findings\(disc)\(portsPart)"
        let c = counts
        log("■ Scan complete: \(c[.critical] ?? 0) critical, \(c[.high] ?? 0) high, \(c[.medium] ?? 0) medium, \(c[.low] ?? 0) low, \(c[.info] ?? 0) info."
            + (discovered.isEmpty ? "" : " Discovered \(discovered.count) reachable URL(s)."))
    }

    private func finishCancelledScan() {
        guard isScanning else { return }
        finishedAt = Date()
        isScanning = false
        activeScanTask = nil
        progressWindow = nil
        isOrchestrating = false
        progress = 0
        statusText = "Scan cancelled"
        log("■ Scan cancelled.")
    }

    var discoveredText: String {
        var out = "# Discovered URLs (\(discovered.count))\n"
        out += "# code\tbytes\tkind\turl\ttitle\n"
        for d in discovered.sorted(by: { $0.url < $1.url }) {
            out += "\(d.status)\t\(d.length)\t\(d.kind.label)\t\(d.url)\t\(d.title ?? "")\n"
        }
        return out
    }

    var openPortsText: String {
        let host = scannedURL?.host ?? target
        var out = "# Open ports on \(host)\n"
        out += "# port/proto\tstate\tservice\tproduct/version\ttls\trtt\tbanner\n"
        for p in openPorts.sorted(by: { $0.port < $1.port }) {
            let ver = p.productVersion ?? ""
            let tls = p.tls == true ? (p.tlsInfo ?? "tls") : ""
            let rtt = p.rttMs.map { "\($0)ms" } ?? ""
            let banner = (p.banner.map { snippet($0, max: 120) }) ?? ""
            out += "\(p.port)/\(p.proto)\t\(p.state.label)\t\(p.service)\t\(ver)\t\(tls)\t\(rtt)\t\(banner)\n"
        }
        return out
    }
}

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
