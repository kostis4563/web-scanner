import Foundation
import Network
import Security

struct OpenPort: Identifiable, Codable, Equatable {
    var id = UUID()
    var port: Int
    var proto: String = "tcp"
    var state: State

    var service: String

    var banner: String?

    var product: String?

    var version: String?

    var risk: Severity?

    var tls: Bool?

    var tlsInfo: String?

    var rttMs: Int?

    var unexpectedService: Bool?

    enum State: String, Codable {
        case open
        case closed
        case filtered

        var label: String {
            switch self {
            case .open:     return "OPEN"
            case .closed:   return "CLOSED"
            case .filtered: return "FILTERED"
            }
        }
    }

    var productVersion: String? {
        let parts = [product, version].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }

    static func == (lhs: OpenPort, rhs: OpenPort) -> Bool {
        lhs.port == rhs.port && lhs.proto == rhs.proto
    }
}

struct PortScanSummary {
    var ports: [OpenPort] = []
    var openCount = 0
    var closedCount = 0
    var filteredCount = 0
    var scanned = 0

    var elapsed: TimeInterval = 0

    var cancelled = false

    var hostResponsive: Bool { openCount > 0 || closedCount > 0 }

    var filteredHidden = 0

    var effectiveTimeoutMs = 0

    var recovered = 0

    var blanketOpen = false

    var blanketOpenCount = 0

    var shownOpenCount: Int { ports.filter { $0.state == .open }.count }

    var probed: Int { openCount + closedCount + filteredCount }

    var rate: Double { elapsed > 0 ? Double(probed) / elapsed : 0 }
}

final class ProbeGate: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    var isDone: Bool {
        lock.lock(); defer { lock.unlock() }
        return done
    }

    func fire(_ block: () -> Void) {
        lock.lock()
        let first = !done
        done = true
        lock.unlock()
        if first { block() }
    }
}

private final class AtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    func set() { lock.lock(); flag = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
}

private final class BannerBox: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private var weSpoke = false
    private var serverSpokeFirst = false

    func markSent() {
        lock.lock(); weSpoke = true; lock.unlock()
    }

    func append(_ d: Data) {
        lock.lock()
        if data.isEmpty && !weSpoke { serverSpokeFirst = true }
        data.append(d)
        lock.unlock()
    }

    var snapshotData: Data {
        lock.lock(); defer { lock.unlock() }
        return data
    }

    var spokeFirst: Bool {
        lock.lock(); defer { lock.unlock() }
        return serverSpokeFirst
    }
}

final class TimeoutBudget: @unchecked Sendable {
    private let lock = NSLock()
    private let ceilingMs: Int
    private let floorMs: Int
    private let enabled: Bool
    private var samples: [Int] = []
    private var currentMs: Int

    init(ceilingMs: Int, floorMs: Int = 250, adaptive: Bool = true) {
        self.ceilingMs = ceilingMs
        self.floorMs = min(floorMs, ceilingMs)
        self.enabled = adaptive
        self.currentMs = ceilingMs
    }

    var timeoutMs: Int {
        lock.lock(); defer { lock.unlock() }
        return currentMs
    }

    func record(rttMs: Int) {
        guard enabled else { return }
        lock.lock(); defer { lock.unlock() }
        samples.append(rttMs)
        guard samples.count >= 5 else { return }

        let worst = samples.suffix(24).max() ?? ceilingMs
        currentMs = min(ceilingMs, max(floorMs, worst * 4 + 120))
    }
}

final class PortScanner {

    struct Config {

        var timeoutMs: Int = 1200

        var concurrency: Int = 256
        var grabBanners: Bool = true

        var retryFiltered: Bool = true

        var adaptiveTimeout: Bool = true

        var probeTLS: Bool = true

        var maxFilteredRows: Int = 250

        var maxRetryPorts: Int = 1500
    }

    private struct Probe {
        let port: Int
        let state: OpenPort.State
        var banner: String? = nil
        var rttMs: Int? = nil
        var tls: TLSProbeInfo? = nil

        var spokeFirst: Bool = false
    }

    struct TLSProbeInfo {
        var version: String?
        var alpn: String?
        var subjectCN: String?
        var issuer: String?

        var summary: String {
            [version, alpn, subjectCN.map { "CN=\($0)" }]
                .compactMap { $0 }
                .joined(separator: " · ")
        }
    }

    private let queue = DispatchQueue(label: "webscanner.portscan", attributes: .concurrent)

    static let blanketOpenThreshold = 100

    static func isPositivelyIdentified(_ op: OpenPort) -> Bool {
        op.state == .open && (op.banner != nil || op.tls == true)
    }

    func scan(host: String, ports: [Int], config: Config,
              progress: @escaping (Int, Int, [OpenPort]) -> Void) async -> PortScanSummary {
        let started = Date()
        var summary = PortScanSummary()
        let total = ports.count
        summary.scanned = total
        guard total > 0 else { return summary }

        var cfg = config
        cfg.concurrency = Self.usableConcurrency(cfg.concurrency)
        let budget = TimeoutBudget(ceilingMs: max(120, cfg.timeoutMs), adaptive: cfg.adaptiveTimeout)

        var pending: [OpenPort] = []
        var lastFlush = Date()
        var done = 0
        func flush(force: Bool) {
            let elapsed = Date().timeIntervalSince(lastFlush)
            guard force || pending.count >= 24 || elapsed > 0.2 else { return }
            let batch = pending.sorted { $0.port < $1.port }
            pending.removeAll(keepingCapacity: true)
            lastFlush = Date()
            progress(min(done, total), total, batch)
        }

        var filteredPorts: [Int] = []
        var openProbes: [Probe] = []

        var index = 0
        await withTaskGroup(of: Probe.self) { group in
            let window = min(cfg.concurrency, total)
            while index < window {
                let p = ports[index]; index += 1
                group.addTask { await self.probe(host: host, port: p, config: cfg, budget: budget) }
            }
            while let pr = await group.next() {
                done += 1
                switch pr.state {
                case .open:
                    summary.openCount += 1
                    openProbes.append(pr)
                    if let rtt = pr.rttMs { budget.record(rttMs: rtt) }

                    let op = makeOpenPort(pr)
                    if Self.isPositivelyIdentified(op) { pending.append(op) }
                case .closed:
                    summary.closedCount += 1
                    if let rtt = pr.rttMs { budget.record(rttMs: rtt) }
                case .filtered:

                    filteredPorts.append(pr.port)
                }
                flush(force: false)

                if Task.isCancelled {
                    summary.cancelled = true
                    group.cancelAll()
                    break
                }
                if index < total {
                    let p = ports[index]; index += 1
                    group.addTask { await self.probe(host: host, port: p, config: cfg, budget: budget) }
                }
            }
        }
        flush(force: true)

        var retryTargets: [Int] = []
        var skippedRetry: [Int] = []
        if cfg.retryFiltered, !summary.cancelled, summary.hostResponsive, !filteredPorts.isEmpty {
            if filteredPorts.count <= cfg.maxRetryPorts {
                retryTargets = filteredPorts
            } else {

                let known = filteredPorts.filter { PortCatalog.service(for: $0) != nil }
                retryTargets = Array(known.prefix(cfg.maxRetryPorts))
                let targetSet = Set(retryTargets)
                skippedRetry = filteredPorts.filter { !targetSet.contains($0) }
            }
        }
        if !retryTargets.isEmpty {
            var retryCfg = cfg
            retryCfg.timeoutMs = min(4000, max(1500, cfg.timeoutMs * 2))
            let retryBudget = TimeoutBudget(ceilingMs: retryCfg.timeoutMs, adaptive: false)
            var stillFiltered: [Int] = []

            var rIndex = 0
            await withTaskGroup(of: Probe.self) { group in
                let window = min(retryCfg.concurrency, retryTargets.count)
                while rIndex < window {
                    let p = retryTargets[rIndex]; rIndex += 1
                    group.addTask { await self.probe(host: host, port: p, config: retryCfg, budget: retryBudget) }
                }
                while let pr = await group.next() {
                    switch pr.state {
                    case .open:
                        summary.openCount += 1
                        summary.recovered += 1
                        openProbes.append(pr)
                        let op = makeOpenPort(pr)
                        if Self.isPositivelyIdentified(op) { pending.append(op) }
                    case .closed:
                        summary.closedCount += 1
                        summary.recovered += 1
                    case .filtered:
                        stillFiltered.append(pr.port)
                    }
                    flush(force: false)

                    if Task.isCancelled {
                        summary.cancelled = true
                        group.cancelAll()

                        stillFiltered.append(contentsOf: retryTargets[rIndex...])
                        break
                    }
                    if rIndex < retryTargets.count {
                        let p = retryTargets[rIndex]; rIndex += 1
                        group.addTask { await self.probe(host: host, port: p, config: retryCfg, budget: retryBudget) }
                    }
                }
            }
            filteredPorts = stillFiltered + skippedRetry
            flush(force: true)
        }

        summary.filteredCount = filteredPorts.count

        let allOpenRows = openProbes.map(makeOpenPort)
        let identifiedOpen = allOpenRows.filter(Self.isPositivelyIdentified)
        let unidentifiedOpen = allOpenRows.count - identifiedOpen.count
        let blanket = unidentifiedOpen > Self.blanketOpenThreshold
            || (total >= 20 && unidentifiedOpen >= 15
                && Double(unidentifiedOpen) >= 0.5 * Double(total))

        var rows: [OpenPort]
        if blanket {
            summary.blanketOpen = true
            summary.blanketOpenCount = unidentifiedOpen
            rows = identifiedOpen
        } else {
            rows = allOpenRows
        }

        let shownFiltered = filteredPorts.sorted().prefix(cfg.maxFilteredRows)
        summary.filteredHidden = filteredPorts.count - shownFiltered.count
        rows += shownFiltered.map { OpenPort(port: $0, state: .filtered, service: PortCatalog.service(for: $0)?.name ?? "unknown") }

        summary.ports = rows.sorted { $0.port < $1.port }
        summary.effectiveTimeoutMs = budget.timeoutMs
        summary.elapsed = Date().timeIntervalSince(started)
        return summary
    }

    private func makeOpenPort(_ pr: Probe) -> OpenPort {
        let catalogService = PortCatalog.service(for: pr.port)
        let banner = (pr.banner?.isEmpty ?? true) ? nil : pr.banner
        let inferred = banner.flatMap { ServiceFingerprint.identify(banner: $0) }

        var name = catalogService?.name ?? "unknown"

        var contradictsPort = false

        var fromBanner = false
        if let inferred {
            if catalogService == nil {
                name = inferred
                fromBanner = true
            } else if !ServiceFingerprint.matches(inferred: inferred, catalog: name) {
                name = inferred
                fromBanner = true
                contradictsPort = true
            }
        }

        var op = OpenPort(port: pr.port, state: pr.state, service: name,
                          banner: banner, risk: nil)
        op.rttMs = pr.rttMs
        op.unexpectedService = contradictsPort ? true : nil

        if let tls = pr.tls {
            op.tls = true
            op.tlsInfo = tls.summary.isEmpty ? nil : tls.summary

            if op.service == "HTTP" { op.service = "HTTPS" }
        }
        if let banner = op.banner, let id = VersionChecks.idents(from: banner).first {
            op.product = id.product
            op.version = id.version
        }
        if pr.state == .open {

            op.risk = (fromBanner ? PortCatalog.canonicalService(named: name)?.exposureRisk : nil)
                ?? catalogService?.exposureRisk
        }
        return op
    }

    private func probe(host: String, port: Int, config: Config, budget: TimeoutBudget) async -> Probe {
        let timeoutMs = budget.timeoutMs
        let base: Probe = await withCheckedContinuation { (cont: CheckedContinuation<Probe, Never>) in
            let gate = ProbeGate()
            guard let nwPort = NWEndpoint.Port(rawValue: UInt16(exactly: port) ?? 0), port > 0 else {
                cont.resume(returning: Probe(port: port, state: .closed))
                return
            }
            let startedAt = DispatchTime.now()
            let params = NWParameters.tcp

            params.prohibitExpensivePaths = false
            if let tcp = params.defaultProtocolStack.internetProtocol as? NWProtocolTCP.Options {
                tcp.connectionTimeout = max(1, timeoutMs / 1000)
                tcp.noDelay = true
                tcp.enableKeepalive = false
            }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)

            func elapsedMs() -> Int {
                Int((DispatchTime.now().uptimeNanoseconds - startedAt.uptimeNanoseconds) / 1_000_000)
            }

            func finish(_ state: OpenPort.State, banner: String?, rttMs: Int?,
                        spokeFirst: Bool = false) {
                gate.fire {
                    conn.cancel()
                    cont.resume(returning: Probe(port: port, state: state, banner: banner,
                                                 rttMs: rttMs, spokeFirst: spokeFirst))
                }
            }

            let connected = AtomicFlag()
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    connected.set()
                    let rtt = elapsedMs()
                    if config.grabBanners {
                        let wait = min(1400, max(400, rtt * 3 + 350))
                        PortScanner.grabBanner(conn, host: host, port: port,
                                               waitMs: wait, queue: self.queue) { banner, spokeFirst in
                            finish(.open, banner: banner, rttMs: rtt, spokeFirst: spokeFirst)
                        }
                    } else {
                        finish(.open, banner: nil, rttMs: rtt)
                    }
                case .waiting(let err):
                    finish(PortScanner.classify(err), banner: nil, rttMs: elapsedMs())
                case .failed(let err):
                    finish(PortScanner.classify(err), banner: nil, rttMs: elapsedMs())
                case .cancelled:
                    finish(.filtered, banner: nil, rttMs: nil)
                default:
                    break
                }
            }

            self.queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) {
                if !connected.value { finish(.filtered, banner: nil, rttMs: nil) }
            }

            self.queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs + 2500)) {
                finish(connected.value ? .open : .filtered, banner: nil, rttMs: nil)
            }
            conn.start(queue: self.queue)
        }

        guard base.state == .open, config.probeTLS else { return base }

        let identified = base.banner.flatMap { ServiceFingerprint.identify(banner: $0) } != nil
        let unreadable = base.banner.map { $0.isEmpty || Self.looksBinary($0) } ?? true
        let shouldTryTLS = PortCatalog.tlsPorts.contains(port)
            || (!identified && unreadable && !base.spokeFirst)
        guard shouldTryTLS else { return base }

        let rtt = base.rttMs ?? timeoutMs / 3
        var out = base
        if let info = await Self.tlsProbe(host: host, port: port, rttMs: rtt,
                                          timeoutMs: min(3000, max(900, rtt * 4 + 400))) {
            out.tls = info.0
            if let overBanner = info.1, !overBanner.isEmpty { out.banner = overBanner }
        }
        return out
    }

    private static func classify(_ err: NWError) -> OpenPort.State {
        if case .posix(let code) = err {
            switch code {
            case .ECONNREFUSED, .ECONNRESET:
                return .closed
            case .EHOSTDOWN, .ENETDOWN, .ENETUNREACH, .EHOSTUNREACH:
                return .filtered
            default:
                return .filtered
            }
        }
        return .filtered
    }

    private static func grabBanner(_ conn: NWConnection, host: String, port: Int,
                                   waitMs: Int, queue: DispatchQueue,
                                   completion: @escaping (String?, Bool) -> Void) {
        let gate = ProbeGate()
        let box = BannerBox()
        func done() {
            gate.fire {
                let data = box.snapshotData
                completion(data.isEmpty ? nil : sanitizeBanner(data), box.spokeFirst)
            }
        }

        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
            if let data, !data.isEmpty { box.append(data) }
            done()
        }

        if let nudge = PortCatalog.probePayload(port: port, host: host) {
            box.markSent()
            conn.send(content: nudge, completion: .contentProcessed { _ in })
            queue.asyncAfter(deadline: .now() + .milliseconds(waitMs)) { done() }
        } else {

            let listen = max(200, waitMs * 2 / 5)
            queue.asyncAfter(deadline: .now() + .milliseconds(listen)) {
                guard !gate.isDone else { return }
                box.markSent()
                conn.send(content: Data(PortCatalog.httpProbe(host: host, port: port).utf8),
                          completion: .contentProcessed { _ in })
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(waitMs)) { done() }
        }
    }

    private static func sanitizeBanner(_ data: Data) -> String {
        var out = String.UnicodeScalarView()
        var lastWasDot = false
        for byte in data.prefix(1024) {
            let scalar = Unicode.Scalar(byte)
            if byte == 0x0a || byte == 0x0d || byte == 0x09 || (byte >= 0x20 && byte < 0x7f) {
                out.append(scalar)
                lastWasDot = false
            } else if !lastWasDot {
                out.append(".")
                lastWasDot = true
            }
        }
        return String(String.UnicodeScalarView(out)).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func looksBinary(_ s: String) -> Bool {
        let scalars = Array(s.unicodeScalars.prefix(64))
        guard !scalars.isEmpty else { return true }
        let printable = scalars.filter {
            $0.value == 9 || $0.value == 10 || $0.value == 13 || ($0.value >= 32 && $0.value < 127)
        }.count
        return Double(printable) / Double(scalars.count) < 0.75
    }

    private static func tlsProbe(host: String, port: Int, rttMs: Int,
                                 timeoutMs: Int) async -> (TLSProbeInfo, String?)? {
        await withCheckedContinuation { (cont: CheckedContinuation<(TLSProbeInfo, String?)?, Never>) in
            guard let nwPort = NWEndpoint.Port(rawValue: UInt16(exactly: port) ?? 0), port > 0 else {
                cont.resume(returning: nil); return
            }
            let gate = ProbeGate()
            let queue = DispatchQueue(label: "webscanner.portscan.tls")
            let certBox = CertBox()

            let tls = NWProtocolTLS.Options()
            let sec = tls.securityProtocolOptions
            sec_protocol_options_set_tls_server_name(sec, host)
            sec_protocol_options_add_tls_application_protocol(sec, "h2")
            sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
            sec_protocol_options_set_verify_block(sec, { _, trustRef, complete in
                let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
                if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                   let leaf = chain.first {
                    var cn: CFString?
                    SecCertificateCopyCommonName(leaf, &cn)
                    certBox.set(cn: cn as String?,
                                issuer: chain.count > 1
                                    ? (SecCertificateCopySubjectSummary(chain[1]) as String?)
                                    : nil)
                }
                complete(true)
            }, queue)

            let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort,
                                    using: NWParameters(tls: tls))
            func finish(_ value: (TLSProbeInfo, String?)?) {
                gate.fire { conn.cancel(); cont.resume(returning: value) }
            }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    var info = TLSProbeInfo()
                    if let md = conn.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata {
                        let meta = md.securityProtocolMetadata
                        info.version = tlsVersionName(
                            sec_protocol_metadata_get_negotiated_tls_protocol_version(meta))
                        if let alpn = sec_protocol_metadata_get_negotiated_protocol(meta) {
                            info.alpn = String(cString: alpn)
                        }
                    }
                    let (cn, issuer) = certBox.value
                    info.subjectCN = cn
                    info.issuer = issuer

                    guard info.alpn != "h2" else { finish((info, nil)); return }

                    let box = BannerBox()
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                        if let data, !data.isEmpty { box.append(data) }
                        let text = sanitizeBanner(box.snapshotData)
                        finish((info, text.isEmpty ? nil : text))
                    }
                    conn.send(content: Data(PortCatalog.httpProbe(host: host, port: port).utf8),
                              completion: .contentProcessed { _ in })
                    queue.asyncAfter(deadline: .now() + .milliseconds(min(1200, max(400, rttMs * 3)))) {
                        let text = sanitizeBanner(box.snapshotData)
                        finish((info, text.isEmpty ? nil : text))
                    }
                case .failed, .waiting:
                    finish(nil)
                default:
                    break
                }
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) { finish(nil) }
            conn.start(queue: queue)
        }
    }

    private final class CertBox: @unchecked Sendable {
        private let lock = NSLock()
        private var cn: String?
        private var issuer: String?
        func set(cn: String?, issuer: String?) {
            lock.lock(); self.cn = cn; self.issuer = issuer; lock.unlock()
        }
        var value: (String?, String?) {
            lock.lock(); defer { lock.unlock() }
            return (cn, issuer)
        }
    }

    private static func tlsVersionName(_ v: tls_protocol_version_t) -> String? {
        switch v.rawValue {
        case 0x0300: return "SSL 3.0"
        case 0x0301: return "TLS 1.0"
        case 0x0302: return "TLS 1.1"
        case 0x0303: return "TLS 1.2"
        case 0x0304: return "TLS 1.3"
        default:     return nil
        }
    }

    static func usableConcurrency(_ requested: Int) -> Int {
        var lim = rlimit()
        var available = 256
        if getrlimit(RLIMIT_NOFILE, &lim) == 0 {
            if lim.rlim_cur < lim.rlim_max {
                var raised = lim
                raised.rlim_cur = min(lim.rlim_max, rlim_t(10240))
                if setrlimit(RLIMIT_NOFILE, &raised) == 0 { lim = raised }
            }
            available = Int(min(lim.rlim_cur, rlim_t(100_000)))
        }
        return max(8, min(requested, available - 96))
    }
}

enum ServiceFingerprint {

    private static let rules: [(needle: String, service: String, prefixOnly: Bool)] = [
        ("SSH-",                    "SSH",          true),
        ("HTTP/1.",                 "HTTP",         true),
        ("HTTP/0.9",                "HTTP",         true),
        ("RFB 00",                  "VNC",          true),
        ("+OK",                     "POP3",         true),
        ("* OK",                    "IMAP",         true),
        ("AMQP",                    "AMQP/RabbitMQ", true),
        ("-NOAUTH",                 "Redis",        true),
        ("-DENIED",                 "Redis",        true),
        ("redis_version:",          "Redis",        false),
        ("-ERR unknown command",    "Redis",        false),
        ("STAT pid",                "Memcached",    false),
        ("STAT uptime",             "Memcached",    false),
        ("mysql_native_password",   "MySQL",        false),
        ("caching_sha2_password",   "MySQL",        false),
        ("MariaDB",                 "MariaDB",      false),
        ("PostgreSQL",              "PostgreSQL",   false),
        ("unsupported frontend protocol", "PostgreSQL", false),
        ("invalid startup packet",  "PostgreSQL",   false),
        ("MongoDB",                 "MongoDB",      false),
        ("ElasticSearch",           "Elasticsearch", false),
        ("\"cluster_name\"",        "Elasticsearch", false),
        ("Couchdb",                 "CouchDB",      false),
        ("ClickHouse",              "ClickHouse",   false),
        ("Docker",                  "Docker API",   false),
        ("SMBs",                    "SMB",          false),
        ("NNTP",                    "NNTP",         false),
        ("ESMTP",                   "SMTP",         false),
        ("Postfix",                 "SMTP",         false),
        ("Exim",                    "SMTP",         false),
        ("FTP server",              "FTP",          false),
        ("vsFTPd",                  "FTP",          false),
        ("FileZilla Server",        "FTP",          false),
        ("ProFTPD",                 "FTP",          false),
        ("Zabbix",                  "Zabbix Agent", false),
        ("SIP/2.0",                 "SIP",          false),
        ("OpenVPN",                 "OpenVPN",      false),
        ("neo4j",                   "Neo4j",        false),
        ("cassandra",               "Cassandra",    false),
    ]

    static func identify(banner: String) -> String? {
        let trimmed = banner.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let lower = trimmed.lowercased()

        for rule in rules {
            let needle = rule.needle.lowercased()
            if rule.prefixOnly {
                if lower.hasPrefix(needle) { return rule.service }
            } else if lower.contains(needle) {
                return rule.service
            }
        }

        if trimmed.hasPrefix("220 ") || trimmed.hasPrefix("220-") {
            if lower.contains("smtp") || lower.contains("mail") { return "SMTP" }
            if lower.contains("ftp") { return "FTP" }
        }
        return nil
    }

    static func matches(inferred: String, catalog: String) -> Bool {
        let a = inferred.lowercased(), b = catalog.lowercased()
        if a == b || b.contains(a) || a.contains(b) { return true }
        let httpish = ["http", "https", "webmin", "cpanel", "whm", "kibana", "proxy",
                       "rabbitmq mgmt", "hadoop", "sonarqube", "web"]
        if a.contains("http") && httpish.contains(where: { b.contains($0) }) { return true }

        let families: [Set<String>] = [
            ["mysql", "mariadb"],
            ["redis", "redis (alt)"],
            ["postgresql", "postgresql (alt)"],
            ["elasticsearch", "elasticsearch (transport)"],
            ["mongodb", "mongodb (config)", "mongodb http"],
            ["smtp", "smtps", "smtp-submission"],
            ["imap", "imaps"],
            ["pop3", "pop3s"],
            ["ldap", "ldaps"],
            ["docker api", "docker api (plain)", "docker api (tls)"],
            ["neo4j", "neo4j browser", "neo4j bolt"],
            ["cassandra", "cassandra (thrift)"],
        ]
        return families.contains { $0.contains(a) && $0.contains(b) }
    }
}

enum PortCatalog {

    struct Service {
        let name: String

        let exposureRisk: Severity?
        let why: String
        let fix: String
        let reference: String

        var command: String? = nil
    }

    static func service(for port: Int) -> Service? { services[port] }

    static let httpPorts: Set<Int> = [
        80, 81, 88, 443, 591, 2082, 2083, 2086, 2087, 3000, 4000, 5000, 5601,
        7001, 7474, 8000, 8008, 8009, 8080, 8081, 8082, 8086, 8088, 8090, 8123,
        8161, 8443, 8500, 8834, 8888, 8983, 9000, 9001, 9090, 9200, 9443, 9800,
        10000, 15672, 16010, 18080, 28017, 50070,
    ]

    static let tlsPorts: Set<Int> = [
        443, 465, 563, 636, 989, 990, 992, 993, 995, 2083, 2087, 2096, 2376,
        4443, 5061, 5986, 6443, 7443, 8443, 8834, 9443, 10250, 10443,
    ]

    static func probePayload(port: Int, host: String) -> Data? {
        if httpPorts.contains(port) { return Data(httpProbe(host: host, port: port).utf8) }
        switch port {

        case 6379, 6380:    return Data("INFO server\r\n".utf8)
        case 11211:         return Data("version\r\n".utf8)
        case 9418:          return Data("0032git-upload-pack /\u{0}host=\(host)\u{0}".utf8)
        case 4369:          return Data("\u{0}\u{01}n".utf8)
        default:            return nil
        }
    }

    static func httpProbe(host: String, port: Int) -> String {
        let hostHeader = (port == 80 || port == 443) ? host : "\(host):\(port)"
        return "HEAD / HTTP/1.0\r\nHost: \(hostHeader)\r\nUser-Agent: WebScanner\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    }

    private static func web(_ name: String) -> Service {
        Service(name: name, exposureRisk: nil,
                why: "", fix: "", reference: "")
    }

    private static func db(_ name: String, _ risk: Severity, cmd: String = "nc {host} {port}") -> Service {
        Service(
            name: name, exposureRisk: risk,
            why: "A \(name) database port is reachable from the network. Databases should never be exposed to the internet: attackers can brute-force credentials, exploit unauthenticated defaults, or attack the database software directly to read/modify all stored data.",
            fix: "Bind \(name) to localhost or a private network interface, put it behind a firewall/security group that only allows trusted hosts, require strong authentication, and never expose it publicly.",
            reference: "CWE-668: Exposure of Resource to Wrong Sphere",
            command: cmd)
    }

    private static func remote(_ name: String, _ risk: Severity, cleartext: Bool = false,
                               cmd: String = "nc {host} {port}") -> Service {
        Service(
            name: name, exposureRisk: risk,
            why: cleartext
                ? "\(name) transmits credentials and session data in cleartext. Anyone on the network path can capture logins, and the service itself is a prime brute-force / known-exploit target."
                : "\(name) provides remote access to the host. Exposed to the internet it is a constant brute-force and exploitation target; a single weak credential or unpatched CVE yields full remote control.",
            fix: cleartext
                ? "Disable \(name) entirely and use an encrypted alternative (e.g. SSH instead of Telnet/rlogin). If unavoidable, restrict it to a VPN/private network."
                : "Restrict \(name) to a VPN or an allow-listed set of source IPs, enforce strong credentials + MFA, and keep the server patched. Do not expose it to the public internet.",
            reference: cleartext ? "CWE-319: Cleartext Transmission" : "CWE-284: Improper Access Control",
            command: cmd)
    }

    private static func admin(_ name: String, _ risk: Severity, what: String,
                              cmd: String? = nil) -> Service {
        Service(
            name: name, exposureRisk: risk,
            why: "\(name) is reachable from the network. \(what)",
            fix: "Bind \(name) to localhost or a private network, require authentication, and firewall the port from untrusted networks. Management interfaces should never be internet-facing.",
            reference: "CWE-284: Improper Access Control",
            command: cmd)
    }

    static let services: [Int: Service] = [
        20:  remote("FTP-Data", .medium, cleartext: true),
        21:  remote("FTP", .medium, cleartext: true, cmd: "ftp {host}   # try user 'anonymous'"),
        22:  Service(name: "SSH", exposureRisk: .info,
                     why: "SSH is exposed to the network. Traffic is encrypted, but an internet-facing SSH port is a continuous brute-force target and any auth or protocol CVE becomes remotely exploitable.",
                     fix: "Restrict SSH to a VPN/allow-listed IPs where possible, disable password auth in favor of keys, disable root login, and keep OpenSSH patched.",
                     reference: "CWE-284",
                     command: "ssh-audit {host} -p {port}   # audit algorithms & auth methods (no login)"),
        23:  remote("Telnet", .high, cleartext: true, cmd: "telnet {host} {port}"),
        25:  Service(name: "SMTP", exposureRisk: .info,
                     why: "An SMTP service is reachable. If it relays mail without authentication it can be abused for spam/spoofing.",
                     fix: "Ensure the mail server is not an open relay, require authentication for submission, and expose only the ports you need (587 submission, 465 SMTPS).",
                     reference: "CWE-284",
                     command: "nc {host} {port}   # then: HELO x / VRFY root"),
        53:  web("DNS"),
        69:  remote("TFTP", .high, cleartext: true, cmd: "tftp {host}   # then: get /etc/passwd"),
        79:  remote("Finger", .low, cleartext: true),
        80:  web("HTTP"),
        110: remote("POP3", .low, cleartext: true),
        111: Service(name: "RPCbind", exposureRisk: .medium,
                     why: "Portmapper/rpcbind is exposed, revealing RPC services (often NFS). It aids enumeration and can be abused for reflection/amplification DDoS.",
                     fix: "Firewall port 111 (and associated RPC services) from untrusted networks; disable rpcbind if not required.",
                     reference: "CWE-668",
                     command: "rpcinfo -p {host}"),
        113: web("Ident"),
        119: remote("NNTP", .low, cleartext: true),
        123: web("NTP"),
        135: remote("MSRPC", .high),
        137: remote("NetBIOS-NS", .high, cmd: "nmblookup -A {host}"),
        138: remote("NetBIOS-DGM", .high),
        139: remote("NetBIOS-SSN", .high, cmd: "smbclient -L //{host} -N"),
        143: remote("IMAP", .low, cleartext: true),
        161: Service(name: "SNMP", exposureRisk: .medium,
                     why: "SNMP is reachable and frequently runs with default community strings ('public'/'private'), leaking device configuration and sometimes allowing writes.",
                     fix: "Firewall SNMP from the internet, disable v1/v2c, use SNMPv3 with authentication, and change default community strings.",
                     reference: "CWE-284",
                     command: "snmpwalk -v2c -c public {host}"),
        179: admin("BGP", .medium, what: "An exposed BGP speaker can be targeted for session hijacking or resource exhaustion; peering should only be reachable from configured neighbours.",
                   cmd: "nc {host} {port}"),
        389: db("LDAP", .medium, cmd: "ldapsearch -x -H ldap://{host}:{port} -b '' -s base"),
        427: admin("SLP", .medium, what: "Service Location Protocol leaks a directory of services and is a high-factor UDP amplification vector (CVE-2023-29552).",
                   cmd: "nmap -p {port} --script slp-discovery {host}"),
        443: web("HTTPS"),
        445: remote("SMB", .high, cmd: "smbclient -L //{host} -N"),
        465: web("SMTPS"),
        500: web("IKE/IPsec"),
        502: admin("Modbus", .critical, what: "Modbus is an industrial control protocol with no authentication whatsoever - anyone who can reach it can read and write PLC registers, i.e. operate physical equipment.",
                   cmd: "nmap -p {port} --script modbus-discover {host}"),
        512: remote("rexec", .high, cleartext: true),
        513: remote("rlogin", .high, cleartext: true),
        514: remote("rsh/syslog", .high, cleartext: true),
        515: remote("LPD/Printer", .medium, cleartext: true),
        548: remote("AFP", .medium, cmd: "nmap -p {port} --script afp-serverinfo {host}"),
        554: web("RTSP"),
        563: web("NNTPS"),
        587: web("SMTP-Submission"),
        593: remote("RPC over HTTP", .high),
        623: admin("IPMI", .critical, what: "IPMI/BMC gives out-of-band control of the physical server (power, console, virtual media) and its authentication has structural flaws (cipher-zero, RAKP hash disclosure) that allow remote password recovery.",
                   cmd: "nmap -p {port} -sU --script ipmi-cipher-zero {host}"),
        631: web("IPP/CUPS"),
        636: db("LDAPS", .medium),
        873: Service(name: "rsync", exposureRisk: .high,
                     why: "An rsync daemon is exposed. Misconfigured modules frequently allow anonymous read (or write) of entire directory trees.",
                     fix: "Firewall rsync, require auth on every module, and set 'read only = yes' unless writes are essential.",
                     reference: "CWE-668",
                     command: "rsync rsync://{host}/   # list modules, then pull one"),
        902: admin("VMware ESXi", .high, what: "The ESXi host agent is reachable; hypervisor management ports should never face untrusted networks.",
                   cmd: "nc {host} {port}"),
        989: web("FTPS-Data"),
        990: web("FTPS"),
        993: web("IMAPS"),
        995: web("POP3S"),
        1080: Service(name: "SOCKS Proxy", exposureRisk: .high,
                      why: "An open SOCKS proxy lets attackers pivot and route traffic through your host, masking their origin.",
                      fix: "Require authentication and restrict the proxy to trusted clients, or disable it.",
                      reference: "CWE-441",
                      command: "curl --socks5 {host}:{port} https://ifconfig.me"),
        1099: admin("Java RMI", .critical, what: "The RMI registry is a classic remote-code-execution vector: exposed registries allow object injection and deserialization attacks that run code as the JVM user.",
                    cmd: "nmap -p {port} --script rmi-dumpregistry {host}"),
        1194: web("OpenVPN"),
        1433: db("MSSQL", .high, cmd: "sqlcmd -S {host},{port} -U sa   # or: mssqlclient.py sa@{host}"),
        1434: db("MSSQL Browser", .medium, cmd: "nmap -sU -p {port} --script ms-sql-info {host}"),
        1521: db("Oracle DB", .high, cmd: "sqlplus system/oracle@{host}:{port}/XE"),
        1723: remote("PPTP VPN", .medium),
        1883: db("MQTT", .high, cmd: "mosquitto_sub -h {host} -p {port} -t '#' -v   # subscribe to everything"),
        1900: admin("UPnP/SSDP", .medium, what: "SSDP is a strong UDP amplification vector and exposed UPnP frequently allows unauthenticated port-forward creation through the device.",
                    cmd: "nmap -sU -p {port} --script upnp-info {host}"),
        2049: Service(name: "NFS", exposureRisk: .high,
                      why: "NFS is exposed. Public NFS exports can allow reading or writing files with weak or no authentication.",
                      fix: "Restrict NFS to trusted hosts via firewall + export lists, and prefer Kerberos-authenticated (sec=krb5) exports.",
                      reference: "CWE-668",
                      command: "showmount -e {host}   # then mount an export"),
        2082: web("cPanel"),
        2083: web("cPanel (SSL)"),
        2086: web("WHM"),
        2087: web("WHM (SSL)"),
        2181: db("ZooKeeper", .high, cmd: "echo stat | nc {host} {port}"),
        2222: Service(name: "SSH (alt)", exposureRisk: .info,
                      why: "SSH is exposed on an alternate port. Traffic is encrypted, but an internet-facing SSH port is a continuous brute-force target and any auth or protocol CVE becomes remotely exploitable.",
                      fix: "Restrict SSH to a VPN/allow-listed IPs, disable password auth in favor of keys, disable root login, and keep OpenSSH patched. A non-standard port is not a security control.",
                      reference: "CWE-284",
                      command: "ssh-audit {host} -p {port}"),
        2375: Service(name: "Docker API (plain)", exposureRisk: .critical,
                      why: "An unencrypted Docker Engine API is exposed. Anyone who can reach it has root-equivalent control: they can start privileged containers and mount the host filesystem for full host takeover.",
                      fix: "Never expose the Docker API on the network. Bind it to a local socket, or require mutual TLS (2376) and firewall it to trusted hosts only.",
                      reference: "CWE-284",
                      command: "docker -H tcp://{host}:{port} ps   # full root-equivalent control"),
        2376: remote("Docker API (TLS)", .high, cmd: "docker -H tcp://{host}:{port} --tls ps"),
        2379: db("etcd", .high, cmd: "curl http://{host}:{port}/v2/keys/?recursive=true"),
        2380: db("etcd-peer", .high),
        2483: db("Oracle DB (TCP)", .high),
        2484: db("Oracle DB (TLS)", .high),
        3000: web("HTTP-alt/Dev"),
        3128: Service(name: "Squid Proxy", exposureRisk: .high,
                      why: "An HTTP proxy is reachable. Open proxies let attackers relay traffic through your host and often reach internal services the proxy can see but the internet cannot (SSRF by design).",
                      fix: "Require authentication, restrict the proxy ACLs to trusted client networks, and firewall the port.",
                      reference: "CWE-441: Unintended Proxy or Intermediary",
                      command: "curl -x http://{host}:{port} http://169.254.169.254/latest/meta-data/"),
        3260: db("iSCSI", .high, cmd: "iscsiadm -m discovery -t st -p {host}:{port}"),
        3299: admin("SAP Router", .high, what: "SAP Router proxies connections into the SAP landscape and is routinely abused to reach internal application servers.",
                    cmd: "nmap -p {port} --script sap-router-info {host}"),
        3306: db("MySQL", .high, cmd: "mysql -h {host} -P {port} -u root   # try empty/weak password"),
        3389: remote("RDP", .high, cmd: "xfreerdp /v:{host}:{port} /u:Administrator"),
        3632: admin("distcc", .critical, what: "distcc executes compiler commands supplied by clients; exposed daemons allow trivial unauthenticated remote command execution (CVE-2004-2687).",
                    cmd: "nmap -p {port} --script distcc-cve2004-2687 {host}"),
        3690: db("SVN", .low, cmd: "svn ls svn://{host}:{port}/"),
        4369: admin("Erlang EPMD", .high, what: "The Erlang port mapper reveals node names and, combined with a guessable cookie, allows remote code execution on the Erlang/Elixir VM (RabbitMQ, CouchDB).",
                    cmd: "epmd -names -address {host}"),
        4444: Service(name: "Metasploit/alt", exposureRisk: .medium,
                      why: "Port 4444 is commonly used by remote-access/backdoor tooling (Metasploit default). Verify what is listening here.",
                      fix: "Identify the listening process; if it is not an intended service, treat the host as potentially compromised and investigate.",
                      reference: "CWE-506"),
        4505: admin("SaltStack Publisher", .critical, what: "The Salt master publish port has a history of unauthenticated remote-code-execution flaws (CVE-2020-11651/11652) and controls every connected minion.",
                    cmd: "nc {host} {port}"),
        4506: admin("SaltStack Request", .critical, what: "The Salt master request port has a history of unauthenticated remote-code-execution flaws (CVE-2020-11651/11652) and controls every connected minion.",
                    cmd: "nc {host} {port}"),
        4840: admin("OPC UA", .high, what: "OPC UA is an industrial automation protocol; exposed servers frequently allow anonymous sessions that can read and write process data.",
                    cmd: "nc {host} {port}"),
        5000: web("HTTP-alt/Dev"),
        5060: remote("SIP", .medium, cleartext: true, cmd: "svmap {host}:{port}"),
        5061: web("SIP-TLS"),
        5432: db("PostgreSQL", .high, cmd: "psql -h {host} -p {port} -U postgres   # try empty/weak password"),
        5555: admin("Android ADB", .critical, what: "An exposed ADB daemon grants an unauthenticated remote shell on the device - it is one of the most heavily botnet-scanned ports on the internet.",
                    cmd: "adb connect {host}:{port} && adb shell id"),
        5601: web("Kibana"),
        5672: db("AMQP/RabbitMQ", .medium),
        5900: remote("VNC", .high, cmd: "vncviewer {host}::{port}"),
        5901: remote("VNC", .high, cmd: "vncviewer {host}::{port}"),
        5984: db("CouchDB", .high, cmd: "curl http://{host}:{port}/_all_dbs"),
        5985: admin("WinRM (HTTP)", .high, what: "Windows Remote Management gives full remote PowerShell execution to anyone with valid credentials, and over plain HTTP the traffic is not confidential.",
                    cmd: "evil-winrm -i {host} -u Administrator"),
        5986: admin("WinRM (HTTPS)", .medium, what: "Windows Remote Management gives full remote PowerShell execution to anyone with valid credentials; it is a prime credential-stuffing target.",
                    cmd: "evil-winrm -i {host} -u Administrator -S"),
        6000: remote("X11", .medium, cleartext: true, cmd: "xwd -display {host}:0 -root -out /tmp/screen.xwd"),
        6001: remote("X11", .medium, cleartext: true),
        6379: Service(name: "Redis", exposureRisk: .critical,
                      why: "Redis is reachable and by default requires no authentication. An unauthenticated attacker can read/flush all data and often achieve remote code execution (e.g. writing an SSH key or module).",
                      fix: "Bind Redis to localhost, enable 'requirepass' with a strong password (or ACLs), enable protected-mode, and firewall port 6379 from the internet.",
                      reference: "CWE-306: Missing Authentication for Critical Function",
                      command: "redis-cli -h {host} -p {port} INFO   # unauthenticated? then CONFIG GET dir"),
        6443: remote("Kubernetes API", .high, cmd: "kubectl --server=https://{host}:{port} --insecure-skip-tls-verify get pods -A"),
        6660: remote("IRC", .low),
        6667: remote("IRC", .low),
        7001: db("WebLogic", .high),
        7077: admin("Spark Master", .critical, what: "An exposed Spark master accepts job submissions, which is arbitrary code execution on the cluster.",
                    cmd: "curl http://{host}:8080/   # master UI lists workers & apps"),
        8000: web("HTTP-alt"),
        8005: admin("Tomcat Shutdown", .critical, what: "The Tomcat shutdown port stops the server on receipt of a plaintext word (default 'SHUTDOWN') with no authentication.",
                    cmd: "printf 'SHUTDOWN' | nc {host} {port}"),
        8008: web("HTTP-alt"),
        8009: Service(name: "AJP (Tomcat)", exposureRisk: .high,
                      why: "The Tomcat AJP connector is exposed. AJP has been abused for file read / SSRF (Ghostcat, CVE-2020-1938) and should not be reachable externally.",
                      fix: "Firewall port 8009, disable the AJP connector if unused, and set a 'secret' if it must stay enabled.",
                      reference: "CVE-2020-1938 (Ghostcat)",
                      command: "nmap -p {port} --script ajp-request {host}"),
        8020: db("Hadoop NameNode IPC", .high),
        8080: web("HTTP-Proxy/alt"),
        8081: web("HTTP-alt"),
        8086: db("InfluxDB", .medium),
        8088: web("HTTP-alt"),
        8161: admin("ActiveMQ Console", .high, what: "The ActiveMQ web console ships with default credentials (admin/admin) and allows browsing and injecting messages.",
                    cmd: "curl -u admin:admin http://{host}:{port}/admin/"),
        8443: web("HTTPS-alt"),
        8500: admin("Consul", .critical, what: "The Consul HTTP API defaults to no ACLs; an exposed agent leaks service inventory and KV data and can register services or run scripted health checks.",
                    cmd: "curl http://{host}:{port}/v1/kv/?recurse"),
        8686: admin("JMX/JMXMP", .critical, what: "An unauthenticated JMX endpoint allows MBean invocation, which is a well-trodden path to remote code execution in the JVM.",
                    cmd: "java -jar mjet.jar {host} {port} info"),
        8888: web("HTTP-alt"),
        8983: db("Apache Solr", .high, cmd: "curl \"http://{host}:{port}/solr/admin/cores?action=STATUS\""),
        9000: web("HTTP-alt/SonarQube"),
        9001: web("HTTP-alt/Supervisor"),
        9042: db("Cassandra", .high, cmd: "cqlsh {host} {port}"),
        9090: web("HTTP-alt/Prometheus"),
        9092: db("Kafka", .medium, cmd: "kafka-console-consumer.sh --bootstrap-server {host}:{port} --list"),
        9100: admin("JetDirect / Printer", .medium, what: "Raw print ports accept arbitrary PostScript/PJL, which can be used to read printer storage, harvest queued documents, or brick the device.",
                    cmd: "nc {host} {port}"),
        9200: db("Elasticsearch", .high, cmd: "curl http://{host}:{port}/_cat/indices?v"),
        9300: db("Elasticsearch (transport)", .high),
        9418: admin("Git daemon", .medium, what: "The git:// daemon serves repositories with no authentication; if export-all is set it may expose private repositories and their history.",
                    cmd: "git clone git://{host}/repo.git"),
        10000: web("Webmin"),
        10250: admin("Kubelet API", .critical, what: "The kubelet read/write API can list pods and exec into containers on the node; when anonymous auth is enabled that is unauthenticated code execution in the cluster.",
                     cmd: "curl -k https://{host}:{port}/pods"),
        11211: Service(name: "Memcached", exposureRisk: .high,
                       why: "Memcached is exposed with no authentication. It leaks cached application data and is a powerful UDP reflection/amplification DDoS vector.",
                       fix: "Bind Memcached to localhost, disable UDP (-U 0), and firewall port 11211 from untrusted networks.",
                       reference: "CWE-306",
                       command: "printf 'stats\\r\\n' | nc {host} {port}"),
        11214: db("Memcached (SSL)", .high),
        15672: web("RabbitMQ Mgmt"),
        16010: web("HBase Master UI"),
        18080: web("Spark History UI"),
        20000: admin("DNP3 / Webmin-alt", .high, what: "DNP3 is an unauthenticated SCADA protocol; on IT hosts this port is also used by Webmin's alternate listener. Identify which is running.",
                     cmd: "nmap -p {port} --script dnp3-info {host}"),
        27017: db("MongoDB", .high, cmd: "mongosh \"mongodb://{host}:{port}\"   # then: show dbs"),
        27018: db("MongoDB", .high, cmd: "mongosh \"mongodb://{host}:{port}\""),
        27019: db("MongoDB (config)", .high, cmd: "mongosh \"mongodb://{host}:{port}\""),
        28017: db("MongoDB HTTP", .high, cmd: "curl http://{host}:{port}/   # legacy status/REST interface"),
        50070: web("Hadoop NameNode"),
        61616: db("ActiveMQ", .high, cmd: "nc {host} {port}"),

        3050:  db("Firebird", .high, cmd: "isql-fb -u SYSDBA -p masterkey {host}/{port}:employee"),
        5433:  db("PostgreSQL (alt)", .high, cmd: "psql -h {host} -p {port} -U postgres"),
        6380:  Service(name: "Redis (alt)", exposureRisk: .critical,
                       why: "A Redis instance is reachable on an alternate port and, by default, requires no authentication. An unauthenticated attacker can read/flush all data and often achieve remote code execution.",
                       fix: "Bind Redis to localhost, enable 'requirepass'/ACLs, enable protected-mode, and firewall the port from the internet.",
                       reference: "CWE-306: Missing Authentication for Critical Function",
                       command: "redis-cli -h {host} -p {port} INFO"),
        7474:  db("Neo4j Browser", .high, cmd: "curl http://{host}:{port}/   # then try neo4j/neo4j"),
        7687:  db("Neo4j Bolt", .high, cmd: "cypher-shell -a bolt://{host}:{port} -u neo4j -p neo4j"),
        8123:  db("ClickHouse (HTTP)", .high, cmd: "curl \"http://{host}:{port}/?query=SHOW+DATABASES\""),
        9004:  db("ClickHouse (native)", .high, cmd: "clickhouse-client -h {host} --port {port}"),
        9160:  db("Cassandra (Thrift)", .high, cmd: "cqlsh {host} {port}"),
        50000: db("IBM Db2", .high, cmd: "db2 connect to sample user db2inst1"),
    ]

    private static let canonicalPorts: [String: Int] = [
        "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25, "pop3": 110, "imap": 143,
        "nntp": 119, "http": 80, "vnc": 5900, "redis": 6379, "memcached": 11211,
        "mysql": 3306, "mariadb": 3306, "postgresql": 5432, "mongodb": 27017,
        "elasticsearch": 9200, "couchdb": 5984, "clickhouse": 8123,
        "docker api": 2375, "smb": 445, "amqp/rabbitmq": 5672, "neo4j": 7687,
        "cassandra": 9042, "sip": 5060, "openvpn": 1194,
    ]

    static func canonicalService(named name: String) -> Service? {
        guard let port = canonicalPorts[name.lowercased()] else { return nil }
        return services[port]
    }

    static func resolvedService(for port: OpenPort) -> Service? {
        if port.unexpectedService == true || services[port.port] == nil,
           let svc = canonicalService(named: port.service) {
            return svc
        }
        return services[port.port]
    }

    static let fast: [Int] = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    ]

    static let top100: [Int] = [
        7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
        119, 135, 137, 139, 143, 144, 161, 179, 199, 389, 427, 443, 444, 445,
        465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993,
        995, 1025, 1026, 1027, 1080, 1110, 1433, 1521, 1723, 1755, 1900, 2000,
        2001, 2049, 2121, 2181, 2375, 2717, 3000, 3128, 3306, 3389, 3986, 4444,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5601, 5631, 5666,
        5800, 5900, 5984, 6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080,
        8081, 8443, 8888, 9000, 9090, 9100, 9200, 10000, 11211, 27017, 32768,
        49152, 49157,
    ]

    static let extended: [Int] = {
        var s = Set(top100)
        s.formUnion(services.keys)
        s.formUnion([
            1, 3, 13, 17, 19, 24, 33, 42, 43, 49, 70, 82, 83, 84, 85, 89, 90,
            99, 100, 109, 125, 146, 175, 220, 340, 366, 406, 407, 416, 425,
            458, 481, 497, 500, 512, 524, 541, 545, 555, 563, 593, 616, 617,
            636, 666, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783,
            787, 800, 801, 808, 843, 880, 888, 898, 900, 901, 902, 903, 911,
            981, 987, 992, 999, 1000, 1001, 1007, 1010, 1021, 1022, 1023, 1024,
            1029, 1058, 1059, 1064, 1065, 1066, 1069, 1071, 1074, 1092, 1099,
            1178, 1183, 1200, 1234, 1236, 1259, 1300, 1311, 1352, 1417, 1434,
            1443, 1455, 1494, 1500, 1524, 1533, 1580, 1583, 1594, 1600, 1641,
            1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1782, 1801, 1863,
            1875, 1900, 1935, 1998, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
            2010, 2013, 2020, 2022, 2030, 2033, 2040, 2043, 2045, 2046, 2047,
            2048, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119,
            2126, 2135, 2144, 2160, 2170, 2179, 2190, 2222, 2260, 2288, 2366,
            2376, 2379, 2380, 2383, 2601, 2717, 2725, 2809, 2811, 2869, 2875,
            2909, 2910, 2920, 2967, 2968, 2998, 3001, 3003, 3005, 3007, 3011,
            3013, 3017, 3030, 3031, 3052, 3071, 3077, 3168, 3211, 3221, 3260,
            3261, 3268, 3269, 3283, 3300, 3301, 3323, 3325, 3333, 3351, 3367,
            3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527,
            3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800,
            3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880,
            3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
            4443, 4505, 4506, 4567, 4711, 4712, 4786, 4840, 4848, 4899, 4993,
            5001, 5002, 5003, 5004, 5005, 5010, 5044, 5050, 5051, 5060, 5061,
            5222, 5269, 5353, 5555, 5556, 5666, 5672, 5800, 5801, 5900, 5901,
            5902, 5985, 5986, 6002, 6003, 6004, 6005, 6006, 6007, 6066, 6443,
            6660, 6666, 6667, 6668, 6669, 7000, 7001, 7002, 7070, 7077, 7080,
            7180, 7443, 7474, 7687, 7777, 8005, 8006, 8010, 8020, 8025, 8082,
            8083, 8085, 8086, 8087, 8089, 8090, 8091, 8161, 8180, 8181, 8333,
            8500, 8686, 8834, 8983, 9001, 9002, 9003, 9042, 9060, 9080, 9092,
            9100, 9160, 9200, 9300, 9418, 9443, 9800, 9981, 9999, 10001, 10250,
            10443, 11211, 11214, 15672, 16010, 18080, 20000, 25565, 27015,
            27018, 27019, 28017, 32768, 32769, 49152, 49153, 49154, 49155,
            50000, 50070, 61616,
        ])
        return s.sorted()
    }()

    static func ports(for profile: PortProfile, custom: String = "") -> [Int] {
        switch profile {
        case .fast:     return fast
        case .top100:   return top100
        case .extended: return extended
        case .full:     return Array(1...65535)
        case .custom:   return parseSpec(custom)
        }
    }

    static let siteSweep: [Int] = [
        21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 161, 389, 445, 512, 513,
        514, 873, 1080, 1099, 1433, 1521, 2049, 2181, 2375, 2379, 3128, 3306,
        3389, 4506, 5432, 5555, 5601, 5900, 5984, 5985, 6379, 6443, 8009, 8080,
        8161, 8443, 8500, 9000, 9200, 10250, 11211, 15672, 27017,
    ]

    static let databaseSweep: [Int] = [
        389, 636,
        1433, 1434, 1521, 2483, 2484, 3050,
        1883,
        2181, 2379, 2380,
        3306, 5432, 5433,
        5672, 15672,
        5984,
        6379, 6380,
        7474, 7687,
        8086,
        8123, 9004,
        8983,
        9042, 9160,
        9092,
        9200, 9300,
        11211, 11214,
        27017, 27018, 27019, 28017,
        50000,
        61616,
    ]

    static let infoServicePorts: [(port: Int, role: String)] = [

        (80, "Web / Backend"), (443, "Web / Backend"), (8080, "Web / Backend"),
        (8000, "Web / Backend"), (8443, "Web / Backend"), (8888, "Web / Backend"),
        (3000, "Web / Backend"), (5000, "Web / Backend"), (9000, "Web / Backend"),
        (8008, "Web / Backend"), (8081, "Web / Backend"), (9090, "Web / Backend"),
        (7001, "Web / Backend"), (4000, "Web / Backend"),

        (3306, "Database"), (5432, "Database"), (1433, "Database"), (1521, "Database"),
        (27017, "Database"), (9042, "Database"), (9200, "Database"), (5984, "Database"),
        (8086, "Database"), (7474, "Database"), (5433, "Database"), (8983, "Database"),

        (6379, "Cache / Queue"), (11211, "Cache / Queue"), (5672, "Cache / Queue"),
        (9092, "Cache / Queue"), (2181, "Cache / Queue"), (15672, "Cache / Queue"),
        (1883, "Cache / Queue"), (61616, "Cache / Queue"),

        (25, "Mail"), (587, "Mail"), (465, "Mail"), (143, "Mail"), (993, "Mail"),
        (110, "Mail"), (995, "Mail"),

        (22, "Remote / Admin"), (23, "Remote / Admin"), (3389, "Remote / Admin"),
        (5900, "Remote / Admin"), (445, "Remote / Admin"), (5985, "Remote / Admin"),

        (2375, "Infrastructure"), (2376, "Infrastructure"), (6443, "Infrastructure"),
        (389, "Infrastructure"), (636, "Infrastructure"), (161, "Infrastructure"),
        (2379, "Infrastructure"), (8500, "Infrastructure"), (10250, "Infrastructure"),
    ]

    static func parseSpec(_ spec: String) -> [Int] {
        var out = Set<Int>()
        for token in spec.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" }) {
            let t = token.trimmingCharacters(in: .whitespaces)
            guard !t.isEmpty else { continue }
            if let dash = t.firstIndex(of: "-") {
                let lo = Int(t[t.startIndex..<dash].trimmingCharacters(in: .whitespaces))
                let hi = Int(t[t.index(after: dash)...].trimmingCharacters(in: .whitespaces))
                if let lo, let hi, lo <= hi {
                    for p in lo...hi where (1...65535).contains(p) { out.insert(p) }
                }
            } else if let p = Int(t), (1...65535).contains(p) {
                out.insert(p)
            }
        }
        return out.sorted()
    }

    static func exposureFinding(hostLabel: String, port: OpenPort) -> Finding? {
        guard port.state == .open,
              let svc = resolvedService(for: port), let risk = svc.exposureRisk else { return nil }
        let loc = "\(hostLabel):\(port.port)"
        var evidence = "Port \(port.port)/tcp is OPEN - \(svc.name)"
        if let v = port.version { evidence += "\nDetected: \(port.product ?? svc.name) \(v)" }
        if let tls = port.tlsInfo { evidence += "\nTLS: \(tls)" }
        if let b = port.banner, !b.isEmpty { evidence += "\nBanner: \(snippet(b, max: 200))" }

        var detail = "TCP port \(port.port) (\(svc.name)) accepts connections from the network. \(svc.why)"
        if port.unexpectedService == true {
            let expected = services[port.port]?.name
            evidence += "\nIdentified from the service banner, not the port number"
                + (expected.map { " (port \(port.port) normally serves \($0))" } ?? "")
            detail += " The service was identified from its banner rather than its port number, so port-based firewall rules and inventories are likely to have missed it."
        }
        let command = svc.command?
            .replacingOccurrences(of: "{host}", with: hostLabel)
            .replacingOccurrences(of: "{port}", with: "\(port.port)")
        return Finding(
            title: "Exposed \(svc.name) service (port \(port.port))",
            severity: risk,
            category: "Exposed Service",
            location: loc,
            detail: detail,
            evidence: evidence,
            exploit: svc.why,
            remediation: svc.fix,
            reference: svc.reference,
            reproduction: command)
    }
}
