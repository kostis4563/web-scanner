import Foundation
import Security

struct RequestTiming {
    var dnsMs: Double?
    var tcpMs: Double?
    var tlsMs: Double?
    var ttfbMs: Double?
    var downloadMs: Double?
    var totalMs: Double?
    var wallMs: Double
    var reusedConnection = false
    var networkProtocol: String?
    var tlsVersion: String?
    var wireBytes: Int?
    var headerBytes: Int?
    var decodedBytes: Int
    var handshakeRttMs: Double?
    var redirectCount: Int = 0

    var timingTotal: Double? { totalMs ?? wallMs }

    var setupMs: Double? {
        let parts = [dnsMs, tcpMs, tlsMs].compactMap { $0 }
        return parts.isEmpty ? nil : parts.reduce(0, +)
    }

    static func from(metrics: URLSessionTaskMetrics?, wallMs: Double, decodedBytes: Int) -> RequestTiming {
        var t = RequestTiming(wallMs: wallMs, decodedBytes: decodedBytes)
        t.totalMs = wallMs
        guard let txs = metrics?.transactionMetrics, let last = txs.last else { return t }

        func ms(_ a: Date?, _ b: Date?) -> Double? {
            guard let a, let b else { return nil }
            let d = b.timeIntervalSince(a) * 1000
            return d >= 0 ? d : nil
        }

        var dns = 0.0, tcp = 0.0, tls = 0.0
        var sawDNS = false, sawTCP = false, sawTLS = false
        var handshake: Double?
        var headerBytes = 0
        for tx in txs {
            if let v = ms(tx.domainLookupStartDate, tx.domainLookupEndDate) { dns += v; sawDNS = true }
            let connect = ms(tx.connectStartDate, tx.secureConnectionStartDate)
                ?? ms(tx.connectStartDate, tx.connectEndDate)
            if let v = connect {
                tcp += v; sawTCP = true
                handshake = min(handshake ?? v, v)
            }
            if let v = ms(tx.secureConnectionStartDate, tx.secureConnectionEndDate) { tls += v; sawTLS = true }
            headerBytes += Int(tx.countOfResponseHeaderBytesReceived)
        }
        t.dnsMs = sawDNS ? dns : nil
        t.tcpMs = sawTCP ? tcp : nil
        t.tlsMs = sawTLS ? tls : nil
        t.handshakeRttMs = handshake
        t.redirectCount = max(0, txs.count - 1)

        t.ttfbMs = ms(last.requestStartDate, last.responseStartDate)
        t.downloadMs = ms(last.responseStartDate, last.responseEndDate)
        if let total = ms(txs.first?.fetchStartDate, last.responseEndDate) { t.totalMs = total }
        t.reusedConnection = last.isReusedConnection
        t.networkProtocol = normalizeProtocol(last.networkProtocolName)
        t.wireBytes = Int(last.countOfResponseBodyBytesReceived)
        t.headerBytes = headerBytes
        if #available(macOS 13.0, *) {
            for tx in txs.reversed() where tx.negotiatedTLSProtocolVersion != nil {
                t.tlsVersion = tlsString(tx.negotiatedTLSProtocolVersion!)
                break
            }
        }
        return t
    }

    private static func normalizeProtocol(_ raw: String?) -> String? {
        guard let p = raw?.lowercased() else { return nil }
        if p.contains("h3") || p.contains("quic") { return "HTTP/3" }
        if p.contains("h2") || p.contains("http/2") { return "HTTP/2" }
        if p.contains("1.1") { return "HTTP/1.1" }
        if p.contains("1.0") { return "HTTP/1.0" }
        return p.uppercased()
    }

    private static func tlsString(_ v: tls_protocol_version_t) -> String {
        switch v {
        case .TLSv10: return "TLS 1.0"
        case .TLSv11: return "TLS 1.1"
        case .TLSv12: return "TLS 1.2"
        case .TLSv13: return "TLS 1.3"
        default: return "TLS (other)"
        }
    }
}

enum ResourceType: String, CaseIterable {
    case document, script, stylesheet, image, font, media, other

    var label: String {
        switch self {
        case .document:   return "HTML"
        case .script:     return "JavaScript"
        case .stylesheet: return "CSS"
        case .image:      return "Images"
        case .font:       return "Fonts"
        case .media:      return "Media"
        case .other:      return "Other"
        }
    }

    var symbol: String {
        switch self {
        case .document:   return "doc.richtext"
        case .script:     return "curlybraces"
        case .stylesheet: return "paintbrush"
        case .image:      return "photo"
        case .font:       return "textformat"
        case .media:      return "film"
        case .other:      return "shippingbox"
        }
    }
}

struct ResourceStat: Identifiable {
    var name: String
    var url: String
    var type: ResourceType
    var wireBytes: Int
    var decodedBytes: Int
    var ms: Double?
    var compressed: Bool?
    var cached: Bool
    var contentType: String

    var status: Int = 200
    var host: String = ""
    var thirdParty: Bool = false
    var setupMs: Double? = nil
    var ttfbMs: Double? = nil
    var downloadMs: Double? = nil
    var reused: Bool = false
    var depth: Int = 2
    var renderBlocking: Bool = false
    var cacheStatus: String? = nil

    var compressionWaste: Int = 0
    var minifyWaste: Int = 0
    var imageWaste: Int = 0
    var wasteReasons: [String] = []

    var wastedBytes: Int { compressionWaste + minifyWaste + imageWaste }

    var id: String { url }
    var totalMs: Double? { ms }
}

struct ResourceGroup: Identifiable {
    var type: ResourceType
    var count: Int
    var wireBytes: Int
    var id: String { type.rawValue }
}

struct OriginStat: Identifiable {
    var host: String
    var thirdParty: Bool
    var requests: Int
    var wireBytes: Int
    var slowestMs: Double?
    var blockingRequests: Int
    var setupMs: Double?
    var preconnected: Bool
    var id: String { host }
}

struct TTFBStats {
    var all: [Double] = []
    var cold: [Double] = []
    var warm: [Double] = []

    var best: Double? { all.min() }
    var worst: Double? { all.max() }
    var median: Double? { percentile(0.50) }
    var p95: Double? { percentile(0.95) }
    var coldBest: Double? { cold.min() }
    var warmBest: Double? { warm.min() }

    var jitterMs: Double? {
        guard let b = best, let w = worst, all.count >= 2 else { return nil }
        return w - b
    }

    var jitterRatio: Double? {
        guard let b = best, b > 0, let w = worst, all.count >= 2 else { return nil }
        return w / b
    }

    func percentile(_ p: Double) -> Double? {
        guard !all.isEmpty else { return nil }
        let sorted = all.sorted()
        let idx = min(sorted.count - 1, max(0, Int((Double(sorted.count - 1) * p).rounded())))
        return sorted[idx]
    }
}

struct Opportunity: Identifiable {
    var id = UUID()
    var title: String
    var savedMs: Double
    var savedBytes: Int
    var severity: Severity
    var why: String
    var steps: [String]
    var evidence: [String]
    var reference: String

    var impactLabel: String {
        if savedMs >= 1000 { return String(format: "~%.1f s faster", savedMs / 1000) }
        if savedMs >= 1 { return String(format: "~%.0f ms faster", savedMs) }
        return "quality fix"
    }
}

struct NetworkProfile {
    var name: String
    var kbps: Double
    var rttMs: Double
    var bytesPerMs: Double { kbps / 8 }

    static let all: [NetworkProfile] = [
        NetworkProfile(name: "Wi-Fi / cable", kbps: 30_000, rttMs: 20),
        NetworkProfile(name: "Fast 4G",       kbps: 9_000,  rttMs: 60),
        NetworkProfile(name: "Slow 4G",       kbps: 1_600,  rttMs: 150),
        NetworkProfile(name: "3G",            kbps: 780,    rttMs: 300),
    ]
    static let reference = NetworkProfile(name: "Slow 4G", kbps: 1_600, rttMs: 150)
}

struct NetworkEstimate: Identifiable {
    var profile: String
    var firstByteMs: Double
    var fullLoadMs: Double
    var id: String { profile }
}

struct ChainStep: Identifiable {
    var name: String
    var url: String
    var type: ResourceType
    var ms: Double
    var bytes: Int
    var depth: Int
    var id: String { "\(depth)|\(url)" }
}

struct AssetSample {
    var url: URL
    var response: HTTPResponse
    var timing: RequestTiming
    var depth: Int = 2
    var renderBlocking: Bool = false
}

struct PerformanceProbe {
    var home: HTTPResponse
    var coldSamples: [RequestTiming] = []
    var warmSamples: [RequestTiming] = []
    var discoveredAssetCount: Int = 0
    var assets: [AssetSample] = []
    var revalidationStatus: Int? = nil
}

struct PerformanceReport {
    var url: String
    var status: Int
    var score: Int
    var grade: String
    var scoreBreakdown: [String]

    var dnsMs: Double?
    var tcpMs: Double?
    var tlsMs: Double?

    var ttfb: TTFBStats
    var ttfbBestMs: Double?
    var ttfbMedianMs: Double?
    var ttfbColdMs: Double?
    var ttfbWarmMs: Double?
    var downloadMs: Double?
    var coldTotalMs: Double?
    var networkRTTMs: Double?
    var serverProcessingMs: Double?

    var networkProtocol: String?
    var tlsVersion: String?
    var http3Available: Bool
    var cdn: String?
    var cacheStatus: String?
    var connectionReused: Bool
    var revalidates304: Bool?

    var htmlDecodedBytes: Int
    var htmlWireBytes: Int?
    var htmlCompressed: Bool?
    var renderBlockingScripts: Int
    var renderBlockingStyles: Int

    var groups: [ResourceGroup]
    var resources: [ResourceStat]
    var largest: [ResourceStat]
    var slowest: [ResourceStat]
    var origins: [OriginStat]
    var thirdPartyRequests: Int
    var thirdPartyBytes: Int
    var thirdPartyBlockingMs: Double

    var criticalChain: [ChainStep]
    var criticalChainDepth: Int
    var criticalChainMs: Double

    var jsDecodedBytes: Int
    var jsExecMs: Double

    var totalWireBytes: Int
    var totalDecodedBytes: Int
    var wastedBytes: Int
    var repeatVisitBytes: Int
    var requestCount: Int
    var sampledAssetCount: Int
    var assetsTruncated: Bool

    var opportunities: [Opportunity]
    var estimates: [NetworkEstimate]

    var findings: [Finding]
}

enum PerformanceChecks {

    static let discoverCap = 250
    static let fetchCap = 60
    static let cssChildCap = 20

    static func report(probe: PerformanceProbe) -> PerformanceReport {
        let home = probe.home
        let samples = probe.coldSamples + probe.warmSamples

        var ttfb = TTFBStats()
        ttfb.cold = probe.coldSamples.compactMap { $0.ttfbMs }
        ttfb.warm = probe.warmSamples.filter { $0.reusedConnection }.compactMap { $0.ttfbMs }
        ttfb.all = samples.compactMap { $0.ttfbMs }

        let cold = probe.coldSamples.first ?? probe.warmSamples.first
        let proto = samples.compactMap { $0.networkProtocol }.first
        let tls = samples.compactMap { $0.tlsVersion }.first
        let reused = samples.contains { $0.reusedConnection }

        let rtt = probe.coldSamples.compactMap { $0.handshakeRttMs }.min()
            ?? probe.coldSamples.compactMap { $0.tcpMs }.min()
            ?? cold?.handshakeRttMs ?? cold?.tcpMs
        let serverProcessing = ttfb.best.map { max(0, $0 - (rtt ?? 0)) }

        let htmlWire = cold?.wireBytes
        let htmlCompressed = looksCompressed(cold, header: home.header("content-encoding"))
        let http3 = (home.header("alt-svc")?.lowercased().contains("h3") ?? false) || proto == "HTTP/3"
        let cdn = cdnHint(home)
        let (rbScripts, rbStyles) = countRenderBlocking(home.text)

        let pageHost = home.finalURL.host ?? ""
        let pageDomain = baseDomain(pageHost)
        let preconnects = preconnectHosts(home.text, base: home.finalURL)

        var resources: [ResourceStat] = []

        let docWire = htmlWire ?? home.body.count
        var doc = ResourceStat(
            name: home.finalURL.host ?? "document", url: home.finalURL.absoluteString,
            type: .document, wireBytes: docWire, decodedBytes: home.body.count,
            ms: cold?.timingTotal, compressed: htmlCompressed,
            cached: hasLongCache(home), contentType: home.contentType)
        doc.status = home.status
        doc.host = pageHost
        doc.setupMs = cold?.setupMs
        doc.ttfbMs = ttfb.best
        doc.downloadMs = cold?.downloadMs
        doc.reused = cold?.reusedConnection ?? false
        doc.depth = 1
        doc.cacheStatus = cacheHitStatus(home)
        applyWaste(&doc, response: home)
        resources.append(doc)

        for a in probe.assets {
            let type = classify(url: a.url, contentType: a.response.contentType)
            let wire = a.timing.wireBytes ?? a.response.body.count
            var r = ResourceStat(
                name: displayName(a.url), url: a.url.absoluteString, type: type,
                wireBytes: wire, decodedBytes: a.response.body.count,
                ms: a.timing.timingTotal,
                compressed: looksCompressed(a.timing, header: a.response.header("content-encoding")),
                cached: hasLongCache(a.response), contentType: a.response.contentType)
            r.status = a.response.status
            r.host = a.url.host ?? ""
            r.thirdParty = !r.host.isEmpty && baseDomain(r.host) != pageDomain
            r.setupMs = a.timing.setupMs
            r.ttfbMs = a.timing.ttfbMs
            r.downloadMs = a.timing.downloadMs
            r.reused = a.timing.reusedConnection
            r.depth = a.depth
            r.renderBlocking = a.renderBlocking
            r.cacheStatus = cacheHitStatus(a.response)
            applyWaste(&r, response: a.response)
            resources.append(r)
        }

        var groupMap: [ResourceType: (count: Int, bytes: Int)] = [:]
        for r in resources {
            let g = groupMap[r.type] ?? (0, 0)
            groupMap[r.type] = (g.count + 1, g.bytes + r.wireBytes)
        }
        let groups = ResourceType.allCases
            .compactMap { t -> ResourceGroup? in
                guard let g = groupMap[t], g.count > 0 else { return nil }
                return ResourceGroup(type: t, count: g.count, wireBytes: g.bytes)
            }
            .sorted { $0.wireBytes > $1.wireBytes }

        let largest = resources.sorted { $0.wireBytes > $1.wireBytes }.prefix(6).map { $0 }
        let slowest = resources
            .filter { ($0.ms ?? 0) > 0 }
            .sorted { ($0.ms ?? 0) > ($1.ms ?? 0) }
            .prefix(10).map { $0 }

        let origins = buildOrigins(resources, preconnects: preconnects)
        let thirdParty = resources.filter { $0.thirdParty }
        let thirdPartyBlocking = thirdParty.filter { $0.renderBlocking }.reduce(0.0) { $0 + ($1.ms ?? 0) }

        let (chain, chainDepth, chainMs) = buildCriticalChain(resources: resources, cold: cold)

        let jsBytes = resources.filter { $0.type == .script }.reduce(0) { $0 + $1.decodedBytes }
        let jsExec = Double(jsBytes) / 1024.0

        let totalWire = resources.reduce(0) { $0 + $1.wireBytes }
        let totalDecoded = resources.reduce(0) { $0 + $1.decodedBytes }
        let wasted = resources.reduce(0) { $0 + $1.wastedBytes }
        let repeatVisit = resources.filter { !$0.cached && $0.type != .document }.reduce(0) { $0 + $1.wireBytes }
        let requestCount = 1 + probe.discoveredAssetCount
        let truncated = probe.assets.count < probe.discoveredAssetCount

        let estimates = estimateLoad(totalWireBytes: totalWire, serverProcessingMs: serverProcessing,
                                     tls13: tls == "TLS 1.3", chainDepth: chainDepth,
                                     proto: proto, requestCount: requestCount)

        let redirected = home.requestedURL.absoluteString != home.finalURL.absoluteString

        let opportunities = buildOpportunities(
            home: home, resources: resources, origins: origins, ttfb: ttfb, rtt: rtt,
            proto: proto, tls: tls, http3: http3, cdn: cdn, chainDepth: chainDepth,
            jsBytes: jsBytes, jsExec: jsExec, redirected: redirected,
            renderBlockingCount: rbScripts + rbStyles, repeatVisitBytes: repeatVisit,
            revalidationStatus: probe.revalidationStatus, preconnects: preconnects,
            pageDomain: pageDomain)

        let (score, breakdown) = computeScore(
            ttfb: ttfb, proto: proto, tls: tls, http3: http3,
            htmlCompressed: htmlCompressed, totalWire: totalWire,
            requestCount: requestCount, renderBlocking: rbScripts + rbStyles,
            resources: resources, redirected: redirected, chainDepth: chainDepth,
            jsExec: jsExec, thirdPartyBytes: thirdParty.reduce(0) { $0 + $1.wireBytes })

        var report = PerformanceReport(
            url: home.finalURL.absoluteString, status: home.status,
            score: score, grade: grade(score), scoreBreakdown: breakdown,
            dnsMs: cold?.dnsMs, tcpMs: cold?.tcpMs, tlsMs: cold?.tlsMs,
            ttfb: ttfb,
            ttfbBestMs: ttfb.best, ttfbMedianMs: ttfb.median,
            ttfbColdMs: ttfb.coldBest, ttfbWarmMs: ttfb.warmBest,
            downloadMs: cold?.downloadMs, coldTotalMs: cold?.timingTotal,
            networkRTTMs: rtt, serverProcessingMs: serverProcessing,
            networkProtocol: proto, tlsVersion: tls, http3Available: http3, cdn: cdn,
            cacheStatus: cacheHitStatus(home), connectionReused: reused,
            revalidates304: probe.revalidationStatus.map { $0 == 304 },
            htmlDecodedBytes: home.body.count, htmlWireBytes: htmlWire, htmlCompressed: htmlCompressed,
            renderBlockingScripts: rbScripts, renderBlockingStyles: rbStyles,
            groups: groups, resources: resources, largest: largest, slowest: slowest,
            origins: origins,
            thirdPartyRequests: thirdParty.count,
            thirdPartyBytes: thirdParty.reduce(0) { $0 + $1.wireBytes },
            thirdPartyBlockingMs: thirdPartyBlocking,
            criticalChain: chain, criticalChainDepth: chainDepth, criticalChainMs: chainMs,
            jsDecodedBytes: jsBytes, jsExecMs: jsExec,
            totalWireBytes: totalWire, totalDecodedBytes: totalDecoded,
            wastedBytes: wasted, repeatVisitBytes: repeatVisit,
            requestCount: requestCount, sampledAssetCount: probe.assets.count, assetsTruncated: truncated,
            opportunities: opportunities, estimates: estimates,
            findings: [])

        var findings: [Finding] = [summary(report: report, samples: samples)]
        if let f = documentStatus(report: report, home: home) { findings.insert(f, at: 0) }
        if let f = improvementPlan(report: report) { findings.append(f) }
        if let f = slowestResources(report: report) { findings.append(f) }
        if let f = criticalChainFinding(report: report) { findings.append(f) }
        if let f = serverResponseTime(report: report) { findings.append(f) }
        if let f = ttfbConsistency(report: report) { findings.append(f) }
        if let f = edgeCacheFinding(report: report) { findings.append(f) }
        if let f = thirdPartyFinding(report: report) { findings.append(f) }
        if let f = protocolUpgrade(report: report) { findings.append(f) }
        if let f = http3Suggestion(report: report) { findings.append(f) }
        if let f = tls13(version: tls) { findings.append(f) }
        if let f = compression(home: home, timing: cold) { findings.append(f) }
        if let f = uncompressedAssets(report: report) { findings.append(f) }
        if let f = minificationFinding(report: report) { findings.append(f) }
        if let f = largeDocument(home: home) { findings.append(f) }
        if let f = pageWeight(report: report) { findings.append(f) }
        if let f = jsCostFinding(report: report) { findings.append(f) }
        if let f = renderBlocking(report: report, url: home.finalURL) { findings.append(f) }
        if let f = imageOptimization(html: home.text, resources: resources, pageURL: home.finalURL) { findings.append(f) }
        if let f = fontOptimization(html: home.text, resources: resources, pageURL: home.finalURL) { findings.append(f) }
        if let f = assetAudit(resources: resources) { findings.append(f) }
        if let f = repeatVisitFinding(report: report) { findings.append(f) }
        if let f = htmlCaching(home: home) { findings.append(f) }
        if let f = brokenAssets(report: report) { findings.append(f) }
        if let f = networkSimulation(report: report) { findings.append(f) }
        if let f = serverTiming(home: home) { findings.append(f) }
        if let f = redirectChain(home: home) { findings.append(f) }
        report.findings = findings
        return report
    }

    private static func applyWaste(_ r: inout ResourceStat, response: HTTPResponse) {
        var reasons: [String] = []

        if isCompressible(r.contentType), r.decodedBytes >= 2048, r.compressed == false {
            r.compressionWaste = Int(Double(r.decodedBytes) * 0.72)
            reasons.append("not compressed (~\(kb(r.compressionWaste)) recoverable with Brotli/gzip)")
        }

        if r.type == .script || r.type == .stylesheet {
            let saved = minificationWaste(response, decoded: r.decodedBytes)
            if saved > 0 {
                r.minifyWaste = r.compressionWaste > 0 ? saved / 3 : saved
                reasons.append("not minified (~\(kb(r.minifyWaste)) of whitespace/comments)")
            }
        }

        if r.type == .image, r.decodedBytes > 60_000 {
            let ct = r.contentType.lowercased()
            let ext = (URL(string: r.url)?.pathExtension ?? "").lowercased()
            var factor = 0.0
            var label = ""
            if ct.contains("png") || ext == "png" { factor = 0.45; label = "PNG → WebP/AVIF" }
            else if ct.contains("jpeg") || ct.contains("jpg") || ["jpg", "jpeg"].contains(ext) { factor = 0.30; label = "JPEG → WebP/AVIF" }
            else if ct.contains("gif") || ext == "gif" { factor = 0.80; label = "GIF → WebP or MP4" }
            if factor > 0 {
                r.imageWaste = Int(Double(r.decodedBytes) * factor)
                reasons.append("\(label) (~\(kb(r.imageWaste)))")
            }
            if r.decodedBytes > 300_000 {
                reasons.append("oversized for the web at \(kb(r.decodedBytes)) - resize to display size")
            }
        }

        r.wasteReasons = reasons
    }

    private static func minificationWaste(_ r: HTTPResponse, decoded: Int) -> Int {
        guard decoded >= 4096 else { return 0 }
        let text = r.text
        let utf8 = text.utf8
        guard utf8.count > 1024 else { return 0 }
        var ws = 0
        for b in utf8 where b == 32 || b == 9 || b == 10 || b == 13 { ws += 1 }
        let ratio = Double(ws) / Double(utf8.count)
        guard ratio > 0.12 else { return 0 }
        return Int(Double(decoded) * min(0.45, ratio - 0.03))
    }

    private static func buildOrigins(_ resources: [ResourceStat], preconnects: Set<String>) -> [OriginStat] {
        var map: [String: OriginStat] = [:]
        for r in resources where !r.host.isEmpty {
            var o = map[r.host] ?? OriginStat(host: r.host, thirdParty: r.thirdParty, requests: 0,
                                              wireBytes: 0, slowestMs: nil, blockingRequests: 0,
                                              setupMs: nil, preconnected: preconnects.contains(r.host))
            o.requests += 1
            o.wireBytes += r.wireBytes
            if let m = r.ms { o.slowestMs = max(o.slowestMs ?? 0, m) }
            if r.renderBlocking { o.blockingRequests += 1 }
            if let s = r.setupMs, s > 0 { o.setupMs = max(o.setupMs ?? 0, s) }
            map[r.host] = o
        }
        return map.values.sorted { $0.wireBytes > $1.wireBytes }
    }

    private static func buildCriticalChain(resources: [ResourceStat],
                                           cold: RequestTiming?) -> ([ChainStep], Int, Double) {
        var steps: [ChainStep] = []
        let doc = resources.first { $0.depth == 1 }
        if let doc {
            steps.append(ChainStep(name: doc.name, url: doc.url, type: .document,
                                   ms: doc.ms ?? cold?.timingTotal ?? 0, bytes: doc.wireBytes, depth: 1))
        }

        let blocking = resources.filter { $0.renderBlocking && $0.depth == 2 }
            .sorted { ($0.ms ?? 0) > ($1.ms ?? 0) }
        if let worstBlocking = blocking.first {
            steps.append(ChainStep(name: worstBlocking.name, url: worstBlocking.url, type: worstBlocking.type,
                                   ms: worstBlocking.ms ?? 0, bytes: worstBlocking.wireBytes, depth: 2))
        }
        let nested = resources.filter { $0.depth >= 3 }.sorted { ($0.ms ?? 0) > ($1.ms ?? 0) }
        if let worstNested = nested.first {
            steps.append(ChainStep(name: worstNested.name, url: worstNested.url, type: worstNested.type,
                                   ms: worstNested.ms ?? 0, bytes: worstNested.wireBytes, depth: 3))
        }

        let depth = steps.count
        let total = steps.reduce(0.0) { $0 + $1.ms }
        return (steps, depth, total)
    }

    private static func estimateLoad(totalWireBytes: Int, serverProcessingMs: Double?,
                                     tls13: Bool, chainDepth: Int, proto: String?,
                                     requestCount: Int) -> [NetworkEstimate] {
        let think = serverProcessingMs ?? 100
        let http1Penalty = (proto == "HTTP/1.1" || proto == "HTTP/1.0")
            ? Double(max(0, requestCount - 6)) / 6.0 : 0

        return NetworkProfile.all.map { p in
            let handshake = p.rttMs * (1  + 1  + (tls13 ? 1 : 2))
            let firstByte = handshake + think + p.rttMs
            let transfer = Double(totalWireBytes) / p.bytesPerMs
            let chain = Double(max(0, chainDepth - 1)) * p.rttMs
            let queueing = http1Penalty * p.rttMs
            return NetworkEstimate(profile: p.name,
                                   firstByteMs: firstByte,
                                   fullLoadMs: firstByte + transfer + chain + queueing)
        }
    }

    private static func msForBytes(_ bytes: Int) -> Double {
        Double(bytes) / NetworkProfile.reference.bytesPerMs
    }

    private static func buildOpportunities(home: HTTPResponse, resources: [ResourceStat],
                                           origins: [OriginStat], ttfb: TTFBStats, rtt: Double?,
                                           proto: String?, tls: String?, http3: Bool, cdn: String?,
                                           chainDepth: Int, jsBytes: Int, jsExec: Double,
                                           redirected: Bool, renderBlockingCount: Int,
                                           repeatVisitBytes: Int, revalidationStatus: Int?,
                                           preconnects: Set<String>, pageDomain: String) -> [Opportunity] {
        var out: [Opportunity] = []
        let refRTT = NetworkProfile.reference.rttMs

        if let best = ttfb.best, best > 250 {
            let target = cdn == nil ? 200.0 : 150.0
            let saved = best - target
            let slowSegments = serverTimingSegments(home).prefix(3)
            var evidence = ["Best TTFB \(ms(best)) · median \(ms(ttfb.median)) · p95 \(ms(ttfb.p95))"]
            if let r = rtt { evidence.append("Measured network round trip: \(ms(r)) — so ~\(ms(max(0, best - r))) of that is the server thinking") }
            if !slowSegments.isEmpty { evidence.append("Server-Timing says: " + slowSegments.joined(separator: ", ")) }
            out.append(Opportunity(
                title: "Cut server response time (TTFB \(ms(best)))",
                savedMs: saved, savedBytes: 0,
                severity: best > 1200 ? .high : (best > 600 ? .medium : .low),
                why: "Nothing paints until the first byte arrives, so TTFB is added to every other timing on the page. Getting to under \(ms(target)) moves the whole waterfall left.",
                steps: [
                    "Put a full-page or fragment cache in front of the slow handler (Redis/Memcached, Varnish, or your framework's page cache).",
                    cdn == nil
                        ? "Add a CDN and let it cache HTML at the edge — this alone often takes TTFB from hundreds of ms to tens."
                        : "You already have \(cdn!): make HTML actually cacheable at the edge (s-maxage + stale-while-revalidate) and check for a cache HIT header.",
                    "Profile the request: log per-phase timings and emit a Server-Timing header so you can see DB vs template vs upstream.",
                    "Fix the slowest queries — add indexes, kill N+1 patterns, and pool database connections.",
                    "Keep the app warm (no cold starts): use persistent workers or provisioned concurrency on serverless.",
                ],
                evidence: evidence,
                reference: "https://web.dev/articles/ttfb"))
        }

        let uncompressed = resources.filter { $0.compressionWaste > 0 }
        if !uncompressed.isEmpty {
            let bytes = uncompressed.reduce(0) { $0 + $1.compressionWaste }
            out.append(Opportunity(
                title: "Enable Brotli/gzip on \(uncompressed.count) text response(s)",
                savedMs: msForBytes(bytes), savedBytes: bytes,
                severity: bytes > 200_000 ? .medium : .low,
                why: "Text compresses by 70–90%. Every uncompressed byte is paid on every single visit by every visitor.",
                steps: [
                    "Turn on Brotli (fall back to gzip) for text/html, text/css, application/javascript, application/json, image/svg+xml and XML.",
                    "nginx: `brotli on; brotli_types …;` or `gzip on; gzip_types …;`  ·  Apache: `mod_brotli`/`mod_deflate`  ·  Caddy & most CDNs: on by default, just verify.",
                    "Pre-compress static build output (`.br` / `.gz` next to the original) so the server never compresses at request time.",
                    "Verify with `curl -H 'Accept-Encoding: br,gzip' -I <url>` and confirm a `content-encoding` header comes back.",
                ],
                evidence: uncompressed.prefix(6).map { "\($0.name) — \(kb($0.decodedBytes)) uncompressed" },
                reference: "https://web.dev/articles/reduce-network-payloads-using-text-compression"))
        }

        let imageWaste = resources.filter { $0.imageWaste > 0 }
            .sorted { $0.imageWaste > $1.imageWaste }
        if !imageWaste.isEmpty {
            let bytes = imageWaste.reduce(0) { $0 + $1.imageWaste }
            out.append(Opportunity(
                title: "Re-encode \(imageWaste.count) image(s) to modern formats",
                savedMs: msForBytes(bytes), savedBytes: bytes,
                severity: bytes > 500_000 ? .medium : .low,
                why: "Images are usually the largest thing on a page and the most compressible. AVIF/WebP typically cut 30–50% off the same visual quality.",
                steps: [
                    "Serve AVIF with a WebP fallback via `<picture>`, or let your CDN/image service negotiate the format automatically.",
                    "Resize to the largest size actually displayed and ship `srcset`/`sizes` so phones do not download desktop-sized images.",
                    "Add `loading=\"lazy\"` + `decoding=\"async\"` to below-the-fold images, and `fetchpriority=\"high\"` to the LCP image only.",
                    "Always set `width`/`height` (or `aspect-ratio`) so the layout does not shift while images load.",
                ],
                evidence: imageWaste.prefix(6).map { "\($0.name) — \(kb($0.decodedBytes)), \($0.wasteReasons.joined(separator: "; "))" },
                reference: "https://web.dev/articles/optimize-lcp#optimize-the-lcp-image"))
        }
        let unminified = resources.filter { $0.minifyWaste > 0 }
        if !unminified.isEmpty {
            let bytes = unminified.reduce(0) { $0 + $1.minifyWaste }
            out.append(Opportunity(
                title: "Minify \(unminified.count) JavaScript/CSS file(s)",
                savedMs: msForBytes(bytes), savedBytes: bytes,
                severity: .low,
                why: "These files still carry source formatting and comments — bytes that cost download time and parse time but do nothing at runtime.",
                steps: [
                    "Run the production build through esbuild/terser (JS) and cssnano/lightningcss (CSS) — usually one flag in your bundler.",
                    "Ship source maps separately (`//# sourceMappingURL=` on a `.map` file) so debugging still works.",
                    "Drop dead code: tree-shaking plus `NODE_ENV=production` removes dev-only branches.",
                ],
                evidence: unminified.prefix(6).map { "\($0.name) — \(kb($0.decodedBytes))" },
                reference: "https://web.dev/articles/reduce-network-payloads-using-text-compression"))
        }

        let blockingResources = resources.filter { $0.renderBlocking }
        if renderBlockingCount >= 3 {
            let measured = blockingResources.reduce(0.0) { $0 + ($1.ms ?? 0) }
            let saved = max(Double(min(renderBlockingCount, 10)) * refRTT * 0.4, measured * 0.5)
            out.append(Opportunity(
                title: "Unblock rendering (\(renderBlockingCount) blocking resource(s))",
                savedMs: saved, savedBytes: 0,
                severity: renderBlockingCount >= 10 ? .medium : .low,
                why: "The browser refuses to paint until every blocking script and stylesheet is downloaded and processed. Each one is a serial step in front of your first paint.",
                steps: [
                    "Add `defer` to every `<script src>` that is not needed before paint (or `async` for independent analytics-style scripts).",
                    "Inline the critical CSS for above-the-fold content and load the rest with `<link rel=\"preload\" as=\"style\" onload=\"this.rel='stylesheet'\">`.",
                    "Split CSS by media (`media=\"print\"`, `media=\"(min-width:900px)\"`) so non-matching sheets stop blocking.",
                    "Move third-party tags (chat, A/B, analytics) out of the blocking path — load them after `load` or via a tag manager set to async.",
                ],
                evidence: blockingResources.isEmpty
                    ? ["\(renderBlockingCount) blocking `<script>`/`<link rel=stylesheet>` tag(s) in the HTML"]
                    : blockingResources.prefix(6).map { "\($0.name) — \(ms($0.ms)) blocking" },
                reference: "https://web.dev/articles/render-blocking-resources"))
        }

        let uncached = resources.filter { !$0.cached && $0.type != .document && $0.status == 200 }
        if uncached.count >= 2 {
            out.append(Opportunity(
                title: "Cache \(uncached.count) static asset(s) for repeat visits",
                savedMs: msForBytes(repeatVisitBytes) * 0.9, savedBytes: repeatVisitBytes,
                severity: repeatVisitBytes > 500_000 ? .medium : .low,
                why: "Without a long `Cache-Control`, returning visitors re-download \(kb(repeatVisitBytes)) they already have. This is the cheapest win on the whole list.",
                steps: [
                    "Fingerprint filenames (`app.9f3c1a.js`) so the content can never go stale, then send `Cache-Control: public, max-age=31536000, immutable`.",
                    "For non-fingerprinted assets use a shorter `max-age` plus an `ETag` so revalidation is a cheap 304.",
                    "Set the header at the CDN as well as the origin — the edge is where most repeat requests land.",
                ],
                evidence: uncached.prefix(6).map { "\($0.name) — \(kb($0.wireBytes)), Cache-Control missing or short" },
                reference: "https://web.dev/articles/uses-long-cache-ttl"))
        }

        let thirdOrigins = origins.filter { $0.thirdParty }
        if !thirdOrigins.isEmpty {
            let unconnected = thirdOrigins.filter { !$0.preconnected }
            let tpBytes = thirdOrigins.reduce(0) { $0 + $1.wireBytes }
            if !unconnected.isEmpty {
                let saved = Double(min(unconnected.count, 4)) * refRTT * 2
                out.append(Opportunity(
                    title: "Preconnect to \(unconnected.count) third-party origin(s)",
                    savedMs: saved, savedBytes: 0,
                    severity: .low,
                    why: "Every new origin costs a DNS lookup, a TCP handshake and a TLS handshake — about three round trips — and the browser only starts them when it discovers the URL deep in the HTML.",
                    steps: [
                        "Add `<link rel=\"preconnect\" href=\"https://host\" crossorigin>` in `<head>` for the 2–4 origins on the critical path (fonts, image CDN, main API).",
                        "Use `<link rel=\"dns-prefetch\">` for the less critical ones — cheaper, and a useful fallback.",
                        "Do not preconnect to more than ~4 origins; each open connection has a cost of its own.",
                        "Better still: self-host the small stuff (fonts, a single analytics snippet) so there is no extra origin at all.",
                    ],
                    evidence: unconnected.prefix(6).map { "\($0.host) — \($0.requests) request(s), \(kb($0.wireBytes))\($0.setupMs.map { s in ", \(ms(s)) connection setup" } ?? "")" },
                    reference: "https://web.dev/articles/preconnect-and-dns-prefetch"))
            }
            if tpBytes > 300_000 || thirdOrigins.count >= 5 {
                out.append(Opportunity(
                    title: "Trim third-party weight (\(thirdOrigins.count) origins, \(kb(tpBytes)))",
                    savedMs: msForBytes(tpBytes / 3), savedBytes: tpBytes / 3,
                    severity: tpBytes > 1_000_000 ? .medium : .low,
                    why: "Third-party code is bytes and main-thread time you do not control, on servers whose latency you cannot fix.",
                    steps: [
                        "Audit what each origin is for and delete the ones nobody reads the data from.",
                        "Load the survivors lazily — after first interaction, on idle (`requestIdleCallback`), or inside a facade (click-to-load embeds for video/maps/chat).",
                        "Self-host what you can: fonts, small libraries, and analytics collectors all work from your own origin.",
                        "Sandbox heavy widgets in an `<iframe>` so they cannot block your main thread.",
                    ],
                    evidence: thirdOrigins.prefix(6).map { "\($0.host) — \($0.requests) request(s), \(kb($0.wireBytes))" },
                    reference: "https://web.dev/articles/third-party-summary"))
            }
        }

        if let p = proto, p == "HTTP/1.1" || p == "HTTP/1.0" {
            out.append(Opportunity(
                title: "Upgrade from \(p) to HTTP/2 or HTTP/3",
                savedMs: refRTT * 3, savedBytes: 0,
                severity: .medium,
                why: "On \(p) the browser opens ~6 connections and queues everything else behind them. HTTP/2 multiplexes all of it over one connection with compressed headers.",
                steps: [
                    "Flip HTTP/2 on at the edge: nginx `listen 443 ssl http2;`, Apache `Protocols h2 http/1.1`, Caddy/CDNs have it on by default.",
                    "Then enable HTTP/3 (QUIC over UDP 443) and advertise it with `Alt-Svc: h3=\":443\"`.",
                    "Once on HTTP/2, drop the HTTP/1 workarounds — domain sharding, image sprites and inlining now hurt more than they help.",
                ],
                evidence: ["Negotiated protocol: \(p)"],
                reference: "https://web.dev/articles/performance-http2"))
        } else if proto == "HTTP/2" && !http3 {
            out.append(Opportunity(
                title: "Enable HTTP/3 (QUIC)",
                savedMs: refRTT, savedBytes: 0, severity: .low,
                why: "QUIC removes TCP head-of-line blocking and sets up connections in fewer round trips — the difference shows up exactly where your users are weakest: flaky mobile networks.",
                steps: [
                    "Turn on HTTP/3 at your CDN (Cloudflare, Fastly, CloudFront, Bunny) or server (nginx 1.25+, Caddy, LiteSpeed).",
                    "Confirm the `Alt-Svc: h3=\":443\"; ma=86400` header is being sent so browsers know to upgrade.",
                    "Make sure UDP/443 is not blocked by a firewall in front of the origin.",
                ],
                evidence: ["Negotiated: HTTP/2 · no `h3` advertised in Alt-Svc"],
                reference: "https://web.dev/articles/http3"))
        }

        if let t = tls, t != "TLS 1.3", t.hasPrefix("TLS") {
            out.append(Opportunity(
                title: "Enable TLS 1.3",
                savedMs: refRTT, savedBytes: 0, severity: .low,
                why: "TLS 1.3 finishes the handshake in one round trip instead of two, and supports 0-RTT resumption for returning visitors.",
                steps: [
                    "Add TLS 1.3 to the protocol list (nginx `ssl_protocols TLSv1.2 TLSv1.3;`) and keep 1.2 for old clients.",
                    "Enable session resumption / session tickets so repeat connections skip the full handshake.",
                    "Turn on OCSP stapling so the browser does not make its own revocation round trip.",
                ],
                evidence: ["Negotiated TLS version: \(t)"],
                reference: "https://www.rfc-editor.org/rfc/rfc8446"))
        }

        if jsBytes > 300_000 {
            out.append(Opportunity(
                title: "Reduce JavaScript (\(kb(jsBytes)) parsed on the main thread)",
                savedMs: jsExec * 0.4, savedBytes: jsBytes / 3,
                severity: jsBytes > 1_000_000 ? .medium : .low,
                why: "A mid-tier phone spends roughly a millisecond per kilobyte parsing, compiling and running JS — about \(ms(jsExec)) here — and the page cannot respond to taps while that happens.",
                steps: [
                    "Code-split by route and lazy-import anything below the fold or behind an interaction (`import()`).",
                    "Check the bundle with a treemap (`vite-bundle-visualizer`, `webpack-bundle-analyzer`) and remove the biggest dependency you barely use — date/lodash/icon libraries are the usual culprits.",
                    "Prefer per-function imports over whole-library imports so tree-shaking can work.",
                    "Ship modern syntax to modern browsers (`type=\"module\"`) instead of transpiling everything down to ES5.",
                    "Move expensive work off the main thread with a Web Worker, or to the server entirely.",
                ],
                evidence: ["JavaScript: \(kb(jsBytes)) decoded across \(resources.filter { $0.type == .script }.count) file(s)",
                           "Estimated main-thread cost: \(ms(jsExec)) on a mid-tier phone"],
                reference: "https://web.dev/articles/bootup-time"))
        }

        if chainDepth >= 3 {
            out.append(Opportunity(
                title: "Shorten the critical request chain (\(chainDepth) levels deep)",
                savedMs: Double(chainDepth - 2) * refRTT * 1.5, savedBytes: 0,
                severity: .low,
                why: "Resources found inside other resources cannot start downloading until their parent has arrived and been parsed. Each extra level is at least another full round trip before first paint.",
                steps: [
                    "`<link rel=\"preload\">` the fonts and hero images that are currently discovered inside CSS, so they start immediately.",
                    "Inline the small critical CSS instead of making the browser fetch a stylesheet to find out what else it needs.",
                    "Avoid `@import` inside CSS — it adds a whole serial level; concatenate at build time instead.",
                    "Consider `103 Early Hints` or HTTP/2 server push at the CDN to start critical assets during server think time.",
                ],
                evidence: ["Deepest discovery level measured: \(chainDepth)"],
                reference: "https://web.dev/articles/critical-rendering-path"))
        }

        if redirected {
            out.append(Opportunity(
                title: "Remove the landing redirect",
                savedMs: refRTT * 2, savedBytes: 0, severity: .low,
                why: "The entry URL redirects before any content is served, so the first byte of real HTML costs an extra round trip (and often a second TLS handshake).",
                steps: [
                    "Point links, ads and sitemaps at the final canonical URL directly.",
                    "Collapse chains (`http → https → www → /path`) into a single hop.",
                    "Send HSTS with `preload` so browsers skip the `http → https` hop entirely.",
                ],
                evidence: ["Requested: \(home.requestedURL.absoluteString)", "Final: \(home.finalURL.absoluteString)"],
                reference: "https://web.dev/articles/redirects"))
        }

        if let status = cacheHitStatus(home), edgeCacheHit(status) == false, cdn != nil {
            out.append(Opportunity(
                title: "HTML is missing the \(cdn!) edge cache",
                savedMs: max(0, (ttfb.best ?? 300) - 60), savedBytes: 0,
                severity: .low,
                why: "The CDN reported a cache MISS, so every visitor's request travels all the way to your origin. The edge is right there — it is just not being allowed to answer.",
                steps: [
                    "Send `Cache-Control: public, s-maxage=60, stale-while-revalidate=86400` on cacheable HTML.",
                    "Stop setting cookies on cacheable responses — a `Set-Cookie` makes most CDNs skip the cache.",
                    "Normalise the cache key: ignore marketing query parameters (utm_*, fbclid) so variants collapse into one entry.",
                    "Use tag/surrogate-key purging so you can cache aggressively and invalidate instantly on publish.",
                ],
                evidence: ["Cache status header: \(status)"],
                reference: "https://web.dev/articles/http-cache"))
        }

        let broken = resources.filter { $0.status >= 400 && $0.depth > 1 }
        if !broken.isEmpty {
            out.append(Opportunity(
                title: "Fix \(broken.count) failing asset request(s)",
                savedMs: broken.reduce(0.0) { $0 + ($1.ms ?? 0) }, savedBytes: 0,
                severity: .medium,
                why: "These requests cost a full round trip and return nothing usable — pure latency for zero benefit, and often a visibly broken page.",
                steps: [
                    "Remove or repair the referencing tag in the HTML/CSS.",
                    "Check your build output actually ships these paths (a stale hash or missing copy step is the usual cause).",
                    "Add a link/asset check to CI so a 404 asset fails the build instead of the page.",
                ],
                evidence: broken.prefix(6).map { "HTTP \($0.status) — \($0.url)" },
                reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status"))
        }

        return out.sorted { $0.savedMs > $1.savedMs }
    }

    private static func serverTimingSegments(_ home: HTTPResponse) -> [String] {
        guard let raw = home.header("server-timing") else { return [] }
        return raw.split(separator: ",").compactMap { part in
            let fields = part.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
            guard let name = fields.first, !name.isEmpty else { return nil }
            guard let durField = fields.first(where: { $0.lowercased().hasPrefix("dur=") }),
                  let d = Double(durField.dropFirst(4)) else { return nil }
            return String(format: "%@ %.0f ms", name, d)
        }
    }

    private static func computeScore(ttfb: TTFBStats, proto: String?, tls: String?, http3: Bool,
                                     htmlCompressed: Bool?, totalWire: Int, requestCount: Int,
                                     renderBlocking: Int, resources: [ResourceStat],
                                     redirected: Bool, chainDepth: Int, jsExec: Double,
                                     thirdPartyBytes: Int) -> (Int, [String]) {
        var s = 100.0
        var notes: [String] = []
        func deduct(_ n: Double, _ why: String) {
            guard n > 0 else { return }
            s -= n
            notes.append(String(format: "-%.0f  %@", n, why))
        }

        if let t = ttfb.best {
            switch t {
            case ..<200:  break
            case ..<500:  deduct(8,  "TTFB \(ms(t)) (aim < 200 ms)")
            case ..<1000: deduct(16, "slow TTFB \(ms(t))")
            case ..<1800: deduct(26, "very slow TTFB \(ms(t))")
            default:      deduct(34, "very slow TTFB \(ms(t))")
            }
        }
        if let ratio = ttfb.jitterRatio, let j = ttfb.jitterMs, j > 250 {
            if ratio > 3      { deduct(6, String(format: "inconsistent TTFB (%.1f× spread, %@)", ratio, ms(j))) }
            else if ratio > 2 { deduct(3, String(format: "variable TTFB (%.1f× spread)", ratio)) }
        }
        if proto == "HTTP/1.1" || proto == "HTTP/1.0" { deduct(8, "served over \(proto!)") }
        if tls == "TLS 1.2" || tls == "TLS 1.1" || tls == "TLS 1.0" { deduct(3, "\(tls!) (no TLS 1.3)") }
        if htmlCompressed == false { deduct(8, "HTML not compressed") }

        let mb = Double(totalWire) / 1_048_576
        if mb > 4      { deduct(20, String(format: "heavy page (%.1f MB)", mb)) }
        else if mb > 2 { deduct(12, String(format: "large page (%.1f MB)", mb)) }
        else if mb > 1 { deduct(6,  String(format: "page weight %.1f MB", mb)) }

        if requestCount > 80      { deduct(12, "\(requestCount) requests") }
        else if requestCount > 50 { deduct(7,  "\(requestCount) requests") }
        else if requestCount > 30 { deduct(3,  "\(requestCount) requests") }

        if renderBlocking >= 12     { deduct(10, "\(renderBlocking) render-blocking resources") }
        else if renderBlocking >= 6 { deduct(4,  "\(renderBlocking) render-blocking resources") }

        let uncompressed = resources.filter { isCompressible($0.contentType) && $0.decodedBytes >= 2048 && $0.compressed == false }
        deduct(min(12, Double(uncompressed.count) * 3), "\(uncompressed.count) uncompressed text asset(s)")

        let uncached = resources.filter { $0.type != .document && !$0.cached }
        deduct(min(6, Double(uncached.count)), "\(uncached.count) asset(s) without long caching")

        let bigImages = resources.filter { $0.type == .image && $0.decodedBytes > 200_000 }
        deduct(min(10, Double(bigImages.count) * 3), "\(bigImages.count) oversized image(s)")

        if jsExec > 1500      { deduct(8, String(format: "heavy JavaScript (~%.0f ms main-thread)", jsExec)) }
        else if jsExec > 600  { deduct(4, String(format: "sizeable JavaScript (~%.0f ms main-thread)", jsExec)) }

        let tpMB = Double(thirdPartyBytes) / 1_048_576
        if tpMB > 1        { deduct(6, String(format: "%.1f MB of third-party content", tpMB)) }
        else if tpMB > 0.4 { deduct(3, String(format: "%.1f MB of third-party content", tpMB)) }

        if chainDepth >= 4      { deduct(6, "\(chainDepth)-level critical request chain") }
        else if chainDepth == 3 { deduct(3, "3-level critical request chain") }

        let broken = resources.filter { $0.status >= 400 && $0.depth > 1 }
        deduct(min(6, Double(broken.count) * 2), "\(broken.count) failing asset request(s)")

        if redirected { deduct(3, "redirect before first byte") }

        return (max(0, min(100, Int(s.rounded()))), notes)
    }

    static func grade(_ score: Int) -> String {
        switch score {
        case 95...:  return "A+"
        case 90...:  return "A"
        case 80...:  return "B"
        case 70...:  return "C"
        case 60...:  return "D"
        default:     return "F"
        }
    }

    private static func summary(report r: PerformanceReport, samples: [RequestTiming]) -> Finding {
        var lines: [String] = []
        lines.append("Performance score: \(r.score)/100 (grade \(r.grade))")
        lines.append("URL: \(r.url)  ·  HTTP \(r.status)")
        if let p = r.networkProtocol { lines.append("Protocol: \(p)\(r.http3Available ? " (HTTP/3 advertised)" : "")") }
        if let t = r.tlsVersion { lines.append("TLS: \(t)") }
        lines.append("Server response (TTFB): best \(ms(r.ttfb.best)) · median \(ms(r.ttfb.median)) · p95 \(ms(r.ttfb.p95)) · worst \(ms(r.ttfb.worst))")
        if let rtt = r.networkRTTMs, let think = r.serverProcessingMs {
            lines.append("Split: ~\(ms(rtt)) network round trip + ~\(ms(think)) server processing")
        }
        if let warm = r.ttfbWarmMs, let coldT = r.ttfbColdMs {
            lines.append("TTFB cold \(ms(coldT)) → warm \(ms(warm)) (connection reuse)")
        }
        let setup = [("DNS", r.dnsMs), ("TCP", r.tcpMs), ("TLS", r.tlsMs)]
            .compactMap { $0.1 == nil ? nil : "\($0.0) \(ms($0.1))" }.joined(separator: " · ")
        if !setup.isEmpty { lines.append("Connection setup (cold): \(setup)") }
        lines.append("Content download: \(ms(r.downloadMs))  ·  HTML load: \(ms(r.coldTotalMs))")
        if let wire = r.htmlWireBytes {
            let comp = r.htmlCompressed == true ? " (compressed)" : (r.htmlCompressed == false ? " (not compressed)" : "")
            lines.append("HTML transfer: \(kb(wire)) → \(kb(r.htmlDecodedBytes))\(comp)")
        }
        lines.append("Page weight\(r.assetsTruncated ? " (sampled)" : ""): \(kb(r.totalWireBytes)) over \(r.requestCount) request(s)")
        let bd = r.groups.map { "\($0.type.label) \($0.count)×/\(kb($0.wireBytes))" }.joined(separator: ", ")
        if !bd.isEmpty { lines.append("By type: \(bd)") }
        if r.jsDecodedBytes > 0 {
            lines.append("JavaScript: \(kb(r.jsDecodedBytes)) — roughly \(ms(r.jsExecMs)) of main-thread work on a mid-tier phone")
        }
        if r.thirdPartyRequests > 0 {
            lines.append("Third-party: \(r.thirdPartyRequests) request(s), \(kb(r.thirdPartyBytes)) from \(r.origins.filter { $0.thirdParty }.count) origin(s)")
        }
        lines.append("Critical request chain: \(r.criticalChainDepth) level(s), ~\(ms(r.criticalChainMs)) on the measured path")
        if r.wastedBytes > 0 { lines.append("Recoverable bytes: ~\(kb(r.wastedBytes)) with compression/minification/modern image formats") }
        if let cdn = r.cdn { lines.append("CDN / edge: \(cdn)\(r.cacheStatus.map { " (\($0))" } ?? "")") }
        if let slow = r.slowest.first, let m = slow.ms {
            lines.append("Slowest single request: \(slow.name) — \(ms(m))")
        }
        let est = r.estimates.map { "\($0.profile) ~\(seconds($0.fullLoadMs))" }.joined(separator: " · ")
        if !est.isEmpty { lines.append("Modelled full load: \(est)") }

        return Finding(
            title: "Performance score: \(r.score)/100 (\(r.grade))",
            severity: .info,
            category: "Performance",
            location: r.url,
            detail: "Measured load characteristics for this page:\n" + lines.map { "• \($0)" }.joined(separator: "\n"),
            evidence: "TTFB sampled over \(samples.count) request(s) (\(r.ttfb.cold.count) on cold connections, \(r.ttfb.warm.count) reusing one); connection setup from the cold requests; page weight from \(r.sampledAssetCount) measured asset(s) via URLSession transfer metrics."
                + (r.scoreBreakdown.isEmpty ? "\nScore: 100/100 — no deductions." : "\nScore deductions:\n" + r.scoreBreakdown.map { "  \($0)" }.joined(separator: "\n")),
            exploit: "Informational baseline. The score weights TTFB and its consistency, protocol, compression, page weight, requests, render-blocking, JavaScript cost, third-party weight, chain depth, images and caching. The findings below name the specific fixes, ranked by how much time each one buys back.",
            remediation: "Target: TTFB < 200 ms, HTTP/2 or HTTP/3, TLS 1.3, compressed and minified text, far-future asset caching, modern image formats, and a lean page (< 1 MB, few requests, shallow chain). Start with the \"biggest wins\" finding — it is ordered by estimated time saved.",
            reference: "https://web.dev/articles/ttfb")
    }

    private static func documentStatus(report r: PerformanceReport, home: HTTPResponse) -> Finding? {
        guard r.status != 200 else { return nil }
        let kind: String
        switch r.status {
        case 401, 403: kind = "an authorization or bot-protection response"
        case 404:      kind = "a not-found page"
        case 429:      kind = "a rate-limit response"
        case 500...:   kind = "a server error page"
        case 300..<400: kind = "an unfollowed redirect"
        default:       kind = "a non-standard response"
        }
        let tiny = home.body.count < 20_000
        return Finding(
            title: "Measured page returned HTTP \(r.status) — results describe \(kind)",
            severity: .medium, category: "Performance", location: r.url,
            detail: "The request came back as HTTP \(r.status)\(tiny ? " with only \(kb(home.body.count)) of content" : ""), so every timing, byte count and score below describes that response — not the page a real visitor sees.\n\nA WAF, CDN bot rule or geo-block is the usual cause: the scanner's User-Agent is not a browser, so protection layers answer it with a challenge instead of the site.",
            evidence: "HTTP \(r.status) · \(kb(home.body.count)) body · \(home.contentType)\nServer: \(home.header("server") ?? "(none)")\nRequested: \(home.requestedURL.absoluteString)\nFinal: \(home.finalURL.absoluteString)",
            exploit: "Treat the score as unmeasured. It reflects how fast the block page is, which tells you nothing about the site's real performance.",
            remediation: [
                "Re-run against a URL that serves content to non-browser clients, or allowlist this scanner in your WAF/CDN for the test.",
                "Set a browser User-Agent in the scan's request options if the protection is UA-based.",
                "If you did not expect a block here, check whether real users or crawlers are getting it too — a \(r.status) on the landing page is a bigger problem than any timing on this list.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/\(r.status)")
    }

    private static func improvementPlan(report r: PerformanceReport) -> Finding? {
        guard !r.opportunities.isEmpty else {
            return Finding(
                title: "No significant performance problems found",
                severity: .info, category: "Performance", location: r.url,
                detail: "The deep probe measured TTFB across \(r.ttfb.all.count) samples, \(r.sampledAssetCount) asset(s), \(r.origins.count) origin(s) and a \(r.criticalChainDepth)-level request chain without finding a fixable bottleneck worth listing.",
                evidence: "TTFB best \(ms(r.ttfb.best)) · page \(kb(r.totalWireBytes)) · \(r.requestCount) request(s) · \(r.networkProtocol ?? "?")",
                exploit: "Nothing is measurably holding this page back.",
                remediation: "Keep it that way: budget page weight in CI, watch TTFB p95 rather than the average, and re-run this scan after each release.",
                reference: "https://web.dev/articles/fast")
        }

        let top = Array(r.opportunities.prefix(8))
        let totalMs = top.reduce(0.0) { $0 + $1.savedMs }
        let totalBytes = top.reduce(0) { $0 + $1.savedBytes }
        let worst = top.first!.severity

        var body: [String] = []
        for (i, o) in top.enumerated() {
            body.append("\(i + 1). \(o.title)  —  \(o.impactLabel)\(o.savedBytes > 0 ? ", saves \(kb(o.savedBytes))" : "")")
            body.append("     Why: \(o.why)")
            for s in o.steps { body.append("       → \(s)") }
            if let first = o.evidence.first { body.append("     Seen: \(first)\(o.evidence.count > 1 ? " (+\(o.evidence.count - 1) more)" : "")") }
            body.append("")
        }

        var evidence: [String] = []
        for o in top {
            evidence.append("\(o.title) — est. \(ms(o.savedMs)) saved\(o.savedBytes > 0 ? ", \(kb(o.savedBytes))" : "")")
            for e in o.evidence.prefix(4) { evidence.append("    · \(e)") }
        }

        return Finding(
            title: "How to make this page faster: \(top.count) ranked fix(es), ~\(seconds(totalMs)) recoverable",
            severity: worst == .info ? .low : worst,
            category: "Performance",
            location: r.url,
            detail: "Ranked by how much load time each fix buys back on a Slow-4G-class connection (1.6 Mbps, 150 ms RTT — roughly a real phone on a real network):\n\n"
                + body.joined(separator: "\n"),
            evidence: "Estimated total: ~\(seconds(totalMs)) faster and \(kb(totalBytes)) lighter if every item is done.\n\n"
                + evidence.joined(separator: "\n"),
            exploit: "Each item is time a real visitor currently waits. The top of the list is where the time actually is — the bottom items are polish. Fixing items 1–3 usually captures most of the available gain.",
            remediation: top.enumerated().map { "\($0.offset + 1). \($0.element.title) (\($0.element.impactLabel))\n" + $0.element.steps.map { "   • \($0)" }.joined(separator: "\n") }.joined(separator: "\n\n"),
            reference: top.first?.reference ?? "https://web.dev/articles/fast")
    }

    private static func slowestResources(report r: PerformanceReport) -> Finding? {
        let slow = r.slowest.filter { ($0.ms ?? 0) >= 40 }
        guard slow.count >= 2 else { return nil }

        func breakdown(_ s: ResourceStat) -> String {
            var parts: [String] = []
            if let v = s.setupMs, v > 0 { parts.append("connect \(ms(v))") }
            if let v = s.ttfbMs, v > 0 { parts.append("wait \(ms(v))") }
            if let v = s.downloadMs, v > 0 { parts.append("download \(ms(v))") }
            if s.reused { parts.append("reused connection") }
            return parts.isEmpty ? "—" : parts.joined(separator: " · ")
        }

        func diagnosis(_ s: ResourceStat) -> String {
            if let setup = s.setupMs, setup > 120, s.thirdParty {
                return "most of it is connection setup to a third-party origin — preconnect or self-host it"
            }
            if let dl = s.downloadMs, let wait = s.ttfbMs, dl > wait * 1.5, s.wireBytes > 100_000 {
                return "download-bound at \(kb(s.wireBytes)) — this one is about size, not the server"
            }
            if let wait = s.ttfbMs, wait > 300 {
                return "server-bound: \(ms(wait)) of waiting before a single byte came back — cache it or move it to the edge"
            }
            if s.renderBlocking {
                return "render-blocking, so this time is added directly in front of first paint"
            }
            if s.depth >= 3 {
                return "only discovered after its parent stylesheet was parsed — preload it to start it earlier"
            }
            if !s.cached {
                return "no long cache lifetime, so returning visitors pay this again"
            }
            return "largest contributors: \(breakdown(s))"
        }

        let lines = slow.prefix(8).map { s in
            "\(ms(s.ms))  \(s.type.label.padded(10))  \(s.name)\n        \(breakdown(s))\n        → \(diagnosis(s))"
                + (s.thirdParty ? "\n        third-party: \(s.host)" : "")
        }

        let slowestOne = slow[0]
        let sev: Severity = (slowestOne.ms ?? 0) > 2000 ? .medium : .low

        return Finding(
            title: "Slowest requests on the page (worst: \(slowestOne.name) at \(ms(slowestOne.ms)))",
            severity: sev, category: "Performance", location: r.url,
            detail: "Per-request timing, slowest first. Each line splits into connection setup, server wait and download, so you can tell a slow server from a fat file:\n\n"
                + lines.joined(separator: "\n\n"),
            evidence: slow.prefix(10).map { "\(ms($0.ms))  \($0.url)  [\(kb($0.wireBytes)), HTTP \($0.status)]" }.joined(separator: "\n"),
            exploit: "These requests are where the page's load time actually goes. A slow blocking resource delays first paint for everyone; a slow third-party resource does the same and you cannot even fix it at the source.",
            remediation: [
                "Server-bound (long wait, small download): cache the response, or serve it from the CDN edge.",
                "Download-bound (large file): compress, minify, re-encode images, or split the bundle.",
                "Setup-bound (long connect on a third-party host): `preconnect`, or move the asset to your own origin.",
                "Deep in the chain (discovered inside CSS/JS): `preload` it so it starts with everything else.",
                "Blocking and not needed for first paint: `defer`/`async` it, or load it after the page is interactive.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://developer.chrome.com/docs/devtools/network/reference")
    }

    private static func criticalChainFinding(report r: PerformanceReport) -> Finding? {
        guard r.criticalChainDepth >= 2, !r.criticalChain.isEmpty else { return nil }
        let steps = r.criticalChain.map { s in
            String(repeating: "    ", count: max(0, s.depth - 1))
                + "└─ \(s.name)  [\(s.type.label), \(kb(s.bytes)), \(ms(s.ms))]"
        }
        return Finding(
            title: "Critical request chain is \(r.criticalChainDepth) level(s) deep (~\(ms(r.criticalChainMs)))",
            severity: r.criticalChainDepth >= 3 ? .low : .info,
            category: "Performance", location: r.url,
            detail: "Nothing paints until this serial path finishes. Each level can only start after its parent has been downloaded and parsed:\n\n"
                + steps.joined(separator: "\n")
                + "\n\nMeasured path cost: \(ms(r.criticalChainMs)) on this connection — on a 150 ms-RTT mobile network each extra level adds at least another round trip on top.",
            evidence: r.criticalChain.map { "L\($0.depth): \($0.url) — \(ms($0.ms)), \(kb($0.bytes))" }.joined(separator: "\n"),
            exploit: "A deep chain is latency multiplied: the browser cannot even discover level 3 until level 2 has arrived, so slow networks pay the round trips serially and first paint slides out.",
            remediation: "Flatten it: `preload` the level-3 resources (fonts, hero image) from the HTML, inline critical CSS, remove CSS `@import`, and consider `103 Early Hints` so the browser starts fetching while the server is still thinking.",
            reference: "https://web.dev/articles/critical-rendering-path")
    }

    private static func serverResponseTime(report r: PerformanceReport) -> Finding? {
        guard let best = r.ttfb.best else { return nil }
        let sev: Severity
        let title: String
        switch best {
        case ..<200:   sev = .info;   title = "Fast server response time (TTFB \(ms(best)))"
        case ..<500:   sev = .low;    title = "Server response time could be tightened (TTFB \(ms(best)))"
        case ..<1200:  sev = .medium; title = "Slow server response time (TTFB \(ms(best)))"
        default:       sev = .high;   title = "Very slow server response time (TTFB \(ms(best)))"
        }
        let cdnLine = r.cdn == nil
            ? "No CDN/edge cache detected - a CDN can cut TTFB dramatically for distant users."
            : "A CDN/edge layer (\(r.cdn!)) is present; make sure cacheable responses actually hit the edge (look for a cache HIT header)."
        var split = ""
        if let rtt = r.networkRTTMs, let think = r.serverProcessingMs {
            split = " Of that, about \(ms(rtt)) is the network round trip and about \(ms(think)) is your server actually building the response — the second number is the one you control."
        }
        return Finding(
            title: title, severity: sev, category: "Performance", location: "TTFB",
            detail: "Time to first byte was \(ms(best)) at best, \(ms(r.ttfb.median)) median and \(ms(r.ttfb.p95)) at p95 across \(r.ttfb.all.count) samples. TTFB captures backend processing plus one network round trip; the browser cannot start rendering until it arrives."
                + split
                + (r.ttfbWarmMs.map { " Warm (reused-connection) TTFB was \(ms($0))." } ?? ""),
            evidence: "Best: \(ms(best))  ·  Median: \(ms(r.ttfb.median))  ·  p95: \(ms(r.ttfb.p95))  ·  Worst: \(ms(r.ttfb.worst))\nCold-connection samples: \(r.ttfb.cold.map { ms($0) }.joined(separator: ", "))\nWarm-connection samples: \(r.ttfb.warm.map { ms($0) }.joined(separator: ", "))",
            exploit: sev == .info
                ? "Users get a responsive first byte. No action needed here."
                : "A high TTFB delays the entire page: nothing paints until the first byte arrives, hurting Core Web Vitals (LCP), search ranking and bounce rate.",
            remediation: [
                "Cache rendered pages / expensive queries (full-page, object, or CDN edge cache).",
                "Optimize the slowest database queries and add indexes; avoid N+1 queries.",
                "Reuse connections (HTTP keep-alive, pooled DB connections); keep the app warm.",
                cdnLine,
                "Emit a `Server-Timing` header so you can see which backend phase owns the time.",
                "Move compute closer to users (multi-region, edge functions) for a global audience.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://web.dev/articles/ttfb")
    }

    private static func ttfbConsistency(report r: PerformanceReport) -> Finding? {
        guard r.ttfb.all.count >= 3, let jitter = r.ttfb.jitterMs, let ratio = r.ttfb.jitterRatio,
              let best = r.ttfb.best, let worst = r.ttfb.worst else { return nil }
        guard jitter > 250, ratio > 2 else { return nil }
        return Finding(
            title: String(format: "Inconsistent server response time (%.1f× spread, %@ swing)", ratio, ms(jitter)),
            severity: ratio > 4 ? .medium : .low,
            category: "Performance", location: "TTFB",
            detail: "Across \(r.ttfb.all.count) identical requests the server answered in as little as \(ms(best)) and as much as \(ms(worst)). An average would have hidden this — but real users land on the slow end regularly, and it is the p95 that shapes how the site feels.",
            evidence: "Samples: " + r.ttfb.all.map { ms($0) }.joined(separator: ", ")
                + "\nBest \(ms(best)) · median \(ms(r.ttfb.median)) · p95 \(ms(r.ttfb.p95)) · worst \(ms(worst))",
            exploit: "Variance this wide usually means something is only sometimes cached — a cache miss path, a cold serverless container, a connection-pool exhaustion, or a noisy neighbour on shared hosting. The slow path is a real experience for a real share of visitors.",
            remediation: [
                "Look at p95/p99 in your monitoring, not the mean — the mean is hiding this.",
                "If it is serverless: raise minimum instances / provisioned concurrency to kill cold starts.",
                "If it is caching: find the miss path (cookies on cacheable responses, varying query strings, short TTLs) and make hits the default.",
                "Check database connection pool size and slow-query logs at the moments TTFB spikes.",
                "On shared hosting, sustained variance is often the neighbours — a dedicated or larger instance is the fix.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://web.dev/articles/ttfb")
    }

    private static func edgeCacheFinding(report r: PerformanceReport) -> Finding? {
        guard let status = r.cacheStatus, let hit = edgeCacheHit(status) else { return nil }
        if hit {
            return Finding(
                title: "HTML is being served from the edge cache (\(status))",
                severity: .info, category: "Performance", location: r.url,
                detail: "The CDN reported a cache hit for the document, which is why TTFB is \(ms(r.ttfb.best)). Requests are being answered near the user instead of travelling to the origin.",
                evidence: "Cache status: \(status)\(r.cdn.map { " · \($0)" } ?? "")",
                exploit: "Nothing to fix — this is the behaviour you want.",
                remediation: "Keep it: use `stale-while-revalidate` so users never wait on a revalidation, and tag-based purging so you can cache aggressively and still publish instantly.",
                reference: "https://web.dev/articles/http-cache")
        }
        return Finding(
            title: "Edge cache is not serving the HTML (\(status))",
            severity: .low, category: "Performance", location: r.url,
            detail: "A CDN is in front of this site\(r.cdn.map { " (\($0))" } ?? ""), but it reported `\(status)` for the document — so this request went all the way to the origin. The edge is doing TLS termination only, not saving you any time.",
            evidence: "Cache status header: \(status)\nTTFB best: \(ms(r.ttfb.best))\nCache-Control: \(r.resources.first?.cached == true ? "long" : "short/absent")",
            exploit: "Every visitor pays full origin latency plus backend processing on a request the edge could have answered in tens of milliseconds.",
            remediation: [
                "Send `Cache-Control: public, s-maxage=60, stale-while-revalidate=86400` on HTML that is not per-user.",
                "Remove `Set-Cookie` from cacheable responses — it makes most CDNs bypass the cache entirely.",
                "Normalise the cache key so `utm_*`/`fbclid` variants collapse into one cached entry.",
                "For personalised pages, cache the shell and load the personal part client-side, or use edge-side includes.",
                "Verify with `curl -sI <url> | grep -i 'cf-cache-status\\|x-cache\\|age'` after deploying.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://web.dev/articles/http-cache")
    }

    private static func thirdPartyFinding(report r: PerformanceReport) -> Finding? {
        let third = r.origins.filter { $0.thirdParty }
        guard !third.isEmpty else { return nil }
        let bytes = r.thirdPartyBytes
        guard third.count >= 2 || bytes > 150_000 else { return nil }

        let rows = third.prefix(8).map { o in
            "\(o.host) — \(o.requests) request(s), \(kb(o.wireBytes))"
                + (o.slowestMs.map { ", slowest \(ms($0))" } ?? "")
                + (o.blockingRequests > 0 ? ", \(o.blockingRequests) render-blocking" : "")
                + (o.preconnected ? ", preconnected" : ", no preconnect")
        }
        let share = r.totalWireBytes > 0 ? Double(bytes) / Double(r.totalWireBytes) * 100 : 0
        let sev: Severity = (bytes > 800_000 || r.thirdPartyBlockingMs > 500) ? .medium : .low

        return Finding(
            title: String(format: "%d third-party origin(s) account for %@ (%.0f%% of the page)", third.count, kb(bytes), share),
            severity: sev, category: "Performance", location: r.url,
            detail: "Content loaded from domains you do not control:\n" + rows.map { "• \($0)" }.joined(separator: "\n")
                + (r.thirdPartyBlockingMs > 0 ? String(format: "\n\nOf that, ~%.0f ms sits on the render-blocking path.", r.thirdPartyBlockingMs) : ""),
            evidence: third.map { "\($0.host): \($0.requests) req, \(kb($0.wireBytes))\($0.setupMs.map { s in ", setup \(ms(s))" } ?? "")" }.joined(separator: "\n"),
            exploit: "Third-party latency is latency you cannot fix. Each new origin also costs DNS + TCP + TLS (about three round trips) before its first byte, and third-party JavaScript competes for the same main thread as your own code.",
            remediation: [
                "Preconnect to the 2–4 origins on the critical path: `<link rel=\"preconnect\" href=\"https://host\" crossorigin>`.",
                "Self-host what you reasonably can — fonts especially; it removes an entire origin from the critical path.",
                "Lazy-load widgets behind a facade (a click-to-load thumbnail for video/maps/chat).",
                "Give third-party scripts `async`/`defer` and load non-essential tags after the `load` event.",
                "Re-audit the list quarterly — third-party tags accumulate and nobody removes them.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://web.dev/articles/third-party-summary")
    }

    private static func jsCostFinding(report r: PerformanceReport) -> Finding? {
        guard r.jsDecodedBytes > 250_000 else { return nil }
        let scripts = r.resources.filter { $0.type == .script }.sorted { $0.decodedBytes > $1.decodedBytes }
        let sev: Severity = r.jsDecodedBytes > 1_000_000 ? .medium : .low
        return Finding(
            title: "JavaScript costs about \(ms(r.jsExecMs)) of main-thread work (\(kb(r.jsDecodedBytes)))",
            severity: sev, category: "Performance", location: r.url,
            detail: "The page ships \(kb(r.jsDecodedBytes)) of JavaScript across \(scripts.count) file(s). Bytes are only half the cost: a mid-tier phone spends roughly one millisecond per kilobyte parsing, compiling and executing, so this is on the order of \(ms(r.jsExecMs)) during which the page cannot respond to taps.\n\nLargest bundles:\n"
                + scripts.prefix(5).map { "• \($0.name) — \(kb($0.decodedBytes)) decoded\($0.thirdParty ? " (third-party: \($0.host))" : "")" }.joined(separator: "\n"),
            evidence: "Total JS: \(kb(r.jsDecodedBytes)) decoded / \(kb(scripts.reduce(0) { $0 + $1.wireBytes })) transferred\nEstimated main-thread cost: \(ms(r.jsExecMs)) on a mid-tier phone (~1 ms per KB)",
            exploit: "Heavy JavaScript delays interactivity (INP) far more than it delays painting. The page can look ready while taps do nothing, which users experience as the site being broken rather than slow.",
            remediation: [
                "Code-split per route and `import()` anything behind an interaction or below the fold.",
                "Run a bundle treemap and remove the largest dependency you barely use (moment, full lodash, whole icon sets).",
                "Import per function (`import debounce from 'lodash/debounce'`) so tree-shaking can actually work.",
                "Ship modern syntax with `<script type=\"module\">` instead of ES5 transpiled output plus polyfills.",
                "Push heavy computation into a Web Worker or onto the server.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://web.dev/articles/bootup-time")
    }

    private static func uncompressedAssets(report r: PerformanceReport) -> Finding? {
        let bad = r.resources.filter { $0.type != .document && isCompressible($0.contentType) && $0.decodedBytes >= 2048 && $0.compressed == false }
        guard !bad.isEmpty else { return nil }
        let recoverable = bad.reduce(0) { $0 + Int(Double($1.decodedBytes) * 0.72) }
        return Finding(
            title: "\(bad.count) text asset(s) served without compression (~\(kb(recoverable)) recoverable)",
            severity: recoverable > 200_000 ? .medium : .low,
            category: "Performance", location: r.url,
            detail: "These responses are compressible text but arrived uncompressed:\n"
                + bad.prefix(10).map { "• \($0.name) — \(kb($0.decodedBytes)) (\($0.contentType))" }.joined(separator: "\n")
                + "\n\nBrotli typically removes 70–90% of text. On a Slow-4G connection that is roughly \(ms(msForBytes(recoverable))) off every first visit.",
            evidence: bad.prefix(10).map { "\($0.url) — \(kb($0.decodedBytes)) decoded, \(kb($0.wireBytes)) on the wire, content-encoding: \($0.compressed == false ? "none" : "?")" }.joined(separator: "\n"),
            exploit: "Every visitor downloads several times more bytes than necessary, on every visit, and pays for it in time and mobile data.",
            remediation: "Enable Brotli (with gzip fallback) for all text content types at the server or CDN, and pre-compress build output so it costs nothing at request time. Confirm with `curl -H 'Accept-Encoding: br' -I <url>`.",
            reference: "https://web.dev/articles/reduce-network-payloads-using-text-compression")
    }

    private static func minificationFinding(report r: PerformanceReport) -> Finding? {
        let bad = r.resources.filter { $0.minifyWaste > 0 }
        guard !bad.isEmpty else { return nil }
        let bytes = bad.reduce(0) { $0 + $1.minifyWaste }
        return Finding(
            title: "\(bad.count) script/stylesheet(s) are not minified (~\(kb(bytes)))",
            severity: .low, category: "Performance", location: r.url,
            detail: "These files still contain source formatting — indentation, blank lines and comments — which the browser downloads and parses for nothing:\n"
                + bad.prefix(10).map { "• \($0.name) — \(kb($0.decodedBytes)), \($0.wasteReasons.first(where: { $0.hasPrefix("not minified") }) ?? "")" }.joined(separator: "\n"),
            evidence: bad.prefix(10).map { "\($0.url) — \(kb($0.decodedBytes)) decoded" }.joined(separator: "\n"),
            exploit: "Unminified assets waste download time and parse time on every uncached visit. Combined with missing compression the effect multiplies.",
            remediation: "Minify production JS with esbuild/terser and CSS with lightningcss/cssnano (a build flag in every modern bundler), emit external source maps for debugging, and make sure the production build — not the dev build — is what gets deployed.",
            reference: "https://web.dev/articles/reduce-network-payloads-using-text-compression")
    }

    private static func repeatVisitFinding(report r: PerformanceReport) -> Finding? {
        guard r.repeatVisitBytes > 100_000 else { return nil }
        let uncached = r.resources.filter { !$0.cached && $0.type != .document }
        return Finding(
            title: "Repeat visitors re-download \(kb(r.repeatVisitBytes)) (\(uncached.count) asset(s))",
            severity: r.repeatVisitBytes > 700_000 ? .medium : .low,
            category: "Performance", location: r.url,
            detail: "These assets carry no long-lived `Cache-Control`, so a returning visitor fetches them again instead of reading them from disk in microseconds:\n"
                + uncached.prefix(10).map { "• \($0.name) — \(kb($0.wireBytes))" }.joined(separator: "\n")
                + "\n\nOn a Slow-4G connection that is about \(ms(msForBytes(r.repeatVisitBytes))) of avoidable waiting on every return visit."
                + (r.revalidates304 == false ? "\n\nThe HTML also did not answer a conditional request with 304 Not Modified, so even revalidation costs a full download." : ""),
            evidence: uncached.prefix(10).map { "\($0.url) — \(kb($0.wireBytes)), cached: no" }.joined(separator: "\n")
                + (r.revalidates304.map { "\nConditional re-request of the HTML returned: \($0 ? "304 Not Modified" : "a full 200 response")" } ?? ""),
            exploit: "Repeat visits are the majority of traffic on most sites. Without caching, none of that traffic gets the instant load it could have.",
            remediation: [
                "Fingerprint static filenames and send `Cache-Control: public, max-age=31536000, immutable`.",
                "For unfingerprinted files use a short `max-age` plus a strong `ETag` so revalidation is a 304.",
                "Set the headers at the CDN too, not just the origin.",
                "Consider a service worker for an app-shell style instant repeat load.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://web.dev/articles/uses-long-cache-ttl")
    }

    private static func brokenAssets(report r: PerformanceReport) -> Finding? {
        let broken = r.resources.filter { $0.status >= 400 && $0.depth > 1 }
        guard !broken.isEmpty else { return nil }
        return Finding(
            title: "\(broken.count) referenced asset(s) fail to load",
            severity: .medium, category: "Performance", location: r.url,
            detail: "The page references resources that return an error status. Each one costs a full round trip and delivers nothing:\n"
                + broken.prefix(10).map { "• HTTP \($0.status) — \($0.url)" }.joined(separator: "\n"),
            evidence: broken.prefix(10).map { "HTTP \($0.status) · \(ms($0.ms)) · \($0.url)" }.joined(separator: "\n"),
            exploit: "Beyond the wasted latency, missing CSS or JS can leave the page visually broken or non-functional while still counting against load time.",
            remediation: "Remove or fix the referencing tags, verify the build actually emits these paths, and add an asset/link check to CI so a 404 fails the build rather than the page.",
            reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status")
    }

    private static func networkSimulation(report r: PerformanceReport) -> Finding? {
        guard !r.estimates.isEmpty else { return nil }
        let rows = r.estimates.map { e in
            "\(e.profile.padded(16)) first byte ~\(ms(e.firstByteMs))   ·   full load ~\(seconds(e.fullLoadMs))"
        }
        let slow4G = r.estimates.first { $0.profile == "Slow 4G" }
        let sev: Severity = (slow4G?.fullLoadMs ?? 0) > 8000 ? .medium : ((slow4G?.fullLoadMs ?? 0) > 4000 ? .low : .info)
        return Finding(
            title: "Modelled load time on real-world connections (Slow 4G ~\(seconds(slow4G?.fullLoadMs ?? 0)))",
            severity: sev, category: "Performance", location: r.url,
            detail: "Your scan ran on this machine's connection. This projects the same page onto the connections your visitors actually use:\n\n"
                + rows.joined(separator: "\n")
                + "\n\nModel: \(kb(r.totalWireBytes)) transferred, ~\(ms(r.serverProcessingMs)) of server processing, a \(r.criticalChainDepth)-level request chain, \(r.tlsVersion ?? "TLS") handshake, over \(r.networkProtocol ?? "HTTP"). These are estimates, not measurements — treat them as a comparison tool between builds, not as a lab number.",
            evidence: r.estimates.map { "\($0.profile): TTFB ~\(ms($0.firstByteMs)), load ~\(seconds($0.fullLoadMs))" }.joined(separator: "\n")
                + "\nInputs — bytes: \(r.totalWireBytes), server think: \(ms(r.serverProcessingMs)), chain depth: \(r.criticalChainDepth), protocol: \(r.networkProtocol ?? "?")",
            exploit: sev == .info
                ? "The page holds up acceptably even on a slow mobile connection."
                : "Most mobile visitors are closer to the Slow 4G row than to Wi-Fi. At these times a meaningful share of visitors abandon before the page finishes.",
            remediation: "The two inputs you can move are bytes and server think time. Cut page weight (compression, modern image formats, code splitting) and cut TTFB (edge caching); the chain-depth term drops when you preload what CSS currently discovers late.",
            reference: "https://web.dev/articles/performance-budgets-101")
    }

    private static func protocolUpgrade(report r: PerformanceReport) -> Finding? {
        guard let proto = r.networkProtocol, proto == "HTTP/1.1" || proto == "HTTP/1.0" else { return nil }
        return Finding(
            title: "Served over \(proto) - upgrade to HTTP/2 or HTTP/3",
            severity: .low, category: "Performance", location: "Transport",
            detail: "The page negotiated \(proto). HTTP/2 multiplexes many requests over one connection (no head-of-line blocking, header compression); HTTP/3 (QUIC) additionally removes TCP head-of-line blocking and speeds up connection setup.",
            evidence: "Negotiated application protocol: \(proto)",
            exploit: "On \(proto) each asset competes for a few connections and pays per-request overhead, so pages with many resources load noticeably slower - especially on high-latency mobile networks. This page makes \(r.requestCount) request(s).",
            remediation: "Enable HTTP/2 at your web server / load balancer / CDN (a one-line toggle on nginx, Apache, Caddy, Cloudflare, …) and enable HTTP/3 where available. Both require HTTPS, which is already in place. Afterwards, remove HTTP/1 workarounds like domain sharding and sprite sheets.",
            reference: "https://web.dev/articles/performance-http2")
    }

    private static func http3Suggestion(report r: PerformanceReport) -> Finding? {
        guard let proto = r.networkProtocol, proto == "HTTP/2" else { return nil }
        if r.http3Available {
            return Finding(
                title: "HTTP/3 (QUIC) is available", severity: .info, category: "Performance", location: "Transport",
                detail: "The server advertises HTTP/3 via Alt-Svc while serving this request over HTTP/2. Returning visitors' browsers will upgrade to HTTP/3 automatically.",
                evidence: "Negotiated: HTTP/2  ·  Alt-Svc advertises h3",
                exploit: "Nothing to fix - this is a good signal. HTTP/3 improves performance on lossy/mobile networks.",
                remediation: "No action needed. Confirm HTTP/3 is enabled at every edge/region.",
                reference: "https://web.dev/articles/http3")
        }
        return Finding(
            title: "Enable HTTP/3 (QUIC) for faster mobile connections",
            severity: .low, category: "Performance", location: "Transport",
            detail: "The page is served over HTTP/2 and does not advertise HTTP/3 (no Alt-Svc `h3`). HTTP/3 runs over QUIC/UDP: it removes TCP head-of-line blocking and sets up connections in fewer round trips - a real win on lossy or high-latency mobile networks.",
            evidence: "Negotiated: HTTP/2  ·  Alt-Svc: \(r.cdn ?? "no h3 advertised")",
            exploit: "Without HTTP/3, users on flaky networks pay for TCP retransmission stalls and slower handshakes that QUIC would avoid.",
            remediation: "Turn on HTTP/3 at your CDN or web server (Cloudflare, Fastly, nginx w/ quic, Caddy, LiteSpeed all support it), advertise it via `Alt-Svc: h3=\":443\"`, and make sure UDP/443 is open.",
            reference: "https://web.dev/articles/http3")
    }

    private static func tls13(version: String?) -> Finding? {
        guard let version, version == "TLS 1.2" || version == "TLS 1.1" || version == "TLS 1.0" else { return nil }
        return Finding(
            title: "TLS handshake uses \(version) - enable TLS 1.3",
            severity: .low, category: "Performance", location: "Transport",
            detail: "The connection negotiated \(version). TLS 1.3 completes the handshake in a single round trip (vs two for 1.2) and supports 0-RTT resumption, shaving latency off every new connection.",
            evidence: "Negotiated TLS version: \(version)",
            exploit: "Every cold connection pays an extra round trip for the handshake, adding latency for first-time and returning visitors alike - and older TLS versions are weaker cryptographically.",
            remediation: "Turn on TLS 1.3 in your server / CDN TLS settings (widely supported since 2018). Keep 1.2 for old clients but prefer 1.3, and enable session resumption plus OCSP stapling.",
            reference: "https://www.rfc-editor.org/rfc/rfc8446")
    }

    private static func compression(home: HTTPResponse, timing: RequestTiming?) -> Finding? {
        guard isCompressible(home.contentType) else { return nil }
        let decoded = home.body.count
        guard decoded >= 2048 else { return nil }
        guard looksCompressed(timing, header: home.header("content-encoding")) == false else { return nil }
        let sev: Severity = decoded >= 50_000 ? .medium : .low
        return Finding(
            title: "Text response is not compressed",
            severity: sev, category: "Performance", location: home.finalURL.absoluteString,
            detail: "The HTML response (\(kb(decoded)), \(home.contentType)) was sent without gzip/Brotli compression. Text compresses by roughly 70-90%, so this is wasted bytes on every load - about \(kb(Int(Double(decoded) * 0.72))) recoverable here.",
            evidence: "Content-Type: \(home.contentType)\nDecoded size: \(kb(decoded))\nContent-Encoding: \(home.header("content-encoding") ?? "(none)")"
                + (timing?.wireBytes.map { "\nBytes over the wire: \(kb($0))" } ?? ""),
            exploit: "Uncompressed HTML/CSS/JS means more bytes to download, slower first paint and higher bandwidth cost - worst on slow mobile connections.",
            remediation: "Enable Brotli (preferred) or gzip for text content types (text/html, css, javascript, json, svg, xml) at your server or CDN.",
            reference: "https://web.dev/articles/reduce-network-payloads-using-text-compression")
    }

    private static func largeDocument(home: HTTPResponse) -> Finding? {
        let size = home.body.count
        guard size >= 150_000 else { return nil }
        return Finding(
            title: "Large HTML document (\(kb(size)))",
            severity: size >= 500_000 ? .medium : .low, category: "Performance",
            location: home.finalURL.absoluteString,
            detail: "The HTML document alone is \(kb(size)). Large documents take longer to download and parse, delaying first paint and increasing memory use.",
            evidence: "HTML size: \(kb(size)) (\(size) bytes)",
            exploit: "A heavy HTML payload pushes back first paint and interactivity, and often signals inlined data, server-rendered bloat or missing pagination.",
            remediation: "Minify HTML, avoid inlining large JSON/data blobs, paginate or lazy-load long lists, and stream above-the-fold content first. Ensure compression is on.",
            reference: "https://web.dev/articles/reduce-network-payloads-using-text-compression")
    }

    private static func pageWeight(report r: PerformanceReport) -> Finding? {
        let mb = Double(r.totalWireBytes) / 1_048_576
        guard mb > 1.5 || r.requestCount > 50 else { return nil }
        let sev: Severity = (mb > 3 || r.requestCount > 80) ? .medium : .low
        let heavy = r.groups.prefix(3).map { "\($0.type.label): \(kb($0.wireBytes)) (\($0.count))" }.joined(separator: ", ")
        return Finding(
            title: String(format: "Heavy page: %.1f MB across %d request(s)", mb, r.requestCount),
            severity: sev, category: "Performance", location: r.url,
            detail: "The page transfers \(kb(r.totalWireBytes))\(r.assetsTruncated ? " (sampled)" : "") over \(r.requestCount) request(s). Heaviest types - \(heavy). More bytes and more requests mean slower loads, especially on mobile."
                + (r.wastedBytes > 0 ? " About \(kb(r.wastedBytes)) of this is recoverable with compression, minification and modern image formats." : ""),
            evidence: "Total transfer: \(kb(r.totalWireBytes))\nRequests: \(r.requestCount)\nBy type: " + r.groups.map { "\($0.type.label) \($0.count)×/\(kb($0.wireBytes))" }.joined(separator: ", ")
                + "\nLargest: " + r.largest.prefix(5).map { "\($0.name) \(kb($0.wireBytes))" }.joined(separator: ", "),
            exploit: "A heavy, request-dense page delays load and interactivity and burns users' data - hurting engagement and Core Web Vitals.",
            remediation: "Bundle & code-split JS, tree-shake unused code, compress and lazy-load images, subset fonts, remove unused CSS, and cut third-party scripts. Serve everything from a CDN over HTTP/2/3, and set a page-weight budget in CI so it cannot creep back.",
            reference: "https://web.dev/articles/fast#optimize-your-images-and-videos")
    }

    private static func renderBlocking(report r: PerformanceReport, url: URL) -> Finding? {
        let total = r.renderBlockingScripts + r.renderBlockingStyles
        guard total >= 5 else { return nil }
        let measured = r.resources.filter { $0.renderBlocking }.sorted { ($0.ms ?? 0) > ($1.ms ?? 0) }
        var detail = "The page references \(r.renderBlockingScripts) synchronous script(s) and \(r.renderBlockingStyles) stylesheet(s) that block rendering. The browser must download and process each before it can paint meaningful content."
        if !measured.isEmpty {
            detail += "\n\nMeasured blocking resources, slowest first:\n"
                + measured.prefix(6).map { "• \($0.name) — \(ms($0.ms)), \(kb($0.wireBytes))\($0.thirdParty ? " (third-party: \($0.host))" : "")" }.joined(separator: "\n")
        }
        return Finding(
            title: "\(total) render-blocking resource(s) in the page",
            severity: total >= 12 ? .medium : .low, category: "Performance", location: url.absoluteString,
            detail: detail,
            evidence: "Blocking <script> (no async/defer/module): \(r.renderBlockingScripts)\nStylesheet <link rel=stylesheet>: \(r.renderBlockingStyles)"
                + (measured.isEmpty ? "" : "\n" + measured.prefix(8).map { "\(ms($0.ms))  \($0.url)" }.joined(separator: "\n")),
            exploit: "Each render-blocking resource adds a serial step before first paint, inflating LCP and making the page feel slow - especially on high-latency connections.",
            remediation: "Add `defer`/`async` to scripts and use `type=\"module\"`; inline critical CSS and load the rest asynchronously (`media`/`preload`); split sheets by media query; bundle and code-split; preconnect to third-party origins.",
            reference: "https://web.dev/articles/render-blocking-resources")
    }

    private static func imageOptimization(html: String, resources: [ResourceStat], pageURL: URL) -> Finding? {
        let images = resources.filter { $0.type == .image }
        let big = images.filter { $0.decodedBytes > 200_000 }
            .sorted { $0.decodedBytes > $1.decodedBytes }
        let legacy = images.filter {
            let ct = $0.contentType.lowercased()
            return $0.decodedBytes > 100_000 && (ct.contains("jpeg") || ct.contains("jpg") || ct.contains("png"))
                && !ct.contains("webp") && !ct.contains("avif")
        }

        let imgTags = captureTags("<img[^>]*>", html)
        let missingDims = imgTags.filter { let l = $0.lowercased(); return !(l.contains(" width") && l.contains(" height")) }.count
        let noLazy = imgTags.filter { !$0.lowercased().contains("loading=") }.count
        let recoverable = images.reduce(0) { $0 + $1.imageWaste }

        guard !big.isEmpty || !legacy.isEmpty || (imgTags.count >= 4 && (missingDims >= 3 || noLazy >= 4)) else { return nil }
        let sev: Severity = (!big.isEmpty || !legacy.isEmpty) ? .medium : .low

        var lines: [String] = []
        if !big.isEmpty {
            lines.append("Oversized image(s): " + big.prefix(4).map { "\($0.name) \(kb($0.decodedBytes))" }.joined(separator: ", "))
        }
        if !legacy.isEmpty {
            lines.append("Legacy format (JPEG/PNG) where WebP/AVIF would be smaller: " + legacy.prefix(4).map { $0.name }.joined(separator: ", "))
        }
        if imgTags.count >= 4 && missingDims >= 3 { lines.append("\(missingDims)/\(imgTags.count) <img> tags lack width/height (causes layout shift / CLS).") }
        if imgTags.count >= 4 && noLazy >= 4 { lines.append("\(noLazy)/\(imgTags.count) <img> tags have no loading=\"lazy\".") }
        if recoverable > 0 { lines.append("Re-encoding the measured images would recover about \(kb(recoverable)).") }

        return Finding(
            title: "Images can be optimized\(recoverable > 0 ? " (~\(kb(recoverable)) recoverable)" : "")",
            severity: sev, category: "Performance", location: pageURL.absoluteString,
            detail: "Image delivery has room to improve:\n" + lines.map { "• \($0)" }.joined(separator: "\n"),
            evidence: lines.joined(separator: "\n")
                + (big.isEmpty ? "" : "\n" + big.prefix(6).map { "\($0.url) — \(kb($0.decodedBytes))" }.joined(separator: "\n")),
            exploit: "Large or legacy-format images dominate page weight and slow the Largest Contentful Paint; missing dimensions cause layout shifts (poor CLS); eager loading of off-screen images wastes bandwidth.",
            remediation: "Serve WebP/AVIF with responsive `srcset`/`sizes`, compress and resize to display dimensions, set explicit `width`/`height` (or `aspect-ratio`), add `loading=\"lazy\"` to below-the-fold images, `fetchpriority=\"high\"` to the LCP image, and use a CDN image pipeline that negotiates format automatically.",
            reference: "https://web.dev/articles/optimize-lcp#optimize-the-lcp-image")
    }

    private static func fontOptimization(html: String, resources: [ResourceStat], pageURL: URL) -> Finding? {
        let fonts = resources.filter { $0.type == .font }
        let lower = html.lowercased()
        let googleFonts = lower.contains("fonts.googleapis.com") || lower.contains("fonts.gstatic.com")
        let hasWebFonts = !fonts.isEmpty || googleFonts
        guard hasWebFonts else { return nil }

        let hasPreload = lower.contains("rel=\"preload\"") && lower.contains("as=\"font\"")
            || lower.contains("rel=preload") && lower.contains("as=font")
        let hasDisplaySwap = lower.contains("font-display") || lower.contains("display=swap") || lower.contains("&display=swap")
        let hasPreconnect = lower.contains("preconnect") && (lower.contains("gstatic") || lower.contains("fonts."))
        let lateFonts = fonts.filter { $0.depth >= 3 }

        var issues: [String] = []
        if !hasPreload && !fonts.isEmpty { issues.append("no `<link rel=preload as=font>` for the primary font(s)") }
        if !hasDisplaySwap { issues.append("no `font-display: swap` detected (text may be invisible during font load - FOIT)") }
        if googleFonts && !hasPreconnect { issues.append("no `preconnect` to the font host") }
        if !lateFonts.isEmpty { issues.append("\(lateFonts.count) font(s) are only discovered after a stylesheet is parsed, so they start late") }
        guard !issues.isEmpty else { return nil }

        let fontBytes = fonts.reduce(0) { $0 + $1.wireBytes }
        return Finding(
            title: "Web fonts can be optimized",
            severity: .low, category: "Performance", location: pageURL.absoluteString,
            detail: "The page uses web fonts (\(fonts.count) file(s)\(fontBytes > 0 ? ", \(kb(fontBytes))" : googleFonts ? ", via Google Fonts" : "")) but: " + issues.joined(separator: "; ") + ".",
            evidence: "Font files: \(fonts.count)\nGoogle Fonts: \(googleFonts ? "yes" : "no")\npreload: \(hasPreload)  ·  font-display: \(hasDisplaySwap)  ·  preconnect: \(hasPreconnect)"
                + (fonts.isEmpty ? "" : "\n" + fonts.prefix(6).map { "\($0.name) — \(kb($0.wireBytes)), \(ms($0.ms)), level \($0.depth)" }.joined(separator: "\n")),
            exploit: "Unoptimized fonts block text rendering (invisible or swapping text), add render-blocking requests, and delay a stable first paint.",
            remediation: "Add `font-display: swap` (or `optional`), `preload` the critical font from the HTML, `preconnect` to the font host, self-host and subset fonts to the characters you actually use, and ship WOFF2 only.",
            reference: "https://web.dev/articles/font-best-practices")
    }

    private static func assetAudit(resources: [ResourceStat]) -> Finding? {
        let assets = resources.filter { $0.type != .document }
        guard !assets.isEmpty else { return nil }
        let uncompressed = assets.filter { isCompressible($0.contentType) && $0.decodedBytes >= 2048 && $0.compressed == false }
        let uncached = assets.filter { !$0.cached }
        let totalWire = assets.reduce(0) { $0 + $1.wireBytes }

        guard !uncompressed.isEmpty || uncached.count >= 2 else {
            return Finding(
                title: "Static assets are compressed and cacheable",
                severity: .info, category: "Performance", location: "\(assets.count) asset(s)",
                detail: "The \(assets.count) measured asset(s) totalling \(kb(totalWire)) are served compressed with cache headers. Good.",
                evidence: "Total transfer: \(kb(totalWire))",
                exploit: "No action needed for the measured assets.",
                remediation: "Keep setting far-future `Cache-Control: max-age, immutable` on fingerprinted files and compress new text assets.",
                reference: "https://web.dev/articles/uses-long-cache-ttl")
        }

        let sev: Severity = !uncompressed.isEmpty ? .medium : .low
        var lines: [String] = ["Measured \(assets.count) asset(s), \(kb(totalWire)) transferred."]
        if !uncompressed.isEmpty { lines.append("Uncompressed text asset(s): " + uncompressed.prefix(8).map { $0.name }.joined(separator: ", ")) }
        if !uncached.isEmpty { lines.append("Missing far-future caching: " + uncached.prefix(8).map { $0.name }.joined(separator: ", ")) }
        if let slow = assets.max(by: { ($0.ms ?? 0) < ($1.ms ?? 0) }), let sms = slow.ms { lines.append("Slowest asset: \(slow.name) (\(ms(sms)))") }

        return Finding(
            title: "Static assets can be optimized (\(uncompressed.count) uncompressed, \(uncached.count) uncached)",
            severity: sev, category: "Performance", location: "\(assets.count) asset(s)",
            detail: "Measurement of page assets shows opportunities to cut bytes and repeat-visit load time:\n" + lines.map { "• \($0)" }.joined(separator: "\n"),
            evidence: lines.joined(separator: "\n"),
            exploit: "Uncompressed assets waste bandwidth on every visit; assets without long cache lifetimes are re-downloaded instead of served instantly from cache.",
            remediation: "Enable Brotli/gzip for text assets, add `Cache-Control: max-age=31536000, immutable` to fingerprinted/static files, serve from a CDN, and minify CSS/JS. Use content-hashed filenames so long caching is safe.",
            reference: "https://web.dev/articles/uses-long-cache-ttl")
    }

    private static func htmlCaching(home: HTTPResponse) -> Finding? {
        let cc = home.header("cache-control")
        let etag = home.header("etag")
        let lastMod = home.header("last-modified")

        guard cc == nil, etag == nil, lastMod == nil else { return nil }
        return Finding(
            title: "HTML response has no caching or validation headers",
            severity: .low, category: "Performance", location: home.finalURL.absoluteString,
            detail: "The document response sends no `Cache-Control`, `ETag` or `Last-Modified`. Even for frequently-changing HTML, a validator lets the browser revalidate with a cheap 304 Not Modified instead of re-downloading the whole page.",
            evidence: "Cache-Control: (none)\nETag: (none)\nLast-Modified: (none)",
            exploit: "Repeat visits re-download the full HTML every time instead of getting a small 304, wasting bandwidth and adding latency.",
            remediation: "Send an `ETag` (or `Last-Modified`) so browsers can revalidate, and a suitable `Cache-Control` (e.g. `no-cache` to force revalidation, or a short `max-age`/`s-maxage` with `stale-while-revalidate` for pages that tolerate slight staleness).",
            reference: "https://web.dev/articles/http-cache")
    }

    private static func serverTiming(home: HTTPResponse) -> Finding? {
        guard let raw = home.header("server-timing"), !raw.isEmpty else { return nil }

        let entries = raw.split(separator: ",").compactMap { part -> String? in
            let fields = part.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
            guard let name = fields.first, !name.isEmpty else { return nil }
            var dur: String?; var desc: String?
            for f in fields.dropFirst() {
                if f.lowercased().hasPrefix("dur=") { dur = String(f.dropFirst(4)) }
                if f.lowercased().hasPrefix("desc=") { desc = String(f.dropFirst(5)).trimmingCharacters(in: CharacterSet(charactersIn: "\"")) }
            }
            let d = dur.flatMap(Double.init).map { String(format: "%.0f ms", $0) }
            return "\(name)" + (d.map { " = \($0)" } ?? "") + (desc.map { " (\($0))" } ?? "")
        }
        guard !entries.isEmpty else { return nil }
        return Finding(
            title: "Server-Timing exposes backend breakdown",
            severity: .info, category: "Performance", location: home.finalURL.absoluteString,
            detail: "The server sent a `Server-Timing` header breaking down where its response time went:\n" + entries.map { "• \($0)" }.joined(separator: "\n"),
            evidence: "Server-Timing: \(snippet(raw, max: 240))",
            exploit: "Informational - use these server-side segments to pinpoint which backend phase (DB, cache, template, upstream) dominates TTFB.",
            remediation: "Attack the largest segment first (e.g. cache a slow DB phase). Keep Server-Timing in staging; consider restricting it in production if the internal detail is sensitive.",
            reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing")
    }

    private static func redirectChain(home: HTTPResponse) -> Finding? {
        guard home.requestedURL.absoluteString != home.finalURL.absoluteString else { return nil }
        return Finding(
            title: "Landing URL redirects before serving content",
            severity: .low, category: "Performance", location: home.finalURL.absoluteString,
            detail: "The requested URL redirected before returning the page. Each redirect is an extra round trip (sometimes an extra TLS handshake) before anything renders.",
            evidence: "Requested: \(home.requestedURL.absoluteString)\nFinal: \(home.finalURL.absoluteString)",
            exploit: "Redirects delay the first byte by one or more full round trips - costly on mobile and multiplied when chained (http→https→www→…).",
            remediation: "Link and advertise the final canonical URL directly, collapse redirect chains to a single hop, and use HSTS (with preload) so browsers skip the http→https redirect.",
            reference: "https://web.dev/articles/redirects")
    }

    static func assetURLs(html rawHTML: String, base: URL, limit: Int) -> [URL] {
        let html = strippingHTMLComments(rawHTML)
        var ranked: [(rank: Int, url: URL)] = []
        var seen = Set<String>()
        func add(_ raw: String, rank: Int) {
            let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !s.isEmpty, !s.hasPrefix("data:"), !s.hasPrefix("#"),
                  !s.hasPrefix("mailto:"), !s.hasPrefix("tel:"), !s.hasPrefix("javascript:") else { return }
            guard let u = URL(string: s, relativeTo: base)?.absoluteURL,
                  u.scheme == "http" || u.scheme == "https" else { return }
            if seen.insert(u.absoluteString).inserted { ranked.append((rank, u)) }
        }
        for src in capture("<script[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']", html) { add(src, rank: 0) }
        for tag in captureTags("<link[^>]+>", html) {
            let l = tag.lowercased()
            guard let href = attr("href", in: tag) else { continue }
            if l.contains("stylesheet") { add(href, rank: 0) }
            else if l.contains("as=\"font\"") || l.contains("as=font") { add(href, rank: 1) }
            else if l.contains("preload") || l.contains("icon") { add(href, rank: 2) }
        }
        for src in capture("<img[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']", html) { add(src, rank: 1) }

        for set in capture("<(?:img|source)[^>]+srcset\\s*=\\s*[\"']([^\"']+)[\"']", html) {
            for candidate in set.split(separator: ",") {
                if let first = candidate.split(separator: " ").first(where: { !$0.isEmpty }) {
                    add(String(first), rank: 2)
                }
            }
        }
        for src in capture("<source[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']", html) { add(src, rank: 2) }
        for src in capture("<(?:video|audio)[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']", html) { add(src, rank: 2) }

        for src in capture("url\\(\\s*[\"']?([^\"')]+)[\"']?\\s*\\)", html) { add(src, rank: 3) }
        return ranked.sorted { $0.rank < $1.rank }.prefix(limit).map { $0.url }
    }

    static func cssSubResources(css: String, base: URL, limit: Int) -> [URL] {

        let body = strippingCSSComments(css)
        let importScope = String(body.prefix(while: { $0 != "{" }))

        var out: [URL] = []
        var seen = Set<String>()
        func add(_ raw: String) {
            let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !s.isEmpty, !s.hasPrefix("data:"), !s.hasPrefix("#") else { return }
            guard let u = URL(string: s, relativeTo: base)?.absoluteURL,
                  u.scheme == "http" || u.scheme == "https" else { return }
            if seen.insert(u.absoluteString).inserted { out.append(u) }
        }
        for src in capture("@import\\s+(?:url\\()?\\s*[\"']([^\"']+)[\"']", importScope) { add(src) }
        for src in capture("url\\(\\s*[\"']?([^\"')]+)[\"']?\\s*\\)", body) { add(src) }
        return Array(droppingRedundantFontFormats(out).prefix(limit))
    }

    private static func droppingRedundantFontFormats(_ urls: [URL]) -> [URL] {
        let rank = ["woff2": 0, "woff": 1, "ttf": 2, "otf": 3, "eot": 4, "svg": 5]

        func stem(_ u: URL) -> String {
            (u.lastPathComponent.split(separator: ".").first.map(String.init) ?? u.lastPathComponent).lowercased()
        }
        var best: [String: Int] = [:]
        var members: [String: Int] = [:]
        for u in urls {
            guard let r = rank[u.pathExtension.lowercased()] else { continue }
            let k = stem(u)
            best[k] = min(best[k] ?? r, r)
            members[k] = (members[k] ?? 0) + 1
        }
        return urls.filter { u in
            let ext = u.pathExtension.lowercased()
            guard let r = rank[ext] else { return true }
            let k = stem(u)

            if ext == "svg", (members[k] ?? 0) <= 1 { return true }
            return r == (best[k] ?? r)
        }
    }

    static func renderBlockingURLs(html rawHTML: String, base: URL) -> Set<String> {
        let html = strippingHTMLComments(rawHTML)
        var out = Set<String>()
        func add(_ raw: String) {
            guard let u = URL(string: raw.trimmingCharacters(in: .whitespacesAndNewlines), relativeTo: base)?.absoluteURL else { return }
            out.insert(u.absoluteString)
        }
        for tag in captureTags("<script[^>]*>", html) {
            let l = tag.lowercased()
            guard l.contains(" src") else { continue }
            if l.contains(" async") || l.contains(" defer") { continue }
            if l.contains("type=\"module\"") || l.contains("type='module'") { continue }
            if let src = attr("src", in: tag) { add(src) }
        }
        for tag in captureTags("<link[^>]+>", html) {
            let l = tag.lowercased()
            guard l.contains("stylesheet") else { continue }
            if l.contains("preload") { continue }
            if l.contains("media=\"print\"") || l.contains("media='print'") { continue }
            if let href = attr("href", in: tag) { add(href) }
        }
        return out
    }

    static func preconnectHosts(_ rawHTML: String, base: URL) -> Set<String> {
        let html = strippingHTMLComments(rawHTML)
        var out = Set<String>()
        for tag in captureTags("<link[^>]+>", html) {
            let l = tag.lowercased()
            guard l.contains("preconnect") || l.contains("dns-prefetch") else { continue }
            guard let href = attr("href", in: tag),
                  let u = URL(string: href, relativeTo: base)?.absoluteURL,
                  let h = u.host else { continue }
            out.insert(h)
        }
        return out
    }

    private static func countRenderBlocking(_ rawHTML: String) -> (scripts: Int, styles: Int) {
        let html = strippingHTMLComments(rawHTML)
        var scripts = 0
        for tag in captureTags("<script[^>]*>", html) {
            let l = tag.lowercased()
            guard l.contains(" src") else { continue }
            if l.contains(" async") || l.contains(" defer") { continue }
            if l.contains("type=\"module\"") || l.contains("type='module'") { continue }
            scripts += 1
        }
        var styles = 0
        for tag in captureTags("<link[^>]+>", html) {
            let l = tag.lowercased()
            guard l.contains("stylesheet") else { continue }
            if l.contains("preload") { continue }
            if l.contains("media=\"print\"") || l.contains("media='print'") { continue }
            styles += 1
        }
        return (scripts, styles)
    }

    static func classify(url: URL, contentType: String) -> ResourceType {
        let ct = contentType.lowercased()
        let ext = url.pathExtension.lowercased()
        if ct.contains("javascript") || ct.contains("ecmascript") || ["js", "mjs", "cjs"].contains(ext) { return .script }
        if ct.contains("css") || ext == "css" { return .stylesheet }
        if ct.contains("font") || ["woff", "woff2", "ttf", "otf", "eot"].contains(ext) { return .font }
        if ct.hasPrefix("image/") || ["png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp"].contains(ext) { return .image }
        if ct.hasPrefix("video/") || ct.hasPrefix("audio/") || ["mp4", "webm", "mp3", "ogg", "wav", "mov"].contains(ext) { return .media }
        if ct.contains("html") { return .document }
        return .other
    }

    static func cdnHint(_ r: HTTPResponse) -> String? {
        let server = (r.header("server") ?? "").lowercased()
        if server.contains("cloudflare") || r.header("cf-ray") != nil { return "Cloudflare" }
        if server.contains("akamai") || r.header("x-akamai-transformed") != nil { return "Akamai" }
        if server.contains("fastly") || r.header("x-served-by") != nil { return "Fastly" }
        if r.header("x-amz-cf-id") != nil || (r.header("via")?.lowercased().contains("cloudfront") ?? false) { return "Amazon CloudFront" }
        if r.header("x-vercel-cache") != nil || server.contains("vercel") { return "Vercel Edge" }
        if r.header("x-nf-request-id") != nil || server.contains("netlify") { return "Netlify Edge" }
        if r.header("x-cache") != nil || r.header("x-cache-status") != nil { return "CDN cache (x-cache)" }
        return nil
    }

    static func edgeCacheHit(_ status: String?) -> Bool? {
        guard let raw = status?.uppercased(), !raw.isEmpty else { return nil }
        let nearest = raw.split(separator: ",").last.map(String.init) ?? raw
        for scope in [nearest, raw] {
            if scope.contains("HIT") || scope.contains("REVALIDATED") || scope.contains("STALE") { return true }
            if scope.contains("MISS") || scope.contains("BYPASS") || scope.contains("DYNAMIC")
                || scope.contains("EXPIRED") || scope.contains("NONE") { return false }
        }
        return nil
    }

    static func cacheHitStatus(_ r: HTTPResponse) -> String? {
        for key in ["cf-cache-status", "x-cache", "x-cache-status", "x-vercel-cache", "x-nf-request-id-cache", "cdn-cache", "x-drupal-cache"] {
            if let v = r.header(key), !v.isEmpty { return v.trimmingCharacters(in: .whitespaces) }
        }
        if let age = r.header("age"), let n = Int(age.trimmingCharacters(in: .whitespaces)), n > 0 {
            return "HIT (age \(n)s)"
        }
        return nil
    }

    private static func isCompressible(_ ct: String) -> Bool {
        let c = ct.lowercased()
        return c.contains("text/") || c.contains("javascript") || c.contains("json")
            || c.contains("xml") || c.contains("svg") || c.contains("css") || c.contains("+json")
    }

    private static func looksCompressed(_ t: RequestTiming?, header: String?) -> Bool? {
        if let h = header?.lowercased(),
           h.contains("gzip") || h.contains("br") || h.contains("deflate") || h.contains("zstd") {
            return true
        }
        guard let t, let wire = t.wireBytes, wire > 0, t.decodedBytes > 0 else { return nil }
        return Double(wire) < Double(t.decodedBytes) * 0.9
    }

    private static func hasLongCache(_ r: HTTPResponse) -> Bool {
        let cc = (r.header("cache-control") ?? "").lowercased()
        if cc.contains("immutable") { return true }
        if cc.contains("no-store") || cc.contains("no-cache") { return false }
        if let range = cc.range(of: "max-age=") {
            let digits = cc[range.upperBound...].prefix { $0.isNumber }
            if let age = Int(digits) { return age >= 86_400 }
        }
        return false
    }

    private static func displayName(_ url: URL) -> String {
        let last = url.lastPathComponent
        if last.isEmpty || last == "/" { return url.host ?? url.absoluteString }
        return last
    }

    static func baseDomain(_ host: String) -> String {
        let parts = host.lowercased().split(separator: ".").map(String.init)
        guard parts.count > 2 else { return parts.joined(separator: ".") }
        let secondLevel: Set<String> = ["co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "gr"]
        if secondLevel.contains(parts[parts.count - 2]), parts[parts.count - 1].count <= 3 {
            return parts.suffix(3).joined(separator: ".")
        }
        return parts.suffix(2).joined(separator: ".")
    }

    static func ms(_ v: Double?) -> String {
        guard let v else { return "—" }
        return v >= 100 ? String(format: "%.0f ms", v) : String(format: "%.1f ms", v)
    }
    static func seconds(_ v: Double?) -> String {
        guard let v else { return "—" }
        return v >= 1000 ? String(format: "%.1f s", v / 1000) : String(format: "%.0f ms", v)
    }
    static func kb(_ n: Int?) -> String {
        guard let n else { return "—" }
        if n < 1024 { return "\(n) B" }
        if n < 1_048_576 { return String(format: "%.1f KB", Double(n) / 1024) }
        return String(format: "%.2f MB", Double(n) / 1_048_576)
    }

    private static func strippingHTMLComments(_ html: String) -> String {
        replacingMatches("<!--[\\s\\S]*?-->", in: html)
    }

    private static func strippingCSSComments(_ css: String) -> String {
        replacingMatches("/\\*[\\s\\S]*?\\*/", in: css)
    }

    private static func replacingMatches(_ pattern: String, in text: String) -> String {
        guard text.contains("<!--") || text.contains("/*"),
              let re = try? NSRegularExpression(pattern: pattern, options: []) else { return text }
        return re.stringByReplacingMatches(in: text,
                                           range: NSRange(location: 0, length: (text as NSString).length),
                                           withTemplate: "")
    }

    private static func capture(_ pattern: String, _ text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).compactMap {
            $0.numberOfRanges > 1 ? ns.substring(with: $0.range(at: 1)) : nil
        }
    }
    private static func captureTags(_ pattern: String, _ text: String) -> [String] {
        guard let re: NSRegularExpression = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { ns.substring(with: $0.range) }
    }
    private static func attr(_ name: String, in tag: String) -> String? {
        capture("\(name)\\s*=\\s*[\"']([^\"']+)[\"']", tag).first
    }
}

extension String {

    func padded(_ width: Int) -> String {
        count >= width ? self : self + String(repeating: " ", count: width - count)
    }
}
