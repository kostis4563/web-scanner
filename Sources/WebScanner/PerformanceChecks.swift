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

    var timingTotal: Double? { totalMs ?? wallMs }

    static func from(metrics: URLSessionTaskMetrics?, wallMs: Double, decodedBytes: Int) -> RequestTiming {
        var t = RequestTiming(wallMs: wallMs, decodedBytes: decodedBytes)
        t.totalMs = wallMs
        guard let tx = metrics?.transactionMetrics.last else { return t }

        func ms(_ a: Date?, _ b: Date?) -> Double? {
            guard let a, let b else { return nil }
            let d = b.timeIntervalSince(a) * 1000
            return d >= 0 ? d : nil
        }
        t.dnsMs = ms(tx.domainLookupStartDate, tx.domainLookupEndDate)

        t.tcpMs = ms(tx.connectStartDate, tx.secureConnectionStartDate)
            ?? ms(tx.connectStartDate, tx.connectEndDate)
        t.tlsMs = ms(tx.secureConnectionStartDate, tx.secureConnectionEndDate)
        t.ttfbMs = ms(tx.requestStartDate, tx.responseStartDate)
        t.downloadMs = ms(tx.responseStartDate, tx.responseEndDate)
        if let total = ms(tx.fetchStartDate, tx.responseEndDate) { t.totalMs = total }
        t.reusedConnection = tx.isReusedConnection
        t.networkProtocol = normalizeProtocol(tx.networkProtocolName)
        t.wireBytes = Int(tx.countOfResponseBodyBytesReceived)
        t.headerBytes = Int(tx.countOfResponseHeaderBytesReceived)
        if let v = tx.negotiatedTLSProtocolVersion { t.tlsVersion = tlsString(v) }
        return t
    }

    private static func normalizeProtocol(_ p: String?) -> String? {
        guard let p = p?.lowercased() else { return nil }
        if p.contains("h3") || p.contains("http/3") { return "HTTP/3" }
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

struct ResourceStat {
    var name: String
    var url: String
    var type: ResourceType
    var wireBytes: Int
    var decodedBytes: Int
    var ms: Double?
    var compressed: Bool?
    var cached: Bool
    var contentType: String
}

struct ResourceGroup: Identifiable {
    var type: ResourceType
    var count: Int
    var wireBytes: Int
    var id: String { type.rawValue }
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

    var ttfbBestMs: Double?
    var ttfbMedianMs: Double?
    var ttfbColdMs: Double?
    var ttfbWarmMs: Double?
    var downloadMs: Double?
    var coldTotalMs: Double?

    var networkProtocol: String?
    var tlsVersion: String?
    var http3Available: Bool
    var cdn: String?
    var connectionReused: Bool

    var htmlDecodedBytes: Int
    var htmlWireBytes: Int?
    var htmlCompressed: Bool?
    var renderBlockingScripts: Int
    var renderBlockingStyles: Int

    var groups: [ResourceGroup]
    var largest: [ResourceStat]
    var totalWireBytes: Int
    var totalDecodedBytes: Int
    var requestCount: Int
    var sampledAssetCount: Int
    var assetsTruncated: Bool

    var findings: [Finding]
}

enum PerformanceChecks {

    static let discoverCap = 200
    static let fetchCap = 40

    static func report(home: HTTPResponse,
                       samples: [RequestTiming],
                       discoveredAssetCount: Int,
                       assets: [(url: URL, response: HTTPResponse, timing: RequestTiming)]) -> PerformanceReport {

        let ttfbs = samples.compactMap { $0.ttfbMs }
        let best = ttfbs.min()
        let median = ttfbs.sorted().dropFirst(ttfbs.count / 2).first
        let cold = samples.first
        let warmTTFB = samples.dropFirst().compactMap { $0.ttfbMs }.min()
        let proto = samples.compactMap { $0.networkProtocol }.first
        let tls = samples.compactMap { $0.tlsVersion }.first
        let reused = samples.contains { $0.reusedConnection }

        let htmlWire = cold?.wireBytes
        let htmlCompressed = looksCompressed(cold, header: home.header("content-encoding"))
        let http3 = (home.header("alt-svc")?.lowercased().contains("h3") ?? false) || proto == "HTTP/3"
        let cdn = cdnHint(home)
        let (rbScripts, rbStyles) = countRenderBlocking(home.text)

        var resources: [ResourceStat] = []

        let docWire = htmlWire ?? home.body.count
        resources.append(ResourceStat(
            name: home.finalURL.host ?? "document", url: home.finalURL.absoluteString,
            type: .document, wireBytes: docWire, decodedBytes: home.body.count,
            ms: cold?.timingTotal, compressed: htmlCompressed,
            cached: hasLongCache(home), contentType: home.contentType))
        for a in assets {
            let type = classify(url: a.url, contentType: a.response.contentType)
            let wire = a.timing.wireBytes ?? a.response.body.count
            resources.append(ResourceStat(
                name: displayName(a.url), url: a.url.absoluteString, type: type,
                wireBytes: wire, decodedBytes: a.response.body.count,
                ms: a.timing.timingTotal,
                compressed: looksCompressed(a.timing, header: a.response.header("content-encoding")),
                cached: hasLongCache(a.response), contentType: a.response.contentType))
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

        let totalWire = resources.reduce(0) { $0 + $1.wireBytes }
        let totalDecoded = resources.reduce(0) { $0 + $1.decodedBytes }
        let requestCount = 1 + discoveredAssetCount
        let truncated = assets.count < discoveredAssetCount

        let (score, breakdown) = computeScore(
            ttfb: best, proto: proto, tls: tls, http3: http3,
            htmlCompressed: htmlCompressed, totalWire: totalWire,
            requestCount: requestCount, renderBlocking: rbScripts + rbStyles,
            resources: resources, redirected: home.requestedURL.absoluteString != home.finalURL.absoluteString)

        var report = PerformanceReport(
            url: home.finalURL.absoluteString, status: home.status,
            score: score, grade: grade(score), scoreBreakdown: breakdown,
            dnsMs: cold?.dnsMs, tcpMs: cold?.tcpMs, tlsMs: cold?.tlsMs,
            ttfbBestMs: best, ttfbMedianMs: median, ttfbColdMs: cold?.ttfbMs, ttfbWarmMs: warmTTFB,
            downloadMs: cold?.downloadMs, coldTotalMs: cold?.timingTotal,
            networkProtocol: proto, tlsVersion: tls, http3Available: http3, cdn: cdn,
            connectionReused: reused,
            htmlDecodedBytes: home.body.count, htmlWireBytes: htmlWire, htmlCompressed: htmlCompressed,
            renderBlockingScripts: rbScripts, renderBlockingStyles: rbStyles,
            groups: groups, largest: largest, totalWireBytes: totalWire, totalDecodedBytes: totalDecoded,
            requestCount: requestCount, sampledAssetCount: assets.count, assetsTruncated: truncated,
            findings: [])

        var findings: [Finding] = [summary(report: report, samples: samples)]
        if let f = serverResponseTime(report: report) { findings.append(f) }
        if let f = protocolUpgrade(report: report) { findings.append(f) }
        if let f = http3Suggestion(report: report) { findings.append(f) }
        if let f = tls13(version: tls) { findings.append(f) }
        if let f = compression(home: home, timing: cold) { findings.append(f) }
        if let f = largeDocument(home: home) { findings.append(f) }
        if let f = pageWeight(report: report) { findings.append(f) }
        if let f = renderBlocking(report: report, url: home.finalURL) { findings.append(f) }
        if let f = imageOptimization(html: home.text, resources: resources, pageURL: home.finalURL) { findings.append(f) }
        if let f = fontOptimization(html: home.text, resources: resources, pageURL: home.finalURL) { findings.append(f) }
        if let f = assetAudit(resources: resources) { findings.append(f) }
        if let f = htmlCaching(home: home) { findings.append(f) }
        if let f = serverTiming(home: home) { findings.append(f) }
        if let f = redirectChain(home: home) { findings.append(f) }
        report.findings = findings
        return report
    }

    private static func computeScore(ttfb: Double?, proto: String?, tls: String?, http3: Bool,
                                     htmlCompressed: Bool?, totalWire: Int, requestCount: Int,
                                     renderBlocking: Int, resources: [ResourceStat],
                                     redirected: Bool) -> (Int, [String]) {
        var s = 100.0
        var notes: [String] = []
        func deduct(_ n: Double, _ why: String) {
            guard n > 0 else { return }
            s -= n
            notes.append(String(format: "-%.0f  %@", n, why))
        }

        if let t = ttfb {
            switch t {
            case ..<200:  break
            case ..<500:  deduct(8,  "TTFB \(ms(t)) (aim < 200 ms)")
            case ..<1000: deduct(16, "slow TTFB \(ms(t))")
            case ..<1800: deduct(26, "very slow TTFB \(ms(t))")
            default:      deduct(34, "very slow TTFB \(ms(t))")
            }
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
        lines.append("Server response (TTFB): best \(ms(r.ttfbBestMs)), median \(ms(r.ttfbMedianMs))")
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
        if let cdn = r.cdn { lines.append("CDN / edge: \(cdn)") }

        return Finding(
            title: "Performance score: \(r.score)/100 (\(r.grade))",
            severity: .info,
            category: "Performance",
            location: r.url,
            detail: "Measured load characteristics for this page:\n" + lines.map { "• \($0)" }.joined(separator: "\n"),
            evidence: "TTFB sampled over \(samples.count) request(s); connection setup from the cold request; page weight from \(r.sampledAssetCount) sampled asset(s) via URLSession transfer metrics."
                + (r.scoreBreakdown.isEmpty ? "\nScore: 100/100 — no deductions." : "\nScore deductions:\n" + r.scoreBreakdown.map { "  \($0)" }.joined(separator: "\n")),
            exploit: "Informational baseline. The score weights the factors below (TTFB, protocol, compression, page weight, requests, render-blocking, images, caching). The individual Performance findings list the highest-leverage fixes.",
            remediation: "Target: TTFB < 200 ms, HTTP/2 or HTTP/3, TLS 1.3, compressed text, far-future asset caching, and a lean page (< 1 MB, few requests). See the Performance findings below for specifics.",
            reference: "https://web.dev/articles/ttfb")
    }

    private static func serverResponseTime(report r: PerformanceReport) -> Finding? {
        guard let best = r.ttfbBestMs else { return nil }
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
        return Finding(
            title: title, severity: sev, category: "Performance", location: "TTFB",
            detail: "Time to first byte was \(ms(best)) at best and \(ms(r.ttfbMedianMs)) median. TTFB captures backend processing plus one network round trip; the browser can't start rendering until it arrives."
                + (r.ttfbWarmMs.map { " Warm (reused-connection) TTFB was \(ms($0))." } ?? ""),
            evidence: "Best TTFB: \(ms(best))  ·  Median: \(ms(r.ttfbMedianMs))  ·  Cold: \(ms(r.ttfbColdMs))  ·  Warm: \(ms(r.ttfbWarmMs))",
            exploit: sev == .info
                ? "Users get a responsive first byte. No action needed here."
                : "A high TTFB delays the entire page: nothing paints until the first byte arrives, hurting Core Web Vitals (LCP), search ranking and bounce rate.",
            remediation: [
                "Cache rendered pages / expensive queries (full-page, object, or CDN edge cache).",
                "Optimize the slowest database queries and add indexes; avoid N+1 queries.",
                "Reuse connections (HTTP keep-alive, pooled DB connections); keep the app warm.",
                cdnLine,
                "Move compute closer to users (multi-region, edge functions) for a global audience.",
            ].map { "• \($0)" }.joined(separator: "\n"),
            reference: "https://web.dev/articles/ttfb")
    }

    private static func protocolUpgrade(report r: PerformanceReport) -> Finding? {
        guard let proto = r.networkProtocol, proto == "HTTP/1.1" || proto == "HTTP/1.0" else { return nil }
        return Finding(
            title: "Served over \(proto) - upgrade to HTTP/2 or HTTP/3",
            severity: .low, category: "Performance", location: "Transport",
            detail: "The page negotiated \(proto). HTTP/2 multiplexes many requests over one connection (no head-of-line blocking, header compression); HTTP/3 (QUIC) additionally removes TCP head-of-line blocking and speeds up connection setup.",
            evidence: "Negotiated application protocol: \(proto)",
            exploit: "On \(proto) each asset competes for a few connections and pays per-request overhead, so pages with many resources load noticeably slower - especially on high-latency mobile networks.",
            remediation: "Enable HTTP/2 at your web server / load balancer / CDN (a one-line toggle on nginx, Apache, Caddy, Cloudflare, …) and enable HTTP/3 where available. Both require HTTPS, which is already in place.",
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
            remediation: "Turn on HTTP/3 at your CDN or web server (Cloudflare, Fastly, nginx w/ quic, Caddy, LiteSpeed all support it) and advertise it via the Alt-Svc header.",
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
            remediation: "Turn on TLS 1.3 in your server / CDN TLS settings (widely supported since 2018). Keep 1.2 for old clients but prefer 1.3.",
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
            detail: "The HTML response (\(kb(decoded)), \(home.contentType)) was sent without gzip/Brotli compression. Text compresses by roughly 70-90%, so this is wasted bytes on every load.",
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
            remediation: "Minify HTML, avoid inlining large JSON/data blobs, paginate or lazy-load long lists, and stream above-the-fold content. Ensure compression is on.",
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
            detail: "The page transfers \(kb(r.totalWireBytes))\(r.assetsTruncated ? " (sampled)" : "") over \(r.requestCount) request(s). Heaviest types - \(heavy). More bytes and more requests mean slower loads, especially on mobile.",
            evidence: "Total transfer: \(kb(r.totalWireBytes))\nRequests: \(r.requestCount)\nBy type: " + r.groups.map { "\($0.type.label) \($0.count)×/\(kb($0.wireBytes))" }.joined(separator: ", "),
            exploit: "A heavy, request-dense page delays load and interactivity and burns users' data - hurting engagement and Core Web Vitals.",
            remediation: "Bundle & code-split JS, tree-shake unused code, compress and lazy-load images, subset fonts, remove unused CSS, and cut third-party scripts. Serve everything from a CDN over HTTP/2/3.",
            reference: "https://web.dev/articles/fast#optimize-your-images-and-videos")
    }

    private static func renderBlocking(report r: PerformanceReport, url: URL) -> Finding? {
        let total = r.renderBlockingScripts + r.renderBlockingStyles
        guard total >= 5 else { return nil }
        return Finding(
            title: "\(total) render-blocking resource(s) in the page",
            severity: total >= 12 ? .medium : .low, category: "Performance", location: url.absoluteString,
            detail: "The page references \(r.renderBlockingScripts) synchronous script(s) and \(r.renderBlockingStyles) stylesheet(s) that block rendering. The browser must download and process each before it can paint meaningful content.",
            evidence: "Blocking <script> (no async/defer/module): \(r.renderBlockingScripts)\nStylesheet <link rel=stylesheet>: \(r.renderBlockingStyles)",
            exploit: "Each render-blocking resource adds a serial step before first paint, inflating LCP and making the page feel slow - especially on high-latency connections.",
            remediation: "Add `defer`/`async` to scripts and use `type=\"module\"`; inline critical CSS and load the rest asynchronously (`media`/`preload`); bundle and code-split; preconnect to third-party origins.",
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

        return Finding(
            title: "Images can be optimized",
            severity: sev, category: "Performance", location: pageURL.absoluteString,
            detail: "Image delivery has room to improve:\n" + lines.map { "• \($0)" }.joined(separator: "\n"),
            evidence: lines.joined(separator: "\n"),
            exploit: "Large or legacy-format images dominate page weight and slow the Largest Contentful Paint; missing dimensions cause layout shifts (poor CLS); eager loading of off-screen images wastes bandwidth.",
            remediation: "Serve WebP/AVIF with responsive `srcset`/`sizes`, compress and resize to display dimensions, set explicit `width`/`height` (or `aspect-ratio`), add `loading=\"lazy\"` to below-the-fold images, and use a CDN image pipeline.",
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

        var issues: [String] = []
        if !hasPreload && !fonts.isEmpty { issues.append("no `<link rel=preload as=font>` for the primary font(s)") }
        if !hasDisplaySwap { issues.append("no `font-display: swap` detected (text may be invisible during font load - FOIT)") }
        if googleFonts && !hasPreconnect { issues.append("no `preconnect` to the font host") }
        guard !issues.isEmpty else { return nil }

        let fontBytes = fonts.reduce(0) { $0 + $1.wireBytes }
        return Finding(
            title: "Web fonts can be optimized",
            severity: .low, category: "Performance", location: pageURL.absoluteString,
            detail: "The page uses web fonts (\(fonts.count) file(s)\(fontBytes > 0 ? ", \(kb(fontBytes))" : googleFonts ? ", via Google Fonts" : "")) but: " + issues.joined(separator: "; ") + ".",
            evidence: "Font files: \(fonts.count)\nGoogle Fonts: \(googleFonts ? "yes" : "no")\npreload: \(hasPreload)  ·  font-display: \(hasDisplaySwap)  ·  preconnect: \(hasPreconnect)",
            exploit: "Unoptimized fonts block text rendering (invisible or swapping text), add render-blocking requests, and delay a stable first paint.",
            remediation: "Add `font-display: swap` (or `optional`), `preload` the critical font, `preconnect` to the font host, self-host and subset fonts to the characters you use, and prefer WOFF2.",
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
                detail: "The \(assets.count) sampled asset(s) totalling \(kb(totalWire)) are served compressed with cache headers. Good.",
                evidence: "Total transfer: \(kb(totalWire))",
                exploit: "No action needed for the sampled assets.",
                remediation: "Keep setting far-future `Cache-Control: max-age, immutable` on fingerprinted files and compress new text assets.",
                reference: "https://web.dev/articles/uses-long-cache-ttl")
        }

        let sev: Severity = !uncompressed.isEmpty ? .medium : .low
        var lines: [String] = ["Sampled \(assets.count) asset(s), \(kb(totalWire)) transferred."]
        if !uncompressed.isEmpty { lines.append("Uncompressed text asset(s): " + uncompressed.prefix(8).map { $0.name }.joined(separator: ", ")) }
        if !uncached.isEmpty { lines.append("Missing far-future caching: " + uncached.prefix(8).map { $0.name }.joined(separator: ", ")) }
        if let slow = assets.max(by: { ($0.ms ?? 0) < ($1.ms ?? 0) }), let sms = slow.ms { lines.append("Slowest asset: \(slow.name) (\(ms(sms)))") }

        return Finding(
            title: "Static assets can be optimized (\(uncompressed.count) uncompressed, \(uncached.count) uncached)",
            severity: sev, category: "Performance", location: "\(assets.count) asset(s)",
            detail: "Sampling of page assets shows opportunities to cut bytes and repeat-visit load time:\n" + lines.map { "• \($0)" }.joined(separator: "\n"),
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
            remediation: "Send an `ETag` (or `Last-Modified`) so browsers can revalidate, and a suitable `Cache-Control` (e.g. `no-cache` to force revalidation, or a short `max-age` for pages that tolerate slight staleness).",
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
            remediation: "Link and advertise the final canonical URL directly, collapse redirect chains to a single hop, and use HSTS so browsers skip the http→https redirect.",
            reference: "https://web.dev/articles/redirects")
    }

    static func assetURLs(html: String, base: URL, limit: Int) -> [URL] {
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
        for src in capture("<source[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']", html) { add(src, rank: 2) }
        for src in capture("<(?:video|audio)[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']", html) { add(src, rank: 2) }
        return ranked.sorted { $0.rank < $1.rank }.prefix(limit).map { $0.url }
    }

    private static func countRenderBlocking(_ html: String) -> (scripts: Int, styles: Int) {
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

    static func ms(_ v: Double?) -> String {
        guard let v else { return "—" }
        return v >= 100 ? String(format: "%.0f ms", v) : String(format: "%.1f ms", v)
    }
    static func kb(_ n: Int?) -> String {
        guard let n else { return "—" }
        if n < 1024 { return "\(n) B" }
        if n < 1_048_576 { return String(format: "%.1f KB", Double(n) / 1024) }
        return String(format: "%.2f MB", Double(n) / 1_048_576)
    }

    private static func capture(_ pattern: String, _ text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).compactMap {
            $0.numberOfRanges > 1 ? ns.substring(with: $0.range(at: 1)) : nil
        }
    }
    private static func captureTags(_ pattern: String, _ text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { ns.substring(with: $0.range) }
    }
    private static func attr(_ name: String, in tag: String) -> String? {
        capture("\(name)\\s*=\\s*[\"']([^\"']+)[\"']", tag).first
    }
}
