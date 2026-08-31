import Foundation

struct HTTPResponse {
    let requestedURL: URL
    let finalURL: URL
    let status: Int

    let headers: [String: String]
    let setCookieRaw: String?
    let cookies: [HTTPCookie]
    let body: Data

    var text: String {
        let capped = body.count > 3_000_000 ? body.prefix(3_000_000) : body[...]
        return String(decoding: capped, as: UTF8.self)
    }

    func header(_ name: String) -> String? { headers[name.lowercased()] }
    var contentType: String { header("content-type") ?? "" }
}

actor RequestPacer {
    private var nextEarliest: Date = .distantPast

    func wait(intervalMs: Int) async {
        guard intervalMs > 0 else { return }
        let interval = Double(intervalMs) / 1000.0
        let now = Date()
        let start = max(now, nextEarliest)
        nextEarliest = start.addingTimeInterval(interval)
        let delay = start.timeIntervalSince(now)
        if delay > 0 {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
    }
}

final class HTTPClient: NSObject, URLSessionDelegate, URLSessionTaskDelegate {

    let userAgent = "WebScanner/1.0 (+authorized-security-assessment)"

    var options = RequestOptions.none

    private let pacer = RequestPacer()

    private var lenientSession: URLSession!

    private var noRedirectSession: URLSession!

    private var strictSession: URLSession!

    override init() {
        super.init()

        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 12
        cfg.timeoutIntervalForResource = 20
        cfg.httpAdditionalHeaders = [
            "User-Agent": userAgent,
            "Accept": "*/*",
        ]
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.httpMaximumConnectionsPerHost = 6
        cfg.httpShouldSetCookies = false
        cfg.httpCookieAcceptPolicy = .never

        lenientSession = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
        noRedirectSession = URLSession(configuration: cfg.copy() as! URLSessionConfiguration,
                                       delegate: self, delegateQueue: nil)

        let scfg = cfg.copy() as! URLSessionConfiguration
        strictSession = URLSession(configuration: scfg)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(session === noRedirectSession ? nil : request)
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    func fetch(_ url: URL,
               method: String = "GET",
               extraHeaders: [String: String] = [:],
               body: Data? = nil,
               followRedirects: Bool = true) async -> HTTPResponse? {
        var req = URLRequest(url: url)
        req.httpMethod = method

        for (k, v) in options.resolvedHeaders() { req.setValue(v, forHTTPHeaderField: k) }
        for (k, v) in extraHeaders { req.setValue(v, forHTTPHeaderField: k) }
        if let body { req.httpBody = body }

        await pacer.wait(intervalMs: options.delayMs)

        let session = followRedirects ? lenientSession! : noRedirectSession!
        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else { return nil }

            var headers: [String: String] = [:]
            for (k, v) in http.allHeaderFields {
                if let ks = k as? String, let vs = v as? String {
                    headers[ks.lowercased()] = vs
                }
            }

            let setCookie = http.value(forHTTPHeaderField: "Set-Cookie")
            var cookieFields: [String: String] = [:]
            if let setCookie { cookieFields["Set-Cookie"] = setCookie }
            let cookies = HTTPCookie.cookies(withResponseHeaderFields: cookieFields,
                                             for: http.url ?? url)

            return HTTPResponse(
                requestedURL: url,
                finalURL: http.url ?? url,
                status: http.statusCode,
                headers: headers,
                setCookieRaw: setCookie,
                cookies: cookies,
                body: data
            )
        } catch {
            return nil
        }
    }

    private func timingConfig() -> URLSessionConfiguration {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 15
        cfg.timeoutIntervalForResource = 25
        cfg.httpAdditionalHeaders = [
            "User-Agent": userAgent,
            "Accept": "*/*",
        ]
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.httpShouldSetCookies = false
        cfg.httpCookieAcceptPolicy = .never
        return cfg
    }

    private func timedFetch(_ url: URL, session: URLSession) async -> (HTTPResponse, RequestTiming)? {
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        for (k, v) in options.resolvedHeaders() { req.setValue(v, forHTTPHeaderField: k) }

        await pacer.wait(intervalMs: options.delayMs)

        let collector = MetricsCollector()
        let clock = ContinuousClock()
        let start = clock.now
        do {
            let (data, resp) = try await session.data(for: req, delegate: collector)
            let wallMs = (clock.now - start).milliseconds
            guard let http = resp as? HTTPURLResponse else { return nil }

            var headers: [String: String] = [:]
            for (k, v) in http.allHeaderFields {
                if let ks = k as? String, let vs = v as? String {
                    headers[ks.lowercased()] = vs
                }
            }
            let response = HTTPResponse(
                requestedURL: url,
                finalURL: http.url ?? url,
                status: http.statusCode,
                headers: headers,
                setCookieRaw: http.value(forHTTPHeaderField: "Set-Cookie"),
                cookies: [],
                body: data)

            let timing = RequestTiming.from(metrics: collector.metrics,
                                            wallMs: wallMs, decodedBytes: data.count)
            return (response, timing)
        } catch {
            return nil
        }
    }

    func timedFetches(_ url: URL, count: Int) async -> [(response: HTTPResponse, timing: RequestTiming)] {
        let session = URLSession(configuration: timingConfig())
        defer { session.finishTasksAndInvalidate() }
        var out: [(response: HTTPResponse, timing: RequestTiming)] = []
        for _ in 0..<max(1, count) {
            if let s = await timedFetch(url, session: session) { out.append(s) }
        }
        return out
    }

    func timedAssetFetches(_ urls: [URL], concurrency: Int = 6) async -> [(url: URL, response: HTTPResponse, timing: RequestTiming)] {
        guard !urls.isEmpty else { return [] }
        let session = URLSession(configuration: timingConfig())
        defer { session.finishTasksAndInvalidate() }
        var out: [(url: URL, response: HTTPResponse, timing: RequestTiming)] = []
        for batch in urls.chunked(into: max(1, concurrency)) {
            await withTaskGroup(of: (URL, HTTPResponse, RequestTiming)?.self) { group in
                for u in batch {
                    group.addTask { [weak self] in
                        guard let self, let (r, t) = await self.timedFetch(u, session: session) else { return nil }
                        return (u, r, t)
                    }
                }
                for await res in group { if let res { out.append((res.0, res.1, res.2)) } }
            }
        }
        return out
    }

    func tlsValid(host: String) async -> Bool? {
        guard let url = URL(string: "https://\(host)/") else { return nil }
        var req = URLRequest(url: url)
        req.httpMethod = "HEAD"
        do {
            _ = try await strictSession.data(for: req)
            return true
        } catch let e as URLError {
            switch e.code {
            case .serverCertificateUntrusted,
                 .serverCertificateHasBadDate,
                 .serverCertificateHasUnknownRoot,
                 .serverCertificateNotYetValid,
                 .secureConnectionFailed:
                return false
            default:
                return nil
            }
        } catch {
            return nil
        }
    }
}

final class MetricsCollector: NSObject, URLSessionTaskDelegate {
    private let lock = NSLock()
    private var _metrics: URLSessionTaskMetrics?

    var metrics: URLSessionTaskMetrics? {
        lock.lock(); defer { lock.unlock() }
        return _metrics
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didFinishCollecting metrics: URLSessionTaskMetrics) {
        lock.lock(); _metrics = metrics; lock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

extension Duration {

    var milliseconds: Double {
        let c = components
        return Double(c.seconds) * 1000 + Double(c.attoseconds) / 1_000_000_000_000_000
    }
}
