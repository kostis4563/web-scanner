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

final class HTTPClient: NSObject, URLSessionDelegate, URLSessionTaskDelegate {

    let userAgent = "WebScanner/1.0 (+authorized-security-assessment)"

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
        for (k, v) in extraHeaders { req.setValue(v, forHTTPHeaderField: k) }
        if let body { req.httpBody = body }

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
