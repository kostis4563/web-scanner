import Foundation

struct InfoReport {
    var url: String
    var finalURL: String
    var status: Int
    var reachable: Bool
    var https: Bool
    var redirected: Bool
    var title: String?
    var server: String?
    var poweredBy: String?
    var contentType: String?
    var htmlBytes: Int
    var cookieCount: Int
    var technologies: [DetectedTech]
    var protocols: [String]
    var os: String?
    var host: HostRecon.HostProfile?
    var services: [ServiceStatus]
}

struct DetectedTech: Identifiable {
    var id: String { category + "|" + name }
    var name: String
    var category: String
    var version: String?
}

struct ServiceStatus: Identifiable {
    var id: Int { port }
    var port: Int
    var name: String
    var role: String
    var risk: Severity?
    var version: String?
}

enum InfoChecks {

    static func build(home: HTTPResponse?, profile: HostRecon.HostProfile,
                      services: [ServiceStatus] = []) -> InfoReport {
        guard let h = home else {
            return InfoReport(
                url: profile.host, finalURL: profile.host, status: 0, reachable: false,
                https: false, redirected: false, title: nil, server: nil, poweredBy: nil,
                contentType: nil, htmlBytes: 0, cookieCount: 0, technologies: [],
                protocols: [], os: nil, host: profile, services: services)
        }
        return InfoReport(
            url: h.requestedURL.absoluteString,
            finalURL: h.finalURL.absoluteString,
            status: h.status,
            reachable: true,
            https: h.finalURL.scheme == "https",
            redirected: h.requestedURL.absoluteString != h.finalURL.absoluteString,
            title: HTMLHelpers.title(from: h.text),
            server: h.header("server"),
            poweredBy: h.header("x-powered-by"),
            contentType: h.contentType.isEmpty ? nil : h.contentType,
            htmlBytes: h.body.count,
            cookieCount: h.cookies.count,
            technologies: detectTech(h),
            protocols: protocols(h),
            os: os(server: h.header("server"), powered: h.header("x-powered-by")),
            host: profile, services: services)
    }

    static func discoveredServices(from summary: PortScanSummary) -> [ServiceStatus] {
        let roleMap = Dictionary(
            PortCatalog.infoServicePorts.map { ($0.port, $0.role) },
            uniquingKeysWith: { a, _ in a })
        return summary.ports
            .filter { $0.state == .open }
            .map { op in
                let (name, role) = classify(op, portRole: roleMap[op.port])
                let v = [op.product, op.version].compactMap { $0 }.joined(separator: " ")
                    .trimmingCharacters(in: .whitespaces)
                return ServiceStatus(port: op.port, name: name, role: role,
                                     risk: op.risk, version: v.isEmpty ? nil : v)
            }
            .sorted { $0.port < $1.port }
    }

    private static func classify(_ op: OpenPort, portRole: String?) -> (name: String, role: String) {
        let hay = [op.banner, op.product, op.service].compactMap { $0 }.joined(separator: " ").lowercased()

        let rules: [([String], String, String)] = [
            (["mariadb"], "MariaDB", "Database"),
            (["mysql"], "MySQL", "Database"),
            (["postgres"], "PostgreSQL", "Database"),
            (["mongodb", "mongo "], "MongoDB", "Database"),
            (["elasticsearch", "\"cluster_name\""], "Elasticsearch", "Database"),
            (["couchdb"], "CouchDB", "Database"),
            (["redis", "-redis"], "Redis", "Cache / Queue"),
            (["memcached"], "Memcached", "Cache / Queue"),
            (["rabbitmq", "amqp"], "RabbitMQ", "Cache / Queue"),
            (["kafka"], "Kafka", "Cache / Queue"),
            (["ssh-2.0", "ssh-1.", "openssh"], "SSH", "Remote / Admin"),
            (["ftpd", "220 ftp", "vsftpd", "proftpd", "pure-ftpd"], "FTP", "Remote / Admin"),
            (["esmtp", "smtp"], "SMTP", "Mail"),
            (["imap"], "IMAP", "Mail"),
            (["pop3", "+ok"], "POP3", "Mail"),
            (["rfb 00", "vnc"], "VNC", "Remote / Admin"),
            (["docker"], "Docker", "Infrastructure"),
        ]
        for (needles, name, role) in rules where needles.contains(where: { hay.contains($0) }) {
            return (name, role)
        }
        let name = PortCatalog.service(for: op.port)?.name
            ?? (op.service.isEmpty || op.service == "unknown" ? "Port \(op.port)" : op.service)
        return (name, portRole ?? "Other")
    }

    static func detectTech(_ r: HTTPResponse) -> [DetectedTech] {
        var out: [DetectedTech] = []
        func add(_ name: String, _ category: String, _ version: String? = nil) {
            if let i = out.firstIndex(where: { $0.name.lowercased() == name.lowercased() }) {
                if out[i].version == nil, let version, !version.isEmpty { out[i].version = version }
                return
            }
            out.append(DetectedTech(name: name, category: category, version: version))
        }

        let html = r.text
        let lower = html.lowercased()
        let server = r.header("server")
        let powered = r.header("x-powered-by")
        let cookies = ((r.setCookieRaw ?? "") + " " + r.cookies.map { $0.name }.joined(separator: " ")).lowercased()

        if let server {
            let sl = server.lowercased()
            let ver = VersionChecks.idents(from: server).first?.version
            let table: [(String, [String])] = [
                ("nginx", ["nginx"]), ("Apache", ["apache", "httpd"]),
                ("Microsoft IIS", ["microsoft-iis", "iis"]), ("LiteSpeed", ["litespeed"]),
                ("OpenResty", ["openresty"]), ("Caddy", ["caddy"]),
                ("Apache Tomcat", ["tomcat", "coyote"]), ("Jetty", ["jetty"]),
                ("Envoy", ["envoy"]), ("Kestrel", ["kestrel"]), ("Gunicorn", ["gunicorn"]),
                ("Werkzeug", ["werkzeug"]), ("Phusion Passenger", ["passenger"]),
                ("Cowboy", ["cowboy"]), ("Google Frontend", ["gws", "gse", "google frontend"]),
                ("Amazon S3", ["amazons3"]),
            ]
            var matched = false
            for (name, needles) in table where needles.contains(where: { sl.contains($0) }) {
                add(name, "Web Server", ver); matched = true; break
            }
            if !matched { add(server.split(separator: " ").first.map(String.init) ?? server, "Web Server", ver) }
        }

        if let powered {
            let pl = powered.lowercased()
            if pl.contains("php") { add("PHP", "Language", VersionChecks.idents(from: powered).first { $0.product == "php" }?.version) }
            if pl.contains("asp.net") { add("ASP.NET", "Framework", r.header("x-aspnet-version")) }
            if pl.contains("express") { add("Express", "Framework") }
            if pl.contains("next.js") { add("Next.js", "Framework") }
            if pl.contains("servlet") { add("Java Servlet", "Framework") }
            if pl.contains("phusion") || pl.contains("passenger") { add("Ruby on Rails", "Framework") }
            if pl.contains("plesk") { add("Plesk", "Hosting Panel") }
        }
        if let asp = r.header("x-aspnet-version") { add("ASP.NET", "Framework", asp) }
        if r.header("x-drupal-cache") != nil || r.header("x-drupal-dynamic-cache") != nil { add("Drupal", "CMS") }
        if r.header("x-shopify-stage") != nil { add("Shopify", "E-commerce") }

        let cookieTable: [(String, String, String)] = [
            ("phpsessid", "PHP", "Language"), ("laravel_session", "Laravel", "Framework"),
            ("jsessionid", "Java", "Language"), (".aspnetcore", "ASP.NET Core", "Framework"),
            ("asp.net_sessionid", "ASP.NET", "Framework"), ("connect.sid", "Express", "Framework"),
            ("_rails", "Ruby on Rails", "Framework"), ("csrftoken", "Django", "Framework"),
            ("ci_session", "CodeIgniter", "Framework"), ("wordpress_", "WordPress", "CMS"),
            ("wp-settings", "WordPress", "CMS"), ("woocommerce_", "WooCommerce", "E-commerce"),
            ("prestashop", "PrestaShop", "E-commerce"), ("xf_session", "XenForo", "CMS"),
            ("fe_typo_user", "TYPO3", "CMS"),
        ]
        for (needle, name, cat) in cookieTable where cookies.contains(needle) { add(name, cat) }

        let htmlTable: [(String, String, [String])] = [
            ("WordPress", "CMS", ["/wp-content/", "/wp-includes/", "wp-json"]),
            ("Drupal", "CMS", ["drupal.settings", "/sites/default/files", "drupal-"]),
            ("Joomla", "CMS", ["/media/jui/", "option=com_", "joomla"]),
            ("Ghost", "CMS", ["content=\"ghost", "ghost-"]),
            ("TYPO3", "CMS", ["typo3"]), ("Webflow", "CMS", ["wf-page", "webflow.js", "webflow"]),
            ("Wix", "CMS", ["wixstatic", "_wix", "wix.com"]), ("Squarespace", "CMS", ["squarespace"]),
            ("Magento", "E-commerce", ["mage/", "magento", "/static/version"]),
            ("Shopify", "E-commerce", ["cdn.shopify.com", "shopify"]),
            ("WooCommerce", "E-commerce", ["woocommerce"]), ("BigCommerce", "E-commerce", ["bigcommerce"]),
            ("PrestaShop", "E-commerce", ["prestashop"]),
            ("React", "JS Framework", ["data-reactroot", "react.production", "__react"]),
            ("Next.js", "Framework", ["/_next/", "__next_data__", "__next"]),
            ("Vue.js", "JS Framework", ["data-v-", "vue.js", "__vue__"]),
            ("Nuxt", "Framework", ["/_nuxt/", "__nuxt"]),
            ("Angular", "JS Framework", ["ng-version", "ng-app", "_nghost"]),
            ("Svelte", "JS Framework", ["svelte-"]), ("Gatsby", "Framework", ["___gatsby", "gatsby-"]),
            ("Astro", "Framework", ["astro-island", "/_astro/"]),
            ("Ember.js", "JS Framework", ["ember-view", "ember.js"]),
            ("Alpine.js", "JS Library", ["x-data=", "alpinejs", "alpine.js"]),
            ("jQuery", "JS Library", ["jquery"]), ("Bootstrap", "UI Framework", ["bootstrap"]),
            ("Tailwind CSS", "UI Framework", ["tailwind"]),
            ("Font Awesome", "UI Library", ["font-awesome", "fontawesome"]),
            ("Google Analytics", "Analytics", ["google-analytics.com", "gtag(", "ga('create", "/gtag/js"]),
            ("Google Tag Manager", "Analytics", ["googletagmanager.com/gtm", "gtm.js"]),
            ("Facebook Pixel", "Analytics", ["connect.facebook.net", "fbq("]),
            ("Hotjar", "Analytics", ["static.hotjar.com", "hotjar"]),
            ("Segment", "Analytics", ["cdn.segment.com", "analytics.track"]),
            ("Matomo", "Analytics", ["matomo.js", "piwik.js"]), ("Plausible", "Analytics", ["plausible.io"]),
            ("HubSpot", "Marketing", ["hs-scripts.com", "js.hs-analytics"]),
            ("Cloudflare", "CDN", ["/cdn-cgi/"]), ("jsDelivr", "CDN", ["cdn.jsdelivr.net"]),
            ("cdnjs", "CDN", ["cdnjs.cloudflare.com"]), ("unpkg", "CDN", ["unpkg.com"]),
            ("reCAPTCHA", "Security", ["www.google.com/recaptcha", "grecaptcha"]),
            ("hCaptcha", "Security", ["hcaptcha.com"]),
            ("Cloudflare Turnstile", "Security", ["challenges.cloudflare.com"]),
        ]
        for (name, cat, markers) in htmlTable where markers.contains(where: { lower.contains($0) }) { add(name, cat) }

        if let gen = capture("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", html)
            ?? capture("<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator[\"']", html) {
            addGenerator(gen, add)
        }
        if let xg = r.header("x-generator") { addGenerator(xg, add) }

        return out
    }

    private static func addGenerator(_ gen: String, _ add: (String, String, String?) -> Void) {
        let version = firstVersion(in: gen)
        let g = gen.lowercased()
        let known: [(String, String, String)] = [
            ("wordpress", "WordPress", "CMS"), ("drupal", "Drupal", "CMS"), ("joomla", "Joomla", "CMS"),
            ("ghost", "Ghost", "CMS"), ("typo3", "TYPO3", "CMS"), ("wix", "Wix", "CMS"),
            ("squarespace", "Squarespace", "CMS"), ("hugo", "Hugo", "Static Site Generator"),
            ("jekyll", "Jekyll", "Static Site Generator"), ("gatsby", "Gatsby", "Framework"),
            ("hexo", "Hexo", "Static Site Generator"), ("next.js", "Next.js", "Framework"),
            ("shopify", "Shopify", "E-commerce"), ("elementor", "Elementor", "Page Builder"),
        ]
        for (needle, name, cat) in known where g.contains(needle) { add(name, cat, version); return }

        let name = gen.split(whereSeparator: { $0 == " " || $0.isNumber }).first.map(String.init) ?? gen
        add(snippet(name, max: 30), "Generator", version)
    }

    private static func firstVersion(in s: String) -> String? {

        guard let re = try? NSRegularExpression(pattern: "([0-9]+(?:\\.[0-9]+){0,3})") else { return nil }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return ns.substring(with: m.range(at: 1))
    }

    static func protocols(_ r: HTTPResponse) -> [String] {
        guard let alt = r.header("alt-svc")?.lowercased() else { return [] }
        var out: [String] = []
        if alt.contains("h3") { out.append("HTTP/3") }
        if alt.contains("h2") { out.append("HTTP/2") }
        return out
    }

    static func os(server: String?, powered: String?) -> String? {
        let hay = [server, powered].compactMap { $0 }.joined(separator: " ").lowercased()
        guard !hay.isEmpty else { return nil }
        let table: [(String, [String])] = [
            ("Ubuntu Linux",   ["ubuntu"]),
            ("Debian Linux",   ["debian"]),
            ("CentOS Linux",   ["centos"]),
            ("Red Hat Linux",  ["red hat", "redhat", "rhel"]),
            ("Fedora Linux",   ["fedora"]),
            ("Amazon Linux",   ["amzn", "amazon linux"]),
            ("FreeBSD",        ["freebsd"]),
            ("Windows Server", ["win32", "win64", "windows", "microsoft-iis"]),
            ("Unix",           ["unix"]),
        ]
        for (name, needles) in table where needles.contains(where: { hay.contains($0) }) { return name }
        return nil
    }

    private static func capture(_ pattern: String, _ text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let ns = text as NSString
        guard let m = re.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges > 1 else { return nil }
        return ns.substring(with: m.range(at: 1))
    }
}
