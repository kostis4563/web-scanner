import Foundation

enum SubdomainScan {

    static let candidates: [String] = [

        "dev", "development", "staging", "stage", "test", "testing", "uat", "qa",
        "sandbox", "demo", "preview", "beta", "alpha", "internal", "intranet",
        "admin", "administrator", "adminpanel", "backoffice", "portal", "dashboard",
        "api", "api-dev", "dev-api", "api-staging", "staging-api", "api-test",
        "apis", "graphql", "rest", "gateway", "private", "corp", "secure",

        "git", "gitlab", "gitea", "jenkins", "ci", "cd", "drone", "argocd",
        "grafana", "kibana", "prometheus", "status", "monitor", "monitoring",
        "metrics", "logs", "log", "jira", "confluence", "wiki", "docs", "doc",
        "help", "support", "kb", "registry", "docker", "harbor", "nexus", "vault",
        "k8s", "kube", "rancher", "consul", "traefik", "airflow", "superset",

        "app", "apps", "my", "account", "accounts", "auth", "sso", "login",
        "client", "clients", "customer", "partners", "partner", "vendor",
        "shop", "store", "checkout", "pay", "billing", "invoice",
        "mobile", "m", "web", "www2", "static", "assets", "cdn", "media",
        "img", "images", "files", "download", "downloads", "uploads", "share",
        "blog", "news", "newsletter", "email", "mail", "webmail", "smtp",

        "old", "legacy", "new", "v1", "v2", "v3", "beta2", "next", "canary",
        "prod", "production", "live", "public", "edge", "origin",

        "db", "database", "mysql", "postgres", "redis", "mongo", "backup",
        "backups", "data", "storage", "s3", "ftp", "sftp", "vpn", "remote",
        "proxy", "ns1", "ns2", "mx", "autodiscover", "autoconfig",
    ]

    static func candidateHosts(base: String, limit: Int) -> [String] {
        candidates.prefix(limit).map { "\($0).\(base)" }
    }

    struct TakeoverSig {
        let service: String
        let needles: [String]
    }

    static let takeoverSignatures: [TakeoverSig] = [
        TakeoverSig(service: "GitHub Pages", needles: [
            "there isn't a github pages site here",
            "for root urls (like http://example.com/) you must provide an index.html file"]),
        TakeoverSig(service: "Amazon S3", needles: [
            "nosuchbucket", "the specified bucket does not exist"]),
        TakeoverSig(service: "Heroku", needles: [
            "herokucdn.com/error-pages/no-such-app.html"]),
        TakeoverSig(service: "Fastly", needles: [
            "fastly error: unknown domain"]),
        TakeoverSig(service: "Vercel", needles: [
            "deployment_not_found"]),
        TakeoverSig(service: "Netlify", needles: [
            "not found - request id"]),
        TakeoverSig(service: "Shopify", needles: [
            "sorry, this shop is currently unavailable"]),
        TakeoverSig(service: "Pantheon", needles: [
            "the gods are wise, but do not know of the site which you seek"]),
        TakeoverSig(service: "Tumblr", needles: [
            "whatever you were looking for doesn't currently exist at this address"]),
        TakeoverSig(service: "Ghost", needles: [
            "the thing you were looking for is no longer here"]),
        TakeoverSig(service: "Microsoft Azure App Service", needles: [
            "404 web site not found"]),
        TakeoverSig(service: "Read the Docs", needles: [
            "unknown to read the docs"]),
        TakeoverSig(service: "Zendesk", needles: [
            "help center closed"]),
        TakeoverSig(service: "Cargo", needles: [
            "if you're moving your domain away from cargo"]),
        TakeoverSig(service: "Agile CRM / Helpjuice / Getresponse", needles: [
            "with the url of your choice"]),
    ]

    static func takeoverService(body: String) -> String? {
        let l = body.prefix(20_000).lowercased()
        for sig in takeoverSignatures where sig.needles.contains(where: { l.contains($0) }) {
            return sig.service
        }
        return nil
    }

    static func discoveredFinding(host: String, subdomains: [String]) -> Finding {
        let list = subdomains.sorted().joined(separator: "\n")
        return Finding(
            title: "Additional subdomains discovered (\(subdomains.count))",
            severity: .info,
            category: "Attack Surface",
            location: host,
            detail: "Probing common subdomain names on \(host) found \(subdomains.count) additional live host(s). Forgotten dev/staging/internal subdomains often run older, less-hardened code and expand the attack surface.",
            evidence: "Live subdomains:\n\(list)",
            exploit: "Non-production and internal subdomains are frequently deployed without the hardening of the main site (missing auth, debug on, stale dependencies, exposed data) and are a common entry point. Each should be scanned in its own right.",
            remediation: "Inventory every public subdomain, take down ones that should not be internet-facing, and apply the same security controls (auth, headers, patching) you apply to the main site. Remove DNS records for decommissioned services.",
            reference: "CWE-668: Exposure of Resource to Wrong Sphere")
    }

    static func takeoverFinding(subdomain: String, service: String, response: HTTPResponse) -> Finding {
        Finding(
            title: "Possible subdomain takeover: \(subdomain) (\(service))",
            severity: .high,
            category: "Broken Access Control",
            location: response.finalURL.absoluteString,
            detail: "The subdomain \(subdomain) resolves and responds with a \(service) \"unclaimed resource\" page (HTTP \(response.status)). This is the classic signature of a dangling DNS record pointing at a \(service) resource that no longer exists - an attacker may be able to register it and serve content from your subdomain.",
            evidence: "URL: \(response.finalURL.absoluteString)\nService fingerprint: \(service)\nHTTP \(response.status)\nPreview: \(snippet(response.text, max: 180))",
            exploit: "If the \(service) resource behind this subdomain is unclaimed, an attacker registers it and controls \(subdomain) - hosting phishing on your trusted domain, stealing domain-scoped cookies, bypassing CORS/CSP allow-lists, and passing SPF/domain checks. Verify the CNAME actually dangles before treating as confirmed.",
            remediation: "Remove the dangling DNS record immediately, or re-claim the resource on \(service). Audit all DNS records for CNAMEs pointing at decommissioned third-party services, and adopt a process that deletes DNS entries when a service is torn down.",
            reference: "CWE-350 / Subdomain Takeover")
    }
}
