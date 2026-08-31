import Foundation
import Darwin

enum HostRecon {

    static let category = "Host"

    struct HostProfile {
        var host: String
        var targetIsIP: Bool
        var v4: [String]
        var v6: [String]
        var reverse: String?
        var reverseConfirmed: Bool?
        var org: String?
        var asn: String?
        var geo: String?
        var addressType: String?
        var isHosting: Bool
        var provider: String?
        var cdn: String?
        var cdnIsWAF: Bool
        var dnsProvider: String?
        var mailProvider: String?
        var dnssec: Bool?
        var nsCount: Int
        var mxCount: Int
        var hasSPF: Bool?
        var hasDMARC: Bool?

        var primaryIP: String? { v4.first ?? v6.first }
    }

    static func profile(host: String, home: HTTPResponse?, http: HTTPClient,
                        lookupIPInfo: Bool = true, probeDirectIP: Bool = true,
                        enumerateDNS: Bool = true) async -> [Finding] {
        await inspect(host: host, home: home, http: http,
                      lookupIPInfo: lookupIPInfo, probeDirectIP: probeDirectIP,
                      enumerateDNS: enumerateDNS).findings
    }

    static func inspect(host: String, home: HTTPResponse?, http: HTTPClient,
                        lookupIPInfo: Bool = true, probeDirectIP: Bool = true,
                        enumerateDNS: Bool = true) async -> (profile: HostProfile, findings: [Finding]) {
        var out: [Finding] = []

        let targetIsIP = isIPLiteral(host)
        let (v4, v6) = targetIsIP ? (isIPv6(host) ? ([], [host]) : ([host], []))
                                  : await resolveAsync(host)
        let primary = v4.first ?? v6.first

        var reverse: String?
        var reverseConfirmed: Bool?
        if let ip = primary {
            reverse = await reverseDNSAsync(ip)
            if let r = reverse {
                let fwd = await resolveHost(r)
                reverseConfirmed = (fwd.v4 + fwd.v6).contains(ip)
            }
        }

        var info: IPInfo?
        if lookupIPInfo, let ip = primary, !isPrivateOrReserved(ip) {
            info = await ipInfo(for: ip, http: http)
        }

        let apex = registrableDomain(host)
        var dns: DNSResolver.Result?
        if enumerateDNS, !targetIsIP { dns = await DNSResolver.enumerate(apex: apex) }

        let cdn = home.flatMap { detectCDN($0) }

        let provider = detectProvider(info: info, reverse: reverse, home: home)

        out.append(profileFinding(host: host, v4: v4, v6: v6, reverse: reverse,
                                   reverseConfirmed: reverseConfirmed, info: info,
                                   provider: provider, cdn: cdn, dns: dns, targetIsIP: targetIsIP))

        if let dns, dns.responded {
            out.append(dnsRecordsFinding(apex: apex, dns: dns))
        }

        if let dns, dns.responded {
            out += emailSecurityFindings(apex: apex, dns: dns)
        }

        if let dns, dns.responded {
            out.append(emailAuthFinding(apex: apex, dns: dns))
        }

        if let dns, dns.caaAnswered, dns.caa.isEmpty, home?.finalURL.scheme == "https" || home == nil {
            out.append(caaFinding(apex: apex))
        }

        if enumerateDNS, let dns, !dns.ns.isEmpty,
           let f = await axfrFinding(apex: apex, ns: dns.ns) {
            out.append(f)
        }

        if let home {
            out.append(cdnFinding(host: host, cdn: cdn, info: info, home: home))
        }

        if let home, let stack = stackFinding(host: host, home: home) {
            out.append(stack)
        }

        if probeDirectIP, !targetIsIP, cdn == nil, let home,
           let ip = v4.first, !isPrivateOrReserved(ip),
           let f = await directIPFinding(host: host, ip: ip, home: home, http: http) {
            out.append(f)
        }

        if enumerateDNS, let home, let f = await securityTxtFinding(home: home, http: http) {
            out.append(f)
        }

        let profile = HostProfile(
            host: host, targetIsIP: targetIsIP,
            v4: v4, v6: v6, reverse: reverse, reverseConfirmed: reverseConfirmed,
            org: info?.bestOrg, asn: info?.asDisplay, geo: info?.geoDisplay,
            addressType: info?.addressType, isHosting: info?.isHosting ?? false,
            provider: provider?.name, cdn: cdn?.name, cdnIsWAF: cdn?.isWAF ?? false,
            dnsProvider: dns.flatMap { dnsProvider(ns: $0.ns) },
            mailProvider: dns.flatMap { mailProvider(mx: $0.mx) },
            dnssec: dns?.dnssec, nsCount: dns?.ns.count ?? 0, mxCount: dns?.mx.count ?? 0,
            hasSPF: dns.map { d in d.txt.contains { $0.lowercased().hasPrefix("v=spf1") } },
            hasDMARC: dns.map { d in d.dmarcTxt.contains { $0.lowercased().contains("v=dmarc1") } })
        return (profile, out)
    }

    private static func profileFinding(host: String, v4: [String], v6: [String],
                                       reverse: String?, reverseConfirmed: Bool?, info: IPInfo?,
                                       provider: Provider?, cdn: CDN?, dns: DNSResolver.Result?,
                                       targetIsIP: Bool) -> Finding {
        let primary = v4.first ?? v6.first ?? "unresolved"

        var lines: [String] = []
        lines.append("Host: \(host)")
        if !v4.isEmpty { lines.append("IPv4: \(v4.joined(separator: ", "))") }
        if !v6.isEmpty { lines.append("IPv6: \(v6.joined(separator: ", "))") }
        if let reverse {
            let fc = reverseConfirmed == true ? " (forward-confirmed)"
                   : reverseConfirmed == false ? " (NOT forward-confirmed)" : ""
            lines.append("Reverse DNS: \(reverse)\(fc)")
        }
        if let info {
            if let org = info.bestOrg { lines.append("Organization: \(org)") }
            if let asn = info.asDisplay { lines.append("ASN: \(asn)") }
            if let geo = info.geoDisplay { lines.append("Location: \(geo)") }
            lines.append("Address type: \(info.addressType)")
        }
        if let provider { lines.append("Hosting provider: \(provider.name)") }
        if let cdn { lines.append("Edge / CDN: \(cdn.name)") }
        if let dns {
            if let dnsProv = dnsProvider(ns: dns.ns) { lines.append("DNS provider: \(dnsProv)") }
            if let mailProv = mailProvider(mx: dns.mx) { lines.append("Mail provider: \(mailProv)") }
        }

        var summary = "The site resolves to \(primary)"
        if let provider { summary += ", hosted on \(provider.name)" }
        else if let org = info?.bestOrg { summary += ", hosted by \(org)" }
        if let geo = info?.geoDisplay { summary += " in \(geo)" }
        summary += "."
        if let info, info.isHosting { summary += " The address belongs to a hosting/datacenter network - a typical VPS or cloud server rather than a residential line." }
        if let cdn { summary += " Traffic is fronted by \(cdn.name)." }

        let multi = v4.count + v6.count > 1
        let exploit = "Infrastructure details are the first thing an attacker collects. The IP, ASN and hosting provider reveal where the server lives, which neighbouring hosts share the network, and which provider-specific weaknesses (metadata endpoints, default images, management ports) to try next. Reverse-DNS and cloud tenancy often leak the environment and internal naming conventions."
            + (multi ? "\n\nThe host publishes multiple A/AAAA records, which usually means DNS round-robin or a load balancer sits in front of several origins." : "")

        let evidence = lines.joined(separator: "\n")
            + (info?.source.map { "\n\nIntel source: \($0)" } ?? "")

        return Finding(
            title: "Host & infrastructure profile: \(host)",
            severity: .info,
            category: category,
            location: host,
            detail: summary,
            evidence: evidence,
            exploit: exploit,
            remediation: "This is expected reconnaissance information, not a flaw in itself. To reduce your footprint: front the origin with a CDN/WAF so the real server IP is never exposed, keep the origin's firewall/security-group locked to the CDN and trusted admins, and avoid leaking internal names via reverse DNS. Confirm any exposed management ports are intentional.",
            reference: "OWASP WSTG-INFO / CWE-200: Information Exposure",
            reproduction: primary == "unresolved"
                ? "dig +short \(host)"
                : "dig +short \(host) ; whois \(primary) | grep -iE 'orgname|netname|country|origin'")
    }

    private static func cdnFinding(host: String, cdn: CDN?, info: IPInfo?, home: HTTPResponse) -> Finding {
        let repro = "curl -sI \(home.finalURL.absoluteString) | grep -iE 'server|cf-ray|via|x-cache|x-cdn|x-served-by|x-amz-cf|x-akamai|x-sucuri|x-iinfo'"
        if let cdn {
            let waf = cdn.isWAF ? " and a web application firewall" : ""
            return Finding(
                title: "Edge protection detected: \(cdn.name)",
                severity: .info,
                category: category,
                location: host,
                detail: "Responses are served through \(cdn.name), so a content-delivery / reverse-proxy layer\(waf) sits in front of the origin.",
                evidence: cdn.evidence,
                exploit: "A CDN/WAF hides the origin IP and can filter attacks, which is good - but only while the origin itself is not reachable directly. If the real server IP leaks (old DNS records, SSL certificate transparency logs, email headers, an exposed subdomain), an attacker can connect straight to the origin and skip every protection this edge provides.",
                remediation: "Keep the origin firewalled so it only accepts traffic from the CDN/WAF provider's IP ranges. Rotate the origin IP if it has ever been public, and make sure no subdomain (mail, ftp, cpanel, dev) resolves directly to it.",
                reference: "CWE-693: Protection Mechanism Failure",
                reproduction: repro)
        }

        let datacenter = info?.isHosting == true
        return Finding(
            title: "No CDN or WAF in front of the origin",
            severity: datacenter ? .low : .info,
            category: category,
            location: host,
            detail: "No content-delivery network or web application firewall was detected in the response headers. The scanner appears to be talking to the origin server directly"
                + (datacenter ? ", which sits on a datacenter/VPS network." : "."),
            evidence: "Server: \(home.header("server") ?? "(not sent)")\nNo CDN/WAF signatures (cf-ray, x-amz-cf-id, x-akamai-*, x-sucuri-id, x-iinfo, via, x-cache) were present.",
            exploit: "Without an edge layer the origin IP is public and every request - including automated attacks, vulnerability scans and volumetric floods - reaches the application server unfiltered. There is no first line of defence to absorb DDoS traffic or block common exploit payloads.",
            remediation: "Consider placing the site behind a reputable CDN/WAF (Cloudflare, Fastly, CloudFront, Akamai, …) and restricting the origin firewall to that provider. At minimum, ensure host-based rate limiting and up-to-date patching, since the origin is directly exposed.",
            reference: "CWE-693: Protection Mechanism Failure",
            reproduction: repro)
    }

    private static func stackFinding(host: String, home: HTTPResponse) -> Finding? {
        let server = home.header("server")
        let powered = home.header("x-powered-by")
        let via = home.header("via")
        guard server != nil || powered != nil else { return nil }

        var parts: [String] = []
        if let server { parts.append("Server: \(server)") }
        if let powered { parts.append("X-Powered-By: \(powered)") }
        if let aspnet = home.header("x-aspnet-version") { parts.append("X-AspNet-Version: \(aspnet)") }
        if let gen = home.header("x-generator") { parts.append("X-Generator: \(gen)") }
        if let via { parts.append("Via: \(via)") }
        if let alt = home.header("alt-svc") {
            let l = alt.lowercased()
            var protos: [String] = []
            if l.contains("h3") { protos.append("HTTP/3 (QUIC)") }
            if l.contains("h2") { protos.append("HTTP/2") }
            if !protos.isEmpty { parts.append("Protocols (Alt-Svc): \(protos.joined(separator: ", "))") }
        }

        let os = fingerprintOS(server: server, powered: powered)
        var detail = "The host advertises its software stack in HTTP response headers."
        if let os { detail += " The operating system looks like \(os)." }

        return Finding(
            title: "Server technology stack" + (os.map { " (\($0))" } ?? ""),
            severity: .info,
            category: category,
            location: host,
            detail: detail,
            evidence: parts.joined(separator: "\n"),
            exploit: "Named software and versions let an attacker jump straight to matching CVEs and exploit code without any fingerprinting of their own. The OS family narrows down default paths, package versions and privilege-escalation techniques to try after an initial foothold.",
            remediation: "Suppress version and OS tokens: nginx `server_tokens off;`, Apache `ServerTokens Prod` / `ServerSignature Off`, remove `X-Powered-By` (PHP `expose_php Off`, Express `app.disable('x-powered-by')`), and strip `X-AspNet-Version`/`X-Generator` at the proxy.",
            reference: "CWE-200 / OWASP WSTG-INFO-02",
            reproduction: "curl -sI \(home.finalURL.absoluteString) | grep -iE 'server|x-powered-by|x-aspnet|x-generator|via'")
    }

    private static func dnsRecordsFinding(apex: String, dns: DNSResolver.Result) -> Finding {
        var lines: [String] = []
        if !dns.ns.isEmpty {
            lines.append("Nameservers:\n  " + dns.ns.sorted().joined(separator: "\n  "))
            if let p = dnsProvider(ns: dns.ns) { lines.append("DNS provider: \(p)") }
        }
        if !dns.mx.isEmpty {
            lines.append("Mail servers (MX):\n  " + dns.mx.map { "\($0.preference) \($0.host)" }.joined(separator: "\n  "))
            if let p = mailProvider(mx: dns.mx) { lines.append("Mail provider: \(p)") }
        } else {
            lines.append("Mail servers (MX): none")
        }
        if let soa = dns.soaPrimary {
            lines.append("SOA primary: \(soa)" + (dns.soaSerial.map { " (serial \($0))" } ?? ""))
        }
        if !dns.caa.isEmpty {
            lines.append("CAA (allowed CAs):\n  " + dns.caa.sorted().joined(separator: "\n  "))
        }
        lines.append("DNSSEC: \(dns.dnssec ? "signed (resolver-validated)" : "not detected")")

        let notableTXT = dns.txt.filter {
            let l = $0.lowercased()
            return l.hasPrefix("v=spf1") || l.contains("verification") || l.contains("-site-")
        }
        if !notableTXT.isEmpty {
            lines.append("Notable TXT:\n  " + notableTXT.prefix(8).map { snippet($0, max: 120) }.joined(separator: "\n  "))
        }

        var detail = "DNS zone records for \(apex)."
        if let p = dnsProvider(ns: dns.ns) { detail += " DNS is managed by \(p)." }
        if let p = mailProvider(mx: dns.mx) { detail += " Mail is handled by \(p)." }
        if !dns.dnssec { detail += " The zone is not DNSSEC-signed, so responses can be spoofed by an on-path attacker or poisoned resolver." }

        return Finding(
            title: "DNS records for \(apex)",
            severity: .info,
            category: category,
            location: apex,
            detail: detail,
            evidence: lines.joined(separator: "\n"),
            exploit: "Nameservers, mail servers and TXT records map out the target's providers and third-party services (SaaS verification tokens reveal which vendors are in use). Missing DNSSEC means DNS answers aren't cryptographically authenticated, enabling cache-poisoning / spoofing that can redirect users or issue fraudulent certificates.",
            remediation: "Review TXT records and remove stale verification tokens for services you no longer use (they reveal your vendor stack). Enable DNSSEC at your DNS provider and registrar to authenticate responses.",
            reference: "OWASP WSTG-INFO / CWE-350",
            reproduction: "dig +noall +answer \(apex) NS MX TXT CAA SOA ; dig +dnssec \(apex) SOA")
    }

    private static func emailSecurityFindings(apex: String, dns: DNSResolver.Result) -> [Finding] {
        var out: [Finding] = []
        let hasMail = !dns.mx.isEmpty
        let sevMissing: Severity = hasMail ? .medium : .low
        let spf = dns.txt.first { $0.lowercased().hasPrefix("v=spf1") }
        let dmarc = dns.dmarcTxt.first { $0.lowercased().contains("v=dmarc1") }

        if let spf {
            let l = spf.lowercased()
            let hardFail = l.contains("-all")
            let softFail = l.contains("~all")
            if !hardFail && !softFail {
                out.append(Finding(
                    title: "Weak SPF policy (does not restrict senders)",
                    severity: .low, category: category, location: apex,
                    detail: "The domain publishes an SPF record but its policy does not hard/soft-fail unlisted senders (missing `-all` / `~all`, or using `+all`/`?all`).",
                    evidence: "TXT: \(snippet(spf, max: 200))",
                    exploit: "Without a restrictive `all` mechanism, receivers won't reject mail from unauthorized servers, so attackers can spoof the domain in phishing while still nominally 'passing' SPF.",
                    remediation: "End the SPF record with `-all` (hard fail) once you've listed every legitimate sender. Use `~all` only during rollout.",
                    reference: "RFC 7208 / CWE-290",
                    reproduction: "dig +short \(apex) TXT | grep spf1"))
            }
        } else {
            out.append(Finding(
                title: "No SPF record" + (hasMail ? " (email spoofing possible)" : ""),
                severity: sevMissing, category: category, location: apex,
                detail: "No `v=spf1` TXT record was found for \(apex). SPF tells receiving servers which hosts may send mail as this domain.",
                evidence: "TXT records at \(apex): " + (dns.txt.isEmpty ? "none" : "\(dns.txt.count) present, none begins with v=spf1"),
                exploit: "Without SPF, anyone can send email with a forged From: \(apex) address and it will not fail SPF at the recipient, enabling convincing phishing and business-email-compromise against staff, customers and partners.",
                remediation: "Publish an SPF TXT record listing your legitimate mail senders and ending in `-all`, e.g. `v=spf1 include:_spf.google.com -all`.",
                reference: "RFC 7208 / CWE-290: Authentication Bypass by Spoofing",
                reproduction: "dig +short \(apex) TXT"))
        }

        if let dmarc {
            let policy = dmarcPolicy(dmarc)
            if policy == "none" {
                out.append(Finding(
                    title: "DMARC policy is p=none (monitoring only)",
                    severity: .low, category: category, location: apex,
                    detail: "A DMARC record exists but its policy is `p=none`, so failing mail is reported but never quarantined or rejected.",
                    evidence: "TXT _dmarc.\(apex): \(snippet(dmarc, max: 200))",
                    exploit: "With `p=none`, spoofed mail that fails SPF/DKIM is still delivered to inboxes; DMARC provides visibility but no active protection against domain impersonation.",
                    remediation: "After reviewing DMARC aggregate reports, tighten the policy to `p=quarantine` and then `p=reject` to actively block spoofed mail.",
                    reference: "RFC 7489",
                    reproduction: "dig +short _dmarc.\(apex) TXT"))
            }
        } else {
            out.append(Finding(
                title: "No DMARC record" + (hasMail ? " (email spoofing possible)" : ""),
                severity: sevMissing, category: category, location: apex,
                detail: "No `v=DMARC1` record was found at _dmarc.\(apex). DMARC ties SPF/DKIM together and tells receivers what to do with mail that fails.",
                evidence: "TXT _dmarc.\(apex): none",
                exploit: "Without DMARC, even a domain with SPF/DKIM can be impersonated via alignment gaps, and there is no policy telling receivers to reject forgeries - a primary enabler of phishing and CEO-fraud.",
                remediation: "Publish a DMARC record at _dmarc.\(apex), starting with `v=DMARC1; p=none; rua=mailto:...` to gather reports, then move to `p=quarantine`/`p=reject`.",
                reference: "RFC 7489 / CWE-290",
                reproduction: "dig +short _dmarc.\(apex) TXT"))
        }
        return out
    }

    private static func caaFinding(apex: String) -> Finding {
        Finding(
            title: "No CAA record (any CA may issue certificates)",
            severity: .info,
            category: category,
            location: apex,
            detail: "The domain \(apex) publishes no CAA record, so there is no DNS-level restriction on which certificate authorities may issue TLS certificates for it.",
            evidence: "CAA query for \(apex) returned no records.",
            exploit: "A CAA record is a safety net: it stops a mis-issued or attacker-obtained certificate from a CA you don't use. Without it, any public CA tricked into (or abused for) issuance can mint a valid certificate for your domain, aiding man-in-the-middle attacks.",
            remediation: "Add a CAA record naming only the CA(s) you use, e.g. `\(apex). IN CAA 0 issue \"letsencrypt.org\"`, plus an `iodef` mailto for violation reports.",
            reference: "RFC 8659 / CWE-295",
            reproduction: "dig +short \(apex) CAA")
    }

    private static func emailAuthFinding(apex: String, dns: DNSResolver.Result) -> Finding {
        let hasMail = !dns.mx.isEmpty
        let dkim = !dns.dkimSelectors.isEmpty
        let mtaSts = !dns.mtaSts.isEmpty
        let tlsRpt = !dns.tlsRpt.isEmpty
        let bimi = !dns.bimi.isEmpty

        func mark(_ ok: Bool) -> String { ok ? "present" : "not found" }
        let lines = [
            "DKIM (common selectors): " + (dkim ? "present [\(dns.dkimSelectors.joined(separator: ", "))]" : "none of the common selectors resolved"),
            "MTA-STS: \(mark(mtaSts))",
            "TLS-RPT: \(mark(tlsRpt))",
            "BIMI: \(mark(bimi))",
        ]

        var gaps: [String] = []
        if hasMail && !dkim { gaps.append("DKIM (no common selector found - it may use a custom one)") }
        if hasMail && !mtaSts { gaps.append("MTA-STS (SMTP is vulnerable to downgrade/interception)") }
        if hasMail && !tlsRpt { gaps.append("TLS-RPT (no reporting of SMTP TLS failures)") }

        let severity: Severity = (hasMail && !mtaSts) ? .low : .info
        var detail = "Modern email-authentication and SMTP-transport records for \(apex)."
        if !gaps.isEmpty { detail += " Missing/uncertain: " + gaps.joined(separator: "; ") + "." }
        else if hasMail { detail += " Good coverage of the optional hardening records." }

        return Finding(
            title: "Email authentication coverage (DKIM / MTA-STS / TLS-RPT / BIMI)",
            severity: severity,
            category: category,
            location: apex,
            detail: detail,
            evidence: lines.joined(separator: "\n"),
            exploit: "DKIM cryptographically signs outbound mail (DMARC needs it to enforce). MTA-STS forces receiving servers to use validated TLS, blocking STARTTLS-stripping man-in-the-middle downgrades; without it, a network attacker can read or alter mail in transit. TLS-RPT surfaces those failures. Gaps here weaken deliverability and let attackers spoof or intercept mail.",
            remediation: "Publish DKIM keys and sign all outbound mail; add an MTA-STS policy (`_mta-sts` TXT + a policy file at https://mta-sts.\(apex)/.well-known/mta-sts.txt) in enforce mode; add a TLS-RPT record for visibility. BIMI is optional brand polish once DMARC is at enforcement.",
            reference: "RFC 6376 (DKIM) / RFC 8461 (MTA-STS) / RFC 8460 (TLS-RPT)",
            reproduction: "dig +short _mta-sts.\(apex) TXT ; dig +short default._domainkey.\(apex) TXT")
    }

    private static func axfrFinding(apex: String, ns: [String]) async -> Finding? {
        let targets = Array(Set(ns)).prefix(4).map { $0 }
        let results = await withTaskGroup(of: (String, Bool, [String]).self) { group -> [(String, Bool, [String])] in
            for n in targets {
                group.addTask {
                    let r = await DNSResolver.attemptAXFR(zone: apex, nameserver: n)
                    return (n, r.allowed, r.sample)
                }
            }
            var acc: [(String, Bool, [String])] = []
            for await r in group { acc.append(r) }
            return acc
        }
        guard let hit = results.first(where: { $0.1 }) else { return nil }
        let (nsName, _, sample) = hit
        return Finding(
            title: "DNS zone transfer (AXFR) allowed",
            severity: .high,
            category: category,
            location: "\(nsName) (\(apex))",
            detail: "The nameserver \(nsName) allowed an unauthenticated full zone transfer (AXFR) of \(apex), handing over every DNS record in the zone.",
            evidence: "AXFR of \(apex) from \(nsName) succeeded. Sample records:\n  "
                + sample.prefix(12).joined(separator: "\n  "),
            exploit: "A zone transfer is a complete map of the target: every subdomain, mail server, internal host, staging/dev endpoint and service record in one request. Attackers use it to discover non-public assets (admin panels, VPNs, internal apps) that would otherwise take extensive brute-forcing to find.",
            remediation: "Restrict AXFR to authorized secondary nameservers only (`allow-transfer` in BIND, ACLs elsewhere) and use TSIG-authenticated transfers. Public/recursive resolvers and arbitrary clients must be refused.",
            reference: "CWE-200 / CVE-1999-0532 (unrestricted zone transfer)",
            reproduction: "dig AXFR \(apex) @\(nsName)")
    }

    private static func securityTxtFinding(home: HTTPResponse, http: HTTPClient) async -> Finding? {
        guard let origin = originURL(home.finalURL) else { return nil }
        for path in ["/.well-known/security.txt", "/security.txt"] {
            guard let u = URL(string: origin + path) else { continue }
            if let r = await http.fetch(u), r.status == 200,
               r.text.lowercased().contains("contact:") {
                return Finding(
                    title: "Security disclosure policy published (security.txt)",
                    severity: .info, category: category, location: u.absoluteString,
                    detail: "The host publishes a security.txt (RFC 9116) with vulnerability-disclosure contact details - a positive sign of security maturity.",
                    evidence: snippet(r.text, max: 240),
                    exploit: "Informational: this file is intended to be public. It tells researchers how to report issues; verify the contact/policy links are current.",
                    remediation: "No action needed. Keep the Contact, Expires and Policy fields up to date.",
                    reference: "RFC 9116",
                    reproduction: "curl -s \(u.absoluteString)")
            }
        }
        return nil
    }

    private static func dmarcPolicy(_ record: String) -> String {
        for part in record.lowercased().split(separator: ";") {
            let t = part.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("p=") { return String(t.dropFirst(2)) }
        }
        return "none"
    }

    private static func dnsProvider(ns: [String]) -> String? {
        let hay = ns.joined(separator: " ").lowercased()
        guard !hay.isEmpty else { return nil }
        let table: [(String, [String])] = [
            ("Cloudflare",       ["cloudflare"]),
            ("AWS Route 53",     ["awsdns"]),
            ("Google Cloud DNS", ["googledomains", "ns-cloud", "google.com"]),
            ("Azure DNS",        ["azure-dns"]),
            ("NS1",              ["nsone.net"]),
            ("DNSimple",         ["dnsimple"]),
            ("DigitalOcean",     ["digitalocean"]),
            ("GoDaddy",          ["domaincontrol.com"]),
            ("Namecheap",        ["registrar-servers.com"]),
            ("DNS Made Easy",    ["dnsmadeeasy"]),
            ("Akamai (Edge DNS)",["akam.net", "akamai"]),
            ("Dyn",              ["dynect"]),
        ]
        for (name, needles) in table where needles.contains(where: { hay.contains($0) }) { return name }
        return nil
    }

    private static func mailProvider(mx: [DNSResolver.MXRecord]) -> String? {
        let hay = mx.map { $0.host }.joined(separator: " ").lowercased()
        guard !hay.isEmpty else { return nil }
        let table: [(String, [String])] = [
            ("Google Workspace",  ["google.com", "googlemail.com", "aspmx"]),
            ("Microsoft 365",     ["protection.outlook.com", "mail.protection.outlook", "outlook.com"]),
            ("Proofpoint",        ["pphosted", "proofpoint"]),
            ("Mimecast",          ["mimecast"]),
            ("Zoho Mail",         ["zoho"]),
            ("Proton Mail",       ["protonmail", "proton.me"]),
            ("Amazon SES",        ["amazonses", "amazonaws"]),
            ("Mailgun",           ["mailgun"]),
            ("SendGrid",          ["sendgrid"]),
            ("Fastmail",          ["messagingengine", "fastmail"]),
            ("iCloud Mail",       ["icloud.com", "me.com"]),
            ("Barracuda",         ["barracudanetworks"]),
        ]
        for (name, needles) in table where needles.contains(where: { hay.contains($0) }) { return name }
        return nil
    }

    static func registrableDomain(_ host: String) -> String {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count > 2 else { return host }
        let twoLevel: Set<String> = [
            "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
            "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
            "co.za", "org.za", "co.jp", "or.jp", "ne.jp", "co.kr", "or.kr", "com.br",
            "com.cn", "net.cn", "org.cn", "gov.cn", "co.in", "net.in", "org.in", "com.mx",
            "com.tr", "com.sg", "com.hk", "com.tw", "com.ua", "com.pl", "com.ar",
        ]
        let lastTwo = labels.suffix(2).joined(separator: ".")
        if twoLevel.contains(lastTwo), labels.count >= 3 {
            return labels.suffix(3).joined(separator: ".")
        }
        return lastTwo
    }

    private static func originURL(_ url: URL) -> String? {
        guard let scheme = url.scheme, let host = url.host else { return nil }
        if let port = url.port { return "\(scheme)://\(host):\(port)" }
        return "\(scheme)://\(host)"
    }

    private static func directIPFinding(host: String, ip: String, home: HTTPResponse,
                                        http: HTTPClient) async -> Finding? {
        for scheme in ["https", "http"] {
            guard let u = URL(string: "\(scheme)://\(ip)/") else { continue }
            guard let r = await http.fetch(u), (200..<400).contains(r.status),
                  r.body.count > 200, resembles(r, home) else { continue }
            return Finding(
                title: "Origin application reachable directly by IP",
                severity: .low,
                category: category,
                location: "\(scheme)://\(ip)/",
                detail: "Requesting the origin's raw IP address (\(scheme)://\(ip)/) returns the same application as \(host). The server answers regardless of the Host header (no virtual-host or Host-allowlist enforcement).",
                evidence: "GET \(scheme)://\(ip)/ → HTTP \(r.status), \(r.body.count) bytes; content matches the site served at \(host).",
                exploit: "An origin that responds to its bare IP can be reached without knowing the domain, so domain-scoped protections are bypassable: security scanners, brute-forcers and (where a CDN/WAF fronts the domain) attackers who discover the origin IP can hit the application directly, skipping edge filtering and rate limits.",
                remediation: "Configure the web server to only serve known Host headers (nginx: a catch-all `default_server` returning 444; Apache: a default VirtualHost that denies). Firewall the origin so it only accepts traffic from your CDN/WAF or trusted admin IPs.",
                reference: "CWE-284: Improper Access Control",
                reproduction: "curl -sk -H 'Host: \(host)' \(scheme)://\(ip)/ -o /dev/null -w '%{http_code}\\n'")
        }
        return nil
    }

    private static func resembles(_ a: HTTPResponse, _ b: HTTPResponse) -> Bool {
        let ta = HTMLHelpers.title(from: a.text)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let tb = HTMLHelpers.title(from: b.text)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let ta, let tb, !ta.isEmpty, ta == tb { return true }
        let la = a.body.count, lb = b.body.count
        return lb > 0 && abs(la - lb) <= max(256, lb / 20)
    }

    struct CDN { let name: String; let isWAF: Bool; let evidence: String }

    private static func detectCDN(_ r: HTTPResponse) -> CDN? {
        func h(_ n: String) -> String? { r.header(n) }
        let server = (h("server") ?? "").lowercased()
        let via = (h("via") ?? "").lowercased()
        let setCookie = (r.setCookieRaw ?? "").lowercased()

        let signatures: [(String, Bool, Bool, String)] = [
            ("Cloudflare", true, h("cf-ray") != nil || server.contains("cloudflare"),
             "cf-ray: \(h("cf-ray") ?? "-"), server: \(h("server") ?? "-")"),
            ("AWS CloudFront", false, h("x-amz-cf-id") != nil || via.contains("cloudfront") || server.contains("cloudfront"),
             "x-amz-cf-id: \(h("x-amz-cf-id") ?? "-"), via: \(h("via") ?? "-")"),
            ("Fastly", false, h("x-served-by")?.lowercased().contains("cache-") == true || h("x-fastly-request-id") != nil || via.contains("varnish") && h("x-served-by") != nil,
             "x-served-by: \(h("x-served-by") ?? "-"), x-cache: \(h("x-cache") ?? "-")"),
            ("Akamai", true, h("x-akamai-transformed") != nil || server.contains("akamaighost") || h("x-akamai-request-id") != nil,
             "server: \(h("server") ?? "-"), x-akamai-*: present"),
            ("Sucuri", true, h("x-sucuri-id") != nil || server.contains("sucuri"),
             "x-sucuri-id: \(h("x-sucuri-id") ?? "-"), x-sucuri-cache: \(h("x-sucuri-cache") ?? "-")"),
            ("Imperva Incapsula", true, h("x-iinfo") != nil || h("x-cdn")?.lowercased().contains("incapsula") == true || setCookie.contains("incap_ses") || setCookie.contains("visid_incap"),
             "x-iinfo: \(h("x-iinfo") ?? "-"), x-cdn: \(h("x-cdn") ?? "-")"),
            ("Microsoft Azure", false, h("x-azure-ref") != nil || h("x-msedge-ref") != nil || server.contains("azure"),
             "x-azure-ref / x-msedge-ref present, server: \(h("server") ?? "-")"),
            ("Google", false, server == "gws" || via.contains("google") || h("x-goog-generation") != nil,
             "server: \(h("server") ?? "-"), via: \(h("via") ?? "-")"),
            ("StackPath / MaxCDN", false, server.contains("netdna") || server.contains("stackpath"),
             "server: \(h("server") ?? "-")"),
            ("BunnyCDN", false, server.contains("bunnycdn"),
             "server: \(h("server") ?? "-")"),
            ("KeyCDN", false, server.contains("keycdn"),
             "server: \(h("server") ?? "-")"),
            ("CDN77", false, server.contains("cdn77"),
             "server: \(h("server") ?? "-")"),
            ("Varnish cache", false, via.contains("varnish") || h("x-varnish") != nil,
             "x-varnish: \(h("x-varnish") ?? "-"), via: \(h("via") ?? "-")"),
            ("DDoS-Guard", true, server.contains("ddos-guard") || setCookie.contains("__ddg"),
             "server: \(h("server") ?? "-")"),
            ("Qrator", true, server.contains("qrator") || h("qrator-id") != nil,
             "server: \(h("server") ?? "-")"),
            ("Gcore", false, server.contains("gcore") || h("x-id") != nil && server.contains("gc"),
             "server: \(h("server") ?? "-")"),
            ("ArvanCloud", true, server.contains("arvan") || h("x-arvancloud") != nil,
             "server: \(h("server") ?? "-")"),
            ("Section.io", false, server.contains("section.io") || h("section-io-id") != nil,
             "server: \(h("server") ?? "-")"),
            ("Netlify", false, server.contains("netlify") || h("x-nf-request-id") != nil,
             "server: \(h("server") ?? "-")"),
            ("Vercel", false, h("x-vercel-id") != nil || server.contains("vercel"),
             "x-vercel-id: \(h("x-vercel-id") ?? "-")"),
        ]
        for (name, isWAF, matched, ev) in signatures where matched {
            return CDN(name: name, isWAF: isWAF, evidence: ev)
        }

        if h("x-cache") != nil || h("x-cdn") != nil || !via.isEmpty {
            return CDN(name: "Reverse proxy / cache (unbranded)", isWAF: false,
                       evidence: "via: \(h("via") ?? "-"), x-cache: \(h("x-cache") ?? "-"), x-cdn: \(h("x-cdn") ?? "-")")
        }
        return nil
    }

    struct Provider { let name: String }

    private static func detectProvider(info: IPInfo?, reverse: String?, home: HTTPResponse?) -> Provider? {
        let hay = [info?.org, info?.isp, info?.asname, info?.asField, reverse,
                   home?.header("server")]
            .compactMap { $0 }.joined(separator: " ").lowercased()
        guard !hay.isEmpty else { return nil }

        let table: [(String, [String])] = [
            ("Amazon AWS",        ["amazon", "aws", "amazonaws", "ec2"]),
            ("Google Cloud",      ["google", "googleusercontent", "gcp"]),
            ("Microsoft Azure",   ["microsoft", "azure"]),
            ("DigitalOcean",      ["digitalocean"]),
            ("Linode / Akamai",   ["linode"]),
            ("Hetzner",           ["hetzner", "your-server.de"]),
            ("OVH",               ["ovh"]),
            ("Vultr",             ["vultr", "choopa", "constant company"]),
            ("Contabo",           ["contabo"]),
            ("Scaleway / Online", ["scaleway", "online s.a.s", "online sas"]),
            ("Oracle Cloud",      ["oracle"]),
            ("Alibaba Cloud",     ["alibaba", "aliyun"]),
            ("Cloudflare",        ["cloudflare"]),
            ("Leaseweb",          ["leaseweb"]),
            ("GoDaddy",           ["godaddy", "secureserver"]),
            ("Namecheap",         ["namecheap"]),
            ("Hostinger",         ["hostinger"]),
            ("DreamHost",         ["dreamhost"]),
            ("IBM Cloud",         ["softlayer", "ibm cloud"]),
            ("Hostinger",         ["hostinger"]),
            ("Fly.io",            ["fly.io", "fly-", "fly.dev"]),
            ("Render",            ["render.com", "onrender"]),
            ("Heroku",            ["heroku"]),
            ("Netlify",           ["netlify"]),
            ("Vercel",            ["vercel"]),
            ("GitHub Pages",      ["github.io", "fastly-github", "github.com"]),
            ("Fastly",            ["fastly"]),
            ("Datacamp/Bunny",    ["datacamp", "bunny"]),
            ("Tencent Cloud",     ["tencent"]),
            ("G-Core Labs",       ["g-core", "gcore"]),
        ]
        for (name, needles) in table where needles.contains(where: { hay.contains($0) }) {
            return Provider(name: name)
        }
        return nil
    }

    private static func fingerprintOS(server: String?, powered: String?) -> String? {
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
        for (name, needles) in table where needles.contains(where: { hay.contains($0) }) {
            return name
        }
        return nil
    }

    struct IPInfo {
        var query: String?
        var org: String?
        var isp: String?
        var asField: String?
        var asname: String?
        var country: String?
        var region: String?
        var city: String?
        var reverse: String?
        var isHosting: Bool = false
        var isProxy: Bool = false
        var isMobile: Bool = false
        var source: String? = "ip-api.com"

        var bestOrg: String? {
            let o = (org?.isEmpty == false) ? org : nil
            return o ?? ((isp?.isEmpty == false) ? isp : nil)
        }
        var asDisplay: String? { (asField?.isEmpty == false) ? asField : asname }
        var geoDisplay: String? {
            let parts = [city, region, country].compactMap { $0 }.filter { !$0.isEmpty }
            return parts.isEmpty ? nil : parts.joined(separator: ", ")
        }
        var addressType: String {
            if isHosting { return "Hosting / datacenter (VPS or cloud server)" }
            if isMobile { return "Mobile carrier network" }
            if isProxy { return "Proxy / VPN / anonymizer" }
            return "ISP / residential or business network"
        }
    }

    private static func ipInfo(for ip: String, http: HTTPClient) async -> IPInfo? {
        let fields = "status,message,country,regionName,city,isp,org,as,asname,reverse,hosting,proxy,mobile,query"
        guard let url = URL(string: "http://ip-api.com/json/\(ip)?fields=\(fields)") else { return nil }
        guard let r = await http.fetch(url), r.status == 200,
              let obj = try? JSONSerialization.jsonObject(with: r.body) as? [String: Any],
              (obj["status"] as? String) == "success" else { return nil }
        func s(_ k: String) -> String? {
            let v = obj[k] as? String
            return (v?.isEmpty == false) ? v : nil
        }
        return IPInfo(
            query: s("query"),
            org: s("org"),
            isp: s("isp"),
            asField: s("as"),
            asname: s("asname"),
            country: s("country"),
            region: s("regionName"),
            city: s("city"),
            reverse: s("reverse"),
            isHosting: (obj["hosting"] as? Bool) ?? false,
            isProxy: (obj["proxy"] as? Bool) ?? false,
            isMobile: (obj["mobile"] as? Bool) ?? false)
    }

    static func resolveHost(_ host: String) async -> (v4: [String], v6: [String]) {
        if isIPLiteral(host) { return isIPv6(host) ? ([], [host]) : ([host], []) }
        return await resolveAsync(host)
    }

    private static func resolveAsync(_ host: String) async -> (v4: [String], v6: [String]) {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async { cont.resume(returning: resolve(host)) }
        }
    }

    private static func reverseDNSAsync(_ ip: String) async -> String? {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async { cont.resume(returning: reverseDNS(ip)) }
        }
    }

    private static func resolve(_ host: String) -> (v4: [String], v6: [String]) {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, result != nil else { return ([], []) }
        defer { freeaddrinfo(result) }

        var v4: [String] = [], v6: [String] = []
        var seen = Set<String>()
        var node = result
        while let n = node {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(n.pointee.ai_addr, n.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                           nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(cString: buf)
                if seen.insert(ip).inserted {
                    if n.pointee.ai_family == AF_INET { v4.append(ip) }
                    else if n.pointee.ai_family == AF_INET6 { v6.append(ip) }
                }
            }
            node = n.pointee.ai_next
        }
        return (v4, v6)
    }

    private static func reverseDNS(_ ip: String) -> String? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_NUMERICHOST

        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(ip, nil, &hints, &result) == 0, let node = result else { return nil }
        defer { freeaddrinfo(result) }

        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(node.pointee.ai_addr, node.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                          nil, 0, NI_NAMEREQD) == 0 else { return nil }
        let name = String(cString: buf)
        return (name.isEmpty || name == ip) ? nil : name
    }

    private static func isIPv6(_ s: String) -> Bool { s.contains(":") }

    private static func isIPLiteral(_ s: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return s.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
    }

    static func isPrivateOrReserved(_ ip: String) -> Bool {
        if ip.contains(":") {
            let l = ip.lowercased()
            if l == "::1" || l == "::" { return true }
            return l.hasPrefix("fc") || l.hasPrefix("fd")
                || l.hasPrefix("fe8") || l.hasPrefix("fe9")
                || l.hasPrefix("fea") || l.hasPrefix("feb")
        }
        let p = ip.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4 else { return true }
        let (a, b) = (p[0], p[1])
        if a == 10 || a == 127 || a == 0 || a >= 224 { return true }
        if a == 172 && (16...31).contains(b) { return true }
        if a == 192 && b == 168 { return true }
        if a == 169 && b == 254 { return true }
        if a == 100 && (64...127).contains(b) { return true }
        return false
    }
}
