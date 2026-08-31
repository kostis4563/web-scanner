import Foundation

struct DatabaseReport {
    var host: String
    var hostReachable: Bool
    var webReachable: Bool
    var portsScanned: Int

    var exposedServices: [ExposedDB]
    var unauthCount: Int
    var adminToolCount: Int
    var dumpCount: Int
    var credentialCount: Int
    var errorDisclosure: Bool
    var injectionCount: Int

    var posture: Posture
    var recommendations: [Recommendation]

    struct ExposedDB: Identifiable {
        var id: Int { port }
        var port: Int
        var name: String
        var version: String?
        var risk: Severity?
        var unauthenticated: Bool
    }

    struct Recommendation: Identifiable {
        enum Status { case actionNeeded, review, good }
        var id = UUID()
        var status: Status
        var title: String
        var detail: String
    }

    enum Posture {
        case unknown
        case secured
        case exposed
        case vulnerable

        var label: String {
            switch self {
            case .unknown:    return "Host unreachable"
            case .secured:    return "No database exposed"
            case .exposed:    return "Database reachable"
            case .vulnerable: return "Critical exposure"
            }
        }

        var blurb: String {
            switch self {
            case .unknown:
                return "The host did not respond on any scanned port. It may be down, fully firewalled, or blocking this scanner."
            case .secured:
                return "No database, cache, or admin surface was reachable from the outside. That's the goal for internet-facing hosts - your data stores appear to be bound to localhost or behind a firewall. Review the checklist below to keep it that way."
            case .exposed:
                return "A database/cache port (or a web admin tool) is reachable from the network. Even with authentication, an exposed data store is a constant brute-force and exploitation target. Restrict it to trusted networks."
            case .vulnerable:
                return "A database was reachable AND weakly protected - unauthenticated access, a leaked dump, or injection was confirmed. Treat this as urgent: assume the data is readable by anyone."
            }
        }
    }
}

extension DatabaseChecks {

    static func buildReport(host: String, hostReachable: Bool, webReachable: Bool,
                            summary: PortScanSummary, findings: [Finding]) -> DatabaseReport {
        let openDB = summary.ports.filter { $0.state == .open }
        func inCategory(_ c: String) -> [Finding] { findings.filter { $0.category == c } }

        let unauth     = inCategory("Exposed Database")
        let admin      = inCategory("Database Admin Tool")
        let dumps      = inCategory("Database File Exposure")
        let creds      = inCategory("Database Credential Exposure")
        let errs       = inCategory("Database Error Disclosure")
        let injection  = findings.filter { $0.category == "Injection" }

        var exposed: [DatabaseReport.ExposedDB] = openDB.map { op in
            let isUnauth = unauth.contains { $0.location.hasSuffix(":\(op.port)") }
            let v = [op.product, op.version].compactMap { $0 }
                .joined(separator: " ").trimmingCharacters(in: .whitespaces)
            return DatabaseReport.ExposedDB(
                port: op.port,
                name: PortCatalog.service(for: op.port)?.name
                    ?? (op.service == "unknown" ? "Port \(op.port)" : op.service),
                version: v.isEmpty ? nil : v,
                risk: op.risk,
                unauthenticated: isUnauth)
        }

        let shownPorts = Set(exposed.map { $0.port })
        for f in unauth {
            guard let port = Int(f.location.split(separator: ":").last.map(String.init) ?? ""),
                  !shownPorts.contains(port) else { continue }
            exposed.append(DatabaseReport.ExposedDB(
                port: port,
                name: PortCatalog.service(for: port)?.name ?? "Port \(port)",
                version: nil, risk: .critical, unauthenticated: true))
        }
        exposed.sort { $0.port < $1.port }

        let posture: DatabaseReport.Posture
        if !hostReachable {
            posture = .unknown
        } else if !unauth.isEmpty || !dumps.isEmpty || !creds.isEmpty || !injection.isEmpty {
            posture = .vulnerable
        } else if !exposed.isEmpty || !admin.isEmpty {
            posture = .exposed
        } else {
            posture = .secured
        }

        let recs = recommendations(exposedCount: exposed.count, unauth: unauth.count,
                                   admin: admin.count, dumps: dumps.count, creds: creds.count,
                                   errorDisclosure: !errs.isEmpty, injection: injection.count)

        return DatabaseReport(
            host: host, hostReachable: hostReachable, webReachable: webReachable,
            portsScanned: summary.scanned, exposedServices: exposed,
            unauthCount: unauth.count, adminToolCount: admin.count,
            dumpCount: dumps.count, credentialCount: creds.count, errorDisclosure: !errs.isEmpty,
            injectionCount: injection.count, posture: posture, recommendations: recs)
    }

    private static func recommendations(exposedCount: Int, unauth: Int, admin: Int,
                                        dumps: Int, creds: Int, errorDisclosure: Bool,
                                        injection: Int) -> [DatabaseReport.Recommendation] {
        typealias R = DatabaseReport.Recommendation
        var out: [R] = []

        if exposedCount > 0 {
            out.append(R(status: .actionNeeded, title: "Take the database off the public network",
                         detail: "\(exposedCount) database/cache port(s) answered from the internet. Bind the service to 127.0.0.1 or a private interface (e.g. MySQL bind-address, PostgreSQL listen_addresses, Redis bind/protected-mode) and put a firewall / security group in front that only allows trusted hosts."))
        } else {
            out.append(R(status: .good, title: "Database not reachable from the network",
                         detail: "No database port responded externally. Keep binding data stores to localhost / a private network and never open their ports to 0.0.0.0."))
        }

        if unauth > 0 {
            out.append(R(status: .actionNeeded, title: "Require authentication - it's currently open",
                         detail: "A data store answered queries with no credentials. Enable authentication immediately, set a strong unique password (or ACLs/roles), and rotate anything that may have been exposed."))
        } else if exposedCount > 0 {
            out.append(R(status: .review, title: "Enforce strong, unique credentials",
                         detail: "Reachable DB ports must never rely on default or weak logins (root with empty password, postgres/postgres, neo4j/neo4j, admin/pass). Use long unique secrets from a password manager and disable unused default accounts."))
        } else {
            out.append(R(status: .review, title: "Require authentication with strong credentials",
                         detail: "Confirm every data store demands authentication, uses unique non-default credentials, and disables anonymous/guest access - even on internal networks (defense in depth)."))
        }

        out.append(R(status: .review, title: "Encrypt connections with TLS",
                     detail: "Require TLS for all client↔database traffic so credentials and data aren't sent in cleartext (MySQL require_secure_transport, PostgreSQL ssl=on + sslmode=verify-full, Redis TLS, MongoDB net.tls). Verify certificates, don't just enable them."))

        out.append(R(status: .review, title: "Use least-privilege database accounts",
                     detail: "Give each application its own account with only the rights it needs. Never let an app connect as root/superuser/admin, and scope grants per-database/schema so a single leaked credential can't touch everything."))

        if admin > 0 {
            out.append(R(status: .actionNeeded, title: "Remove or lock down web database admin tools",
                         detail: "A web admin tool (phpMyAdmin / Adminer / Mongo Express / …) is reachable. Delete it from production, or restrict it to a VPN / allow-listed IPs behind strong auth, and keep it patched - these are prime takeover targets."))
        } else {
            out.append(R(status: .review, title: "Keep web DB admin tools out of production",
                         detail: "Don't ship phpMyAdmin/Adminer/pgAdmin/Mongo Express on public hosts. If needed, bind them to localhost and reach them over an SSH tunnel or VPN."))
        }

        if dumps > 0 {
            out.append(R(status: .actionNeeded, title: "Get database dumps out of the web root",
                         detail: "A downloadable SQL dump / SQLite file was found - that's your whole dataset. Delete it from served directories now, block *.sql/*.sqlite*/*.db/*.bak/*.gz at the web server, and rotate any exposed secrets."))
        } else {
            out.append(R(status: .review, title: "Store backups outside the web root",
                         detail: "Keep dumps and DB files out of any served directory, block backup extensions at the server, and keep encrypted, access-controlled, regularly-tested backups off-host."))
        }

        if creds > 0 {
            out.append(R(status: .actionNeeded, title: "Rotate leaked database credentials now",
                         detail: "A config file (.env, wp-config backup, database.yml, application.properties, …) served the live database host, username and password. Delete it from the web root, block dotfiles/backup extensions at the server, and immediately rotate every exposed credential - assume it is already known to attackers."))
        } else {
            out.append(R(status: .review, title: "Keep credentials out of the web root",
                         detail: "Store .env / config files above the served directory, block dotfiles and backup extensions (.bak/.save/.old/~), and load database secrets from the environment or a secrets manager - never commit them where they can be fetched over HTTP."))
        }

        if injection > 0 {
            out.append(R(status: .actionNeeded, title: "Fix confirmed injection",
                         detail: "User input reaches a query unparameterized. Switch to parameterized queries / prepared statements (or an ORM with bound parameters), validate/allow-list any dynamic identifiers, and re-test with sqlmap."))
        } else {
            out.append(R(status: .review, title: "Prevent injection by construction",
                         detail: "Use parameterized queries / an ORM everywhere - never string-concatenate input into SQL or Mongo queries. Validate and allow-list input, and apply least-privilege so injection can't escalate."))
        }

        if errorDisclosure {
            out.append(R(status: .actionNeeded, title: "Stop leaking database errors",
                         detail: "Raw DB errors are shown to visitors, revealing the engine and schema. Turn off verbose/debug errors in production, return generic error pages, and log details server-side only."))
        } else {
            out.append(R(status: .review, title: "Return generic errors in production",
                         detail: "Ensure debug mode is off and database exceptions are caught and logged server-side rather than rendered to users."))
        }

        out.append(R(status: .review, title: "Keep the database engine patched",
                     detail: "Run a supported version and apply security updates promptly - many high-impact DB CVEs are remotely exploitable. Subscribe to your engine's security advisories."))

        out.append(R(status: .review, title: "Audit and monitor access",
                     detail: "Enable audit/connection logging, alert on failed-login spikes and access from unexpected sources, and periodically review who/what can reach the database."))

        return out
    }
}
