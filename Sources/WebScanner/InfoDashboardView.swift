import SwiftUI
import AppKit

struct InfoDashboard: View {
    let report: InfoReport

    private var host: HostRecon.HostProfile? { report.host }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()
            tiles
            if !report.technologies.isEmpty {
                Divider(); technologies
            }
            if let h = host, dnsHasData(h) {
                Divider(); dnsPosture(h)
            }
            Divider(); servicesSection
        }
        .padding(14)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(accent.opacity(0.30), lineWidth: 1))
    }

    private var accent: Color { .blue }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            ZStack {
                Circle().fill(accent.opacity(0.14)).frame(width: 56, height: 56)
                Image(systemName: report.reachable ? "globe" : "globe.badge.chevron.backward")
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(accent)
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text("OVERVIEW").font(.caption2.bold()).foregroundStyle(.secondary)
                    statusChip
                    if report.https {
                        Label("HTTPS", systemImage: "lock.fill").labelStyle(.titleAndIcon)
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(.green)
                    } else if report.reachable {
                        Label("HTTP", systemImage: "lock.open.fill")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(.orange)
                    }
                }
                Text(report.title ?? (host?.host ?? report.url))
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1).truncationMode(.tail)
                Text(report.finalURL)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
        }
    }

    private var statusChip: some View {
        let text = report.reachable ? "HTTP \(report.status)" : "No web server"
        let color: Color = !report.reachable ? .secondary
            : (200..<400).contains(report.status) ? .green
            : (report.status < 500 ? .orange : .red)
        return Text(text)
            .font(.system(size: 9, weight: .bold))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(color.opacity(0.16))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    private var tiles: some View {
        let cols = [GridItem(.adaptive(minimum: 158), spacing: 8)]
        return LazyVGrid(columns: cols, alignment: .leading, spacing: 8) {
            if let ip = host?.primaryIP { tile("server.rack", "IP Address", ip, accent) }
            if let rev = host?.reverse { tile("arrow.uturn.left", "Reverse DNS", rev) }
            if let prov = host?.provider { tile("cloud", "Hosting", prov, accent) }
            else if let org = host?.org { tile("cloud", "Organization", org) }
            if let asn = host?.asn { tile("number", "ASN", asn) }
            if let geo = host?.geo { tile("mappin.and.ellipse", "Location", geo) }
            if let cdn = host?.cdn { tile(host!.cdnIsWAF ? "shield.lefthalf.filled" : "bolt.horizontal",
                                          host!.cdnIsWAF ? "CDN / WAF" : "CDN / Edge", cdn, .green) }
            if let server = report.server { tile("desktopcomputer", "Server", server) }
            if let os = report.os { tile("cpu", "OS", os) }
            if let dnsp = host?.dnsProvider { tile("network", "DNS Provider", dnsp) }
            if let mailp = host?.mailProvider { tile("envelope", "Mail Provider", mailp) }
            if !report.protocols.isEmpty { tile("arrow.left.arrow.right", "Protocols", report.protocols.joined(separator: ", "), accent) }
            if let ct = report.contentType { tile("doc.text", "Content-Type", ct) }
            if report.reachable { tile("scalemass", "Page size", PerformanceChecks.kb(report.htmlBytes)) }
            if report.cookieCount > 0 { tile("circle.grid.cross", "Cookies", "\(report.cookieCount) set") }
            if let addr = host?.addressType { tile("point.3.connected.trianglepath.dotted", "Network", addr) }
        }
    }

    private func tile(_ icon: String, _ label: String, _ value: String, _ color: Color = .secondary) -> some View {
        HStack(spacing: 9) {
            Image(systemName: icon).font(.system(size: 13)).foregroundStyle(color).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(label.uppercased()).font(.system(size: 8.5, weight: .bold)).foregroundStyle(.secondary)
                Text(value)
                    .font(.system(size: 12, weight: .semibold))
                    .lineLimit(1).minimumScaleFactor(0.7)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 7).padding(.horizontal, 9)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private static let techCategoryOrder = [
        "CMS", "E-commerce", "Framework", "Language", "Web Server", "JS Framework",
        "JS Library", "UI Framework", "UI Library", "Static Site Generator",
        "Page Builder", "Analytics", "Marketing", "CDN", "Security", "Hosting Panel",
        "Generator",
    ]

    private var techCategoriesPresent: [String] {
        let known = InfoDashboard.techCategoryOrder.filter { c in report.technologies.contains { $0.category == c } }
        let extra = report.technologies.map { $0.category }.filter { !InfoDashboard.techCategoryOrder.contains($0) }
        return known + Array(Set(extra)).sorted()
    }

    private var technologies: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("TECHNOLOGIES").font(.caption2.bold()).foregroundStyle(.secondary)
            ForEach(techCategoriesPresent, id: \.self) { cat in
                let items = report.technologies.filter { $0.category == cat }
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(cat.uppercased())
                        .font(.system(size: 8.5, weight: .bold)).foregroundStyle(.tertiary)
                        .frame(width: 76, alignment: .leading)
                    FlowRow(spacing: 6, lineSpacing: 5) {
                        ForEach(items) { techChip($0) }
                    }
                }
            }
        }
    }

    private func techChip(_ t: DetectedTech) -> some View {
        HStack(spacing: 4) {
            Text(t.name).font(.system(size: 10, weight: .medium))
            if let v = t.version, !v.isEmpty {
                Text(v).font(.system(size: 9, design: .monospaced)).foregroundStyle(accent.opacity(0.7))
            }
        }
        .foregroundStyle(accent)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(accent.opacity(0.12))
        .clipShape(Capsule())
    }

    private func dnsHasData(_ h: HostRecon.HostProfile) -> Bool {
        h.nsCount > 0 || h.mxCount > 0 || h.dnssec != nil || h.hasSPF != nil || h.hasDMARC != nil
    }

    private func dnsPosture(_ h: HostRecon.HostProfile) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("DNS & EMAIL").font(.caption2.bold()).foregroundStyle(.secondary)
            FlowRow(spacing: 8, lineSpacing: 6) {
                if h.nsCount > 0 { chip("\(h.nsCount) nameserver\(h.nsCount == 1 ? "" : "s")", .secondary, "network") }
                if h.mxCount > 0 { chip("\(h.mxCount) mail server\(h.mxCount == 1 ? "" : "s")", .secondary, "envelope") }
                if let d = h.dnssec { statusPill("DNSSEC", ok: d) }
                if let spf = h.hasSPF { statusPill("SPF", ok: spf) }
                if let dmarc = h.hasDMARC { statusPill("DMARC", ok: dmarc) }
            }
        }
    }

    private func chip(_ text: String, _ color: Color, _ icon: String) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon).font(.system(size: 9))
            Text(text).font(.system(size: 10))
        }
        .foregroundStyle(color)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(color.opacity(0.10))
        .clipShape(Capsule())
    }

    private func statusPill(_ label: String, ok: Bool) -> some View {
        HStack(spacing: 4) {
            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill").font(.system(size: 9))
            Text(label).font(.system(size: 10, weight: .medium))
        }
        .foregroundStyle(ok ? .green : .orange)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background((ok ? Color.green : Color.orange).opacity(0.12))
        .clipShape(Capsule())
    }

    private static let roleOrder = [
        "Web / Backend", "Database", "Cache / Queue", "Mail", "Remote / Admin",
        "Infrastructure", "Other",
    ]

    private var rolesPresent: [String] {
        InfoDashboard.roleOrder.filter { role in report.services.contains { $0.role == role } }
    }

    private var servicesSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("SERVICE PORTS").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                Text(report.services.isEmpty ? "none open"
                     : "\(report.services.count) port\(report.services.count == 1 ? "" : "s") open")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
            }
            if report.services.isEmpty {
                Text(report.reachable
                     ? "Only web ports responded — no database / backend / service ports are exposed."
                     : "No open service ports detected on this host.")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(rolesPresent, id: \.self) { role in
                    let items = report.services.filter { $0.role == role }
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(role.uppercased())
                            .font(.system(size: 8.5, weight: .bold)).foregroundStyle(.tertiary)
                            .frame(width: 76, alignment: .leading)
                        FlowRow(spacing: 6, lineSpacing: 5) {
                            ForEach(items) { serviceChip($0) }
                        }
                    }
                }
            }
        }
    }

    private func serviceChip(_ s: ServiceStatus) -> some View {
        let color = serviceColor(s)
        return HStack(spacing: 5) {
            Text("\(s.port)")
                .font(.system(size: 10.5, weight: .bold, design: .monospaced))
            Text(s.name).font(.system(size: 10))
            if let v = s.version, !v.isEmpty {
                Text(v).font(.system(size: 9)).foregroundStyle(color.opacity(0.75)).lineLimit(1)
            }
        }
        .foregroundStyle(color)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(color.opacity(0.14))
        .clipShape(Capsule())
        .help("\(s.name) runs on port \(s.port)\(s.version.map { " (\($0))" } ?? "")")
    }

    private func serviceColor(_ s: ServiceStatus) -> Color {
        switch s.risk {
        case .critical, .high: return .red
        case .medium:          return .orange
        case .low:             return .blue
        default:               return .green
        }
    }
}
