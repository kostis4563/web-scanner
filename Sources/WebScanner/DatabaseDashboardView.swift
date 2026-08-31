import SwiftUI
import AppKit

struct DatabaseDashboard: View {
    let report: DatabaseReport

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()
            tiles
            Divider()
            exposedSection
            Divider()
            checklist
            Divider()
            coverageNote
        }
        .padding(14)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(accent.opacity(0.30), lineWidth: 1))
    }

    private var accent: Color {
        switch report.posture {
        case .unknown:    return .secondary
        case .secured:    return .green
        case .exposed:    return .orange
        case .vulnerable: return .red
        }
    }

    private var postureIcon: String {
        switch report.posture {
        case .unknown:    return "questionmark.circle"
        case .secured:    return "checkmark.shield.fill"
        case .exposed:    return "lock.open.fill"
        case .vulnerable: return "exclamationmark.octagon.fill"
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            ZStack {
                Circle().fill(accent.opacity(0.14)).frame(width: 56, height: 56)
                Image(systemName: postureIcon)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(accent)
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text("DATABASE POSTURE").font(.caption2.bold()).foregroundStyle(.secondary)
                    Text(report.posture.label)
                        .font(.system(size: 9, weight: .bold))
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(accent.opacity(0.16))
                        .foregroundStyle(accent)
                        .clipShape(Capsule())
                }
                Text(report.host)
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
                Text(report.posture.blurb)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }

    private var tiles: some View {
        let cols = [GridItem(.adaptive(minimum: 150), spacing: 8)]
        return LazyVGrid(columns: cols, alignment: .leading, spacing: 8) {
            tile("dot.radiowaves.left.and.right", "Ports swept", "\(report.portsScanned)")
            tile("cylinder.split.1x2", "DB services reachable", "\(report.exposedServices.count)",
                 report.exposedServices.isEmpty ? .green : .orange)
            if report.unauthCount > 0 {
                tile("lock.open.fill", "Unauthenticated", "\(report.unauthCount)", .red)
            }
            if report.adminToolCount > 0 {
                tile("wrench.and.screwdriver.fill", "Admin tools", "\(report.adminToolCount)", .red)
            }
            if report.dumpCount > 0 {
                tile("arrow.down.doc.fill", "Exposed dumps", "\(report.dumpCount)", .red)
            }
            if report.credentialCount > 0 {
                tile("key.fill", "Leaked credentials", "\(report.credentialCount)", .red)
            }
            if report.injectionCount > 0 {
                tile("syringe.fill", "Injection", "\(report.injectionCount)", .red)
            }
            if report.errorDisclosure {
                tile("exclamationmark.bubble.fill", "Error leak", "yes", .orange)
            }
        }
    }

    private func tile(_ icon: String, _ label: String, _ value: String, _ color: Color = .secondary) -> some View {
        HStack(spacing: 9) {
            Image(systemName: icon).font(.system(size: 13)).foregroundStyle(color).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(label.uppercased()).font(.system(size: 8.5, weight: .bold)).foregroundStyle(.secondary)
                Text(value)
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1).minimumScaleFactor(0.7)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 7).padding(.horizontal, 9)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var exposedSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("REACHABLE DATA STORES").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                Text(report.exposedServices.isEmpty ? "none"
                     : "\(report.exposedServices.count) open")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
            }
            if report.exposedServices.isEmpty {
                Label("No database, cache, or queue port answered from the network.",
                      systemImage: "checkmark.circle.fill")
                    .font(.system(size: 10)).foregroundStyle(.green)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                FlowRow(spacing: 6, lineSpacing: 5) {
                    ForEach(report.exposedServices) { serviceChip($0) }
                }
            }
        }
    }

    private func serviceChip(_ s: DatabaseReport.ExposedDB) -> some View {
        let color: Color = s.unauthenticated ? .red
            : (s.risk == .critical || s.risk == .high ? .red : (s.risk == .medium ? .orange : .blue))
        return HStack(spacing: 5) {
            Text("\(s.port)").font(.system(size: 10.5, weight: .bold, design: .monospaced))
            Text(s.name).font(.system(size: 10))
            if let v = s.version, !v.isEmpty {
                Text(v).font(.system(size: 9)).foregroundStyle(color.opacity(0.75)).lineLimit(1)
            }
            if s.unauthenticated {
                Text("NO AUTH").font(.system(size: 8, weight: .heavy))
                    .padding(.horizontal, 4).padding(.vertical, 1)
                    .background(Color.red.opacity(0.22)).clipShape(Capsule())
            }
        }
        .foregroundStyle(color)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(color.opacity(0.14))
        .clipShape(Capsule())
        .help("\(s.name) on port \(s.port)\(s.unauthenticated ? " — answered without authentication" : "")")
    }

    private var checklist: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("HARDENING CHECKLIST").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                let action = report.recommendations.filter { $0.status == .actionNeeded }.count
                if action > 0 {
                    Text("\(action) need\(action == 1 ? "s" : "") attention")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.red)
                }
            }
            ForEach(report.recommendations) { rec in row(rec) }
        }
    }

    private func row(_ rec: DatabaseReport.Recommendation) -> some View {
        let (icon, color): (String, Color) = {
            switch rec.status {
            case .actionNeeded: return ("exclamationmark.triangle.fill", .red)
            case .review:       return ("circle", .blue)
            case .good:         return ("checkmark.circle.fill", .green)
            }
        }()
        return HStack(alignment: .top, spacing: 9) {
            Image(systemName: icon).font(.system(size: 12)).foregroundStyle(color)
                .frame(width: 16).padding(.top, 1)
            VStack(alignment: .leading, spacing: 2) {
                Text(rec.title).font(.system(size: 11.5, weight: .semibold))
                Text(rec.detail).font(.system(size: 10)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 5).padding(.horizontal, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(rec.status == .actionNeeded ? 0.08 : 0.04))
        .clipShape(RoundedRectangle(cornerRadius: 7))
    }

    private var coverageNote: some View {
        VStack(alignment: .leading, spacing: 5) {
            Label("SCAN COVERAGE", systemImage: "info.circle")
                .font(.caption2.bold()).foregroundStyle(.secondary)
            Text("This is a black-box scan from outside the host. A database bound to localhost or behind a firewall is invisible here - which is exactly what you want. If your database wasn't detected, the likely reasons are:")
                .font(.system(size: 10)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            bullet("It's properly firewalled / bound to localhost (the ideal outcome).")
            bullet("It listens on a non-standard port not in the default sweep — add it under EXTRA DB PORTS and rescan.")
            bullet("It requires credentials or TLS the scanner didn't present, so it refused the connection.")
            bullet("The host is fronted by a proxy/CDN, so the database lives on a different backend host.")
            Text("The checklist above applies either way — use it to confirm your setup is as locked-down as it looks.")
                .font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 2)
        }
    }

    private func bullet(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("•").font(.system(size: 10)).foregroundStyle(.tertiary)
            Text(text).font(.system(size: 10)).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
