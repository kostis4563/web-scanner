import SwiftUI
import AppKit

struct PerformanceDashboard: View {
    let report: PerformanceReport

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            scoreHeader
            if hasTiming { Divider(); timingCard }
            Divider()
            transportTiles
            Divider()
            payloadCard
        }
        .padding(14)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(gradeColor.opacity(0.30), lineWidth: 1))
    }

    private var scoreHeader: some View {
        HStack(alignment: .center, spacing: 16) {
            ZStack {
                Circle().stroke(gradeColor.opacity(0.15), lineWidth: 8)
                Circle()
                    .trim(from: 0, to: max(0.001, CGFloat(report.score) / 100))
                    .stroke(gradeColor, style: StrokeStyle(lineWidth: 8, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                VStack(spacing: -1) {
                    Text("\(report.score)").font(.system(size: 25, weight: .bold, design: .rounded))
                    Text("/100").font(.system(size: 9)).foregroundStyle(.secondary)
                }
            }
            .frame(width: 74, height: 74)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text("PERFORMANCE").font(.caption2.bold()).foregroundStyle(.secondary)
                    Text("Grade \(report.grade)")
                        .font(.caption.bold())
                        .padding(.horizontal, 8).padding(.vertical, 2)
                        .background(gradeColor.opacity(0.18))
                        .foregroundStyle(gradeColor)
                        .clipShape(Capsule())
                }
                Text("TTFB \(PerformanceChecks.ms(report.ttfbBestMs)) · \(report.networkProtocol ?? "?")\(report.tlsVersion.map { " · \($0)" } ?? "")")
                    .font(.system(size: 12, weight: .semibold))
                Text(report.url)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
    }

    private var hasTiming: Bool { !timingSegments.isEmpty }

    private var timingSegments: [(name: String, ms: Double, color: Color)] {
        var out: [(String, Double, Color)] = []
        func seg(_ n: String, _ v: Double?, _ c: Color) { if let v, v > 0 { out.append((n, v, c)) } }
        seg("DNS", report.dnsMs, Color(red: 0.55, green: 0.35, blue: 0.85))
        seg("TCP", report.tcpMs, Color(red: 0.16, green: 0.48, blue: 0.83))
        seg("TLS", report.tlsMs, Color(red: 0.10, green: 0.60, blue: 0.62))
        seg("Server (TTFB)", report.ttfbColdMs ?? report.ttfbBestMs, Color(red: 0.90, green: 0.55, blue: 0.11))
        seg("Download", report.downloadMs, Color(red: 0.24, green: 0.62, blue: 0.34))
        return out
    }

    private var timingCard: some View {
        let segs = timingSegments
        let total = segs.reduce(0) { $0 + $1.ms }
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("COLD LOAD TIMELINE").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                Text(PerformanceChecks.ms(report.coldTotalMs ?? total))
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
            }
            GeometryReader { geo in
                HStack(spacing: 1) {
                    ForEach(Array(segs.enumerated()), id: \.offset) { _, s in
                        Rectangle()
                            .fill(s.color)
                            .frame(width: max(2, geo.size.width * CGFloat(s.ms / max(total, 0.001))))
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 4))
            }
            .frame(height: 14)

            FlowRow(spacing: 10, lineSpacing: 4) {
                ForEach(Array(segs.enumerated()), id: \.offset) { _, s in
                    HStack(spacing: 4) {
                        Circle().fill(s.color).frame(width: 7, height: 7)
                        Text("\(s.name) \(PerformanceChecks.ms(s.ms))")
                            .font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                }
            }
            if let warm = report.ttfbWarmMs, let cold = report.ttfbColdMs, warm < cold {
                Text("Warm connection reuse: TTFB \(PerformanceChecks.ms(cold)) → \(PerformanceChecks.ms(warm))")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
            }
        }
    }

    private var transportTiles: some View {
        let cols = [GridItem(.adaptive(minimum: 104), spacing: 8)]
        return LazyVGrid(columns: cols, alignment: .leading, spacing: 8) {
            tile("Protocol", report.networkProtocol ?? "—",
                 good: report.networkProtocol == "HTTP/2" || report.networkProtocol == "HTTP/3")
            tile("TLS", report.tlsVersion ?? "—", good: report.tlsVersion == "TLS 1.3")
            tile("HTTP/3", report.http3Available ? "Yes" : "No", good: report.http3Available)
            tile("Compression", report.htmlCompressed == true ? "On" : (report.htmlCompressed == false ? "Off" : "—"),
                 good: report.htmlCompressed == true, bad: report.htmlCompressed == false)
            tile("CDN / Edge", report.cdn ?? "None", good: report.cdn != nil, neutral: report.cdn == nil)
            tile("Requests", "\(report.requestCount)", good: report.requestCount <= 30, bad: report.requestCount > 80)
        }
    }

    private func tile(_ label: String, _ value: String, good: Bool = false, bad: Bool = false, neutral: Bool = false) -> some View {
        let color: Color = bad ? .orange : (good ? .green : .secondary)
        return VStack(alignment: .leading, spacing: 2) {
            Text(label.uppercased()).font(.system(size: 8.5, weight: .bold)).foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(neutral ? Color.secondary : color)
                .lineLimit(1).minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 6).padding(.horizontal, 8)
        .background((neutral ? Color.secondary : color).opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 7))
    }

    private var payloadCard: some View {
        let total = max(report.totalWireBytes, 1)
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("PAGE WEIGHT\(report.assetsTruncated ? " (SAMPLED)" : "")")
                    .font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                Text(PerformanceChecks.kb(report.totalWireBytes))
                    .font(.system(size: 12, weight: .bold, design: .rounded))
            }
            GeometryReader { geo in
                HStack(spacing: 1) {
                    ForEach(report.groups) { g in
                        Rectangle()
                            .fill(color(for: g.type))
                            .frame(width: max(1, geo.size.width * CGFloat(Double(g.wireBytes) / Double(total))))
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 4))
            }
            .frame(height: 12)

            FlowRow(spacing: 12, lineSpacing: 5) {
                ForEach(report.groups) { g in
                    HStack(spacing: 5) {
                        Image(systemName: g.type.symbol)
                            .font(.system(size: 9))
                            .foregroundStyle(color(for: g.type))
                        Text("\(g.type.label) \(g.count)× · \(PerformanceChecks.kb(g.wireBytes))")
                            .font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                }
            }

            if report.largest.count > 1 {
                Divider().padding(.vertical, 2)
                Text("LARGEST RESOURCES").font(.system(size: 8.5, weight: .bold)).foregroundStyle(.secondary)
                ForEach(Array(report.largest.prefix(4).enumerated()), id: \.offset) { _, r in
                    HStack(spacing: 6) {
                        Image(systemName: r.type.symbol).font(.system(size: 9)).foregroundStyle(color(for: r.type)).frame(width: 14)
                        Text(r.name).font(.system(size: 10, design: .monospaced))
                            .lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 6)
                        Text(PerformanceChecks.kb(r.wireBytes))
                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var gradeColor: Color {
        switch report.grade.first {
        case "A": return .green
        case "B": return .blue
        case "C": return Color(red: 0.82, green: 0.62, blue: 0.08)
        case "D": return .orange
        default:  return .red
        }
    }

    private func color(for t: ResourceType) -> Color {
        switch t {
        case .document:   return .secondary
        case .script:     return Color(red: 0.85, green: 0.65, blue: 0.13)
        case .stylesheet: return Color(red: 0.16, green: 0.48, blue: 0.83)
        case .image:      return Color(red: 0.24, green: 0.62, blue: 0.34)
        case .font:       return Color(red: 0.55, green: 0.35, blue: 0.85)
        case .media:      return Color(red: 0.86, green: 0.36, blue: 0.55)
        case .other:      return Color(red: 0.50, green: 0.50, blue: 0.55)
        }
    }
}

struct FlowRow: Layout {
    var spacing: CGFloat = 8
    var lineSpacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x > 0 && x + s.width > maxWidth {
                x = 0; y += rowHeight + lineSpacing; rowHeight = 0
            }
            x += s.width + spacing
            rowHeight = max(rowHeight, s.height)
        }
        return CGSize(width: maxWidth == .infinity ? x : maxWidth, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let maxWidth = bounds.width
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x > 0 && x + s.width > maxWidth {
                x = 0; y += rowHeight + lineSpacing; rowHeight = 0
            }
            v.place(at: CGPoint(x: bounds.minX + x, y: bounds.minY + y), proposal: ProposedViewSize(s))
            x += s.width + spacing
            rowHeight = max(rowHeight, s.height)
        }
    }
}
