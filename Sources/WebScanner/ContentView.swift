import SwiftUI
import AppKit

extension Severity {
    var color: Color {
        switch self {
        case .critical: return Color(red: 0.83, green: 0.14, blue: 0.16)
        case .high:     return Color(red: 0.90, green: 0.44, blue: 0.11)
        case .medium:   return Color(red: 0.82, green: 0.62, blue: 0.08)
        case .low:      return Color(red: 0.16, green: 0.48, blue: 0.83)
        case .info:     return Color.secondary
        }
    }
}

struct ContentView: View {
    @StateObject private var vm = ScannerViewModel()

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar()
            Divider()
            HSplitView {
                ControlPanel(vm: vm)
                    .frame(minWidth: 320, idealWidth: 360, maxWidth: 460)
                ResultsPanel(vm: vm)
                    .frame(minWidth: 460, maxWidth: .infinity)
            }
        }
        .frame(minWidth: 900, minHeight: 620)
    }
}

private struct HeaderBar: View {
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 1) {
                Text("Web Scanner")
                    .font(.system(size: 16, weight: .bold))
                Text("Find weaknesses, exploit paths, and fixes - plus exposed secrets")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Label("Authorized testing only", systemImage: "exclamationmark.triangle.fill")
                .font(.caption.weight(.medium))
                .foregroundStyle(.orange)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }
}

private struct ControlPanel: View {
    @ObservedObject var vm: ScannerViewModel

    private var canScan: Bool {
        vm.authorized && !vm.isScanning &&
        !vm.target.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {

                VStack(alignment: .leading, spacing: 6) {
                    Text("TARGET DOMAIN").font(.caption2.bold()).foregroundStyle(.secondary)
                    TextField("example.com", text: $vm.target)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                        .onSubmit { if canScan { vm.startScan() } }
                        .disabled(vm.isScanning)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("SCAN DEPTH").font(.caption2.bold()).foregroundStyle(.secondary)
                    Picker("", selection: $vm.intensity) {
                        ForEach(ScanIntensity.allCases) { level in
                            Text(level.label).tag(level)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .disabled(vm.isScanning)
                    Text(vm.intensity.blurb)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Toggle(isOn: $vm.authorized) {
                        Text("I am authorized to test this target")
                            .font(.callout)
                    }
                    Toggle(isOn: $vm.deepSecretScan) {
                        Text("Deep secret scan - all files (HTML, JS, CSS, JSON, configs, .env)")
                            .font(.callout)
                    }
                    .disabled(vm.isScanning)
                    Toggle(isOn: $vm.revealSecrets) {
                        Text("Reveal full secret values in findings")
                            .font(.callout)
                    }
                    .disabled(vm.isScanning)
                    if vm.revealSecrets {
                        Label("Reports & exports will contain plaintext passwords/tokens. Handle securely.",
                              systemImage: "eye.trianglebadge.exclamationmark")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Button(action: { vm.startScan() }) {
                    HStack {
                        if vm.isScanning {
                            ProgressView().controlSize(.small)
                            Text("Scanning...")
                        } else {
                            Image(systemName: "magnifyingglass")
                            Text("Scan")
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                .disabled(!canScan)

                if vm.isScanning || vm.progress > 0 {
                    VStack(alignment: .leading, spacing: 4) {
                        ProgressView(value: vm.progress)
                        Text(vm.statusText).font(.caption).foregroundStyle(.secondary)
                    }
                }

                Divider()

                SummaryView(vm: vm)

                if vm.report != nil {
                    HStack {
                        Button {
                            if let r = vm.report {
                                save(ReportExporter.markdown(r), name: "scan-report.md")
                            }
                        } label: { Label("Markdown", systemImage: "doc.text") }
                        Button {
                            if let r = vm.report {
                                save(ReportExporter.json(r), name: "scan-report.json")
                            }
                        } label: { Label("JSON", systemImage: "curlybraces") }
                    }
                    .controlSize(.small)
                }

                Divider()

                VStack(alignment: .leading, spacing: 6) {
                    Text("CONSOLE").font(.caption2.bold()).foregroundStyle(.secondary)
                    ScrollViewReader { proxy in
                        ScrollView {
                            VStack(alignment: .leading, spacing: 2) {
                                ForEach(Array(vm.logLines.enumerated()), id: \.offset) { idx, line in
                                    Text(line)
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .id(idx)
                                }
                            }
                            .padding(8)
                        }
                        .frame(height: 150)
                        .background(Color(NSColor.textBackgroundColor))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
                        .onChange(of: vm.logLines.count) { _ in
                            if let last = vm.logLines.indices.last {
                                withAnimation { proxy.scrollTo(last, anchor: .bottom) }
                            }
                        }
                    }
                }

                Spacer(minLength: 0)
            }
            .padding(16)
        }
        .background(Color(NSColor.windowBackgroundColor))
    }

    private func save(_ text: String, name: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        if panel.runModal() == .OK, let url = panel.url {
            try? text.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}

private struct SummaryView: View {
    @ObservedObject var vm: ScannerViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("RESULTS").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                if let r = vm.report {
                    Text("Grade \(r.grade)")
                        .font(.caption.bold())
                        .padding(.horizontal, 8).padding(.vertical, 2)
                        .background(gradeColor(r.grade).opacity(0.18))
                        .foregroundStyle(gradeColor(r.grade))
                        .clipShape(Capsule())
                }
            }
            let c = vm.counts
            HStack(spacing: 6) {
                ForEach(Severity.allCases, id: \.self) { sev in
                    VStack(spacing: 2) {
                        Text("\(c[sev] ?? 0)").font(.headline).foregroundStyle(sev.color)
                        Text(sev.label).font(.system(size: 9)).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .background(sev.color.opacity(0.10))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }
        }
    }

    private func gradeColor(_ g: String) -> Color {
        switch g.first {
        case "A": return .green
        case "B": return .blue
        case "C": return .yellow
        case "D": return .orange
        default:  return .red
        }
    }
}

private struct ResultsPanel: View {
    @ObservedObject var vm: ScannerViewModel

    var body: some View {
        Group {
            if vm.findings.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 10) {
                        ForEach(vm.sortedFindings) { finding in
                            FindingCard(finding: finding)
                        }
                    }
                    .padding(16)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.underPageBackgroundColor))
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: vm.isScanning ? "magnifyingglass" : "checkmark.shield")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text(vm.isScanning ? "Scanning..." : "No findings yet")
                .font(.title3).foregroundStyle(.secondary)
            if !vm.isScanning {
                Text("Enter a domain, confirm authorization, and press Scan.")
                    .font(.callout).foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct FindingCard: View {
    let finding: Finding
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: finding.severity.symbol)
                        .foregroundStyle(finding.severity.color)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.title).font(.headline)
                        Text(finding.category).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(finding.severity.label.uppercased())
                        .font(.caption2.bold())
                        .padding(.horizontal, 7).padding(.vertical, 3)
                        .background(finding.severity.color.opacity(0.16))
                        .foregroundStyle(finding.severity.color)
                        .clipShape(Capsule())
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.caption).foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: 10) {
                    Divider().padding(.vertical, 4)
                    labeled("Location", finding.location, mono: true)
                    section("What it is", finding.detail)
                    section("Evidence", finding.evidence, mono: true)
                    section("How it could be exploited", finding.exploit, tint: .orange)
                    section("How to fix it", finding.remediation, tint: .green)
                    if let ref = finding.reference {
                        labeled("Reference", ref)
                    }
                }
                .padding(.top, 4)
            }
        }
        .padding(12)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(finding.severity.color.opacity(0.25), lineWidth: 1)
        )
    }

    private func section(_ title: String, _ body: String, mono: Bool = false, tint: Color = .secondary) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title.uppercased())
                .font(.caption2.bold())
                .foregroundStyle(tint == .secondary ? Color.secondary : tint)
            Text(body)
                .font(mono ? .system(size: 11, design: .monospaced) : .callout)
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func labeled(_ title: String, _ value: String, mono: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("\(title):").font(.caption2.bold()).foregroundStyle(.secondary)
            Text(value)
                .font(mono ? .system(size: 11, design: .monospaced) : .caption)
                .textSelection(.enabled)
                .foregroundStyle(.primary)
        }
    }
}
