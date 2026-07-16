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

extension DiscoveredURL.Kind {
    var color: Color {
        switch self {
        case .openDirectory, .mismatch: return Color(red: 0.90, green: 0.44, blue: 0.11)
        case .directory:                return Color(red: 0.16, green: 0.48, blue: 0.83)
        case .file, .defaultFile:       return Color(red: 0.24, green: 0.55, blue: 0.30)
        case .page:                     return Color.secondary
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
                    .frame(minWidth: 340, idealWidth: 380, maxWidth: 480)
                ResultsPanel(vm: vm)
                    .frame(minWidth: 460, maxWidth: .infinity)
            }
        }
        .frame(minWidth: 940, minHeight: 640)
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
                Text("Vulnerabilities, exposed secrets, and content discovery - with exploit paths and fixes")
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

    private var targetLabel: String {
        vm.mode == .urlMask ? "URL TEMPLATE" : "TARGET DOMAIN"
    }
    private var targetPlaceholder: String {
        vm.mode == .urlMask ? "https://[a-z]{1,3}.example.com" : "example.com"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {

                VStack(alignment: .leading, spacing: 6) {
                    Text("MODE").font(.caption2.bold()).foregroundStyle(.secondary)
                    Picker("", selection: $vm.mode) {
                        ForEach(ScanMode.allCases) { m in Text(m.label).tag(m) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .disabled(vm.isScanning)
                    Text(vm.mode.blurb)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text(targetLabel).font(.caption2.bold()).foregroundStyle(.secondary)
                    TextField(targetPlaceholder, text: $vm.target)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                        .onSubmit { if canScan { vm.startScan() } }
                        .disabled(vm.isScanning)
                    if vm.mode == .urlMask {
                        Text("Wildcards:  ?  one char   ·   *  grow   ·   [a-z]  range   ·   {n,m}  repeat   ·   (a,b,c)  choice   ·   $  dictionary word")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.tertiary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                if vm.mode == .siteScan {
                    ScanDepthView(vm: vm)
                }
                if vm.mode == .contentDiscovery {
                    ContentDiscoveryOptions(vm: vm)
                }
                if vm.mode == .urlMask {
                    URLMaskOptions(vm: vm)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Toggle(isOn: $vm.authorized) {
                        Text("I am authorized to test this target").font(.callout)
                    }
                    if vm.mode != .urlMask {
                        Toggle(isOn: $vm.deepSecretScan) {
                            Text(vm.mode == .siteScan
                                 ? "Deep secret scan - all files (HTML, JS, CSS, JSON, configs, .env)"
                                 : "Secret-scan discovered files")
                                .font(.callout)
                        }
                        .disabled(vm.isScanning)
                    }
                    Toggle(isOn: $vm.revealSecrets) {
                        Text("Reveal full secret values in findings").font(.callout)
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

                RequestOptionsView(vm: vm)

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
                ExportRow(vm: vm)
                Divider()
                ConsoleView(vm: vm)
                Spacer(minLength: 0)
            }
            .padding(16)
        }
        .background(Color(NSColor.windowBackgroundColor))
    }
}

// MARK: - Mode-specific option views

private struct ScanDepthView: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("SCAN DEPTH").font(.caption2.bold()).foregroundStyle(.secondary)
            Picker("", selection: $vm.intensity) {
                ForEach(ScanIntensity.allCases) { level in Text(level.label).tag(level) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(vm.isScanning)
            Text(vm.intensity.blurb)
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct ContentDiscoveryOptions: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            WordlistInput(vm: vm)
            LabeledField(label: "EXTENSIONS (-X)", placeholder: "php,bak,old,~", text: $vm.extensionsText, disabled: vm.isScanning)
            HStack(spacing: 14) {
                Toggle("Discover directories (-s)", isOn: $vm.scanDirectories).disabled(vm.isScanning)
                Toggle("Recursive (-r)", isOn: $vm.recursive).disabled(vm.isScanning)
            }
            .font(.caption)
            HStack {
                Text("MAX REQUESTS").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                TextField("", value: $vm.maxRequests, format: .number)
                    .textFieldStyle(.roundedBorder).frame(width: 90).disabled(vm.isScanning)
            }
        }
    }
}

private struct URLMaskOptions: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if vm.target.contains("$") { WordlistInput(vm: vm) }
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("MAX LENGTH (*)").font(.caption2.bold()).foregroundStyle(.secondary)
                    TextField("", value: $vm.maskMaxLength, format: .number)
                        .textFieldStyle(.roundedBorder).disabled(vm.isScanning)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("MAX URLS").font(.caption2.bold()).foregroundStyle(.secondary)
                    TextField("", value: $vm.maskLimit, format: .number)
                        .textFieldStyle(.roundedBorder).disabled(vm.isScanning)
                }
            }
        }
    }
}

private struct WordlistInput: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("WORDLIST").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                Button("Choose file…") { chooseFile() }
                    .controlSize(.small).disabled(vm.isScanning)
            }
            TextField("file path or https://… (comma-separated), blank = built-in list",
                      text: $vm.wordlistSource)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 11, design: .monospaced))
                .disabled(vm.isScanning)
            Text("Or paste words (one per line):").font(.caption2).foregroundStyle(.tertiary)
            TextEditor(text: $vm.wordlistText)
                .font(.system(size: 11, design: .monospaced))
                .frame(height: 60)
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
                .disabled(vm.isScanning)
        }
    }

    private func chooseFile() {
        let p = NSOpenPanel()
        p.canChooseFiles = true
        p.canChooseDirectories = false
        p.allowsMultipleSelection = false
        if p.runModal() == .OK, let url = p.url { vm.wordlistSource = url.path }
    }
}

private struct LabeledField: View {
    let label: String
    let placeholder: String
    @Binding var text: String
    var disabled: Bool = false
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption2.bold()).foregroundStyle(.secondary)
            TextField(placeholder, text: $text)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12, design: .monospaced))
                .disabled(disabled)
        }
    }
}

private struct RequestOptionsView: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("CUSTOM HEADERS (-H, one per line)").font(.caption2.bold()).foregroundStyle(.secondary)
                    TextEditor(text: $vm.customHeaders)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(height: 46)
                        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
                        .disabled(vm.isScanning)
                }
                LabeledField(label: "COOKIE (-c)", placeholder: "name=value; other=value", text: $vm.cookie, disabled: vm.isScanning)
                LabeledField(label: "BASIC AUTH (-u)", placeholder: "user:password", text: $vm.basicAuth, disabled: vm.isScanning)
                LabeledField(label: "USER-AGENT (-a)", placeholder: "custom user agent", text: $vm.userAgentOverride, disabled: vm.isScanning)
                HStack {
                    Text("DELAY ms (-z)").font(.caption2.bold()).foregroundStyle(.secondary)
                    Spacer()
                    TextField("", value: $vm.requestDelayMs, format: .number)
                        .textFieldStyle(.roundedBorder).frame(width: 80).disabled(vm.isScanning)
                }
                if vm.mode != .siteScan {
                    Divider()
                    HStack(spacing: 8) {
                        LabeledField(label: "IGNORE CODES (-N)", placeholder: "404,403", text: $vm.excludeCodesText, disabled: vm.isScanning)
                        LabeledField(label: "ONLY CODES (-S)", placeholder: "200,301", text: $vm.onlyCodesText, disabled: vm.isScanning)
                    }
                    LabeledField(label: "NOT IN TITLE (--not)", placeholder: "Not Found", text: $vm.notInTitle, disabled: vm.isScanning)
                }
            }
            .padding(.top, 6)
        } label: {
            Text("Advanced request options")
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
        }
    }
}

private struct ExportRow: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        if vm.report != nil || !vm.discovered.isEmpty {
            HStack {
                if vm.report != nil {
                    Button {
                        if let r = vm.report { save(ReportExporter.markdown(r), name: "scan-report.md") }
                    } label: { Label("Markdown", systemImage: "doc.text") }
                    Button {
                        if let r = vm.report { save(ReportExporter.json(r), name: "scan-report.json") }
                    } label: { Label("JSON", systemImage: "curlybraces") }
                }
                if !vm.discovered.isEmpty {
                    Button {
                        save(vm.discoveredText, name: "discovered-urls.txt")
                    } label: { Label("URLs", systemImage: "link") }
                }
            }
            .controlSize(.small)
        }
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

private struct ConsoleView: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
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
            if !vm.discovered.isEmpty {
                Text("\(vm.discovered.count) reachable URL(s) discovered")
                    .font(.caption2).foregroundStyle(.secondary)
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

// MARK: - Results panel

private struct ResultsPanel: View {
    @ObservedObject var vm: ScannerViewModel
    @State private var tab: Tab = .findings

    private enum Tab { case findings, discovered }

    var body: some View {
        VStack(spacing: 0) {
            if !vm.discovered.isEmpty {
                Picker("", selection: $tab) {
                    Text("Findings (\(vm.findings.count))").tag(Tab.findings)
                    Text("Discovered (\(vm.discovered.count))").tag(Tab.discovered)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.horizontal, 16)
                .padding(.top, 12)
            }
            Group {
                if tab == .discovered && !vm.discovered.isEmpty {
                    DiscoveredList(vm: vm)
                } else if vm.findings.isEmpty {
                    emptyState
                } else {
                    ScrollView {
                        LazyVStack(spacing: 10) {
                            ForEach(vm.sortedFindings) { finding in FindingCard(finding: finding) }
                        }
                        .padding(16)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.underPageBackgroundColor))
        .onChange(of: vm.discovered.isEmpty) { empty in if empty { tab = .findings } }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: vm.isScanning ? "magnifyingglass" : "checkmark.shield")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text(vm.isScanning ? "Scanning..." : "No findings yet")
                .font(.title3).foregroundStyle(.secondary)
            if !vm.isScanning {
                Text(hint).font(.callout).foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center).padding(.horizontal, 30)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var hint: String {
        switch vm.mode {
        case .siteScan:         return "Enter a domain, confirm authorization, and press Scan."
        case .contentDiscovery: return "Enter a domain and a wordlist (or use the built-in list) to brute-force paths."
        case .urlMask:          return "Enter a URL template with wildcards and press Scan to probe generated URLs."
        }
    }
}

private struct DiscoveredList: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(vm.discovered) { d in
                    DiscoveredRow(d: d)
                    Divider()
                }
            }
            .padding(.vertical, 4)
        }
    }
}

private struct DiscoveredRow: View {
    let d: DiscoveredURL
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text("\(d.status)")
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .foregroundStyle(statusColor)
                .frame(width: 34, alignment: .leading)
            Text(d.kind.label)
                .font(.system(size: 9, weight: .bold))
                .padding(.horizontal, 5).padding(.vertical, 2)
                .background(d.kind.color.opacity(0.16))
                .foregroundStyle(d.kind.color)
                .clipShape(Capsule())
                .frame(width: 74, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(d.url)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(d.notable ? .primary : .secondary)
                    .textSelection(.enabled)
                    .lineLimit(1).truncationMode(.middle)
                if let t = d.title, !t.isEmpty {
                    Text(t).font(.system(size: 10)).foregroundStyle(.tertiary).lineLimit(1)
                }
            }
            Spacer()
            Text("\(d.length) B").font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 14).padding(.vertical, 6)
        .background(d.notable ? d.kind.color.opacity(0.06) : Color.clear)
    }

    private var statusColor: Color {
        switch d.status {
        case 200..<300: return .green
        case 300..<400: return .blue
        case 400..<500: return .orange
        default:        return .red
        }
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
