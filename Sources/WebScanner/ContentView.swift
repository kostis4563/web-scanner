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

extension OpenPort.State {
    var color: Color {
        switch self {
        case .open:     return Color(red: 0.24, green: 0.55, blue: 0.30)
        case .filtered: return Color(red: 0.90, green: 0.44, blue: 0.11)
        case .closed:   return Color.secondary
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
        switch vm.mode {
        case .urlMask:                                               return "URL TEMPLATE"
        case .fullAudit, .portScan, .database, .hostScan, .info, .performance: return "TARGET HOST"
        default:                                                     return "TARGET DOMAIN"
        }
    }
    private var targetPlaceholder: String {
        switch vm.mode {
        case .urlMask:                                               return "https://[a-z]{1,3}.example.com"
        case .fullAudit, .portScan, .database, .hostScan, .info, .performance: return "example.com or 93.184.216.34"
        default:                                                     return "example.com"
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {

                VStack(alignment: .leading, spacing: 6) {
                    Text("MODE").font(.caption2.bold()).foregroundStyle(.secondary)
                    ModeSelector(mode: $vm.mode, disabled: vm.isScanning)
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

                if vm.mode == .siteScan || vm.mode == .database || vm.mode == .userView {
                    ScanDepthView(vm: vm)
                }
                if vm.mode == .fullAudit {
                    Label("Runs at MAXIMUM depth and scans all 65,535 TCP ports. Expect 20-40+ minutes.",
                          systemImage: "gauge.high")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if vm.mode == .contentDiscovery {
                    ContentDiscoveryOptions(vm: vm)
                }
                if vm.mode == .urlMask {
                    URLMaskOptions(vm: vm)
                }
                if vm.mode == .portScan {
                    PortScanOptions(vm: vm)
                }
                if vm.mode == .database {
                    DatabaseOptions(vm: vm)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Toggle(isOn: $vm.authorized) {
                        Text("I am authorized to test this target").font(.callout)
                    }
                    if vm.mode == .siteScan || vm.mode == .contentDiscovery || vm.mode == .fullAudit {
                        Toggle(isOn: $vm.deepSecretScan) {
                            Text(vm.mode == .contentDiscovery
                                 ? "Secret-scan discovered files"
                                 : "Deep secret scan - all files (HTML, JS, CSS, JSON, configs, .env)")
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

                if vm.mode != .portScan {
                    RequestOptionsView(vm: vm)
                }

                HStack(spacing: 8) {
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

                    if vm.canStop {
                        Button(action: { vm.stopScan() }) {
                            Image(systemName: "stop.fill")
                            Text("Stop")
                        }
                        .controlSize(.large)
                    }
                }

                if vm.isScanning || vm.progress > 0 {
                    VStack(alignment: .leading, spacing: 4) {
                        ProgressView(value: vm.displayProgress)
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

private struct ModeSelector: View {
    @Binding var mode: ScanMode
    var disabled: Bool

    private let columns = [GridItem(.adaptive(minimum: 96), spacing: 6)]

    var body: some View {
        LazyVGrid(columns: columns, spacing: 6) {
            ForEach(ScanMode.allCases) { m in
                let selected = (m == mode)
                Button { mode = m } label: {
                    Text(m.label)
                        .font(.caption.weight(selected ? .semibold : .regular))
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 7)
                        .background(selected ? Color.accentColor : Color.secondary.opacity(0.12))
                        .foregroundStyle(selected ? Color.white : Color.primary)
                        .clipShape(RoundedRectangle(cornerRadius: 7))
                }
                .buttonStyle(.plain)
                .disabled(disabled)
            }
        }
    }
}

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

private struct PortScanOptions: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 6) {
                Text("PORT RANGE").font(.caption2.bold()).foregroundStyle(.secondary)
                Picker("", selection: $vm.portProfile) {
                    ForEach(PortProfile.allCases) { p in Text(p.label).tag(p) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .disabled(vm.isScanning)
                Text(vm.portProfile.blurb)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if vm.portProfile == .custom {
                LabeledField(label: "PORTS", placeholder: "22,80,443,8000-8100",
                             text: $vm.customPorts, disabled: vm.isScanning)
                Text("\(PortCatalog.parseSpec(vm.customPorts).count) port(s) selected")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
            Toggle("Grab banners (identify service & version)", isOn: $vm.grabBanners)
                .font(.caption)
                .disabled(vm.isScanning)
            Toggle("Detect TLS on open ports (HTTPS on odd ports, certificate CN)",
                   isOn: $vm.portProbeTLS)
                .font(.caption)
                .disabled(vm.isScanning)
            Toggle("Re-probe timed-out ports (fewer false \"filtered\")",
                   isOn: $vm.portRetryFiltered)
                .font(.caption)
                .disabled(vm.isScanning)
            Toggle("Adaptive timeout (tighten to the host's round-trip)",
                   isOn: $vm.portAdaptiveTimeout)
                .font(.caption)
                .disabled(vm.isScanning)
            HStack {
                Text("TIMEOUT ms / port").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()

                TextField("", value: $vm.portTimeoutMs, format: .number.grouping(.never))
                    .textFieldStyle(.roundedBorder).frame(width: 80).disabled(vm.isScanning)
            }
            HStack {
                Text("PARALLEL PROBES").font(.caption2.bold()).foregroundStyle(.secondary)
                Spacer()
                TextField("", value: $vm.portConcurrency, format: .number.grouping(.never))
                    .textFieldStyle(.roundedBorder).frame(width: 80).disabled(vm.isScanning)
            }
            if vm.portProfile == .full {
                Label("Full scans are slow and very noisy - authorized targets only.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct DatabaseOptions: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            LabeledField(label: "EXTRA DB PORTS (OPTIONAL)",
                         placeholder: "e.g. 3307, 5433, 27020, 9201",
                         text: $vm.dbExtraPorts, disabled: vm.isScanning)
            Text("Added to the built-in database/cache sweep - use this if your database listens on a non-standard port.")
                .font(.caption2).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
            Toggle(isOn: $vm.dbTestAuth) {
                Text("Actively test for unauthenticated access").font(.callout)
            }
            .disabled(vm.isScanning)
            if vm.dbTestAuth {
                Label("Connects to open Redis/Memcached/PostgreSQL/MongoDB and confirms whether they accept commands with no credentials.",
                      systemImage: "bolt.shield")
                    .font(.caption2).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
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
                if vm.mode == .contentDiscovery || vm.mode == .urlMask {
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
        if vm.report != nil || !vm.discovered.isEmpty || !vm.openPorts.isEmpty {
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
                if !vm.openPorts.isEmpty {
                    Button {
                        save(vm.openPortsText, name: "open-ports.txt")
                    } label: { Label("Ports", systemImage: "network") }
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

private struct ResultsPanel: View {
    @ObservedObject var vm: ScannerViewModel
    @State private var tab: Tab = .findings

    private enum Tab: Hashable { case findings, discovered, ports }

    private var showDiscovered: Bool { !vm.discovered.isEmpty }
    private var showPorts: Bool { !vm.openPorts.isEmpty }
    private var hasTabs: Bool { showDiscovered || showPorts }

    var body: some View {
        VStack(spacing: 0) {
            if hasTabs {
                Picker("", selection: $tab) {
                    Text("Findings (\(vm.findings.count))").tag(Tab.findings)
                    if showDiscovered {
                        Text("Discovered (\(vm.discovered.count))").tag(Tab.discovered)
                    }
                    if showPorts {
                        Text("Ports (\(vm.openPorts.count))").tag(Tab.ports)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.horizontal, 16)
                .padding(.top, 12)
            }
            Group {
                if tab == .discovered && showDiscovered {
                    DiscoveredList(vm: vm)
                } else if tab == .ports && showPorts {
                    PortList(vm: vm)
                } else if vm.findings.isEmpty && vm.perfReport == nil && vm.infoReport == nil && vm.dbReport == nil {
                    emptyState
                } else {
                    ScrollView {
                        LazyVStack(spacing: 10) {
                            if let db = vm.dbReport { DatabaseDashboard(report: db) }
                            if let info = vm.infoReport { InfoDashboard(report: info) }
                            if let rep = vm.perfReport { PerformanceDashboard(report: rep) }
                            ForEach(vm.sortedFindings) { finding in FindingCard(finding: finding) }
                        }
                        .padding(16)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.underPageBackgroundColor))
        .onChange(of: showDiscovered) { on in if !on && tab == .discovered { tab = .findings } }
        .onChange(of: showPorts) { on in if !on && tab == .ports { tab = .findings } }
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
        case .fullAudit:        return "Enter a host and press Scan to run every category at maximum depth plus a full 65,535-port sweep - the most exhaustive scan (can take 20-40+ minutes)."
        case .siteScan:         return "Enter a domain, confirm authorization, and press Scan."
        case .contentDiscovery: return "Enter a domain and a wordlist (or use the built-in list) to brute-force paths."
        case .urlMask:          return "Enter a URL template with wildcards and press Scan to probe generated URLs."
        case .portScan:         return "Enter a host and press Scan to map open TCP ports and their services."
        case .database:         return "Enter a host and press Scan to find exposed databases, unauthenticated access, admin tools, leaked dumps and SQL-injection surface."
        case .hostScan:         return "Enter a host and press Scan to profile its IP, hosting provider, CDN, stack and exposures."
        case .info:             return "Enter a host and press Scan for a quick read-only overview of the target."
        case .performance:      return "Enter a host and press Scan to measure response time (TTFB), page weight and speed - with ways to make it faster."
        case .userView:         return "Enter a domain and press Scan to attack the site as a user would - locally-tamperable fields, client-side trust flags & browser-stored auth, plus active reflected-XSS, open-redirect, SQLi, IDOR, CORS, GraphQL and access-control-bypass tests on the endpoints a visitor controls."
        }
    }
}

private struct PortList: View {
    @ObservedObject var vm: ScannerViewModel

    private var rows: [OpenPort] {
        let visible = vm.showFilteredPorts ? vm.openPorts : vm.openPorts.filter { $0.state == .open }
        let q = vm.portSearch.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return visible }
        return visible.filter { p in
            "\(p.port)".contains(q)
                || p.service.lowercased().contains(q)
                || (p.productVersion?.lowercased().contains(q) ?? false)
                || (p.banner?.lowercased().contains(q) ?? false)
        }
    }

    private var openCount: Int { vm.openPorts.filter { $0.state == .open }.count }
    private var filteredCount: Int { vm.openPorts.filter { $0.state == .filtered }.count }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Toggle("Show filtered", isOn: $vm.showFilteredPorts)
                    .toggleStyle(.checkbox)
                    .font(.caption)
                    .fixedSize()
                TextField("Filter by port, service or banner", text: $vm.portSearch)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .frame(maxWidth: 240)
                Spacer()
                Text(verbatim: "\(openCount) open" + (filteredCount > 0 ? " · \(filteredCount) filtered" : ""))
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            Divider()
            if rows.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "network.slash").font(.system(size: 34)).foregroundStyle(.secondary)
                    Text(vm.openPorts.isEmpty ? "No open ports found" : "No ports match this filter")
                        .font(.callout).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(rows) { p in
                            PortRow(p: p, host: vm.scanHost)
                            Divider()
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }
}

private struct PortRow: View {
    let p: OpenPort
    var host: String = ""
    @State private var expanded = false

    private var canExpand: Bool { p.state == .open && !host.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            } label: {
                header
            }
            .buttonStyle(.plain)
            .disabled(!canExpand)

            if expanded && canExpand {
                PlaybookPanel(playbook: PortPlaybook.build(for: p, host: host))
                    .padding(.horizontal, 14)
                    .padding(.top, 2)
                    .padding(.bottom, 12)
            }
        }
        .background(p.risk != nil ? p.risk!.color.opacity(0.06) : Color.clear)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: canExpand ? (expanded ? "chevron.down" : "chevron.right") : "minus")
                .font(.system(size: 9, weight: .bold))
                .foregroundStyle(canExpand ? Color.secondary : Color.clear)
                .frame(width: 10)
                .padding(.top, 2)

            Text(verbatim: "\(p.port)")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundStyle(p.state.color)
                .frame(width: 52, alignment: .leading)
            Text(p.state.label)
                .font(.system(size: 9, weight: .bold))
                .padding(.horizontal, 5).padding(.vertical, 2)
                .background(p.state.color.opacity(0.16))
                .foregroundStyle(p.state.color)
                .clipShape(Capsule())
                .frame(width: 72, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(p.service).font(.system(size: 12, weight: .semibold))
                    if let v = p.productVersion {
                        Text(v)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    if p.tls == true { tag("TLS", .teal) }
                    if p.unexpectedService == true { tag("UNEXPECTED", .orange) }
                }
                if let tls = p.tlsInfo {
                    Text(tls)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.tail)
                }
                if let b = p.banner, !b.isEmpty {
                    Text(snippet(b, max: 120))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.tail)
                }
                if canExpand && !expanded {
                    Text("Tap for commands to test this service")
                        .font(.system(size: 9))
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            if let rtt = p.rttMs {
                Text(verbatim: "\(rtt) ms")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }
            if let risk = p.risk {
                Text(risk.label.uppercased())
                    .font(.system(size: 9, weight: .bold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(risk.color.opacity(0.16))
                    .foregroundStyle(risk.color)
                    .clipShape(Capsule())
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 6)
        .contentShape(Rectangle())
    }

    private func tag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 8, weight: .bold))
            .padding(.horizontal, 4).padding(.vertical, 1)
            .background(color.opacity(0.16))
            .foregroundStyle(color)
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

private struct PlaybookPanel: View {
    let playbook: PortPlaybook

    @State private var copiedID: UUID? = nil

    private let accent = Color(red: 0.16, green: 0.48, blue: 0.83)
    private let danger = Color(red: 0.83, green: 0.14, blue: 0.16)

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 6) {
                Image(systemName: "terminal")
                Text("HOW TO TEST \(playbook.service.uppercased())")
                Spacer()
                Text("AUTHORIZED TESTING ONLY")
                    .foregroundStyle(.orange)
            }
            .font(.system(size: 10, weight: .bold))
            .foregroundStyle(accent)

            Text(playbook.summary)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            sectionHeader("1 · ACCESS & ENUMERATE", "magnifyingglass", accent)
            ForEach(Array(playbook.steps.enumerated()), id: \.element.id) { idx, step in
                stepView(number: idx + 1, step: step, tint: accent)
            }

            if !playbook.defaultCreds.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    Text("DEFAULT / COMMON CREDENTIALS TO TRY")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.secondary)
                    Text(playbook.defaultCreds.joined(separator: "   •   "))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if let note = playbook.passwordNote {
                calloutBox(icon: "key.fill", title: "IF IT ASKS FOR A PASSWORD",
                           text: note, tint: .orange)
            }

            if !playbook.exploits.isEmpty {
                sectionHeader("2 · EXPLOIT — KNOWN CVEs / RCE", "bolt.fill", danger)
                ForEach(Array(playbook.exploits.enumerated()), id: \.element.id) { idx, step in
                    stepView(number: idx + 1, step: step, tint: danger)
                }
            }

            if !playbook.evidence.isEmpty {
                sectionHeader("3 · EVIDENCE TO CAPTURE", "camera.viewfinder", .green)
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(playbook.evidence, id: \.self) { item in
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: "checkmark.circle")
                                .font(.system(size: 10))
                                .foregroundStyle(.green)
                                .padding(.top, 1)
                            Text(item)
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.green.opacity(0.07))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.underPageBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(accent.opacity(0.25)))
    }

    private func sectionHeader(_ title: String, _ icon: String, _ tint: Color) -> some View {
        HStack(spacing: 5) {
            Image(systemName: icon)
            Text(title)
            VStack { Divider() }
        }
        .font(.system(size: 10, weight: .bold))
        .foregroundStyle(tint)
    }

    private func calloutBox(icon: String, title: String, text: String, tint: Color) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 10))
                .foregroundStyle(tint)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(tint)
                Text(text)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func stepView(number: Int, step: PortPlaybook.Step, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text("\(number). \(step.title)")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(step.command, forType: .string)
                    copiedID = step.id
                    let target = step.id
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        if copiedID == target { copiedID = nil }
                    }
                } label: {
                    Label(copiedID == step.id ? "Copied" : "Copy",
                          systemImage: copiedID == step.id ? "checkmark" : "doc.on.doc")
                        .font(.caption2)
                }
                .buttonStyle(.plain)
                .foregroundStyle(copiedID == step.id ? .green : .secondary)
            }
            Text(step.command)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 5))
                .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(tint.opacity(0.3)))
            if let note = step.note {
                Text(note)
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
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
    @State private var copied = false
    @State private var contentExpanded = false
    @State private var contentCopied = false

    private static let contentPreviewLines = 12

    private var isPerformance: Bool { finding.category == "Performance" }

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
                    if let content = finding.capturedContent, !content.isEmpty {
                        capturedContentSection(content)
                    }
                    section(isPerformance ? "Impact on users" : "How it could be exploited",
                            finding.exploit, tint: .orange)
                    if let repro = finding.reproduction, !repro.isEmpty {
                        reproSection(repro)
                    }
                    section(isPerformance ? "How to make it faster" : "How to fix it",
                            finding.remediation, tint: .green)
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

    private var pocColor: Color { Color(red: 0.55, green: 0.35, blue: 0.85) }

    private func capturedContentSection(_ content: String) -> some View {
        let lines = content.components(separatedBy: "\n")
        let isLong = lines.count > Self.contentPreviewLines
        let shown = (contentExpanded || !isLong)
            ? content
            : lines.prefix(Self.contentPreviewLines).joined(separator: "\n")

        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Label("FILE CONTENTS - \(lines.count) LINE\(lines.count == 1 ? "" : "S")",
                      systemImage: "doc.text.magnifyingglass")
                    .font(.caption2.bold())
                    .foregroundStyle(finding.severity.color)
                Spacer()
                if isLong {
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) { contentExpanded.toggle() }
                    } label: {
                        Label(contentExpanded ? "Show less" : "Show all \(lines.count) lines",
                              systemImage: contentExpanded ? "chevron.up" : "chevron.down")
                            .font(.caption2)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
                Button {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(content, forType: .string)
                    contentCopied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { contentCopied = false }
                } label: {
                    Label(contentCopied ? "Copied" : "Copy file",
                          systemImage: contentCopied ? "checkmark" : "doc.on.doc")
                        .font(.caption2)
                }
                .buttonStyle(.plain)
                .foregroundStyle(contentCopied ? .green : .secondary)
            }

            Text(shown)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(finding.severity.color.opacity(0.35)))

            if isLong && !contentExpanded {
                Text("\(lines.count - Self.contentPreviewLines) more lines hidden")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func reproSection(_ command: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Label("PROOF OF CONCEPT - RUN IN TERMINAL", systemImage: "terminal")
                    .font(.caption2.bold())
                    .foregroundStyle(pocColor)
                Spacer()
                Button {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(command, forType: .string)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.caption2)
                }
                .buttonStyle(.plain)
                .foregroundStyle(copied ? .green : .secondary)
            }
            Text(command)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(pocColor.opacity(0.35)))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
