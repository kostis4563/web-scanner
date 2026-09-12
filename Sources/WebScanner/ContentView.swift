import SwiftUI
import AppKit

extension ScanMode {
    var icon: String {
        switch self {
        case .fullAudit:        return "square.stack.3d.up.fill"
        case .siteScan:         return "shield.lefthalf.filled"
        case .contentDiscovery: return "folder.badge.questionmark"
        case .urlMask:          return "asterisk.circle"
        case .portScan:         return "network"
        case .database:         return "cylinder.split.1x2.fill"
        case .hostScan:         return "server.rack"
        case .info:             return "info.circle"
        case .performance:      return "speedometer"
        case .userView:         return "person.fill.viewfinder"
        }
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .critical: return DS.C.critical
        case .high:     return DS.C.high
        case .medium:   return DS.C.medium
        case .low:      return DS.C.low
        case .info:     return DS.C.info
        }
    }
}

extension DiscoveredURL.Kind {
    var color: Color {
        switch self {
        case .openDirectory, .mismatch: return DS.C.high
        case .directory:                return DS.C.low
        case .file, .defaultFile:       return DS.C.success
        case .page:                     return DS.C.info
        }
    }
}

extension OpenPort.State {
    var color: Color {
        switch self {
        case .open:     return DS.C.success
        case .filtered: return DS.C.high
        case .closed:   return DS.C.info
        }
    }
}

struct ContentView: View {
    @StateObject private var vm = ScannerViewModel()
    @State private var showOptions = true

    var body: some View {
        VStack(spacing: 0) {
            WorkbenchHeader(vm: vm)
            hline()
            TopBar(vm: vm, showOptions: $showOptions)
            hline()
            HStack(alignment: .top, spacing: 0) {
                if showOptions {
                    OptionsDrawer(vm: vm)
                        .frame(width: 352)
                        .frame(maxHeight: .infinity, alignment: .top)
                        .transition(.move(edge: .leading).combined(with: .opacity))
                    border()
                }
                ResultsPanel(vm: vm)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 1100, minHeight: 720)
        .background(DS.C.bg)
        .tint(DS.C.accent)
        .preferredColorScheme(.dark)
        .onOpenURL { url in
            vm.handleDeepLink(url)
        }
    }

    private func border() -> some View {
        Rectangle().fill(DS.C.border).frame(width: 1).frame(maxHeight: .infinity)
    }
}

private func hline() -> some View {
    Rectangle().fill(DS.C.border).frame(height: 1)
}

private struct WorkbenchHeader: View {
    @ObservedObject var vm: ScannerViewModel

    var body: some View {
        HStack(spacing: DS.S.sm) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(DS.C.text)
                Text("W")
                    .font(DS.font(14, .bold))
                    .foregroundStyle(DS.C.bg)
            }
            .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: 0) {
                Text("Web Scanner")
                    .font(DS.font(15, .semibold))
                    .foregroundStyle(DS.C.text)
            }

            Spacer()

            HStack(spacing: 7) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 6, height: 6)
                Text(statusLabel)
                    .font(DS.font(11.5, .medium))
                    .foregroundStyle(DS.C.textDim)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, DS.S.lg)
        .frame(height: 56)
        .background(DS.C.rail)
    }

    private var statusLabel: String {
        if vm.isScanning { return vm.statusText }
        if vm.finishedAt != nil { return vm.statusText }
        if let source = vm.linkedSource { return "Linked · \(source)" }
        return "Idle"
    }

    private var statusColor: Color {
        if vm.isScanning { return DS.C.accent }
        if vm.statusText == "Scan cancelled" { return DS.C.critical }
        if vm.finishedAt != nil { return DS.C.success }
        if vm.linkedSource != nil { return DS.C.accent }
        return DS.C.textFaint
    }
}

private struct TopBar: View {
    @ObservedObject var vm: ScannerViewModel
    @Binding var showOptions: Bool

    private var canScan: Bool {
        vm.authorized && !vm.isScanning &&
        !vm.target.trimmingCharacters(in: .whitespaces).isEmpty
    }
    private var placeholder: String {
        switch vm.mode {
        case .urlMask:                                               return "https://[a-z]{1,3}.example.com"
        case .fullAudit, .portScan, .database, .hostScan, .info, .performance: return "example.com or 93.184.216.34"
        default:                                                     return "example.com"
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: DS.S.sm) {
                Button {
                    withAnimation(.easeInOut(duration: 0.2)) { showOptions.toggle() }
                } label: {
                    Image(systemName: "slider.horizontal.3")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(showOptions ? DS.C.text : DS.C.textDim)
                        .frame(width: 42, height: 42)
                    .background(DS.C.surface)
                    .overlay(RoundedRectangle(cornerRadius: DS.R.sm)
                        .strokeBorder(showOptions ? DS.C.hairlineActive : DS.C.hairline))
                    .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
                }
                .buttonStyle(.plain)
                .help(showOptions ? "Hide configuration" : "Show configuration")

                Button {
                    vm.openDetectionConfig()
                } label: {
                    Image(systemName: "scope")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(DS.C.textDim)
                        .frame(width: 42, height: 42)
                        .background(DS.C.surface)
                        .overlay(RoundedRectangle(cornerRadius: DS.R.sm)
                            .strokeBorder(DS.C.hairline))
                        .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
                }
                .buttonStyle(.plain)
                .help("Open custom detections JSON")

                ScanModeMenu(vm: vm)

                HStack(spacing: 10) {
                    Image(systemName: vm.mode == .urlMask ? "curlybraces" : "globe")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(DS.C.textDim)
                    TextField(placeholder, text: $vm.target)
                        .textFieldStyle(.plain)
                        .font(DS.font(13.5, .medium))
                        .foregroundStyle(DS.C.text)
                        .onSubmit { if canScan { vm.startScan() } }
                        .disabled(vm.isScanning)
                }
                .padding(.horizontal, DS.S.sm)
                .frame(maxWidth: .infinity, minHeight: 42)
                .background(DS.C.surface)
                .clipShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: DS.R.sm)
                    .strokeBorder(DS.C.hairline, lineWidth: 1))

                if vm.isScanning {
                    Button(action: { vm.stopScan() }) {
                        Label("Cancel scan", systemImage: "xmark")
                    }
                    .buttonStyle(DSCancelButtonStyle())
                    .keyboardShortcut(.cancelAction)
                    .disabled(!vm.canStop)
                } else {
                    Button(action: { vm.startScan() }) {
                        HStack(spacing: 8) {
                            Text("Run scan")
                            Image(systemName: "arrow.right")
                                .font(.system(size: 11, weight: .semibold))
                        }
                    }
                    .buttonStyle(DSPrimaryButtonStyle(enabled: canScan))
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!canScan)
                }
            }
            .padding(.horizontal, DS.S.md)
            .padding(.vertical, DS.S.sm)

            if vm.isScanning || !vm.authorized {
                HStack(spacing: DS.S.sm) {
                    if vm.isScanning {
                        Text(vm.statusText)
                            .font(DS.font(10.5))
                            .foregroundStyle(DS.C.textDim)
                            .lineLimit(1)
                        Spacer()
                        Text(String(format: "%.0f%%", vm.displayProgress * 100))
                            .font(DS.mono(9.5, .medium))
                            .foregroundStyle(DS.C.accent)
                    } else {
                        Image(systemName: "lock.fill").font(.system(size: 9))
                        Text("Authorization is required. Enable it in scan settings.")
                            .font(DS.font(10.5, .medium))
                        Spacer()
                    }
                }
                .foregroundStyle(DS.C.warn)
                .padding(.horizontal, DS.S.md)
                .padding(.bottom, DS.S.xs)
            }

            if vm.isScanning {
                GeometryReader { geometry in
                    Rectangle()
                        .fill(DS.C.accent)
                        .frame(width: geometry.size.width * vm.displayProgress, height: 2)
                        .animation(.easeOut(duration: 0.2), value: vm.displayProgress)
                }
                .frame(height: 2)
            }
        }
        .background(DS.C.bg)
    }
}

private struct ScanModeMenu: View {
    @ObservedObject var vm: ScannerViewModel

    var body: some View {
        Menu {
            ForEach(ScanMode.allCases) { mode in
                Button {
                    vm.mode = mode
                } label: {
                    if mode == vm.mode {
                        Label(mode.label, systemImage: "checkmark")
                    } else {
                        Label(mode.label, systemImage: mode.icon)
                    }
                }
            }
        } label: {
            HStack(spacing: 9) {
                Image(systemName: vm.mode.icon)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(DS.C.textBody)
                    .frame(width: 16)

                Text(vm.mode.label)
                    .font(DS.font(12, .semibold))
                    .foregroundStyle(DS.C.text)
                    .lineLimit(1)

                Spacer(minLength: 18)
            }
            .padding(.horizontal, DS.S.sm)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .tint(DS.C.textBody)
        .frame(width: 176, height: 42)
        .background(DS.C.surface)
        .clipShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous)
                .strokeBorder(DS.C.hairline, lineWidth: 1)
        }
        .overlay(alignment: .trailing) {
            Image(systemName: "chevron.down")
                .font(.system(size: 8, weight: .semibold))
                .foregroundStyle(DS.C.textFaint)
                .padding(.trailing, DS.S.sm)
                .allowsHitTesting(false)
        }
        .disabled(vm.isScanning)
        .opacity(vm.isScanning ? 0.65 : 1)
        .help("Choose scan mode")
        .accessibilityLabel("Scan mode, \(vm.mode.label)")
    }
}

private struct OptionsDrawer: View {
    @ObservedObject var vm: ScannerViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DS.S.lg) {
                VStack(alignment: .leading, spacing: DS.S.md) {
                    HStack(alignment: .top) {
                        Text("Scan settings".uppercased())
                            .font(DS.font(10, .semibold))
                            .tracking(0.9)
                            .foregroundStyle(DS.C.textFaint)
                        Spacer()
                        Image(systemName: vm.mode.icon)
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(DS.C.textFaint)
                    }
                    VStack(alignment: .leading, spacing: 7) {
                        Text(vm.mode.label)
                            .font(DS.font(28, .medium))
                            .tracking(-0.7)
                            .foregroundStyle(DS.C.text)
                        Text(vm.mode.blurb)
                            .font(DS.font(12))
                            .foregroundStyle(DS.C.textDim)
                            .lineSpacing(2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                if vm.mode == .siteScan || vm.mode == .database || vm.mode == .userView {
                    ScanDepthView(vm: vm)
                }
                if vm.mode == .fullAudit {
                    NoteBanner(text: "Runs at MAXIMUM depth and scans all 65,535 TCP ports. Expect 20–40+ minutes.",
                               icon: "gauge.high", tint: DS.C.high)
                }
                if vm.mode == .contentDiscovery { ContentDiscoveryOptions(vm: vm) }
                if vm.mode == .urlMask { URLMaskOptions(vm: vm) }
                if vm.mode == .portScan { PortScanOptions(vm: vm) }
                if vm.mode == .database { DatabaseOptions(vm: vm) }

                DSCard(padding: DS.S.sm, radius: DS.R.md) {
                    VStack(alignment: .leading, spacing: DS.S.xs) {
                        Toggle(isOn: $vm.authorized) {
                            Text("I am authorized to test this target").font(DS.font(12.5))
                        }
                        .toggleStyle(.checkbox)
                        if vm.mode == .siteScan || vm.mode == .contentDiscovery || vm.mode == .fullAudit {
                            Toggle(isOn: $vm.deepSecretScan) {
                                Text(vm.mode == .contentDiscovery
                                     ? "Secret-scan discovered files"
                                     : "Deep secret scan — all files (HTML, JS, CSS, JSON, configs, .env)")
                                    .font(DS.font(12.5))
                            }
                            .toggleStyle(.checkbox)
                            .disabled(vm.isScanning)
                        }
                        Toggle(isOn: $vm.revealSecrets) {
                            Text("Reveal full secret values in findings").font(DS.font(12.5))
                        }
                        .toggleStyle(.checkbox)
                        .disabled(vm.isScanning)
                        if vm.revealSecrets {
                            NoteBanner(text: "Reports & exports will contain plaintext passwords / tokens. Handle securely.",
                                       icon: "eye.trianglebadge.exclamationmark", tint: DS.C.high)
                        }
                    }
                    .foregroundStyle(DS.C.textBody)
                }

                if vm.mode != .portScan {
                    RequestOptionsView(vm: vm)
                }

                DSCard(padding: DS.S.sm, radius: DS.R.md) {
                    HStack(spacing: DS.S.sm) {
                        Image(systemName: "scope")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(DS.C.textDim)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Custom detections")
                                .font(DS.font(12.5, .medium))
                                .foregroundStyle(DS.C.textBody)
                            Text("Add signatures and paths without changing Swift")
                                .font(DS.font(10.5))
                                .foregroundStyle(DS.C.textFaint)
                        }
                        Spacer(minLength: DS.S.xs)
                        Button("Edit JSON") { vm.openDetectionConfig() }
                            .buttonStyle(DSSecondaryButtonStyle())
                    }
                }

                SummaryView(vm: vm)
                ExportRow(vm: vm)
                ConsoleView(vm: vm)
                Spacer(minLength: 0)
            }
            .padding(DS.S.lg)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(DS.C.rail)
    }
}

private struct NoteBanner: View {
    let text: String
    var icon: String
    var tint: Color = DS.C.textDim
    var body: some View {
        HStack(alignment: .top, spacing: 7) {
            Image(systemName: icon)
                .font(.system(size: 11))
                .foregroundStyle(tint)
                .padding(.top, 1)
            Text(text)
                .font(DS.font(11.5))
                .foregroundStyle(DS.C.textBody)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(DS.S.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: DS.R.md, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: DS.R.md, style: .continuous)
                .strokeBorder(tint.opacity(0.30), lineWidth: 1)
        )
    }
}

private struct ScanDepthView: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: DS.S.xs) {
            DSLabel("Scan depth")
            Picker("", selection: $vm.intensity) {
                ForEach(ScanIntensity.allCases) { level in Text(level.label).tag(level) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(vm.isScanning)
            Text(vm.intensity.blurb)
                .font(DS.font(11.5))
                .foregroundStyle(DS.C.textDim)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct ContentDiscoveryOptions: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: DS.S.sm) {
            WordlistInput(vm: vm)
            LabeledField(label: "Extensions (-X)", placeholder: "php,bak,old,~", text: $vm.extensionsText, disabled: vm.isScanning)
            HStack(spacing: DS.S.md) {
                Toggle("Discover directories (-s)", isOn: $vm.scanDirectories).toggleStyle(.checkbox).disabled(vm.isScanning)
                Toggle("Recursive (-r)", isOn: $vm.recursive).toggleStyle(.checkbox).disabled(vm.isScanning)
            }
            .font(DS.font(12))
            .foregroundStyle(DS.C.textBody)
            HStack {
                DSLabel("Max requests")
                Spacer()
                TextField("", value: $vm.maxRequests, format: .number)
                    .darkField().frame(width: 84).disabled(vm.isScanning)
            }
        }
    }
}

private struct URLMaskOptions: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: DS.S.sm) {
            Text("Wildcards:  ?  one char   ·   *  grow   ·   [a-z]  range   ·   {n,m}  repeat   ·   (a,b,c)  choice   ·   $  dictionary word")
                .font(DS.mono(10))
                .foregroundStyle(DS.C.textFaint)
                .fixedSize(horizontal: false, vertical: true)
            if vm.target.contains("$") { WordlistInput(vm: vm) }
            HStack(spacing: DS.S.sm) {
                VStack(alignment: .leading, spacing: DS.S.xxs) {
                    DSLabel("Max length (*)")
                    TextField("", value: $vm.maskMaxLength, format: .number).darkField().disabled(vm.isScanning)
                }
                VStack(alignment: .leading, spacing: DS.S.xxs) {
                    DSLabel("Max URLs")
                    TextField("", value: $vm.maskLimit, format: .number).darkField().disabled(vm.isScanning)
                }
            }
        }
    }
}

private struct PortScanOptions: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: DS.S.sm) {
            VStack(alignment: .leading, spacing: DS.S.xs) {
                DSLabel("Port range")
                Picker("", selection: $vm.portProfile) {
                    ForEach(PortProfile.allCases) { p in Text(p.label).tag(p) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .disabled(vm.isScanning)
                Text(vm.portProfile.blurb)
                    .font(DS.font(11.5))
                    .foregroundStyle(DS.C.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if vm.portProfile == .custom {
                LabeledField(label: "Ports", placeholder: "22,80,443,8000-8100",
                             text: $vm.customPorts, disabled: vm.isScanning)
                Text("\(PortCatalog.parseSpec(vm.customPorts).count) port(s) selected")
                    .font(DS.font(11)).foregroundStyle(DS.C.textFaint)
            }
            portToggle("Grab banners (identify service & version)", $vm.grabBanners)
            portToggle("Detect TLS on open ports (HTTPS on odd ports, certificate CN)", $vm.portProbeTLS)
            portToggle("Re-probe timed-out ports (fewer false \"filtered\")", $vm.portRetryFiltered)
            portToggle("Adaptive timeout (tighten to the host's round-trip)", $vm.portAdaptiveTimeout)
            HStack {
                DSLabel("Timeout ms / port")
                Spacer()
                TextField("", value: $vm.portTimeoutMs, format: .number.grouping(.never))
                    .darkField().frame(width: 78).disabled(vm.isScanning)
            }
            HStack {
                DSLabel("Parallel probes")
                Spacer()
                TextField("", value: $vm.portConcurrency, format: .number.grouping(.never))
                    .darkField().frame(width: 78).disabled(vm.isScanning)
            }
            if vm.portProfile == .full {
                NoteBanner(text: "Full scans are slow and very noisy — authorized targets only.",
                           icon: "exclamationmark.triangle", tint: DS.C.high)
            }
        }
    }

    private func portToggle(_ label: String, _ binding: Binding<Bool>) -> some View {
        Toggle(label, isOn: binding)
            .toggleStyle(.checkbox)
            .font(DS.font(12))
            .foregroundStyle(DS.C.textBody)
            .disabled(vm.isScanning)
    }
}

private struct DatabaseOptions: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: DS.S.sm) {
            LabeledField(label: "Extra DB ports (optional)",
                         placeholder: "e.g. 3307, 5433, 27020, 9201",
                         text: $vm.dbExtraPorts, disabled: vm.isScanning)
            Text("Added to the built-in database/cache sweep — use this if your database listens on a non-standard port.")
                .font(DS.font(11)).foregroundStyle(DS.C.textFaint)
                .fixedSize(horizontal: false, vertical: true)
            Toggle(isOn: $vm.dbTestAuth) {
                Text("Actively test for unauthenticated access").font(DS.font(12.5))
            }
            .toggleStyle(.checkbox)
            .foregroundStyle(DS.C.textBody)
            .disabled(vm.isScanning)
            if vm.dbTestAuth {
                NoteBanner(text: "Connects to open Redis / Memcached / PostgreSQL / MongoDB and confirms whether they accept commands with no credentials.",
                           icon: "bolt.shield", tint: DS.C.low)
            }
        }
    }
}

private struct WordlistInput: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        VStack(alignment: .leading, spacing: DS.S.xs) {
            HStack {
                DSLabel("Wordlist")
                Spacer()
                Button("Choose file…") { chooseFile() }
                    .buttonStyle(.plain)
                    .font(DS.font(11, .medium))
                    .foregroundStyle(DS.C.accent)
                    .disabled(vm.isScanning)
            }
            TextField("file path or https://… (comma-separated), blank = built-in list",
                      text: $vm.wordlistSource)
                .darkField()
                .font(DS.mono(11))
                .disabled(vm.isScanning)
            Text("Or paste words (one per line):").font(DS.font(11)).foregroundStyle(DS.C.textFaint)
            TextEditor(text: $vm.wordlistText)
                .darkEditor(height: 62)
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
        VStack(alignment: .leading, spacing: DS.S.xxs) {
            DSLabel(label)
            TextField(placeholder, text: $text)
                .darkField()
                .font(DS.mono(12))
                .disabled(disabled)
        }
    }
}

private struct RequestOptionsView: View {
    @ObservedObject var vm: ScannerViewModel
    @State private var open = false
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { open.toggle() }
            } label: {
                HStack {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .bold))
                        .rotationEffect(.degrees(open ? 90 : 0))
                        .foregroundStyle(DS.C.textDim)
                    Text("Advanced request options")
                        .font(DS.font(12, .medium))
                        .foregroundStyle(DS.C.textBody)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if open {
                VStack(alignment: .leading, spacing: DS.S.sm) {
                    VStack(alignment: .leading, spacing: DS.S.xxs) {
                        DSLabel("Custom headers (-H, one per line)")
                        TextEditor(text: $vm.customHeaders)
                            .darkEditor(height: 46)
                            .disabled(vm.isScanning)
                    }
                    LabeledField(label: "Cookie (-c)", placeholder: "name=value; other=value", text: $vm.cookie, disabled: vm.isScanning)
                    LabeledField(label: "Basic auth (-u)", placeholder: "user:password", text: $vm.basicAuth, disabled: vm.isScanning)
                    LabeledField(label: "User-agent (-a)", placeholder: "custom user agent", text: $vm.userAgentOverride, disabled: vm.isScanning)
                    HStack {
                        DSLabel("Delay ms (-z)")
                        Spacer()
                        TextField("", value: $vm.requestDelayMs, format: .number)
                            .darkField().frame(width: 78).disabled(vm.isScanning)
                    }
                    if vm.mode == .contentDiscovery || vm.mode == .urlMask {
                        hline()
                        HStack(spacing: DS.S.xs) {
                            LabeledField(label: "Ignore (-N)", placeholder: "404,403", text: $vm.excludeCodesText, disabled: vm.isScanning)
                            LabeledField(label: "Only (-S)", placeholder: "200,301", text: $vm.onlyCodesText, disabled: vm.isScanning)
                        }
                        LabeledField(label: "Not in title (--not)", placeholder: "Not Found", text: $vm.notInTitle, disabled: vm.isScanning)
                    }
                }
                .padding(.top, DS.S.sm)
            }
        }
        .padding(DS.S.sm)
        .background(DS.C.surface)
        .clipShape(RoundedRectangle(cornerRadius: DS.R.md, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: DS.R.md, style: .continuous).strokeBorder(DS.C.border))
    }
}

private struct ExportRow: View {
    @ObservedObject var vm: ScannerViewModel
    var body: some View {
        if vm.report != nil || !vm.discovered.isEmpty || !vm.openPorts.isEmpty {
            VStack(alignment: .leading, spacing: DS.S.xs) {
                DSLabel("Export")
                HStack(spacing: DS.S.xs) {
                    if vm.report != nil {
                        exportButton("Markdown", "doc.text") {
                            if let r = vm.report { save(ReportExporter.markdown(r), name: "scan-report.md") }
                        }
                        exportButton("JSON", "curlybraces") {
                            if let r = vm.report { save(ReportExporter.json(r), name: "scan-report.json") }
                        }
                    }
                    if !vm.discovered.isEmpty {
                        exportButton("URLs", "link") { save(vm.discoveredText, name: "discovered-urls.txt") }
                    }
                    if !vm.openPorts.isEmpty {
                        exportButton("Ports", "network") { save(vm.openPortsText, name: "open-ports.txt") }
                    }
                }
            }
        }
    }

    private func exportButton(_ title: String, _ icon: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon).font(DS.font(11.5, .medium))
        }
        .buttonStyle(DSSecondaryButtonStyle())
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
        VStack(alignment: .leading, spacing: DS.S.xs) {
            DSLabel("Console")
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(vm.logLines.enumerated()), id: \.offset) { idx, line in
                            Text(line)
                                .font(DS.mono(10.5))
                                .foregroundStyle(DS.C.textDim)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(idx)
                        }
                    }
                    .padding(DS.S.xs)
                }
                .frame(height: 148)
                .background(DS.C.surface)
                .clipShape(RoundedRectangle(cornerRadius: DS.R.md, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: DS.R.md, style: .continuous).strokeBorder(DS.C.border))
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
        if vm.report != nil || !vm.discovered.isEmpty {
            VStack(alignment: .leading, spacing: DS.S.xs) {
                HStack {
                    DSLabel("Results")
                    Spacer()
                    if let r = vm.report {
                        Text("Grade \(r.grade)")
                            .font(DS.mono(10.5, .semibold))
                            .padding(.horizontal, DS.S.xs).padding(.vertical, 3)
                            .background(gradeColor(r.grade).opacity(0.16))
                            .foregroundStyle(gradeColor(r.grade))
                            .clipShape(RoundedRectangle(cornerRadius: DS.R.xs))
                    }
                }
                let c = vm.counts
                HStack(spacing: 0) {
                    ForEach(Severity.allCases, id: \.self) { sev in
                        VStack(spacing: 2) {
                            Text("\(c[sev] ?? 0)")
                                .font(DS.mono(18, .semibold))
                                .foregroundStyle(sev.color)
                            Text(sev.label.uppercased())
                                .font(DS.mono(8, .semibold))
                                .tracking(0.4)
                                .foregroundStyle(DS.C.textFaint)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, DS.S.xs)
                        .overlay(alignment: .trailing) {
                            if sev != Severity.allCases.last {
                                Rectangle().fill(DS.C.border).frame(width: 1)
                            }
                        }
                    }
                }
                .background(DS.C.surface)
                .clipShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: DS.R.sm).strokeBorder(DS.C.border))
                if !vm.discovered.isEmpty {
                    Text("\(vm.discovered.count) reachable URL(s) discovered")
                        .font(DS.font(11.5)).foregroundStyle(DS.C.textDim)
                }
            }
        }
    }

    private func gradeColor(_ g: String) -> Color {
        switch g.first {
        case "A": return DS.C.success
        case "B": return DS.C.low
        case "C": return DS.C.medium
        case "D": return DS.C.high
        default:  return DS.C.critical
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
                HStack(spacing: 4) {
                    resultTab("Findings", count: vm.findings.count, value: .findings)
                    if showDiscovered {
                        resultTab("Discovered", count: vm.discovered.count, value: .discovered)
                    }
                    if showPorts {
                        resultTab("Ports", count: vm.openPorts.count, value: .ports)
                    }
                    Spacer()
                }
                .padding(.horizontal, DS.S.lg)
                .frame(height: 48)
                .background(DS.C.rail)
                hline()
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
                        .padding(DS.S.lg)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background { CleanBackdrop() }
        .onChange(of: showDiscovered) { on in if !on && tab == .discovered { tab = .findings } }
        .onChange(of: showPorts) { on in if !on && tab == .ports { tab = .findings } }
    }

    private func resultTab(_ title: String, count: Int, value: Tab) -> some View {
        Button {
            withAnimation(.easeOut(duration: 0.16)) { tab = value }
        } label: {
            HStack(spacing: 6) {
                Text(title)
                Text("\(count)")
                    .font(DS.mono(9.5, .medium))
                    .foregroundStyle(DS.C.textFaint)
            }
            .font(DS.font(11.5, .medium))
            .foregroundStyle(tab == value ? DS.C.text : DS.C.textDim)
            .padding(.horizontal, 12)
            .frame(height: 30)
            .background(tab == value ? DS.C.surfaceElev : Color.clear)
            .overlay(RoundedRectangle(cornerRadius: DS.R.sm)
                .strokeBorder(tab == value ? DS.C.hairlineActive : Color.clear))
            .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
        }
        .buttonStyle(.plain)
    }

    private var emptyState: some View {
        Group {
            if vm.isScanning {
                scanActivity
            } else {
                emptyPrompt
            }
        }
        .padding(.horizontal, 56)
        .padding(.top, 68)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var emptyPrompt: some View {
        VStack(alignment: .leading, spacing: 0) {
            Image(systemName: vm.mode.icon)
                .font(.system(size: 18, weight: .medium))
                .foregroundStyle(DS.C.textDim)
                .frame(height: 28, alignment: .top)

            Text(vm.statusText == "Scan cancelled" ? "Scan cancelled" : "Nothing scanned yet")
                .font(DS.font(27, .medium))
                .tracking(-0.65)
                .foregroundStyle(DS.C.text)
                .padding(.top, 18)

            Text(vm.statusText == "Scan cancelled"
                 ? "The scan stopped. Change the target or settings, then run it again when you want."
                 : modeHint)
                .font(DS.font(13.5))
                .foregroundStyle(DS.C.textDim)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 540, alignment: .leading)
                .padding(.top, 9)

            HStack(spacing: 18) {
                Label(vm.mode.label, systemImage: "scope")
                Label("Runs on this Mac", systemImage: "laptopcomputer")
                Label(vm.authorized ? "Authorized" : "Authorization needed",
                      systemImage: vm.authorized ? "checkmark" : "lock")
                    .foregroundStyle(vm.authorized ? DS.C.textDim : DS.C.warn)
            }
            .font(DS.font(11.5, .medium))
            .foregroundStyle(DS.C.textDim)
            .padding(.top, 24)

            Text("Enter a domain or IP above, then choose Run scan.")
                .font(DS.font(11.5))
                .foregroundStyle(DS.C.textFaint)
                .padding(.top, 30)
        }
    }

    private var scanActivity: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 9) {
                ProgressView()
                    .controlSize(.small)
                    .tint(DS.C.accent)
                Text("Scanning \(vm.target)")
                    .font(DS.font(13, .semibold))
                    .foregroundStyle(DS.C.text)
                    .lineLimit(1)
            }

            Text(vm.statusText)
                .font(DS.font(27, .medium))
                .tracking(-0.65)
                .foregroundStyle(DS.C.text)
                .lineLimit(2)
                .padding(.top, 22)

            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    Capsule().fill(DS.C.border)
                    Capsule()
                        .fill(DS.C.textBody)
                        .frame(width: geometry.size.width * vm.displayProgress)
                        .animation(.easeOut(duration: 0.2), value: vm.displayProgress)
                }
            }
            .frame(width: 520, height: 3)
            .padding(.top, 20)

            Text(String(format: "%.0f%% complete", vm.displayProgress * 100))
                .font(DS.mono(10.5, .medium))
                .foregroundStyle(DS.C.textFaint)
                .padding(.top, 9)

            if !recentActivity.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Recent activity")
                        .font(DS.font(11.5, .medium))
                        .foregroundStyle(DS.C.textDim)
                        .padding(.bottom, 2)
                    ForEach(Array(recentActivity.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(DS.mono(10.5))
                            .foregroundStyle(DS.C.textFaint)
                            .lineLimit(1)
                    }
                }
                .padding(.top, 36)
                .frame(maxWidth: 620, alignment: .leading)
            }
        }
    }

    private var recentActivity: [String] {
        Array(vm.logLines.suffix(5))
    }

    private var modeHint: String {
        switch vm.mode {
        case .fullAudit:        return "Checks the site, host, exposed services, leaked data, and every TCP port. A full audit can take 20–40 minutes."
        case .siteScan:         return "Checks a website for weak headers, exposed data, unsafe defaults, and common attack paths."
        case .contentDiscovery: return "Looks for hidden files and directories with your wordlist or the built-in list."
        case .urlMask:          return "Expands a URL pattern and checks which generated addresses are live."
        case .portScan:         return "Maps open TCP ports and identifies the services listening on them."
        case .database:         return "Checks for exposed databases, admin tools, leaked dumps, and unauthenticated access."
        case .hostScan:         return "Profiles the host, network provider, certificates, public services, and infrastructure."
        case .info:             return "Collects a quick, read-only overview of the target and its public services."
        case .performance:      return "Times every request, finds what is slow and why, then ranks the fixes by the time each one saves."
        case .userView:         return "Tests the parts of the site a visitor can control, including forms, redirects, browser storage, and public endpoints."
        }
    }
}

private struct CleanBackdrop: View {
    var body: some View {
        DS.C.bg
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
            HStack(spacing: DS.S.sm) {
                Toggle("Show filtered", isOn: $vm.showFilteredPorts)
                    .toggleStyle(.checkbox)
                    .font(DS.font(12))
                    .foregroundStyle(DS.C.textBody)
                    .fixedSize()
                TextField("Filter by port, service or banner", text: $vm.portSearch)
                    .darkField()
                    .font(DS.font(12))
                    .frame(maxWidth: 240)
                Spacer()
                Text(verbatim: "\(openCount) open" + (filteredCount > 0 ? " · \(filteredCount) filtered" : ""))
                    .font(DS.font(11)).foregroundStyle(DS.C.textDim)
            }
            .padding(.horizontal, DS.S.lg).padding(.vertical, DS.S.sm)
            hline()
            if rows.isEmpty {
                VStack(spacing: DS.S.xs) {
                    Image(systemName: "network.slash").font(.system(size: 32)).foregroundStyle(DS.C.borderStrong)
                    Text(vm.openPorts.isEmpty ? "No open ports found" : "No ports match this filter")
                        .font(DS.font(13)).foregroundStyle(DS.C.textDim)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(rows) { p in
                            PortRow(p: p, host: vm.scanHost)
                            hline()
                        }
                    }
                    .padding(.vertical, DS.S.xxs)
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
            } label: { header }
            .buttonStyle(.plain)
            .disabled(!canExpand)

            if expanded && canExpand {
                PlaybookPanel(playbook: PortPlaybook.build(for: p, host: host))
                    .padding(.horizontal, DS.S.md)
                    .padding(.top, 2)
                    .padding(.bottom, DS.S.sm)
            }
        }
        .background(p.risk != nil ? p.risk!.color.opacity(0.06) : Color.clear)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: DS.S.sm) {
            Image(systemName: canExpand ? (expanded ? "chevron.down" : "chevron.right") : "minus")
                .font(.system(size: 9, weight: .bold))
                .foregroundStyle(canExpand ? DS.C.textDim : Color.clear)
                .frame(width: 10)
                .padding(.top, 3)

            Text(verbatim: "\(p.port)")
                .font(DS.mono(12.5, .bold))
                .foregroundStyle(p.state.color)
                .frame(width: 52, alignment: .leading)
            Text(p.state.label)
                .font(DS.font(9, .bold))
                .padding(.horizontal, 5).padding(.vertical, 2)
                .background(p.state.color.opacity(0.16))
                .foregroundStyle(p.state.color)
                .clipShape(RoundedRectangle(cornerRadius: DS.R.xs))
                .frame(width: 72, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(p.service).font(DS.font(12.5, .semibold)).foregroundStyle(DS.C.text)
                    if let v = p.productVersion {
                        Text(v).font(DS.mono(11)).foregroundStyle(DS.C.textDim)
                    }
                    if p.tls == true { tag("TLS", DS.C.low) }
                    if p.unexpectedService == true { tag("UNEXPECTED", DS.C.high) }
                }
                if let tls = p.tlsInfo {
                    Text(tls).font(DS.mono(10)).foregroundStyle(DS.C.textDim)
                        .lineLimit(1).truncationMode(.tail)
                }
                if let b = p.banner, !b.isEmpty {
                    Text(snippet(b, max: 120)).font(DS.mono(10)).foregroundStyle(DS.C.textFaint)
                        .lineLimit(1).truncationMode(.tail)
                }
                if canExpand && !expanded {
                    Text("Click for commands to test this service")
                        .font(DS.font(9.5)).foregroundStyle(DS.C.accent)
                }
            }
            Spacer()
            if let rtt = p.rttMs {
                Text(verbatim: "\(rtt) ms").font(DS.mono(10)).foregroundStyle(DS.C.textFaint)
            }
            if let risk = p.risk {
                Text(risk.label.uppercased())
                    .font(DS.font(9, .bold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(risk.color.opacity(0.16))
                    .foregroundStyle(risk.color)
                    .clipShape(RoundedRectangle(cornerRadius: DS.R.xs))
            }
        }
        .padding(.horizontal, DS.S.md).padding(.vertical, DS.S.xs)
        .contentShape(Rectangle())
    }

    private func tag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(DS.font(8, .bold))
            .padding(.horizontal, 4).padding(.vertical, 1)
            .background(color.opacity(0.16))
            .foregroundStyle(color)
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

private struct PlaybookPanel: View {
    let playbook: PortPlaybook

    @State private var copiedID: UUID? = nil

    private let accent = DS.C.accent
    private let danger = DS.C.critical

    var body: some View {
        VStack(alignment: .leading, spacing: DS.S.sm) {
            HStack(spacing: 6) {
                Image(systemName: "terminal")
                Text("HOW TO TEST \(playbook.service.uppercased())")
                Spacer()
                Text("AUTHORIZED TESTING ONLY").foregroundStyle(DS.C.warn)
            }
            .font(DS.font(10, .bold))
            .foregroundStyle(accent)

            Text(playbook.summary)
                .font(DS.font(11.5))
                .foregroundStyle(DS.C.textBody)
                .fixedSize(horizontal: false, vertical: true)

            sectionHeader("1 · ACCESS & ENUMERATE", "magnifyingglass", accent)
            ForEach(Array(playbook.steps.enumerated()), id: \.element.id) { idx, step in
                stepView(number: idx + 1, step: step, tint: accent)
            }

            if !playbook.defaultCreds.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    Text("DEFAULT / COMMON CREDENTIALS TO TRY")
                        .font(DS.font(10, .bold))
                        .foregroundStyle(DS.C.textFaint)
                    Text(playbook.defaultCreds.joined(separator: "   •   "))
                        .font(DS.mono(11))
                        .foregroundStyle(DS.C.text)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if let note = playbook.passwordNote {
                calloutBox(icon: "key.fill", title: "IF IT ASKS FOR A PASSWORD",
                           text: note, tint: DS.C.high)
            }

            if !playbook.exploits.isEmpty {
                sectionHeader("2 · EXPLOIT — KNOWN CVEs / RCE", "bolt.fill", danger)
                ForEach(Array(playbook.exploits.enumerated()), id: \.element.id) { idx, step in
                    stepView(number: idx + 1, step: step, tint: danger)
                }
            }

            if !playbook.evidence.isEmpty {
                sectionHeader("3 · EVIDENCE TO CAPTURE", "camera.viewfinder", DS.C.success)
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(playbook.evidence, id: \.self) { item in
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: "checkmark.circle")
                                .font(.system(size: 10))
                                .foregroundStyle(DS.C.success)
                                .padding(.top, 1)
                            Text(item)
                                .font(DS.font(11.5))
                                .foregroundStyle(DS.C.textBody)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(DS.S.xs)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(DS.C.success.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
            }
        }
        .padding(DS.S.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DS.C.surfaceElev)
        .clipShape(RoundedRectangle(cornerRadius: DS.R.md))
        .overlay(RoundedRectangle(cornerRadius: DS.R.md).strokeBorder(accent.opacity(0.22)))
    }

    private func sectionHeader(_ title: String, _ icon: String, _ tint: Color) -> some View {
        HStack(spacing: 5) {
            Image(systemName: icon)
            Text(title)
            Rectangle().fill(tint.opacity(0.28)).frame(height: 1)
        }
        .font(DS.font(10, .bold))
        .foregroundStyle(tint)
    }

    private func calloutBox(icon: String, title: String, text: String, tint: Color) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 10))
                .foregroundStyle(tint)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(DS.font(10, .bold)).foregroundStyle(tint)
                Text(text).font(DS.font(11.5)).foregroundStyle(DS.C.textBody)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(DS.S.xs)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.09))
        .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
    }

    private func stepView(number: Int, step: PortPlaybook.Step, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text("\(number). \(step.title)")
                    .font(DS.font(10, .semibold))
                    .foregroundStyle(DS.C.textDim)
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
                        .font(DS.font(10.5))
                }
                .buttonStyle(.plain)
                .foregroundStyle(copiedID == step.id ? DS.C.success : DS.C.textDim)
            }
            Text(step.command)
                .font(DS.mono(11))
                .foregroundStyle(DS.C.accentBright)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(DS.C.surface)
                .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
                .overlay(RoundedRectangle(cornerRadius: DS.R.sm).strokeBorder(tint.opacity(0.28)))
            if let note = step.note {
                Text(note).font(DS.font(10)).foregroundStyle(DS.C.textFaint)
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
                    hline()
                }
            }
            .padding(.vertical, DS.S.xxs)
        }
    }
}

private struct DiscoveredRow: View {
    let d: DiscoveredURL
    var body: some View {
        HStack(alignment: .top, spacing: DS.S.sm) {
            Text("\(d.status)")
                .font(DS.mono(11, .bold))
                .foregroundStyle(statusColor)
                .frame(width: 34, alignment: .leading)
            Text(d.kind.label)
                .font(DS.font(9, .bold))
                .padding(.horizontal, 5).padding(.vertical, 2)
                .background(d.kind.color.opacity(0.16))
                .foregroundStyle(d.kind.color)
                .clipShape(RoundedRectangle(cornerRadius: DS.R.xs))
                .frame(width: 74, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(d.url)
                    .font(DS.mono(11))
                    .foregroundStyle(d.notable ? DS.C.text : DS.C.textBody)
                    .textSelection(.enabled)
                    .lineLimit(1).truncationMode(.middle)
                if let t = d.title, !t.isEmpty {
                    Text(t).font(DS.font(10)).foregroundStyle(DS.C.textFaint).lineLimit(1)
                }
            }
            Spacer()
            Text("\(d.length) B").font(DS.mono(10)).foregroundStyle(DS.C.textFaint)
        }
        .padding(.horizontal, DS.S.md).padding(.vertical, DS.S.xs)
        .background(d.notable ? d.kind.color.opacity(0.06) : Color.clear)
    }

    private var statusColor: Color {
        switch d.status {
        case 200..<300: return DS.C.success
        case 300..<400: return DS.C.low
        case 400..<500: return DS.C.high
        default:        return DS.C.critical
        }
    }
}

private struct FindingCard: View {
    let finding: Finding
    @State private var expanded = false
    @State private var hovering = false
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
                HStack(spacing: DS.S.sm) {
                    Circle()
                        .fill(finding.severity.color)
                        .frame(width: 8, height: 8)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.title).font(DS.font(13.5, .semibold)).foregroundStyle(DS.C.text)
                        Text(finding.category)
                            .font(DS.font(10.5, .medium))
                            .foregroundStyle(DS.C.textDim)
                    }
                    Spacer()
                    Text(finding.severity.label)
                        .font(DS.font(10, .semibold))
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(finding.severity.color.opacity(0.12))
                        .foregroundStyle(finding.severity.color)
                        .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: 11)).foregroundStyle(DS.C.borderStrong)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: DS.S.sm) {
                    hline().padding(.vertical, DS.S.xxs)
                    labeled("Location", finding.location, mono: true)
                    section("What it is", finding.detail)
                    section("Evidence", finding.evidence, mono: true)
                    if let content = finding.capturedContent, !content.isEmpty {
                        capturedContentSection(content)
                    }
                    section(isPerformance ? "Impact on users" : "How it could be exploited",
                            finding.exploit, tint: DS.C.high)
                    if let repro = finding.reproduction, !repro.isEmpty {
                        reproSection(repro)
                    }
                    section(isPerformance ? "How to make it faster" : "How to fix it",
                            finding.remediation, tint: DS.C.success)
                    if let ref = finding.reference {
                        labeled("Reference", ref)
                    }
                }
                .padding(.top, DS.S.xxs)
            }
        }
        .padding(14)
        .background(hovering && !expanded ? DS.C.hover : DS.C.surfaceElev)
        .clipShape(RoundedRectangle(cornerRadius: DS.R.md, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: DS.R.md, style: .continuous)
                .strokeBorder(DS.C.hairline, lineWidth: 1)
        )
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: hovering)
    }

    private func capturedContentSection(_ content: String) -> some View {
        let lines = content.components(separatedBy: "\n")
        let isLong = lines.count > Self.contentPreviewLines
        let shown = (contentExpanded || !isLong)
            ? content
            : lines.prefix(Self.contentPreviewLines).joined(separator: "\n")

        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: DS.S.xs) {
                Label("FILE CONTENTS — \(lines.count) LINE\(lines.count == 1 ? "" : "S")",
                      systemImage: "doc.text.magnifyingglass")
                    .font(DS.font(10, .bold))
                    .foregroundStyle(finding.severity.color)
                Spacer()
                if isLong {
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) { contentExpanded.toggle() }
                    } label: {
                        Label(contentExpanded ? "Show less" : "Show all \(lines.count) lines",
                              systemImage: contentExpanded ? "chevron.up" : "chevron.down")
                            .font(DS.font(10.5))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(DS.C.textDim)
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
                        .font(DS.font(10.5))
                }
                .buttonStyle(.plain)
                .foregroundStyle(contentCopied ? DS.C.success : DS.C.textDim)
            }

            Text(shown)
                .font(DS.mono(11))
                .foregroundStyle(DS.C.text)
                .textSelection(.enabled)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
                .padding(DS.S.xs)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(DS.C.surface)
                .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
                .overlay(RoundedRectangle(cornerRadius: DS.R.sm)
                    .strokeBorder(finding.severity.color.opacity(0.30)))

            if isLong && !contentExpanded {
                Text("\(lines.count - Self.contentPreviewLines) more lines hidden")
                    .font(DS.font(10.5)).foregroundStyle(DS.C.textDim)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func reproSection(_ command: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Label("PROOF OF CONCEPT — RUN IN TERMINAL", systemImage: "terminal")
                    .font(DS.font(10, .bold))
                    .foregroundStyle(DS.C.poc)
                Spacer()
                Button {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(command, forType: .string)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(DS.font(10.5))
                }
                .buttonStyle(.plain)
                .foregroundStyle(copied ? DS.C.success : DS.C.textDim)
            }
            Text(command)
                .font(DS.mono(11))
                .foregroundStyle(DS.C.accentBright)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(DS.S.xs)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(DS.C.surface)
                .clipShape(RoundedRectangle(cornerRadius: DS.R.sm))
                .overlay(RoundedRectangle(cornerRadius: DS.R.sm).strokeBorder(DS.C.poc.opacity(0.30)))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func section(_ title: String, _ body: String, mono: Bool = false, tint: Color = DS.C.textFaint) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title.uppercased())
                .font(DS.font(10, .bold))
                .tracking(0.4)
                .foregroundStyle(tint)
            Text(body)
                .font(mono ? DS.mono(11) : DS.font(13))
                .foregroundStyle(DS.C.textBody)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func labeled(_ title: String, _ value: String, mono: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("\(title):").font(DS.font(10.5, .bold)).foregroundStyle(DS.C.textFaint)
            Text(value)
                .font(mono ? DS.mono(11) : DS.font(11.5))
                .textSelection(.enabled)
                .foregroundStyle(DS.C.textBody)
        }
    }
}
