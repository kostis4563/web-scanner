import Cocoa
import WebKit
import Combine


final class WebSchemeHandler: NSObject, WKURLSchemeHandler {
    let root: URL
    init(root: URL) { self.root = root }

    private func mime(_ ext: String) -> String {
        switch ext.lowercased() {
        case "html": return "text/html; charset=utf-8"
        case "js", "mjs": return "text/javascript; charset=utf-8"
        case "css": return "text/css; charset=utf-8"
        case "json": return "application/json; charset=utf-8"
        case "svg": return "image/svg+xml"
        case "png": return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "webp": return "image/webp"
        case "ico": return "image/x-icon"
        case "woff2": return "font/woff2"
        case "woff": return "font/woff"
        case "ttf": return "font/ttf"
        default: return "application/octet-stream"
        }
    }

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        guard let url = task.request.url else {
            task.didFailWithError(NSError(domain: "app", code: -1)); return
        }
        var path = url.path
        if path.isEmpty || path == "/" { path = "/index.html" }
        let fileURL = root.appendingPathComponent(path).standardizedFileURL
        guard fileURL.path.hasPrefix(root.standardizedFileURL.path),
              let data = try? Data(contentsOf: fileURL) else {
            let resp = HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!
            task.didReceive(resp); task.didFinish(); return
        }
        let headers = ["Content-Type": mime(fileURL.pathExtension), "Cache-Control": "no-cache"]
        let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!
        task.didReceive(resp)
        task.didReceive(data)
        task.didFinish()
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {}
}


final class DragStrip: NSView {
    override func mouseDown(with event: NSEvent) {
        if event.clickCount == 2 { window?.performZoom(nil); return }
        window?.performDrag(with: event)
    }
    override func resetCursorRects() { addCursorRect(bounds, cursor: .arrow) }
}


@MainActor
final class ScannerBridge: NSObject, WKScriptMessageHandler {
    let vm = ScannerViewModel()
    weak var web: WKWebView?

    private var cancellable: AnyCancellable?
    private var pushScheduled = false

    func attach(to web: WKWebView) {
        self.web = web
        cancellable = vm.objectWillChange.sink { [weak self] _ in self?.schedulePush() }
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let type = body["type"] as? String else { return }

        switch type {
        case "ready":
            pushNow()

        case "start":
            vm.target = (body["target"] as? String) ?? ""
            if let m = body["mode"] as? String, let mode = ScanMode(rawValue: m) { vm.mode = mode }
            if let i = body["intensity"] as? String, let it = ScanIntensity(rawValue: i) { vm.intensity = it }
            vm.authorized = true
            vm.startScan()

        case "stop":
            vm.stopScan()

        case "export":
            exportReport(format: (body["format"] as? String) ?? "markdown")

        case "openExternal":
            if let s = body["url"] as? String, let u = URL(string: s) { NSWorkspace.shared.open(u) }

        default:
            break
        }
    }

    private func schedulePush() {
        guard !pushScheduled else { return }
        pushScheduled = true
        DispatchQueue.main.async { [weak self] in
            self?.pushScheduled = false
            self?.pushNow()
        }
    }

    private struct Snapshot: Encodable {
        var running: Bool
        var done: Bool
        var progress: Double
        var status: String
        var host: String
        var target: String
        var mode: String
        var intensity: String
        var log: [String]
        var findings: [Finding]
    }

    private func pushNow() {
        guard let web = web else { return }
        let snap = Snapshot(
            running: vm.isScanning,
            done: vm.finishedAt != nil && !vm.isScanning,
            progress: vm.displayProgress,
            status: vm.statusText,
            host: vm.scanHost,
            target: vm.target,
            mode: vm.mode.rawValue,
            intensity: vm.intensity.rawValue,
            log: vm.logLines,
            findings: vm.sortedFindings
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(snap),
              let json = String(data: data, encoding: .utf8) else { return }
        web.evaluateJavaScript("window.__wsBridge && window.__wsBridge.emit(\(json));", completionHandler: nil)
    }

    private func exportReport(format: String) {
        guard let report = vm.report else { return }
        let isJSON = format == "json"
        let text = isJSON ? ReportExporter.json(report) : ReportExporter.markdown(report)
        let panel = NSSavePanel()
        panel.nameFieldStringValue = isJSON ? "scan-report.json" : "scan-report.md"
        panel.canCreateDirectories = true
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            try? text.data(using: .utf8)?.write(to: url)
        }
    }
}


@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate {
    var window: NSWindow!
    var web: WKWebView!
    let bridge = ScannerBridge()

    func applicationDidFinishLaunching(_ note: Notification) {
        _ = try? CustomDetections.ensureConfigFile()
        installMainMenu()

        let frame = NSRect(x: 0, y: 0, width: 1100, height: 760)
        window = NSWindow(
            contentRect: frame,
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.toolbar = NSToolbar(identifier: "main")
        window.toolbarStyle = .unifiedCompact
        window.backgroundColor = NSColor(red: 0.035, green: 0.035, blue: 0.035, alpha: 1)
        window.setFrameAutosaveName("WebScannerMain")
        window.minSize = NSSize(width: 860, height: 620)
        window.center()

        let resources = Bundle.main.resourceURL!.appendingPathComponent("web")
        let config = WKWebViewConfiguration()
        config.setURLSchemeHandler(WebSchemeHandler(root: resources), forURLScheme: "app")
        config.userContentController.add(bridge, name: "scanner")

        web = WKWebView(frame: frame, configuration: config)
        web.autoresizingMask = [.width, .height]
        web.setValue(false, forKey: "drawsBackground")
        web.navigationDelegate = self
        web.uiDelegate = self

        let root = NSView(frame: frame)
        root.addSubview(web)
        let strip = DragStrip(frame: NSRect(x: 0, y: frame.height - 40, width: frame.width, height: 40))
        strip.autoresizingMask = [.width, .minYMargin]
        root.addSubview(strip)
        window.contentView = root

        bridge.attach(to: web)
        web.load(URLRequest(url: URL(string: "app://app/index.html")!))

        window.makeKeyAndOrderFront(nil)
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func installMainMenu() {
        let appName = "WebScanner"
        let mainMenu = NSMenu()

        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appItem.submenu = appMenu
        appMenu.addItem(withTitle: "About \(appName)",
                        action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide \(appName)",
                        action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthers = appMenu.addItem(withTitle: "Hide Others",
                        action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(withTitle: "Show All",
                        action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit \(appName)",
                        action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        let editItem = NSMenuItem()
        mainMenu.addItem(editItem)
        let editMenu = NSMenu(title: "Edit")
        editItem.submenu = editMenu
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        let redo = editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "z")
        redo.keyEquivalentModifierMask = [.command, .shift]
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        let windowItem = NSMenuItem()
        mainMenu.addItem(windowItem)
        let windowMenu = NSMenu(title: "Window")
        windowItem.submenu = windowMenu
        windowMenu.addItem(withTitle: "Minimize",
                           action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Zoom",
                           action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        windowMenu.addItem(.separator())
        windowMenu.addItem(withTitle: "Close",
                           action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")

        NSApp.mainMenu = mainMenu
        NSApp.windowsMenu = windowMenu
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls { bridge.vm.handleDeepLink(url) }
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, url.scheme == "http" || url.scheme == "https" {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel); return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, createWebViewWith config: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url { NSWorkspace.shared.open(url) }
        return nil
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }
}


@main
enum WebScannerMain {
    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
