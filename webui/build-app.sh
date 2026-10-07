#!/bin/bash
# Builds the React UI and wraps it in a native macOS .app (WKWebView shell).
# No Electron: a ~60-line Swift launcher compiled with swiftc hosts the web build.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_NAME="WebScanner UI"
BUNDLE="$APP_NAME.app"
DO_RUN=0
[[ "${1:-}" == "--run" ]] && DO_RUN=1

echo "==> Installing dependencies (if needed)"
[[ -d node_modules ]] || npm install

echo "==> Building web bundle (vite)"
npm run build

echo "==> Compiling native launcher"
LAUNCHER_SRC="$(mktemp -t ws-launcher-XXXX).swift"
cat > "$LAUNCHER_SRC" <<'SWIFT'
import Cocoa
import WebKit

// Serves the bundled web build over a custom scheme. WKWebView blocks
// ES-module scripts loaded from file:// (null origin), so we expose the
// files under app://app/ instead, where modules load normally.
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

// Invisible strip over the top of the window. WKWebView swallows mouse events,
// so this native view takes clicks there and hands them to the window to drag.
final class DragStrip: NSView {
    override func mouseDown(with event: NSEvent) {
        if event.clickCount == 2 { window?.performZoom(nil); return }
        window?.performDrag(with: event)
    }
    override func resetCursorRects() { addCursorRect(bounds, cursor: .arrow) }
}

let titleBarHeight: CGFloat = 40   // keep in sync with --header-h in src/index.css

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate {
    var window: NSWindow!
    var web: WKWebView!

    func applicationDidFinishLaunching(_ note: Notification) {
        let frame = NSRect(x: 0, y: 0, width: 1080, height: 760)
        window = NSWindow(
            contentRect: frame,
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        // An empty compact toolbar makes the titlebar taller so the traffic
        // lights sit centred in the 40px bar the web UI draws.
        window.toolbar = NSToolbar(identifier: "main")
        window.toolbarStyle = .unifiedCompact
        window.backgroundColor = NSColor(red: 0.035, green: 0.035, blue: 0.035, alpha: 1)
        window.setFrameAutosaveName("WebScannerUI")
        window.center()

        let resources = Bundle.main.resourceURL!.appendingPathComponent("web")
        let config = WKWebViewConfiguration()
        config.setURLSchemeHandler(WebSchemeHandler(root: resources), forURLScheme: "app")

        web = WKWebView(frame: frame, configuration: config)
        web.autoresizingMask = [.width, .height]
        web.setValue(false, forKey: "drawsBackground")

        let root = NSView(frame: frame)
        root.addSubview(web)
        let strip = DragStrip(frame: NSRect(x: 0, y: frame.height - titleBarHeight,
                                            width: frame.width, height: titleBarHeight))
        strip.autoresizingMask = [.width, .minYMargin]
        root.addSubview(strip)
        window.contentView = root

        web.navigationDelegate = self
        web.uiDelegate = self
        web.load(URLRequest(url: URL(string: "app://app/index.html")!))

        window.makeKeyAndOrderFront(nil)
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    // Anything outside the bundled UI (blxr.net, GitHub, ...) opens in the default browser.
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, url.scheme == "http" || url.scheme == "https" {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel); return
        }
        decisionHandler(.allow)
    }

    // target="_blank" links ask for a new web view; hand them to the browser instead.
    func webView(_ webView: WKWebView, createWebViewWith config: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url { NSWorkspace.shared.open(url) }
        return nil
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
SWIFT

rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources/web"

swiftc -O "$LAUNCHER_SRC" -o "$BUNDLE/Contents/MacOS/WebScannerUI"
rm -f "$LAUNCHER_SRC"

echo "==> Assembling bundle"
cp -R dist/. "$BUNDLE/Contents/Resources/web/"

cat > "$BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>WebScanner UI</string>
  <key>CFBundleDisplayName</key><string>WebScanner UI</string>
  <key>CFBundleIdentifier</key><string>net.blxr.webscanner.ui</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>WebScannerUI</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
</dict>
</plist>
PLIST

echo "==> Code signing (ad-hoc)"
codesign --force --deep --sign - "$BUNDLE" >/dev/null 2>&1 || echo "   (ad-hoc signing skipped)"

echo ""
echo "✅ Built: $SCRIPT_DIR/$BUNDLE"
echo "   Open with:  open \"$BUNDLE\""
echo ""

[[ "$DO_RUN" -eq 1 ]] && open "$BUNDLE"
exit 0
