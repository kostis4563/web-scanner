import SwiftUI

@main
struct WebScannerApp: App {
    init() {
        _ = try? CustomDetections.ensureConfigFile()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}
