// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "WebScanner",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        .executableTarget(
            name: "WebScanner",
            path: "Sources/WebScanner"
        )
    ]
)
