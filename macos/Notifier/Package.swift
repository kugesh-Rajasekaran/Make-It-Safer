// swift-tools-version:5.9
// Make-It-Safer Notifier: the macOS helper app that shows notifications.
import PackageDescription

let package = Package(
    name: "Notifier",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "Notifier", path: "Sources/Notifier")
    ]
)
