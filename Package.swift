// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CVEScout",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "CVEScoutApp", targets: ["CVEScoutApp"]),
        .executable(name: "cvescout", targets: ["CVEScoutCLI"]),
        .library(name: "CVEScoutCore", targets: ["CVEScoutCore"]),
    ],
    targets: [
        .target(name: "CVEScoutCore"),
        .executableTarget(name: "CVEScoutApp", dependencies: ["CVEScoutCore"]),
        .executableTarget(name: "CVEScoutCLI", dependencies: ["CVEScoutCore"]),
        .testTarget(name: "CVEScoutCoreTests", dependencies: ["CVEScoutCore"]),
    ]
)
