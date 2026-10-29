// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "NebulaNode",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "NebulaNode", path: "Sources/NebulaNode"),
        .testTarget(name: "NebulaNodeTests", dependencies: ["NebulaNode"], path: "Tests/NebulaNodeTests"),
    ],
    swiftLanguageModes: [.v5]
)
