// swift-tools-version:5.5
// Intentionally vulnerable Swift package for security testing

import PackageDescription

let package = Package(
    name: "VulnerableIOSApp",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "VulnerableIOSApp",
            targets: ["VulnerableIOSApp"]),
    ],
    dependencies: [
        // VULNERABLE: Outdated dependencies with known vulnerabilities
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "4.9.0"),
        .package(url: "https://github.com/SwiftyJSON/SwiftyJSON.git", from: "4.0.0"),
        .package(url: "https://github.com/realm/realm-swift.git", from: "5.0.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "VulnerableIOSApp",
            dependencies: [
                "Alamofire",
                "SwiftyJSON",
                .product(name: "RealmSwift", package: "realm-swift"),
                "CryptoSwift"
            ]),
        .testTarget(
            name: "VulnerableIOSAppTests",
            dependencies: ["VulnerableIOSApp"]),
    ]
)
