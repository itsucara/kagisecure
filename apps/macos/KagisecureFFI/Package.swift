// swift-tools-version: 6.2
//
// The Rust core, as a local SwiftPM package.
//
// Two targets, on purpose. `kagisecure_ffiFFI` is the binary: a static library plus the C header
// and modulemap that `cargo xtask bindgen` produces, wrapped in an xcframework. `KagisecureFFI`
// is the generated Swift, which is checked into the repository (see
// docs/decisions/0009-checked-in-swift-bindings.md) while the binary is not — running
// `cargo xtask bindgen` is what materialises `Artifacts/`, and a checkout that has not run it
// will fail to resolve this package with a clear message rather than a mysterious link error.

import PackageDescription

let package = Package(
    name: "KagisecureFFI",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "KagisecureFFI", targets: ["KagisecureFFI"])
    ],
    targets: [
        .binaryTarget(
            name: "kagisecure_ffiFFI",
            path: "Artifacts/KagisecureFFI.xcframework"
        ),
        .target(
            name: "KagisecureFFI",
            dependencies: ["kagisecure_ffiFFI"],
            swiftSettings: [
                // Xcode 26 defaults new targets to `MainActor` default isolation, which the
                // UniFFI-generated glue is not written for (mozilla/uniffi-rs#2818): its
                // `Sendable` types and its `nonisolated` free functions stop compiling. The
                // generated code is genuinely thread-agnostic — the Rust side is behind a mutex —
                // so this target opts back out. Only this target: the app's own code keeps the
                // MainActor default it wants.
                .defaultIsolation(nil),
                // Swift 5 language mode, for this generated target only (ADR-0038). UniFFI 0.32's
                // bridge for an async *foreign* trait — `PresenceGate`, which Swift implements
                // and Rust awaits — starts a `Task` from a non-`Sendable` closure in
                // `uniffiTraitInterfaceCallAsync{,WithError}`, which Swift 6's region-based
                // isolation checking rejects as an error. The bridge is sound as written (the
                // closure is handed off exactly once and nothing else touches it), and the
                // generated file is checked in rather than edited (ADR-0009), so the target is
                // compiled in the mode the generator was written for. The app's own code, and
                // the gate the app will implement in phase 2, stay in Swift 6 mode with complete
                // concurrency checking.
                .swiftLanguageMode(.v5),
            ]
        )
    ]
)
