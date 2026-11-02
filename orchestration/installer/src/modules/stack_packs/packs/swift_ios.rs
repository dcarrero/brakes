//! `swift-ios`: an Xcode project (`*.xcodeproj`) or a Swift package
//! (`Package.swift`). `xcodebuild test` needs a scheme, which is never
//! invented: detection fills `{{scheme}}` only when the project shares exactly
//! one (`<project>.xcodeproj/xcshareddata/xcschemes/<name>.xcscheme`), and a
//! package without a project gets `SWIFTPM`. `-destination` is left to
//! xcodebuild, which "defaults to a destination that is compatible with the
//! selected scheme" (`man xcodebuild`, Xcode command line tools, read
//! 2026-10-29). The toolchain pin is `.xcode-version`; CI selects
//! `/Applications/Xcode_<version>.app`, the layout of GitHub's macOS runner
//! images (`actions/runner-images`, macos-15 README, read 2026-10-29). The
//! only macOS target: `ci-baseline`'s `macos` job runs the declared commands.
use crate::Result;

use super::{
    super::{
        App, ContainerSupport, Evidence, PinTable, ProposedCommands, SeedFile, StackId, StackPack,
        Step, TestRunnerProfile,
    },
    run_in,
};

pub const SWIFT_IOS: StackPack = StackPack {
    id: StackId::SwiftIos,
    evidence: &[Evidence::AnyOf(&["*.xcodeproj", "Package.swift"])],
    proposed: ProposedCommands {
        build: None,
        test: Some("xcodebuild test -scheme {{scheme}}"),
        lint: None,
        verify: Some("{{lint}} && {{test}}"),
    },
    // `Package.resolved` pins versions, but neither `swift test` nor
    // `xcodebuild` enforces it by default; no strict flag is proposed.
    lockfile: None,
    toolchain_seed: Some(SeedFile {
        path: ".xcode-version",
        template: include_str!("../../../../../../templates/stack-packs/swift-ios/xcode-version"),
    }),
    container: ContainerSupport::NotApplicable,
    dependabot_ecosystem: "swift",
    // Packages resolve from the git hosts the manifest names, nothing fixed.
    egress_hosts: &[],
    macos_target: true,
    // `-only-testing Target[/Class[/Method]]` and `-enumerate-tests`
    // (`man xcodebuild`).
    test_runner: Some(TestRunnerProfile {
        one_test: "xcodebuild test -scheme {{scheme}} -only-testing '{{name}}'",
        shard: None,
        junit: None,
        list_tests: Some("xcodebuild test -scheme {{scheme}} -enumerate-tests"),
    }),
    otel: None,
    coverage: None,
    no_coverage: Some(
        "xccov's report is not a format diff-cover reads and no converter is pinned, so diff-coverage does not judge swift-ios apps",
    ),
    properties: None,
    mutation: None,
    ci_setup,
};

/// The proposals of a Swift package with no Xcode project: SwiftPM needs no scheme.
pub const SWIFTPM: ProposedCommands = ProposedCommands {
    build: Some("swift build"),
    test: Some("swift test"),
    lint: None,
    verify: Some("{{lint}} && {{test}}"),
};

/// One `run:` step selecting the Xcode the seed names (`.xcode-version` in the
/// app directory) or the pinned one, and printing its version.
fn ci_setup(app: &App, pins: &PinTable) -> Result<Vec<Step>> {
    let command = if app.toolchain {
        "sudo xcode-select -s \"/Applications/Xcode_$(cat .xcode-version).app\" && xcodebuild -version"
            .to_owned()
    } else {
        format!(
            "sudo xcode-select -s /Applications/Xcode_{}.app && xcodebuild -version",
            pins.tool("xcode")?.version
        )
    };
    Ok(vec![run_in(app, "Select Xcode", &command)])
}
