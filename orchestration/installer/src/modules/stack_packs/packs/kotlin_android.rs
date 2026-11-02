//! `kotlin-android`: a Gradle build (`settings.gradle.kts` or `build.gradle.kts`)
//! run through its checked-in wrapper, as the Gradle user guide recommends
//! (`./gradlew`, "Gradle Wrapper Reference", read 2026-10-29). The toolchain
//! pin is `.java-version`, which `actions/setup-java` reads; the wrapper's own
//! pin, `distributionSha256Sum` in `gradle/wrapper/gradle-wrapper.properties`,
//! is the project's and `stack.toolchain-pinned` reports it missing. No
//! lockfile: Gradle's dependency locking is opt-in. No container: a device app.
use crate::Result;

use super::{
    super::{
        App, ContainerSupport, Evidence, PinTable, ProposedCommands, SeedFile, StackId, StackPack,
        Step, TestRunnerProfile,
    },
    DEFAULT_BRANCH_CONDITION,
};

pub const KOTLIN_ANDROID: StackPack = StackPack {
    id: StackId::KotlinAndroid,
    evidence: &[
        Evidence::AnyOf(&["settings.gradle.kts", "build.gradle.kts"]),
        Evidence::AllOf(&["gradlew"]),
    ],
    // `test` only: `assemble`, `lint` and `check` depend on the plugins the
    // build applies, which detection does not read.
    proposed: ProposedCommands {
        build: None,
        test: Some("./gradlew test"),
        lint: None,
        verify: Some("{{lint}} && {{test}}"),
    },
    lockfile: None,
    toolchain_seed: Some(SeedFile {
        path: ".java-version",
        template: include_str!(
            "../../../../../../templates/stack-packs/kotlin-android/java-version"
        ),
    }),
    container: ContainerSupport::NotApplicable,
    dependabot_ecosystem: "gradle",
    // Wrapper distributions (`distributionUrl` of the Gradle wrapper guide);
    // `gradlePluginPortal()`, `mavenCentral()` and `google()` as the Gradle
    // user guide "Declaring repositories" names them (read 2026-10-29);
    // `maven.google.com` redirects artifact paths to `dl.google.com`
    // (observed with a HEAD request the same day).
    egress_hosts: &[
        "services.gradle.org",
        "plugins.gradle.org",
        "repo.maven.apache.org",
        "maven.google.com",
        "dl.google.com",
    ],
    macos_target: false,
    // `--tests` takes a class, `Class.method` or a `*` pattern (Gradle user
    // guide, "Testing in Java & JVM projects", Test filtering). JUnit XML is
    // written under `build/test-results` by default, not by a flag.
    test_runner: Some(TestRunnerProfile {
        one_test: "./gradlew test --tests '{{name}}'",
        shard: None,
        junit: None,
        list_tests: None,
    }),
    otel: None,
    coverage: None,
    no_coverage: Some(
        "no coverage tool is pinned for kotlin-android (JaCoCo is configured in the project's own Gradle build), so diff-coverage does not judge kotlin-android apps",
    ),
    properties: None,
    mutation: None,
    ci_setup,
};

/// `actions/setup-java` (Temurin; `java-version-file` reads the seeded
/// `.java-version`, else the pinned major, README at v6.1.0), then
/// `gradle/actions/setup-gradle`, whose cache is read-only off the default
/// branch (`cache-read-only`, its `setup-gradle.md`) and which validates the
/// wrapper jar against Gradle's published checksums (`validate-wrappers`).
fn ci_setup(app: &App, pins: &PinTable) -> Result<Vec<Step>> {
    let java = Step::new("Set up Java")
        .uses(pins.action("actions/setup-java")?)
        .with("distribution", "temurin");
    let java = if app.toolchain {
        java.with(
            "java-version-file",
            format!("{}.java-version", app.prefix()),
        )
    } else {
        java.with("java-version", pins.tool("java")?.version.clone())
    };
    let gradle = Step::new("Set up Gradle")
        .uses(pins.action("gradle/actions/setup-gradle")?)
        .with(
            "cache-read-only",
            format!("${{{{ !({DEFAULT_BRANCH_CONDITION}) }}}}"),
        )
        .with("validate-wrappers", "true");
    Ok(vec![java, gradle])
}
