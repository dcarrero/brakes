//! `rust`: a Cargo workspace or package. CI installs the toolchain
//! (`rust-toolchain.toml` when seeded, else the pinned channel) with clippy and
//! rustfmt, caches through
//! `Swatinem/rust-cache` saving on the default branch only, and installs
//! nextest only when a declared command uses it.
use crate::Result;

use super::{
    super::{
        App, ContainerSupport, CoverageInstall, CoverageRecipe, CoverageUpload, Evidence,
        Healthcheck, Lockfile, Measure, MutationRecipe, MutationScope, OtelKind, OtelRecipe,
        PinTable, PropertyRecipe, ProposedCommands, Runtime, SeedFile, StackId, StackPack, Step,
        TestRunnerProfile, setup_core_guide,
    },
    OTEL_ENV, save_if,
};

pub const RUST: StackPack = StackPack {
    id: StackId::Rust,
    evidence: &[Evidence::AllOf(&["Cargo.toml", "Cargo.lock"])],
    proposed: ProposedCommands {
        build: Some("cargo build --workspace --all-targets --locked"),
        test: Some("cargo test --workspace --locked"),
        lint: Some("cargo clippy --workspace --all-targets --locked -- -D warnings"),
        verify: Some("{{lint}} && {{test}}"),
    },
    lockfile: Some(Lockfile {
        file: "Cargo.lock",
        strict_flag: "--locked",
    }),
    toolchain_seed: Some(SeedFile {
        path: "rust-toolchain.toml",
        template: include_str!("../../../../../../templates/stack-packs/rust/rust-toolchain.toml"),
    }),
    container: ContainerSupport::Capable {
        runtime: Runtime::Cc,
        port_default: 8080,
        healthcheck_default: Healthcheck::BinaryFlag("--healthcheck"),
    },
    dependabot_ecosystem: "cargo",
    // rustup's default dist server; the sparse index and its `dl` host
    // (https://index.crates.io/config.json, read 2026-10-29).
    egress_hosts: &[
        "static.rust-lang.org",
        "index.crates.io",
        "static.crates.io",
    ],
    macos_target: false,
    // nextest's JUnit output is a profile of `.config/nextest.toml`, not a flag.
    test_runner: Some(TestRunnerProfile {
        one_test: "cargo test --locked {{name}} -- --exact",
        shard: Some("cargo nextest run --locked --partition count:{{i}}/{{n}}"),
        junit: None,
        list_tests: Some("cargo test --locked -- --list"),
    }),
    otel: Some(OtelRecipe {
        kind: OtelKind::Sdk,
        packages: &[
            "opentelemetry",
            "opentelemetry-otlp",
            "tracing-opentelemetry",
        ],
        entrypoint_hint: "",
        env: OTEL_ENV,
        guide: setup_core_guide("docs/agent-setup/observability.md#rust"),
    }),
    // cargo-llvm-cov adds the `llvm-tools-preview` component itself when it
    // is missing (`CARGO_LLVM_COV_SETUP`, README at v0.9.1).
    coverage: Some(CoverageRecipe {
        tool: "cargo-llvm-cov",
        install: CoverageInstall::InstallAction("cargo-llvm-cov"),
        command: "cargo llvm-cov --locked{{tests}} --json --summary-only --output-path coverage.json",
        // The whole workspace unless the project answers its own selection (#1177).
        default_tests: "--workspace",
        report: "coverage.json",
        metric: ".data[0].totals.lines.percent",
        // LCOV, which diff-cover reads (its README, read 2026-10-29).
        diff_command: "cargo llvm-cov --locked{{tests}} --lcov --output-path lcov.info",
        diff_report: "lcov.info",
        // One LCOV report per test job; a line is executed when any job
        // executed it. Only `SF` and `DA` are kept: diff-cover and the
        // characterization check read nothing else (#1349).
        // `$0` and `$2` are awk fields, quoted on purpose (SC2016).
        combine: "# shellcheck disable=SC2016\nfind {{parts}} -type f -name '*.info' | sort | xargs awk -F'[:,]' \
                  '/^SF:/ { f = substr($0, 4); if (!(f in seen)) { seen[f] = 1; order[++n] = f }; next } \
                  /^DA:/ && f != \"\" { k = f SUBSEP $2; if (!(k in hits)) { hits[k] = 0; lines[f] = lines[f] $2 \" \" }; \
                  if ($3 + 0 > hits[k]) hits[k] = $3 + 0; next } \
                  END { for (i = 1; i <= n; i++) { f = order[i]; print \"SF:\" f; m = split(lines[f], l, \" \"); \
                  for (j = 1; j <= m; j++) if (l[j] != \"\") print \"DA:\" l[j] \",\" hits[f SUBSEP l[j]]; print \"end_of_record\" } }' \
                  > lcov.info",
        // The line percentage of the combined LCOV, in the shape `metric`
        // reads: executed `DA` lines over all of them (#22).
        combined_report: "# shellcheck disable=SC2016\nawk -F'[:,]' '/^DA:/ { n++; if ($3 + 0 > 0) h++ } \
                          END { printf \"{\\\"data\\\":[{\\\"totals\\\":{\\\"lines\\\":{\\\"percent\\\":%s}}}]}\\n\", (n ? h * 100 / n : 0) }' \
                          lcov.info > coverage.json",
        // The declared test command runs as declared, instrumented by the
        // environment `show-env` exports (README at v0.9.1, "Get coverage of
        // external tests"); `clean` comes after `show-env`, `report` reads
        // what the command's binaries wrote.
        upload: CoverageUpload {
            measure: Measure::Around {
                before: "source <(cargo llvm-cov show-env --sh)\ncargo llvm-cov clean --workspace",
                after: "cargo llvm-cov report --lcov --output-path lcov.info",
            },
            data: "lcov.info",
            hidden: false,
        },
    }),
    no_coverage: None,
    // proptest reads the seed and the case count from the environment and
    // persists failures beside the test (docs.rs `test_runner::Config`).
    properties: Some(PropertyRecipe {
        seed_env: &[
            ("PROPTEST_RNG_SEED", "{{seed}}"),
            ("PROPTEST_CASES", "{{examples}}"),
        ],
        seed_file: None,
        guide_command: "cargo test --locked --test heldout_properties",
        corpus: "proptest-regressions/ beside the test (FileFailurePersistence::SourceParallel, the default)",
    }),
    // `--in-diff` keeps mutants overlapping the diff's changed regions
    // (mutants.rs "in-diff"); counts in mutants.out/{caught,missed,timeout,unviable}.txt.
    mutation: Some(MutationRecipe {
        tool: "cargo-mutants",
        install: CoverageInstall::InstallAction("cargo-mutants"),
        scope: MutationScope::Diff,
        command: "cargo mutants --no-shuffle --in-diff git.diff",
        stats: None,
        results: "mutants.out",
    }),
    ci_setup,
};

/// The rustup components the proposed commands and a `cargo fmt` check use; the
/// toolchain seed declares the same list (`templates/stack-packs/rust/rust-toolchain.toml`).
pub const COMPONENTS: [&str; 2] = ["clippy", "rustfmt"];

fn ci_setup(app: &App, pins: &PinTable) -> Result<Vec<Step>> {
    // The pinned action refuses an empty `toolchain` input (its action.yml:
    // "'toolchain' is a required input"), so the channel is always passed;
    // when `rust-toolchain.toml` is seeded, rustup's per-directory override
    // still decides which toolchain cargo runs.
    // The pinned action installs `--profile minimal` plus its `components` input
    // (its action.yml), so the proposed `cargo clippy` lint needs them named (#1108).
    let toolchain = Step::new("Install Rust toolchain")
        .uses(pins.action("dtolnay/rust-toolchain")?)
        .with("toolchain", pins.tool("rust")?.version.clone())
        .with("components", COMPONENTS.join(", "));
    let cache = Step::new("Cache cargo registry and target")
        .uses(pins.action("Swatinem/rust-cache")?)
        .with("workspaces", app.path.clone())
        .with("save-if", save_if());
    let mut steps = vec![toolchain, cache];
    if app.declared.values().any(|c| c.contains("cargo nextest")) {
        steps.push(
            Step::new("Install cargo-nextest")
                .uses(pins.action("taiki-e/install-action")?)
                .with("tool", format!("nextest@{}", pins.tool("nextest")?.version)),
        );
    }
    Ok(steps)
}
