//! `go`: a module with `go.mod` and `go.sum`. CI sets Go up from `go.mod` with
//! its own cache off, uses the explicit restore/save pair on the module and
//! build caches, and downloads and verifies modules read-only. The toolchain
//! pin is the `toolchain` directive of `go.mod`, which is never-touch.
use crate::Result;

use super::{
    super::{
        App, ContainerSupport, Evidence, Healthcheck, Lockfile, OtelKind, OtelRecipe, PinTable,
        ProposedCommands, Runtime, StackId, StackPack, Step, TestRunnerProfile, setup_core_guide,
    },
    OTEL_ENV, cache_key, cache_pair, run_in,
};

pub const GO: StackPack = StackPack {
    id: StackId::Go,
    evidence: &[Evidence::AllOf(&["go.mod", "go.sum"])],
    proposed: ProposedCommands {
        build: Some("go build ./..."),
        test: Some("go test ./..."),
        lint: Some("go vet ./..."),
        verify: Some("go mod verify && {{lint}} && {{test}}"),
    },
    lockfile: Some(Lockfile {
        file: "go.sum",
        strict_flag: "-mod=readonly",
    }),
    toolchain_seed: None,
    container: ContainerSupport::Capable {
        runtime: Runtime::Static,
        port_default: 8080,
        healthcheck_default: Healthcheck::BinaryFlag("--healthcheck"),
    },
    dependabot_ecosystem: "gomod",
    // GOPROXY and GOSUMDB defaults (https://go.dev/ref/mod, read 2026-10-29).
    egress_hosts: &["proxy.golang.org", "sum.golang.org"],
    macos_target: false,
    // JUnit needs gotestsum, which the project may add; it is never installed.
    test_runner: Some(TestRunnerProfile {
        one_test: "go test ./... -run '^{{name}}$'",
        shard: None,
        junit: None,
        list_tests: Some("go test ./... -list ."),
    }),
    otel: Some(OtelRecipe {
        kind: OtelKind::Sdk,
        packages: &[
            "go.opentelemetry.io/otel",
            "go.opentelemetry.io/otel/sdk",
            "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp",
        ],
        entrypoint_hint: "",
        env: OTEL_ENV,
        guide: setup_core_guide("docs/agent-setup/observability.md#go"),
    }),
    coverage: None,
    no_coverage: Some(
        "`go test -coverprofile` writes Go's own profile, which diff-cover does not read, and no converter is pinned, so diff-coverage does not judge go apps",
    ),
    properties: None,
    mutation: None,
    ci_setup,
};

fn ci_setup(app: &App, pins: &PinTable) -> Result<Vec<Step>> {
    let go = Step::new("Set up Go")
        .uses(pins.action("actions/setup-go")?)
        .with("go-version-file", format!("{}go.mod", app.prefix()))
        .with("cache", "false");
    let (restore, save) = cache_pair(
        pins,
        "Go module and build caches",
        "~/go/pkg/mod\n~/.cache/go-build",
        &cache_key("go", app, "go.sum"),
    )?;
    let download = run_in(
        app,
        "Download and verify modules",
        "go mod download && go mod verify",
    )
    .env("GOFLAGS", "-mod=readonly");
    Ok(vec![go, restore, download, save])
}
