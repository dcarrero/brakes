//! `python-uv`: a project with `pyproject.toml` and `uv.lock`. CI installs uv
//! with its own cache off and uses the explicit restore/save pair, so the save
//! happens on the default branch only (owner decision closing the spec's Open
//! question 4); `uv python install` reads `.python-version` when it is seeded.
use crate::Result;

use super::{
    super::{
        App, ContainerSupport, CoverageInstall, CoverageRecipe, CoverageUpload, Evidence,
        Healthcheck, Lockfile, Measure, MutationRecipe, MutationScope, OtelKind, OtelRecipe,
        PinTable, PropertyRecipe, ProposedCommands, Runtime, SeedFile, StackId, StackPack, Step,
        TestRunnerProfile, setup_core_guide,
    },
    OTEL_ENV, cache_key, cache_pair, run_in,
};

pub const PYTHON_UV: StackPack = StackPack {
    id: StackId::PythonUv,
    evidence: &[Evidence::AllOf(&["pyproject.toml", "uv.lock"])],
    proposed: ProposedCommands {
        build: None,
        test: Some("uv run --frozen pytest -q"),
        lint: Some("uv run --frozen ruff check ."),
        verify: Some("{{lint}} && {{test}}"),
    },
    lockfile: Some(Lockfile {
        file: "uv.lock",
        strict_flag: "--frozen",
    }),
    toolchain_seed: Some(SeedFile {
        path: ".python-version",
        template: include_str!("../../../../../../templates/stack-packs/python-uv/python-version"),
    }),
    container: ContainerSupport::Capable {
        runtime: Runtime::Python,
        port_default: 8000,
        healthcheck_default: Healthcheck::Command(
            r#"["/usr/bin/python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:{{port}}/')"]"#,
        ),
    },
    dependabot_ecosystem: "uv",
    // The default index and its file storage (pip `models/index.py`, `PyPI`).
    egress_hosts: &["pypi.org", "files.pythonhosted.org"],
    macos_target: false,
    test_runner: Some(TestRunnerProfile {
        one_test: "uv run --frozen pytest {{nodeid}}",
        shard: None,
        junit: Some("--junitxml={{out}}"),
        list_tests: Some("uv run --frozen pytest --collect-only -q"),
    }),
    // `opentelemetry-instrument` as the seeded ENTRYPOINT can run it: the
    // console script's shebang names the build stage's interpreter, and the
    // package has no `__main__`, so its `run()` is called; it puts the
    // auto-instrumentation `sitecustomize` on PYTHONPATH and execs the app.
    // `opentelemetry-bootstrap -a requirements` names the instrumentation
    // packages for the libraries installed; the guide says so.
    otel: Some(OtelRecipe {
        kind: OtelKind::ZeroCode,
        packages: &["opentelemetry-distro", "opentelemetry-exporter-otlp"],
        entrypoint_hint: r#"["/usr/bin/python3", "-c", "from opentelemetry.instrumentation.auto_instrumentation import run; run()", "/usr/bin/python3", "-m", "app"]"#,
        env: OTEL_ENV,
        guide: setup_core_guide("docs/agent-setup/observability.md#python-uv"),
    }),
    // Line coverage: `percent_covered` mixes branches in when the project sets
    // `branch = true`, so the metric divides lines; an empty run is 0, as
    // llvm-cov reports it. The project's `[tool.coverage]` settings apply.
    // `--all-extras` (#1169): pytest often lives in an optional extra, which
    // neither `uv sync --frozen` nor `uv run` installs unless asked.
    // `-i` (#1239): a file a test generated, ran and deleted is a warning, not
    // a failed report, so a measured run always writes its report.
    // pytest-cov (#1342): `coverage run` measures only pytest's own process, so a
    // project running pytest-xdist recorded nothing; pytest-cov gathers every
    // worker into `.coverage` and the report step reads it. `python -m` keeps the
    // working directory on `sys.path`, as `coverage run -m` did.
    // `COVERAGE_CORE=sysmon` (#1370): the default settrace core made a 3.12 xdist
    // suite 3-4x slower. Where sys.monitoring cannot serve (Python < 3.12, branch
    // coverage on 3.12/3.13) coverage.py uses its default core and warns
    // `no-sysmon` (changes 7.4.2 and 7.11.3, read 2026-11-02 for 7.17.0).
    coverage: Some(CoverageRecipe {
        tool: "coverage-py",
        install: CoverageInstall::InCommand,
        command: "COVERAGE_CORE=sysmon uv run --frozen --all-extras --with coverage=={{version}} --with pytest-cov=={{pin:pytest-cov}} \
                  python -m pytest -q --cov --cov-report={{tests}} \
                  && uv run --frozen --all-extras --with coverage=={{version}} coverage json -q -i -o coverage.json",
        // Every test pytest collects unless the project answers a selection (#1177).
        default_tests: "",
        report: "coverage.json",
        metric: "if .totals.num_statements == 0 then 0 \
                 else .totals.covered_lines * 100 / .totals.num_statements end",
        // Cobertura, which diff-cover reads (its README, read 2026-10-29).
        diff_command: "COVERAGE_CORE=sysmon uv run --frozen --all-extras --with coverage=={{version}} --with pytest-cov=={{pin:pytest-cov}} \
                       python -m pytest -q --cov --cov-report={{tests}} \
                       && uv run --frozen --all-extras --with coverage=={{version}} coverage xml -q -i -o coverage.xml",
        diff_report: "coverage.xml",
        // One data file per test job (`.coverage`, or `.coverage.<suffix>` with
        // `parallel`); `coverage combine` takes them by name (#1349), through
        // xargs -0 so no unquoted expansion splits them (SC2046, #1352).
        combine: "find {{parts}} -type f -name '.coverage*' -print0 | sort -z \
                  | xargs -0 uv run --frozen --all-extras --with coverage=={{version}} coverage combine --keep \
                  && uv run --frozen --all-extras --with coverage=={{version}} coverage xml -q -i -o coverage.xml",
        // coverage.py measures the interpreter it starts, so the measured
        // pytest run takes the declared test command's place; it writes the
        // data file `.coverage` that `combine` reads.
        upload: CoverageUpload {
            measure: Measure::Instead(
                "COVERAGE_CORE=sysmon uv run --frozen --all-extras --with coverage=={{version}} --with pytest-cov=={{pin:pytest-cov}} \
                 python -m pytest -q --cov --cov-report={{tests}}",
            ),
            data: ".coverage",
            hidden: true,
        },
    }),
    no_coverage: None,
    // Hypothesis's `ci` profile (active whenever `CI` is set) derandomizes;
    // the seeded conftest under the held-out directory turns randomness back
    // on and reads HELDOUT_EXAMPLES, and the command passes the seed
    // (Hypothesis API reference, read 2026-10-29).
    properties: Some(PropertyRecipe {
        seed_env: &[],
        seed_file: Some(SeedFile {
            path: "{{heldout_dir}}/conftest.py",
            template: include_str!(
                "../../../../../../templates/stack-packs/seeds/heldout-conftest.py"
            ),
        }),
        guide_command: r#"uv run --frozen pytest -q {{heldout_dir}}/properties --hypothesis-seed="$HELDOUT_SEED""#,
        corpus: "@example / @reproduce_failure in the test file",
    }),
    // mutmut 3 has no diff mode: one run per changed file, then the stats
    // file its badge reads (`__main__.py` at 3.8.1). `--all-extras` as for
    // coverage (#1169): the tests' own dependencies often live in an extra.
    mutation: Some(MutationRecipe {
        tool: "mutmut",
        install: CoverageInstall::InCommand,
        scope: MutationScope::ChangedFiles,
        command: r#"uv run --frozen --all-extras --with mutmut=={{version}} mutmut run "{{module}}*""#,
        stats: Some(
            "uv run --frozen --all-extras --with mutmut=={{version}} mutmut export-cicd-stats",
        ),
        results: "mutants/mutmut-cicd-stats.json",
    }),
    ci_setup,
};

fn ci_setup(app: &App, pins: &PinTable) -> Result<Vec<Step>> {
    let uv = Step::new("Install uv")
        .uses(pins.action("astral-sh/setup-uv")?)
        .with("version", pins.tool("uv")?.version.clone())
        .with("enable-cache", "false");
    let (restore, save) = cache_pair(
        pins,
        "uv cache",
        "~/.cache/uv",
        &cache_key("uv", app, "uv.lock"),
    )?;
    let python = if app.toolchain {
        "uv python install".to_owned()
    } else {
        format!("uv python install {}", pins.tool("python")?.version)
    };
    Ok(vec![
        uv,
        restore,
        run_in(app, "Install Python", &python),
        run_in(app, "Sync dependencies", "uv sync --frozen"),
        save,
    ])
}
