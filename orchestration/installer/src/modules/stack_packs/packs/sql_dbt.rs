//! `sql-dbt`: a dbt project (`dbt_project.yml`, "this is how dbt knows a
//! directory is a dbt project", dbt reference, read 2026-10-29). `dbt build`
//! runs seeds, models, snapshots and tests in DAG order; `sqlfluff lint` reads
//! the dialect and the dbt templater from the project's `.sqlfluff`, so
//! detection proposes it only when that file exists. The toolchain pin is
//! `.python-version`, as for `python-uv`; CI installs the pinned `dbt-core`,
//! `sqlfluff` and `sqlfluff-templater-dbt` with pip. The warehouse adapter
//! and `profiles.yml` are the project's: a declared `dbt build` needs the
//! connection the project provides (slice 4, with `db-safety`). dbt's
//! `package-lock.yml` pins packages but `dbt deps` honours it with no flag,
//! so no lockfile with a strict flag is declared. No container: a data pack.
use crate::Result;

use super::{
    super::{
        App, ContainerSupport, Evidence, PinTable, ProposedCommands, SeedFile, StackId, StackPack,
        Step, TestRunnerProfile,
    },
    cache_pair, run_in,
};

pub const SQL_DBT: StackPack = StackPack {
    id: StackId::SqlDbt,
    evidence: &[Evidence::AllOf(&["dbt_project.yml"])],
    proposed: ProposedCommands {
        build: None,
        test: Some("dbt build"),
        lint: Some("sqlfluff lint"),
        verify: Some("{{lint}} && {{test}}"),
    },
    lockfile: None,
    toolchain_seed: Some(SeedFile {
        path: ".python-version",
        template: include_str!("../../../../../../templates/stack-packs/python-uv/python-version"),
    }),
    container: ContainerSupport::NotApplicable,
    dependabot_ecosystem: "pip",
    // pip's default index and its file storage; dbt's package hub
    // (docs.getdbt.com, "Packages": "Package hub, registry for dbt packages").
    egress_hosts: &["pypi.org", "files.pythonhosted.org", "hub.getdbt.com"],
    macos_target: false,
    // `build` and `test` take the standard node selection (`--select`);
    // `dbt ls --resource-type test` lists the tests (dbt reference, "build").
    test_runner: Some(TestRunnerProfile {
        one_test: "dbt test --select '{{name}}'",
        shard: None,
        junit: None,
        list_tests: Some("dbt ls --resource-type test"),
    }),
    otel: None,
    coverage: None,
    no_coverage: Some(
        "a dbt project's models have no line coverage, so diff-coverage does not judge sql-dbt apps",
    ),
    properties: None,
    mutation: None,
    ci_setup,
};

/// `actions/setup-python` (`python-version-file` reads the seeded
/// `.python-version`, else the pinned version; its own cache is left off since
/// it saves on every run), the explicit pip cache pair keyed by the pinned
/// tool versions, and the install between them.
fn ci_setup(app: &App, pins: &PinTable) -> Result<Vec<Step>> {
    let python = Step::new("Set up Python").uses(pins.action("actions/setup-python")?);
    let python = if app.toolchain {
        python.with(
            "python-version-file",
            format!("{}.python-version", app.prefix()),
        )
    } else {
        python.with("python-version", pins.tool("python")?.version.clone())
    };
    let dbt = &pins.tool("dbt-core")?.version;
    let sqlfluff = &pins.tool("sqlfluff")?.version;
    let (restore, save) = cache_pair(
        pins,
        "pip cache",
        "~/.cache/pip",
        &format!("${{{{ runner.os }}}}-pip-dbt-core-{dbt}-sqlfluff-{sqlfluff}"),
    )?;
    let install = run_in(
        app,
        "Install dbt and sqlfluff",
        &format!(
            "python -m pip install dbt-core=={dbt} sqlfluff=={sqlfluff} sqlfluff-templater-dbt=={sqlfluff}"
        ),
    );
    Ok(vec![python, restore, install, save])
}
