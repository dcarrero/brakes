//! The pack shape other modules compile against, and the GitHub Actions step
//! as data that `ci-baseline` embeds. Everything is `'static` data except the
//! inputs of `ci_setup`; a pack holds no `String`, no I/O and no boxed closure.
use crate::{Result, refuse};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr};

use super::pins::PinTable;

/// The stacks a pack can describe. Serialised in kebab-case, as the answers
/// file and `project.json` spell them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StackId {
    Rust,
    PythonUv,
    Node,
    Go,
    KotlinAndroid,
    SwiftIos,
    SqlDbt,
}

impl StackId {
    pub const ALL: [StackId; 7] = [
        StackId::Rust,
        StackId::PythonUv,
        StackId::Node,
        StackId::Go,
        StackId::KotlinAndroid,
        StackId::SwiftIos,
        StackId::SqlDbt,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            StackId::Rust => "rust",
            StackId::PythonUv => "python-uv",
            StackId::Node => "node",
            StackId::Go => "go",
            StackId::KotlinAndroid => "kotlin-android",
            StackId::SwiftIos => "swift-ios",
            StackId::SqlDbt => "sql-dbt",
        }
    }
}

impl fmt::Display for StackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StackId {
    type Err = Box<dyn std::error::Error>;
    fn from_str(text: &str) -> Result<Self> {
        match StackId::ALL.iter().find(|id| id.as_str() == text) {
            Some(id) => Ok(*id),
            None => {
                let names: Vec<_> = StackId::ALL.iter().map(|id| id.as_str()).collect();
                refuse(format!(
                    "stack-packs: `{text}` is not a stack; one of {}",
                    names.join(", ")
                ))
            }
        }
    }
}

/// Files whose presence suggests a pack, at the app path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    AllOf(&'static [&'static str]),
    AnyOf(&'static [&'static str]),
}

/// Commands a pack proposes for `null` fields of `project.json`; `{{lint}}`,
/// `{{test}}` compose and `{{wd}}` is the app path when it is not `.`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposedCommands {
    pub build: Option<&'static str>,
    pub test: Option<&'static str>,
    pub lint: Option<&'static str>,
    pub verify: Option<&'static str>,
}

/// The lockfile a pack expects and the flag that makes installs respect it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lockfile {
    pub file: &'static str,
    pub strict_flag: &'static str,
}

/// A file a pack seeds into the app path (`seed` ownership): its path inside
/// the app and its template under `templates/stack-packs/<pack>/`, whose
/// `{{tools.<key>}}` placeholders resolve from the pin table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedFile {
    pub path: &'static str,
    pub template: &'static str,
}

/// The runtime image family member a container-capable pack runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    Static,
    Cc,
    Python,
    Node,
}

impl Runtime {
    /// The image key suffix in the pin table: `<family>.<runtime>`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Runtime::Static => "static",
            Runtime::Cc => "cc",
            Runtime::Python => "python",
            Runtime::Node => "node",
        }
    }
}

/// The pack's default `HEALTHCHECK`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Healthcheck {
    /// The binary's own flag, e.g. `--healthcheck` (static and cc runtimes).
    BinaryFlag(&'static str),
    /// A command the runtime image can run, as the exec-form JSON array
    /// `HEALTHCHECK CMD` takes (the runtime images have no shell); `{{port}}`
    /// is the app's port.
    Command(&'static str),
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerSupport {
    Capable {
        runtime: Runtime,
        port_default: u16,
        healthcheck_default: Healthcheck,
    },
    /// Device and data packs build no image; `container: true` refuses.
    NotApplicable,
}

/// How a pack runs tests one at a time or in shards (data for `qa`). The
/// placeholders are `qa`'s to fill: `{{name}}` a test name, `{{nodeid}}` a
/// pytest node id, `{{i}}`/`{{n}}` a shard of a count, `{{out}}` a report
/// path, `{{exec}}` the node package manager's binary runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestRunnerProfile {
    pub one_test: &'static str,
    pub shard: Option<&'static str>,
    pub junit: Option<&'static str>,
    pub list_tests: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtelKind {
    ZeroCode,
    Sdk,
}

/// Where a pack's OpenTelemetry instrumentation starts (data for `observability`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtelRecipe {
    pub kind: OtelKind,
    pub packages: &'static [&'static str],
    pub entrypoint_hint: &'static str,
    pub env: &'static [&'static str],
    /// The section of `setup-core`'s observability guide for this pack; `None`
    /// when the build has no `setup-core`, which installs that guide (#1247).
    pub guide: Option<&'static str>,
}

/// `path` with `setup-core`, `None` without it: data never names a guide the
/// build does not install.
pub const fn setup_core_guide(path: &'static str) -> Option<&'static str> {
    if cfg!(feature = "setup-core") {
        Some(path)
    } else {
        None
    }
}

/// How the coverage tool reaches CI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageInstall {
    /// The command fetches the tool itself at its pinned `{{version}}`
    /// (`uv run --with coverage=={{version}}`).
    InCommand,
    /// A `taiki-e/install-action` step with `tool: <name>@<version>`, as
    /// nextest is installed.
    InstallAction(&'static str),
}

/// Line coverage for one stack (data for `security`'s `coverage-ratchet`,
/// SPEC-security.md slice 3): the command that writes `report`, and the jq
/// filter that reads one number from it, the line percentage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageRecipe {
    /// The pin-table `tools` key of the coverage tool.
    pub tool: &'static str,
    pub install: CoverageInstall,
    /// Runs the tests under coverage and writes `report` in the app
    /// directory; `{{version}}` is the tool's pinned version, `{{pin:<key>}}`
    /// another tool's, and `{{tests}}` the test selection.
    pub command: &'static str,
    /// The selection `{{tests}}` takes unless `security` answers
    /// `coverage_test_args.<app id>` (#1177); empty for none.
    pub default_tests: &'static str,
    pub report: &'static str,
    /// A jq filter over `report` printing the line percentage.
    pub metric: &'static str,
    /// Runs the tests under coverage and writes `diff_report`, the per-file
    /// report `diff-cover` reads (security's `diff-coverage`).
    pub diff_command: &'static str,
    /// `coverage.xml` (Cobertura) or `lcov.info` (LCOV), in the app directory.
    pub diff_report: &'static str,
    /// Writes `diff_report` in the app directory from the data the project's
    /// own test jobs uploaded under `{{parts}}` (security's `coverage_source:
    /// project-ci`, #1349), without running a test.
    pub combine: &'static str,
    /// What the project's own CI test job runs and uploads for `combine` (#20).
    pub upload: CoverageUpload,
}

/// How a measured run relates to the project's declared test command (#20).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measure {
    /// The declared test command runs unchanged between `before` and `after`:
    /// the tool instruments what the command builds.
    Around {
        before: &'static str,
        after: &'static str,
    },
    /// The pack's measured run takes the place of the declared test command:
    /// the tool measures only the interpreter it starts itself. `{{version}}`,
    /// `{{pin:<key>}}` and `{{tests}}` as in `CoverageRecipe::command`.
    Instead(&'static str),
}

/// The coverage data a project's test job uploads as
/// `agentic-coverage-<app id>-<job>`, the artifact `diff-coverage` downloads
/// (#20): `brakes` judges it and never measures by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageUpload {
    pub measure: Measure,
    /// The data file the run writes in the app directory.
    pub data: &'static str,
    /// The file name starts with a dot: `upload-artifact` skips it unless
    /// `include-hidden-files` is set (its README at v4.4.0 and later).
    pub hidden: bool,
}

/// The artifact a project's test job `job` uploads for `app`.
pub fn coverage_artifact(app: &App, job: &str) -> String {
    format!("agentic-coverage-{}-{job}", app.id)
}

/// `steps` as the `steps:` items of a job, the form every workflow renders.
pub fn steps_yaml(steps: &[Step]) -> String {
    let mut out = String::new();
    for step in steps {
        crate::modules::ci_baseline::render::step(&mut out, step);
    }
    out
}

impl CoverageRecipe {
    /// `command` with the tool's pinned version and `tests` (the answered
    /// selection) or `default_tests`. Refuses when the pin is missing.
    pub fn render_command(&self, pins: &PinTable, tests: Option<&str>) -> Result<String> {
        Ok(self.with_tests(&with_version(self.command, self.tool, pins)?, tests))
    }

    /// `combine` with the pins and `parts`, the directory the parts were downloaded to.
    pub fn render_combine(&self, pins: &PinTable, parts: &str) -> Result<String> {
        Ok(with_version(self.combine, self.tool, pins)?.replace("{{parts}}", parts))
    }

    /// `diff_command`, rendered as `render_command` renders `command`.
    pub fn render_diff_command(&self, pins: &PinTable, tests: Option<&str>) -> Result<String> {
        Ok(self.with_tests(&with_version(self.diff_command, self.tool, pins)?, tests))
    }

    /// `{{tests}}` as ` <selection>`, or nothing when the selection is empty.
    fn with_tests(&self, template: &str, tests: Option<&str>) -> String {
        let tests = tests.unwrap_or(self.default_tests);
        let tests = if tests.is_empty() {
            String::new()
        } else {
            format!(" {tests}")
        };
        template.replace("{{tests}}", &tests)
    }

    /// The step that installs the tool, or `None` when the command fetches it.
    pub fn install_step(&self, pins: &PinTable) -> Result<Option<Step>> {
        install_step(self.tool, self.install, pins)
    }

    /// The steps of the project's test job `job` for `app` (#20): the tool's
    /// install, the measured run, and the upload of the data as
    /// `coverage_artifact(app, job)`. `test` is the shell that runs the
    /// declared test command; under `Measure::Instead` the pack's run replaces
    /// it. `tests` is the answered selection, as for `render_command`. A job
    /// that is not kebab-case refuses: it names an artifact.
    pub fn upload_steps(
        &self,
        app: &App,
        job: &str,
        test: &str,
        pins: &PinTable,
        tests: Option<&str>,
    ) -> Result<Vec<Step>> {
        let kebab = !job.is_empty()
            && !job.starts_with('-')
            && job
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !kebab {
            return refuse(format!(
                "stack-packs: the coverage artifact's job `{job}` must be kebab-case"
            ));
        }
        let (name, run) = match self.upload.measure {
            Measure::Around { before, after } => (
                "Run the tests under coverage".to_owned(),
                format!("{before}\n{test}\n{after}"),
            ),
            Measure::Instead(command) => (
                "Run the tests under coverage, in place of the declared test command".to_owned(),
                self.with_tests(&with_version(command, self.tool, pins)?, tests),
            ),
        };
        let mut measured = Step::new(name).run(run);
        measured.working_directory = app.working_directory();
        let mut upload = Step::new("Upload the coverage data")
            .uses(pins.action("actions/upload-artifact")?)
            .with("name", coverage_artifact(app, job))
            .with("path", format!("{}{}", app.prefix(), self.upload.data))
            .with("if-no-files-found", "error");
        if self.upload.hidden {
            upload = upload.with("include-hidden-files", "true");
        }
        Ok(self
            .install_step(pins)?
            .into_iter()
            .chain([measured, upload])
            .collect())
    }
}

/// How a pack runs held-out property-based tests with a fresh seed (data for
/// `ci-baseline`'s `heldout-properties`). `{{seed}}` and `{{examples}}` are the
/// job's `HELDOUT_SEED` and `HELDOUT_EXAMPLES`; `{{heldout_dir}}` is the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropertyRecipe {
    /// Environment the job sets for the runner, by variable name.
    pub seed_env: &'static [(&'static str, &'static str)],
    /// A file seeded under the held-out directory that reads the environment.
    pub seed_file: Option<SeedFile>,
    /// What the guide proposes for `heldout_properties_command`; never written
    /// to the answers.
    pub guide_command: &'static str,
    /// Where minimised failures persist, for the guide.
    pub corpus: &'static str,
}

/// What a mutation run is restricted to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationScope {
    /// The changed regions of a `git diff` (`cargo mutants --in-diff`).
    Diff,
    /// Each changed source file, once per file (`{{module}}` in `command`);
    /// for tools without a diff mode.
    ChangedFiles,
}

/// Mutation testing for one stack (data for `security`'s `mutation-diff`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationRecipe {
    /// The pin-table `tools` key of the mutation tool.
    pub tool: &'static str,
    pub install: CoverageInstall,
    pub scope: MutationScope,
    /// Runs the mutants in scope; `{{version}}` is the tool's pin.
    pub command: &'static str,
    /// Writes `results` after the runs, when the tool needs a separate step.
    pub stats: Option<&'static str>,
    /// Where the counts are, relative to the app directory.
    pub results: &'static str,
}

impl MutationRecipe {
    /// `command` with the tool's pinned version. Refuses when the pin is missing.
    pub fn render_command(&self, pins: &PinTable) -> Result<String> {
        with_version(self.command, self.tool, pins)
    }

    /// `stats` with the tool's pinned version, when the recipe has one.
    pub fn render_stats(&self, pins: &PinTable) -> Result<Option<String>> {
        self.stats
            .map(|stats| with_version(stats, self.tool, pins))
            .transpose()
    }

    /// The step that installs the tool, or `None` when the command fetches it.
    pub fn install_step(&self, pins: &PinTable) -> Result<Option<Step>> {
        install_step(self.tool, self.install, pins)
    }
}

fn with_version(template: &str, tool: &str, pins: &PinTable) -> Result<String> {
    let mut out = template.replace("{{version}}", &pins.tool(tool)?.version);
    // `{{pin:<key>}}`: another tool's pinned version (#1342: pytest-cov beside coverage-py).
    while let Some(start) = out.find("{{pin:") {
        let Some(len) = out[start..].find("}}") else {
            break;
        };
        let key = out[start + "{{pin:".len()..start + len].to_owned();
        let version = pins.tool(&key)?.version.clone();
        out.replace_range(start..start + len + "}}".len(), &version);
    }
    Ok(out)
}

/// The `taiki-e/install-action` step for `InstallAction`, as nextest is installed.
fn install_step(tool: &str, install: CoverageInstall, pins: &PinTable) -> Result<Option<Step>> {
    let version = &pins.tool(tool)?.version;
    match install {
        CoverageInstall::InCommand => Ok(None),
        CoverageInstall::InstallAction(name) => Ok(Some(
            Step::new(format!("Install {name}"))
                .uses(pins.action("taiki-e/install-action")?)
                .with("tool", format!("{name}@{version}")),
        )),
    }
}

/// The node package manager, from the lockfile present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

/// One app of a repository as the answers record it: what `ci_setup` reads.
/// `declared` are the `commands.*` of the app's profile, by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    pub id: String,
    pub path: String,
    pub stack: StackId,
    pub container: bool,
    pub toolchain: bool,
    pub package_manager: Option<PackageManager>,
    pub declared: BTreeMap<String, String>,
}

impl App {
    /// The app path as a prefix for files inside it: empty for `.`.
    pub fn prefix(&self) -> String {
        if self.path == "." {
            String::new()
        } else {
            format!("{}/", self.path.trim_end_matches('/'))
        }
    }
    /// The step `working-directory`: `None` for the root app.
    pub fn working_directory(&self) -> Option<String> {
        (self.path != ".").then(|| self.path.clone())
    }
}

/// One stack, described. The shape is the contract; the four packs land in
/// `packs/` as `const` values.
pub struct StackPack {
    pub id: StackId,
    pub evidence: &'static [Evidence],
    pub proposed: ProposedCommands,
    /// `None` for a stack whose tooling has no lockfile-strict install yet.
    pub lockfile: Option<Lockfile>,
    pub toolchain_seed: Option<SeedFile>,
    pub container: ContainerSupport,
    pub dependabot_ecosystem: &'static str,
    /// Hosts the stack's toolchain and dependency fetch reach, by default
    /// configuration; agent-guardrails allows them in the devcontainer firewall.
    pub egress_hosts: &'static [&'static str],
    pub macos_target: bool,
    /// `Some` for `rust`, `python-uv` and `go`; `node`'s depends on the
    /// runner of the app (`node::NodeRunner::profile`), the device and data
    /// packs' on their slices.
    pub test_runner: Option<TestRunnerProfile>,
    /// `Some` for the four first-wave packs.
    pub otel: Option<OtelRecipe>,
    /// `Some` for `rust` and `python-uv`; `node` and `go` stay `None` until
    /// their packs add a line-coverage tool, the device and data packs too.
    pub coverage: Option<CoverageRecipe>,
    /// Why a pack without `coverage` has none, said where the CI audit and
    /// the seed would propose an upload (#20); `None` when `coverage` is set.
    pub no_coverage: Option<&'static str>,
    /// `Some` for `rust` and `python-uv`; `None` for `node` and `go` until
    /// their packs declare a seeded runner (SPEC-stack-packs.md, "Property recipe").
    pub properties: Option<PropertyRecipe>,
    /// `Some` for `rust` and `python-uv` (SPEC-stack-packs.md, "Mutation recipe").
    pub mutation: Option<MutationRecipe>,
    /// Pure: same app, same table, same steps. Refuses when a pin is missing.
    pub ci_setup: fn(&App, &PinTable) -> Result<Vec<Step>>,
}

/// A pinned action as `uses:` carries it: the SHA is the pin, the version a comment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRef {
    pub repo: String,
    pub sha: String,
    pub version: String,
}

impl ActionRef {
    /// The `uses:` value with the version as a trailing comment, the form
    /// Dependabot bumps.
    pub fn uses(&self) -> String {
        format!("{}@{} # {}", self.repo, self.sha, self.version)
    }
}

/// The condition cache save steps carry: save only on the default branch, so a
/// pull request cannot poison the cache (SPEC-ci-baseline.md).
pub const DEFAULT_BRANCH_CONDITION: &str =
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)";

/// One GitHub Actions step as data. Owned here so `ci-baseline`, which depends
/// on this module, can embed it; it serialises with the YAML key names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The step id other expressions read (`steps.<id>.outputs`); packs leave it unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<ActionRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub with: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    #[serde(
        default,
        rename = "working-directory",
        skip_serializing_if = "Option::is_none"
    )]
    pub working_directory: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, rename = "if", skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

impl Step {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            uses: None,
            with: BTreeMap::new(),
            run: None,
            working_directory: None,
            env: BTreeMap::new(),
            condition: None,
        }
    }
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
    pub fn uses(mut self, action: ActionRef) -> Self {
        self.uses = Some(action);
        self
    }
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.with.insert(key.into(), value.into());
        self
    }
    pub fn run(mut self, command: impl Into<String>) -> Self {
        self.run = Some(command.into());
        self
    }
    pub fn working_directory(mut self, path: impl Into<String>) -> Self {
        self.working_directory = Some(path.into());
        self
    }
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }
    pub fn only_on_default_branch(mut self) -> Self {
        self.condition = Some(DEFAULT_BRANCH_CONDITION.to_owned());
        self
    }
}
