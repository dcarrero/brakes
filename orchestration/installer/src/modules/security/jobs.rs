//! The jobs `security` contributes to `ci-baseline`'s workflow through
//! `Module::ci_jobs` (SPEC-security.md, "Contributed CI jobs"; SPEC-ci-baseline.md,
//! Composition): `security-gate`, never skippable, and `deps-scan`, `sast`,
//! `container-scan` (T10, #798), `coverage-ratchet` (#799) and, opt-in,
//! `mutation-diff` (#979), skippable under tier `docs`. Each body is the job
//! mapping at column zero, rendered from
//! `templates/security/fragments/{secrets,deps,sast,codeql,container-*,coverage,
//! mutation-diff}.yml`; the shells are embedded without comment-only lines
//! (`embed.rs`, #1088), every scanner comes from
//! `pins.rs` through `install-tool.sh` or by image digest, and every `uses:` from
//! the shared pin table. `ci-baseline` inserts them; nothing here writes `ci.yml`.
use super::embed::without_comment_lines;
use super::pins::{GITLEAKS, INSTALL_TOOL, OSV_SCANNER, SEMGREP, TRIVY, ToolPin};
use crate::modules::ci_baseline::render::{measurement_minutes, within_job_max};
use crate::modules::ci_baseline::services;
use crate::{
    Result,
    engine::{CiJob, CiTier, Context, answers},
    modules::{
        ci_baseline::{CI_BASELINE, Runner, render::runner_label},
        stack_packs::{
            App, CoverageRecipe, DEFAULT_BRANCH_CONDITION, MutationRecipe, PinTable, StackId,
            StackPack, Step, required_packs,
        },
    },
    refuse,
};
use serde_json::{Value, json};
use std::{fmt::Write as _, path::Path};

pub const SECURITY_GATE: &str = "security-gate";
pub const DEPS_SCAN: &str = "deps-scan";
pub const SAST: &str = "sast";
pub const CONTAINER_SCAN: &str = "container-scan";
pub const COVERAGE_RATCHET: &str = "coverage-ratchet";
pub const MUTATION_DIFF: &str = "mutation-diff";

const MUTATION_JOB: &str =
    include_str!("../../../../../templates/security/fragments/mutation-diff.yml");
/// The shell of `mutation-diff`: runs the pack's recipe on the diff and judges the score.
pub const MUTATION_DIFF_SH: &str =
    include_str!("../../../../../templates/security/fragments/mutation-diff.sh");
/// Every step of `mutation-diff` after the bypass: pull requests only, never a
/// job condition (SPEC-ci-baseline.md, "The contract of a contributed job").
const RUN_CONDITION: &str = "github.event_name == 'pull_request' && steps.bypass.outputs.id == ''";
/// What the shell substitutes for `{{module}}` in the python-uv recipe.
const MODULE_VARIABLE: &str = "$MUTATION_MODULE";
/// The module whose recorded answers expose the pull-request image job
/// (SPEC-security.md, Interface with delivery); not a module yet, so its
/// answers file is read as recorded, never through `answers_of`.
pub const DELIVERY: &str = "delivery";

const SECRETS_JOB: &str = include_str!("../../../../../templates/security/fragments/secrets.yml");
const DEPS_JOB: &str = include_str!("../../../../../templates/security/fragments/deps.yml");
const SAST_JOB: &str = include_str!("../../../../../templates/security/fragments/sast.yml");
const CODEQL_JOB: &str = include_str!("../../../../../templates/security/fragments/codeql.yml");
const CONTAINER_FS_JOB: &str =
    include_str!("../../../../../templates/security/fragments/container-fs.yml");
const CONTAINER_IMAGE_JOB: &str =
    include_str!("../../../../../templates/security/fragments/container-image.yml");
/// The secrets scan of `security-gate`: range on pull requests, full history otherwise.
pub const GITLEAKS_SCAN: &str =
    include_str!("../../../../../templates/security/fragments/gitleaks-scan.sh");
/// What a scanner job prints of its findings: location only, never a value (#1173).
pub const SCANNER_FINDINGS: &str =
    include_str!("../../../../../templates/security/fragments/scanner-findings.sh");
const EXCEPTIONS_CHECK: &str =
    include_str!("../../../../../templates/security/fragments/exceptions-check.sh");
pub(super) const BYPASS_VARIABLE: &str =
    include_str!("../../../../../templates/security/fragments/bypass-variable.sh");
/// The PII declaration check, the sibling step of the exceptions check (T12, #800).
pub const PII_CHECK: &str =
    include_str!("../../../../../templates/security/fragments/pii-check.sh");
const PII_STEP: &str = include_str!("../../../../../templates/security/fragments/pii-step.yml");
const COVERAGE_JOB: &str = include_str!("../../../../../templates/security/fragments/coverage.yml");
const COVERAGE_COMPARE: &str =
    include_str!("../../../../../templates/security/fragments/coverage-ratchet.sh");
/// The condition every step after the bypass step carries.
const NOT_BYPASSED: &str = "steps.bypass.outputs.id == ''";

/// `text` with every non-empty line indented by `n` spaces, ending in a newline
/// without one of its own (the template line it replaces carries it).
pub(super) fn indent(text: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    text.lines()
        .map(|line| {
            if line.is_empty() {
                String::new()
            } else {
                format!("{pad}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The `env:` entries `install-tool.sh` reads for `pin`, sorted, every value quoted.
fn tool_env(pin: &ToolPin) -> String {
    let mut env = pin.env();
    env.sort();
    env.iter()
        .map(|(key, value)| format!("      {key}: \"{value}\""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Replaces every `{{key}}` of `pairs` in `template`; pure. The embedded shells
/// carry no `{{`, so an inserted block is never substituted again.
pub(super) fn fill(template: &str, pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .fold(template.to_owned(), |text, (key, value)| {
            text.replace(&format!("{{{{{key}}}}}"), value)
        })
}

/// `coverage-ratchet`'s and `diff-coverage`'s timeout without a declared budget.
const COVERAGE_TIMEOUT: u32 = 20;
/// `mutation-diff`'s timeout without a declared budget: the mutants' allowance.
const MUTATION_TIMEOUT: u32 = 30;

/// The uncapped timeout of a coverage job that may run the suite
/// `measurements` times (#1213): `max(20, measurements × ceil(ci.cycle_budget_minutes × 1.5))`
/// when the profile declares the budget, else 20. A budget never lowers it.
fn coverage_minutes(cx: &Context<'_>, measurements: u32) -> u32 {
    measurement_minutes(cx).map_or(COVERAGE_TIMEOUT, |m| {
        COVERAGE_TIMEOUT.max(m.saturating_mul(measurements))
    })
}

/// `mutation-diff`'s uncapped timeout (#1213): 30, plus one measurement of the
/// suite (the unmutated baseline run) when the profile declares the budget.
fn mutation_minutes(cx: &Context<'_>) -> u32 {
    MUTATION_TIMEOUT.saturating_add(measurement_minutes(cx).unwrap_or(0))
}

/// [`coverage_minutes`] within GitHub's job maximum (#1228), as rendered.
pub(super) fn coverage_timeout(cx: &Context<'_>, measurements: u32) -> String {
    within_job_max(coverage_minutes(cx, measurements)).to_string()
}

/// [`mutation_minutes`] within GitHub's job maximum (#1228), as rendered.
fn mutation_timeout(cx: &Context<'_>) -> String {
    within_job_max(mutation_minutes(cx)).to_string()
}

/// The coverage jobs this plan renders with their uncapped budget-derived
/// timeouts, in contribution order; empty without a budget (#1228).
pub(super) fn budget_timeouts(cx: &Context<'_>) -> Result<Vec<(String, u32)>> {
    if measurement_minutes(cx).is_none() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    if coverage(cx)?.is_some() {
        out.push((COVERAGE_RATCHET.to_owned(), coverage_minutes(cx, 1)));
    }
    if super::diff_coverage::judged(cx)?.is_some() {
        out.push((
            super::diff_coverage::DIFF_COVERAGE.to_owned(),
            coverage_minutes(cx, 2),
        ));
    }
    if !mutation_apps(cx)?.is_empty() {
        out.push((MUTATION_DIFF.to_owned(), mutation_minutes(cx)));
    }
    Ok(out)
}

/// The `runs-on` label ci-baseline's `runner` answer picks; the label table is ci-baseline's.
pub(super) fn runner(cx: &Context<'_>) -> Result<&'static str> {
    let answer = cx
        .answers_of(CI_BASELINE)?
        .get("runner")
        .and_then(Value::as_str);
    let runner = Runner::available()
        .into_iter()
        .find(|r| Some(r.as_str()) == answer)
        .unwrap_or_else(Runner::default_choice);
    Ok(runner_label(runner))
}

/// `coverage_runner` (#1344): `large` names the configuration's `runners.linux_large`
/// label; `standard` or unanswered is [`runner`]'s.
pub(super) fn coverage_runner(cx: &Context<'_>) -> Result<String> {
    let large = cx.answers.get("coverage_runner").and_then(Value::as_str) == Some(LARGE);
    match crate::config::linux_large_runner() {
        Some(r) if large => Ok(r.label.clone()),
        _ => Ok(runner(cx)?.to_owned()),
    }
}

/// The `coverage_runner` values: `large` only when the configuration names one.
pub fn coverage_runners() -> Vec<&'static str> {
    let mut out = vec![STANDARD];
    if crate::config::linux_large_runner().is_some() {
        out.push(LARGE);
    }
    out
}

const STANDARD: &str = "standard";
const LARGE: &str = "large";

/// The Semgrep registry packs a stack adds to `p/default` (SPEC-security.md,
/// Contributed CI jobs; `p/rust` for Rust, Open question 6 resolved with the
/// `semgrep` default for every stack).
pub fn semgrep_rulesets(stack: StackId) -> &'static [&'static str] {
    match stack {
        StackId::Rust => &["p/rust"],
        StackId::PythonUv => &["p/python"],
        StackId::Node => &["p/javascript", "p/typescript"],
        StackId::Go => &["p/golang"],
        StackId::KotlinAndroid => &["p/kotlin"],
        StackId::SwiftIos => &["p/swift"],
        StackId::SqlDbt => &[],
    }
}

/// The CodeQL language identifier of a stack, `None` where CodeQL has none
/// (github/codeql-action, "languages").
pub fn codeql_language(stack: StackId) -> Option<&'static str> {
    match stack {
        StackId::Rust => Some("rust"),
        StackId::PythonUv => Some("python"),
        StackId::Node => Some("javascript-typescript"),
        StackId::Go => Some("go"),
        StackId::KotlinAndroid => Some("java-kotlin"),
        StackId::SwiftIos => Some("swift"),
        StackId::SqlDbt => None,
    }
}

/// The `sast` answer as a job: Semgrep with the packs of the plan's stacks, or
/// CodeQL with their languages; `None` for `none`. CodeQL refuses when no
/// stack of the plan has a language.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sast {
    Semgrep { configs: Vec<&'static str> },
    CodeQl { languages: Vec<&'static str> },
}

pub fn sast(cx: &Context<'_>) -> Result<Option<Sast>> {
    let answer = cx
        .answers
        .get("sast")
        .and_then(Value::as_str)
        .unwrap_or("semgrep");
    let stacks: Vec<StackId> = {
        let mut stacks: Vec<StackId> = required_packs(cx)?
            .iter()
            .map(|(app, _)| app.stack)
            .collect();
        stacks.sort();
        stacks.dedup();
        stacks
    };
    Ok(match answer {
        "none" => None,
        "codeql" => {
            let languages: Vec<&'static str> =
                stacks.iter().filter_map(|s| codeql_language(*s)).collect();
            if languages.is_empty() {
                return refuse(
                    "Module security: sast codeql needs an app whose stack CodeQL analyses (rust, python-uv, node, go, kotlin-android, swift-ios)",
                );
            }
            Some(Sast::CodeQl { languages })
        }
        _ => {
            let mut configs = vec!["p/default"];
            configs.extend(stacks.iter().flat_map(|s| semgrep_rulesets(*s)));
            Some(Sast::Semgrep { configs })
        }
    })
}

/// The image job `delivery` recorded, with the name of its output holding the
/// reference (`image_ref` unless `delivery` names another), or `None` without
/// `delivery` or its `image_job`. A job id that is not kebab-case refuses.
pub fn delivery_image(root: &Path) -> Result<Option<(String, String)>> {
    let Some(file) = answers::recorded(root, DELIVERY)? else {
        return Ok(None);
    };
    let Some(job) = file.answers.get("image_job").and_then(Value::as_str) else {
        return Ok(None);
    };
    let kebab = !job.is_empty()
        && job.split('-').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    if !kebab {
        return refuse(format!(
            "Module security: delivery records image_job {job:?}, which is not a kebab-case job id"
        ));
    }
    let output = file
        .answers
        .get("image_ref")
        .and_then(Value::as_str)
        .unwrap_or("image_ref");
    // The name is interpolated into an expression: a job output identifier only.
    let identifier = output
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && output
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !identifier {
        return refuse(format!(
            "Module security: delivery records image_ref {output:?}, which is not a job output name"
        ));
    }
    Ok(Some((job.to_owned(), output.to_owned())))
}

/// `container-scan` as the plan needs it: the Trivy severity list and, with
/// `delivery`'s image job, `(job, output)` to scan; `None` when the answer is
/// `false` or nothing to scan exists (no Dockerfile at the root or an app path,
/// no container app, no image job).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerScan {
    pub severity: &'static str,
    pub image: Option<(String, String)>,
}

pub fn container_scan(cx: &Context<'_>) -> Result<Option<ContainerScan>> {
    if cx.answers.get("container_scan").and_then(Value::as_bool) == Some(false) {
        return Ok(None);
    }
    let image = delivery_image(cx.root)?;
    let dockerfile = cx.root.join("Dockerfile").is_file()
        || required_packs(cx)?
            .iter()
            .any(|(app, _)| app.container || cx.root.join(&app.path).join("Dockerfile").is_file());
    if image.is_none() && !dockerfile {
        return Ok(None);
    }
    let severity = match cx.answers.get("severity").and_then(Value::as_str) {
        Some("critical") => "CRITICAL",
        _ => "HIGH,CRITICAL",
    };
    Ok(Some(ContainerScan { severity, image }))
}

/// `coverage_ratchet` answered `true`: the covered apps and the tolerance.
pub struct Coverage {
    pub apps: Vec<(App, CoverageRecipe)>,
    pub tolerance: String,
    /// Per app id, the answered `coverage_test_args` (#1177).
    pub tests: std::collections::BTreeMap<String, String>,
}

impl Coverage {
    /// `.agent-setup/coverage.json` as seeded: every covered app at `0`, since
    /// the installer never invents a measurement.
    pub fn seed(&self) -> String {
        let apps: Vec<String> = self
            .apps
            .iter()
            .map(|(app, _)| format!("    {}: 0", Value::String(app.id.clone())))
            .collect();
        format!(
            "{{\n  \"schema\": 1,\n  \"apps\": {{\n{}\n  }}\n}}\n",
            apps.join(",\n")
        )
    }
}

/// A percentage written as a JSON number with an optional fraction (no sign,
/// no exponent, no leading zero), at most 100: `coverage-ratchet.sh` reads it
/// with `jq --argjson`.
fn percentage(text: &str) -> bool {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, "0"));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    digits(whole)
        && (whole == "0" || !whole.starts_with('0'))
        && digits(fraction)
        && text.parse::<f64>().is_ok_and(|v| v <= 100.0)
}

/// The coverage ratchet of this plan, `None` unless `coverage_ratchet` is
/// `true`; refuses an unparsable tolerance or a plan without a covered app.
pub fn coverage(cx: &Context<'_>) -> Result<Option<Coverage>> {
    super::diff_coverage::check_test_args(cx)?;
    if cx.answers.get("coverage_ratchet").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let tolerance = cx
        .answers
        .get("coverage_tolerance")
        .and_then(Value::as_str)
        .unwrap_or("0.5")
        .to_owned();
    if !percentage(&tolerance) {
        return refuse(format!(
            "Module security: coverage_tolerance {tolerance} is not a percentage between 0 and 100"
        ));
    }
    let apps: Vec<(App, CoverageRecipe)> = required_packs(cx)?
        .into_iter()
        .filter_map(|(app, pack)| pack.coverage.map(|recipe| (app, recipe)))
        .collect();
    if apps.is_empty() {
        return refuse(
            "Module security: coverage_ratchet needs an app whose stack pack declares coverage (python-uv, rust)",
        );
    }
    let tests = apps
        .iter()
        .filter_map(|(app, _)| {
            super::diff_coverage::test_args(cx, app).map(|t| (app.id.clone(), t.to_owned()))
        })
        .collect();
    Ok(Some(Coverage {
        apps,
        tolerance,
        tests,
    }))
}

/// A YAML scalar that reads back as `text`: plain when it cannot be mistaken
/// for anything else, double-quoted otherwise.
fn scalar(text: &str) -> String {
    let plain = text.starts_with(|c: char| c.is_ascii_alphabetic())
        && !text.ends_with(' ')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_./@".contains(c))
        && !["true", "false", "yes", "no", "on", "off", "null", "y", "n"]
            .contains(&text.to_ascii_lowercase().as_str());
    if plain {
        text.to_owned()
    } else {
        format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// A step as an item of the job's `steps:` list, at the indentation of the
/// fragments; `run` is a literal block.
pub(super) fn step_yaml(step: &Step) -> String {
    let mut out = String::new();
    match &step.id {
        Some(id) => {
            let _ = writeln!(
                out,
                "  - id: {}\n    name: {}",
                scalar(id),
                scalar(&step.name)
            );
        }
        None => {
            let _ = writeln!(out, "  - name: {}", scalar(&step.name));
        }
    }
    if let Some(condition) = &step.condition {
        let _ = writeln!(out, "    if: {condition}");
    }
    if let Some(action) = &step.uses {
        let _ = writeln!(out, "    uses: {}", action.uses());
    }
    if let Some(dir) = &step.working_directory {
        let _ = writeln!(out, "    working-directory: {}", scalar(dir));
    }
    for (key, map) in [("with", &step.with), ("env", &step.env)] {
        if !map.is_empty() {
            let _ = writeln!(out, "    {key}:");
            for (k, v) in map {
                if v.contains('\n') {
                    // A literal block keeps the newlines a quoted scalar would fold.
                    let _ = writeln!(
                        out,
                        "      {k}: |-\n{}",
                        indent(v.trim_end_matches('\n'), 8)
                    );
                } else {
                    let _ = writeln!(out, "      {k}: {}", scalar(v));
                }
            }
        }
    }
    if let Some(run) = &step.run {
        let _ = writeln!(out, "    run: |\n{}", indent(run.trim_end(), 6));
    }
    out
}

/// `step` running only when no bypass was granted, keeping its own condition.
fn unless_bypassed(mut step: Step) -> Step {
    step.condition = Some(match step.condition.take() {
        None => NOT_BYPASSED.to_owned(),
        Some(own) => format!("{NOT_BYPASSED} && ({own})"),
    });
    step
}

/// The steps after the bypass step: each covered app's setup and tool install,
/// one measurement per app, `save` (the per-file report `diff-coverage`
/// restores, #978), then the comparison at the root.
fn coverage_steps(coverage: &Coverage, pins: &PinTable, save: Vec<Step>) -> Result<Vec<Step>> {
    let mut steps: Vec<Step> = Vec::new();
    for (app, recipe) in &coverage.apps {
        let pack = crate::modules::stack_packs::packs::pack(app.stack);
        for step in (pack.ci_setup)(app, pins)?
            .into_iter()
            .chain(recipe.install_step(pins)?)
        {
            if !steps.contains(&step) {
                steps.push(step);
            }
        }
    }
    for (app, recipe) in &coverage.apps {
        let mut measure = Step::new(format!("Measure coverage of {}", app.id))
            .run(recipe.render_command(pins, coverage.tests.get(&app.id).map(String::as_str))?);
        measure.working_directory = app.working_directory();
        steps.push(measure);
    }
    let apps: Vec<Value> = coverage
        .apps
        .iter()
        .map(|(app, recipe)| {
            json!({"app": app.id, "report": format!("{}{}", app.prefix(), recipe.report),
                   "metric": recipe.metric})
        })
        .collect();
    steps.extend(save);
    steps.push(
        Step::new("Compare coverage with the record")
            .env("COVERAGE_APPS", Value::Array(apps).to_string())
            .env("COVERAGE_TOLERANCE", coverage.tolerance.clone())
            .run(without_comment_lines(COVERAGE_COMPARE)),
    );
    Ok(steps.into_iter().map(unless_bypassed).collect())
}

/// The lockfiles `deps-scan` scans (#1178): the one each recorded app's pack
/// declares, at `<app path>/<file>`, a node app's from its detected package
/// manager; in app order, without duplicates. Declared, never searched for, so a
/// test fixture's, a template's or an example's lockfile is not scanned.
pub fn deps_lockfiles(cx: &Context<'_>) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for (app, pack) in required_packs(cx)? {
        let Some(lockfile) = pack.lockfile else {
            continue;
        };
        let file = app
            .package_manager
            .map_or(lockfile.file, |pm| pm.lockfile());
        let path = format!("{}{file}", app.prefix());
        if !out.contains(&path) {
            out.push(path);
        }
    }
    Ok(out)
}

/// `text` as one shell word: as is when it holds only characters no shell
/// reads specially, else single-quoted.
fn shell_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/+@-".contains(&b));
    if plain {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The jobs in contribution order: `security-gate` always, `deps-scan` when
/// `deps_scan` applies, `sast` unless `none`, `container-scan` when something
/// to scan exists, `coverage-ratchet` when `coverage_ratchet` is `true`,
/// `diff-coverage` when the root app is judged, `mutation-diff` when
/// `mutation_diff` is `true` (SPEC-security.md, Contributed CI jobs).
pub fn contributed(cx: &Context<'_>) -> Result<Vec<CiJob>> {
    let pins = PinTable::embedded()?;
    let max_days = cx
        .answers
        .get("bypass_max_days")
        .and_then(Value::as_u64)
        .unwrap_or(30)
        .to_string();
    let common = [
        ("runner", runner(cx)?.to_owned()),
        ("coverage_runner", coverage_runner(cx)?),
        ("checkout", pins.action("actions/checkout")?.uses()),
        ("bypass_max_days", max_days),
        (
            "install_tool",
            indent(&without_comment_lines(INSTALL_TOOL), 6),
        ),
    ];
    let secrets = [
        ("gitleaks_env", tool_env(&GITLEAKS)),
        (
            "gitleaks_scan",
            indent(&without_comment_lines(GITLEAKS_SCAN), 6),
        ),
        (
            "exceptions_check",
            indent(&without_comment_lines(EXCEPTIONS_CHECK), 6),
        ),
        (
            "upload_artifact",
            pins.action("actions/upload-artifact")?.uses(),
        ),
    ];
    // The pii-check step joins the gate only with the PII pack; without it the
    // placeholder line goes, so the slice-1 golden is unchanged.
    let pii_step = if super::pii(cx)? {
        fill(
            PII_STEP,
            &[("pii_check", indent(&without_comment_lines(PII_CHECK), 6))],
        )
    } else {
        String::new()
    };
    let secrets_job = SECRETS_JOB.replace("{{pii_step}}\n", &pii_step);
    let mut jobs = vec![CiJob {
        id: SECURITY_GATE.to_owned(),
        yaml: fill(&secrets_job, &[&common[..], &secrets].concat()),
        skippable_under: Vec::new(),
        app: None,
    }];
    if super::deps_scan(cx)? {
        let lockfiles: Vec<String> = deps_lockfiles(cx)?
            .iter()
            .map(|path| format!("--lockfile {}", shell_word(path)))
            .collect();
        let deps = [
            ("osv_env", tool_env(&OSV_SCANNER)),
            ("osv_lockfiles", lockfiles.join(" ")),
            (
                "bypass_variable",
                indent(&without_comment_lines(BYPASS_VARIABLE), 6),
            ),
        ];
        jobs.push(CiJob {
            id: DEPS_SCAN.to_owned(),
            yaml: fill(DEPS_JOB, &[&common[..], &deps].concat()),
            skippable_under: vec![CiTier::Docs],
            app: None,
        });
    }
    let bypass = (
        "bypass_variable",
        indent(&without_comment_lines(BYPASS_VARIABLE), 6),
    );
    let findings = (
        "scanner_findings",
        indent(&without_comment_lines(SCANNER_FINDINGS), 6),
    );
    match sast(cx)? {
        None => {}
        Some(Sast::Semgrep { configs }) => {
            let configs: Vec<String> = configs.iter().map(|c| format!("--config {c}")).collect();
            let semgrep = [
                bypass.clone(),
                findings.clone(),
                ("semgrep_version", SEMGREP.version.to_owned()),
                ("semgrep_image", SEMGREP.pinned()),
                ("semgrep_configs", configs.join(" ")),
            ];
            jobs.push(CiJob {
                id: SAST.to_owned(),
                yaml: fill(SAST_JOB, &[&common[..], &semgrep].concat()),
                skippable_under: vec![CiTier::Docs],
                app: None,
            });
        }
        Some(Sast::CodeQl { languages }) => {
            let codeql = [
                bypass.clone(),
                (
                    "codeql_init",
                    pins.action("github/codeql-action/init")?.uses(),
                ),
                (
                    "codeql_analyze",
                    pins.action("github/codeql-action/analyze")?.uses(),
                ),
                ("codeql_languages", languages.join(",")),
            ];
            jobs.push(CiJob {
                id: SAST.to_owned(),
                yaml: fill(CODEQL_JOB, &[&common[..], &codeql].concat()),
                skippable_under: vec![CiTier::Docs],
                app: None,
            });
        }
    }
    if let Some(scan) = container_scan(cx)? {
        let mut container = vec![
            bypass,
            findings,
            ("trivy_env", tool_env(&TRIVY)),
            ("severity", scan.severity.to_owned()),
        ];
        let template = match scan.image {
            Some((job, output)) => {
                container.push(("image_job", job));
                container.push(("image_output", output));
                CONTAINER_IMAGE_JOB
            }
            None => CONTAINER_FS_JOB,
        };
        jobs.push(CiJob {
            id: CONTAINER_SCAN.to_owned(),
            yaml: fill(template, &[&common[..], &container].concat()),
            skippable_under: vec![CiTier::Docs],
            app: None,
        });
    }
    if let Some(coverage) = coverage(cx)? {
        let save = super::diff_coverage::ratchet_save_steps(cx, &pins)?;
        let steps: String = coverage_steps(&coverage, &pins, save)?
            .iter()
            .map(step_yaml)
            .collect();
        let ratchet = [
            (
                "bypass_variable",
                indent(&without_comment_lines(BYPASS_VARIABLE), 6),
            ),
            ("coverage_steps", steps.trim_end().to_owned()),
            ("timeout", coverage_timeout(cx, 1)),
        ];
        jobs.push(CiJob {
            id: COVERAGE_RATCHET.to_owned(),
            yaml: services::into_job(
                &fill(COVERAGE_JOB, &[&common[..], &ratchet].concat()),
                &services::of_apps(cx, coverage.apps.iter().map(|(app, _)| app))?,
            ),
            skippable_under: vec![CiTier::Docs],
            app: None,
        });
    }
    jobs.extend(super::diff_coverage::job(cx, &pins)?);
    let apps = mutation_apps(cx)?;
    if !apps.is_empty() {
        let mutation = [
            (
                "bypass_variable",
                indent(&without_comment_lines(BYPASS_VARIABLE), 6),
            ),
            ("steps", mutation_steps(cx, &pins, &apps)?),
            ("timeout", mutation_timeout(cx)),
        ];
        jobs.push(CiJob {
            id: MUTATION_DIFF.to_owned(),
            yaml: services::into_job(
                &fill(MUTATION_JOB, &[&common[..], &mutation].concat()),
                &services::of_apps(cx, apps.iter().map(|(app, _, _)| app))?,
            ),
            skippable_under: vec![CiTier::Docs],
            app: None,
        });
    }
    Ok(jobs)
}

/// An app, its pack and the pack's mutation recipe.
pub type MutatedApp = (App, &'static StackPack, MutationRecipe);

/// The apps `mutation-diff` mutates: none unless `mutation_diff`, then every app
/// whose pack declares a mutation recipe. Refuses when `mutation_diff` is true and
/// no app has one (the answer's `when`, which reads stack-packs' answers).
pub fn mutation_apps(cx: &Context<'_>) -> Result<Vec<MutatedApp>> {
    if cx.answers.get("mutation_diff").and_then(Value::as_bool) != Some(true) {
        return Ok(Vec::new());
    }
    let apps: Vec<MutatedApp> = required_packs(cx)?
        .into_iter()
        .filter_map(|(app, pack)| pack.mutation.map(|recipe| (app, pack, recipe)))
        .collect();
    if apps.is_empty() {
        return refuse(format!(
            "Module {}: mutation_diff needs a stack pack that declares mutation (rust, python-uv); no app of this repository has one",
            super::SECURITY
        ));
    }
    Ok(apps)
}

/// Per app: the pack's setup, the tool's install step (once per job), the run
/// of `mutation-diff.sh` in the app directory and the upload of its results.
/// Every step is conditioned on a pull request and no bypass; a step the pack
/// runs only on the default branch (a cache save) never runs here and is left out.
fn mutation_steps(cx: &Context<'_>, pins: &PinTable, apps: &[MutatedApp]) -> Result<String> {
    let min = cx
        .answers
        .get("mutation_min_score")
        .and_then(Value::as_u64)
        .unwrap_or(80);
    let mut steps: Vec<Step> = Vec::new();
    let push = |steps: &mut Vec<Step>, mut step: Step| {
        step.condition = match step.condition.take() {
            None => Some(RUN_CONDITION.to_owned()),
            Some(c) if c == DEFAULT_BRANCH_CONDITION => return,
            Some(c) => Some(format!("{RUN_CONDITION} && ({c})")),
        };
        if !steps.contains(&step) {
            steps.push(step);
        }
    };
    for (app, pack, recipe) in apps {
        for step in (pack.ci_setup)(app, pins)? {
            push(&mut steps, step);
        }
        if let Some(install) = recipe.install_step(pins)? {
            push(&mut steps, install);
        }
        let mut run = Step::new(format!("Mutation testing on the diff ({})", app.id))
            .env("BASE_SHA", "${{ github.event.pull_request.base.sha }}")
            .env(
                "MUTATION_COMMAND",
                recipe
                    .render_command(pins)?
                    .replace("{{module}}", MODULE_VARIABLE),
            )
            .run(format!(
                "set -- {} {min}\n{}",
                recipe.tool,
                without_comment_lines(MUTATION_DIFF_SH)
            ));
        if let Some(stats) = recipe.render_stats(pins)? {
            run = run.env("MUTATION_STATS", stats);
        }
        if let Some(dir) = app.working_directory() {
            run = run.working_directory(dir);
        }
        push(&mut steps, run);
        let upload = Step::new(format!("Upload the mutation results ({})", app.id))
            .uses(pins.action("actions/upload-artifact")?)
            .with("name", format!("mutants-{}", app.id))
            .with("path", format!("{}{}", app.prefix(), recipe.results))
            .with("if-no-files-found", "ignore")
            .with("retention-days", "7");
        steps.push(Step {
            condition: Some("${{ always() && github.event_name == 'pull_request' }}".to_owned()),
            ..upload
        });
    }
    Ok(steps
        .iter()
        .map(step_yaml)
        .collect::<String>()
        .trim_end()
        .to_owned())
}
