//! The security module: the scans and the gates as data (`SPEC-security.md`).
//! T1 (#786) the scanner pin table and the checksum install fragment, T2 (#787)
//! the bypass inventory, T3 (#788) the shell twin of the check; T4 (#790) the
//! `Module` impl: the slice-1 answers, the seeds and the managed guide; T6 (#792)
//! the manual steps with their probes, two of them `remote` items `apply
//! --remote` writes since #854; T5 (#791) the jobs `security-gate` and
//! `deps-scan`, contributed to `ci-baseline`'s workflow through `ci_jobs`; T7
//! (#793) the static `security.*` rules `doctor` reports as warnings; #979 the
//! opt-in `mutation-diff` job and its rule `security.mutation-gate`.
//!
//! In `modules::all()` since #891, before `ci-baseline`: like every module it is
//! active only when recorded in the lock or requested with `install --module`, and
//! the plan refuses it unless `ci-baseline` and `stack-packs` are active too.
//!
//! Every seed is written only when absent and never under `.git/`: installing a
//! hook is the owner's step (`pre-commit install`, `prek install`, `lefthook install`).
pub mod audit;
pub mod diff_coverage;
pub mod embed;
pub mod exceptions;
pub mod jobs;
pub mod pii;
pub mod pins;

pub use pins::{GITLEAKS_HOOK_REV, INSTALL_TOOL, PINS, ToolPin, check_trivy_pin, pin};

use std::path::Path;

use crate::profile::audit_fields;
use crate::{
    Result,
    engine::{
        CiJob, Context, ManualStep, Module, Probe, Rendered,
        answers::{Answers, Schema},
        lock::Ownership,
        manual::Owner,
    },
    host::{
        desired::{Desired, RemoteWrite},
        types::RepositorySettingsPatch,
    },
    modules::stack_packs::{self, STACK_PACKS},
    refuse,
};
use exceptions::{GITLEAKS_CONFIG, INVENTORY, OSV_CONFIG, SEMGREP_IGNORE, Shape, TRIVY_IGNORE};
use pii::{DSAR_PATH, PII_PATH};
use pins::{ACTIONLINT_HOOK, GITLEAKS, PRE_COMMIT_HOOKS};
use serde_json::{Value, json};
use std::fs;

pub const SECURITY: &str = "security";
pub const SECURITY_VERSION: &str = "1.0.0";

pub const GUIDE_PATH: &str = "docs/agent-setup/security-gates.md";
pub const PRE_COMMIT_PATH: &str = ".pre-commit-config.yaml";
pub const LEFTHOOK_PATH: &str = "lefthook.yml";
/// What `hooks-installed` probes: the hook an install command writes in this clone.
pub const HOOK_PATH: &str = ".git/hooks/pre-commit";
/// Where `actionlint` joins the hook seed when it exists.
const WORKFLOWS_DIR: &str = ".github/workflows";

pub const GUIDE: &str = include_str!("../../../../../templates/security/security-gates.md");
const INVENTORY_SEED: &str =
    include_str!("../../../../../templates/security/seeds/security-exceptions.json");
const GITLEAKS_SEED: &str = include_str!("../../../../../templates/security/seeds/gitleaks.toml");
const OSV_SEED: &str = include_str!("../../../../../templates/security/seeds/osv-scanner.toml");
const TRIVY_SEED: &str = include_str!("../../../../../templates/security/seeds/trivyignore.yaml");
/// Semgrep CE's defaults restated (#1194); a root `.semgrepignore` replaces them.
const SEMGREP_SEED: &str = include_str!("../../../../../templates/security/seeds/semgrepignore");
const PRE_COMMIT_SEED: &str =
    include_str!("../../../../../templates/security/seeds/pre-commit-config.yaml");
const PRE_COMMIT_ACTIONLINT: &str =
    include_str!("../../../../../templates/security/seeds/pre-commit-actionlint.yaml");
const LEFTHOOK_SEED: &str = include_str!("../../../../../templates/security/seeds/lefthook.yml");
const LEFTHOOK_ACTIONLINT: &str =
    include_str!("../../../../../templates/security/seeds/lefthook-actionlint.yml");
pub const PII_SEED: &str = include_str!("../../../../../templates/security/seeds/pii.yaml");

pub struct Security;

/// The slice-1 questions, slice 2's `sast`, `container_scan` and `severity`,
/// slice 4's `pii`, slice 3's coverage pair and slice 3c's `mutation_*`
/// (SPEC-security.md, Answers). The `when` of `deps`, `container_scan` and
/// `mutation_diff` read another module's answers or the checkout, which the
/// engine's `when` cannot, so they are applied by `deps_scan`,
/// `jobs::container_scan` and the refusal of `jobs::mutation_apps`.
/// `bypass_max_days` may only tighten the 30 days of decision 2026-10-28, point 11.
pub fn schema() -> Schema {
    Schema::parse(&json!([
        {"id": "secrets_scanner", "type": "string", "enum": ["gitleaks", "betterleaks"],
         "default": "gitleaks",
         "description": "Secrets scanner of security-gate and the hook seed; betterleaks refuses until verified."},
        {"id": "deps", "type": "boolean", "default": true,
         "description": "Scan lockfiles with OSV-Scanner (deps-scan); applies when a stack pack declares a lockfile."},
        {"id": "hooks", "type": "string", "enum": ["pre-commit-config", "lefthook", "none"],
         "default": "pre-commit-config",
         "description": "Hook-manager config to seed: .pre-commit-config.yaml (pre-commit, prek), lefthook.yml, or none."},
        {"id": "bypass_max_days", "type": "integer", "default": 30, "minimum": 1, "maximum": 30,
         "description": "Longest expires - created the exceptions check accepts for job bypasses."},
        {"id": "sast", "type": "string", "enum": ["none", "semgrep", "codeql"], "default": "semgrep",
         "description": "Static analysis job: Semgrep CE by image digest with the stacks' packs, CodeQL (after Code Security is bought), or none."},
        {"id": "container_scan", "type": "boolean", "default": true,
         "description": "Scan with Trivy (container-scan); applies when a Dockerfile, a container app or delivery's image job exists."},
        {"id": "severity", "type": "string", "enum": ["critical", "high-and-critical"],
         "default": "high-and-critical", "when": "container_scan",
         "description": "Trivy failure threshold; OSV-Scanner and Semgrep thresholds are fixed (decision 4)."},
        {"id": "pii", "type": "boolean",
         "description": "PII pack: pii.yaml, the pii-check step and the DSAR runbook; derived true under criticality personal-data-or-payments, where false refuses."},
        {"id": "coverage_ratchet", "type": "boolean", "default": false,
         "description": "Adds coverage-ratchet and seeds .agent-setup/coverage.json; needs an app whose stack pack declares coverage."},
        {"id": "coverage_tolerance", "type": "string", "default": "0.5", "when": "coverage_ratchet",
         "description": "Percentage points a measurement may fall below the record, as a decimal (0.5)."},
        {"id": "coverage_changed_lines", "type": "boolean",
         "description": "Adds diff-coverage (changed lines covered, characterization first); unanswered, on where any app's stack pack has a per-file coverage report."},
        {"id": "coverage_changed_lines_min", "type": "integer", "default": 80, "minimum": 0, "maximum": 100,
         "description": "Percentage of the changed lines a pull request must cover."},
        {"id": "coverage_source", "type": "string", "enum": diff_coverage::SOURCES,
         "description": "Retired (#22) and ignored, with a plan note: diff-coverage and coverage-ratchet only read the coverage data the project's own test jobs upload."},
        {"id": "coverage_runner", "type": "string", "enum": jobs::coverage_runners(), "default": "standard",
         "description": "Runner of coverage-ratchet and diff-coverage: standard is ci-baseline's; large is the configuration's runners.linux_large."},
        {"id": "coverage_test_args.*", "type": "string", "minLength": 1,
         "description": "The test selection the app's test job measures, as its declared test selects them: rust replaces --workspace (-p my-crate), python-uv appends to pytest -q (-m 'not services'); a rust file outside it only warns."},
        {"id": "mutation_diff", "type": "boolean", "default": false,
         "description": "Opt-in mutation-diff: mutation testing of the code a pull request changes; needs a stack pack that declares mutation."},
        {"id": "mutation_min_score", "type": "integer", "default": 80, "minimum": 0, "maximum": 100,
         "when": "mutation_diff",
         "description": "Share of viable mutants in the changed code the tests must kill (percent)."},
    ]))
    .expect("the security schema parses")
}

/// Whether `deps-scan` applies: the `deps` answer, gated on a stack pack of this plan
/// that declares a lockfile (the question's `when`).
pub fn deps_scan(cx: &Context<'_>) -> Result<bool> {
    if cx.answers.get("deps").and_then(Value::as_bool) == Some(false) {
        return Ok(false);
    }
    Ok(stack_packs::required_packs(cx)?
        .iter()
        .any(|(_, pack)| pack.lockfile.is_some()))
}

/// Whether the PII pack applies (T12, #800): the `pii` answer, derived `true`
/// when the profile's `criticality` is `personal-data-or-payments`, where an
/// explicit `false` refuses.
pub fn pii(cx: &Context<'_>) -> Result<bool> {
    let required = pii::required(audit_fields(&cx.profile.value)?.criticality);
    match cx.answers.get("pii").and_then(Value::as_bool) {
        Some(false) if required => refuse(format!(
            "Module {SECURITY}: pii false refuses under criticality personal-data-or-payments; the PII declaration is required there"
        )),
        Some(answer) => Ok(answer),
        None => Ok(required),
    }
}

/// The DSAR runbook for the checkout: rendered from the declaration already in
/// `.agent-setup/pii.yaml` when it is in the seeded shape, else from the seed.
pub fn dsar_runbook(root: &Path) -> String {
    let declaration = fs::read_to_string(root.join(PII_PATH))
        .ok()
        .and_then(|text| match pii::parse(&text) {
            Shape::Generated(d) => Some(d),
            Shape::Unverified { .. } => None,
        })
        .or_else(|| match pii::parse(PII_SEED) {
            Shape::Generated(d) => Some(d),
            Shape::Unverified { .. } => None,
        })
        .unwrap_or_default();
    pii::runbook(&declaration)
}

fn text<'a>(answers: &'a Answers, id: &str, default: &'a str) -> &'a str {
    answers.get(id).and_then(Value::as_str).unwrap_or(default)
}

/// Replaces every `{{key}}` of `pairs` in `template`; pure.
fn fill(template: &str, pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .fold(template.to_owned(), |text, (key, value)| {
            text.replace(&format!("{{{{{key}}}}}"), value)
        })
}

/// The hook-manager seed for `hooks`, or `None` for `none`. gitleaks is pinned to
/// the commit of the release `pins.rs` installs in CI.
pub fn hook_seed(hooks: &str, workflows: bool) -> Option<(&'static str, String)> {
    let common = [
        ("gitleaks_rev", GITLEAKS_HOOK_REV),
        ("gitleaks_version", GITLEAKS.version),
        ("hooks_repo", PRE_COMMIT_HOOKS.repo),
        ("hooks_rev", PRE_COMMIT_HOOKS.rev),
        ("hooks_version", PRE_COMMIT_HOOKS.version),
        ("actionlint_repo", ACTIONLINT_HOOK.repo),
        ("actionlint_rev", ACTIONLINT_HOOK.rev),
        ("actionlint_version", ACTIONLINT_HOOK.version),
    ];
    let (path, template, block) = match hooks {
        "pre-commit-config" => (PRE_COMMIT_PATH, PRE_COMMIT_SEED, PRE_COMMIT_ACTIONLINT),
        "lefthook" => (LEFTHOOK_PATH, LEFTHOOK_SEED, LEFTHOOK_ACTIONLINT),
        _ => return None,
    };
    let (block, tool) = if workflows {
        (block, format!("; actionlint {}", ACTIONLINT_HOOK.version))
    } else {
        ("", String::new())
    };
    let template = template
        .replace("{{actionlint}}\n", block)
        .replace("{{actionlint_tool}}", &tool);
    Some((path, fill(&template, &common)))
}

/// The owner's command for secret scanning with push protection. `{owner}/{repo}`
/// are `gh api` placeholders, resolved by `gh` from the checkout it runs in.
pub const SECRET_SCANNING_STEP: &str = "gh api -X PATCH repos/{owner}/{repo} --input - <<'EOF'
{\"security_and_analysis\":{\"secret_scanning\":{\"status\":\"enabled\"},\"secret_scanning_push_protection\":{\"status\":\"enabled\"}}}
EOF";
pub const PRIVATE_VULNERABILITY_REPORTING_STEP: &str =
    "gh api -X PUT repos/{owner}/{repo}/private-vulnerability-reporting";
/// Informational: Code Security is bought per organization by the owner, never
/// by the installer (decision 2026-10-28, point 11); declared only with
/// `sast == codeql` (T10, #798).
pub const CODE_SECURITY_STEP: &str = "Enable GitHub Code Security for this repository (billing, owner only), then default or advanced CodeQL setup picks up the generated workflow.";

/// The ids of the remote items (decision #848 point 5, #854), in declaration order.
pub const REMOTE_ITEMS: [&str; 2] = ["secret-scanning", "private-vulnerability-reporting"];

/// The desired state of each remote item: the settings its instructions write
/// (SPEC-security.md, Manual steps with probes).
pub fn remote_writes() -> Vec<RemoteWrite> {
    let enabled = || Some("enabled".to_owned());
    vec![
        RemoteWrite {
            id: REMOTE_ITEMS[0].to_owned(),
            desired: Desired::Settings(RepositorySettingsPatch {
                secret_scanning: enabled(),
                secret_scanning_push_protection: enabled(),
                ..RepositorySettingsPatch::default()
            }),
        },
        RemoteWrite {
            id: REMOTE_ITEMS[1].to_owned(),
            desired: Desired::Settings(RepositorySettingsPatch {
                private_vulnerability_reporting: Some(true),
                ..RepositorySettingsPatch::default()
            }),
        },
    ]
}

/// The manual steps (SPEC-security.md, Manual steps with probes). The two remote
/// ones are the probes of the remote items of the same id; a plan refusal is
/// their `failed` evidence. `code-security` is declared only with `sast ==
/// codeql`: informational, probed by `code-scanning-default-setup`, no remote
/// item (buying Code Security is the owner's). `hooks-installed` is local,
/// stays a manual step, follows the `hooks` answer and is not declared for `none`.
fn steps(answers: &Answers) -> Vec<ManualStep> {
    let remote = |id: &str, title: &str, instructions: &str| ManualStep {
        id: id.to_owned(),
        title: title.to_owned(),
        owner: Owner::Owner,
        instructions: instructions.to_owned(),
        probe: Probe::Remote {
            id: id.to_owned(),
            args: Default::default(),
        },
        after: None,
    };
    let mut steps = vec![
        remote(
            "secret-scanning",
            "Enable secret scanning and push protection",
            SECRET_SCANNING_STEP,
        ),
        remote(
            "private-vulnerability-reporting",
            "Enable private vulnerability reporting",
            PRIVATE_VULNERABILITY_REPORTING_STEP,
        ),
    ];
    if text(answers, "sast", "semgrep") == "codeql" {
        steps.push(ManualStep {
            id: "code-security".to_owned(),
            title: "Enable GitHub Code Security for CodeQL".to_owned(),
            owner: Owner::Owner,
            instructions: CODE_SECURITY_STEP.to_owned(),
            probe: Probe::Remote {
                id: "code-scanning-default-setup".to_owned(),
                args: Default::default(),
            },
            after: None,
        });
    }
    let install = match text(answers, "hooks", "pre-commit-config") {
        "pre-commit-config" => Some("pre-commit install (or prek install)"),
        "lefthook" => Some("lefthook install"),
        _ => None,
    };
    if let Some(install) = install {
        steps.push(ManualStep {
            id: "hooks-installed".to_owned(),
            title: "Install the pre-commit hook in this clone".to_owned(),
            owner: Owner::Owner,
            instructions: install.to_owned(),
            probe: Probe::FileExists {
                path: HOOK_PATH.to_owned(),
            },
            after: None,
        });
    }
    steps
}

impl Module for Security {
    fn id(&self) -> &'static str {
        SECURITY
    }
    fn version(&self) -> &'static str {
        SECURITY_VERSION
    }
    /// The jobs join `ci.yml` through `ci-baseline`'s `ci_jobs` (capability map).
    /// `stack-packs`: `deps_scan` reads its answers (`Context::answers_of`).
    fn requires(&self) -> &'static [&'static str] {
        &["ci-baseline", STACK_PACKS]
    }
    fn questions(&self) -> Schema {
        schema()
    }
    /// A declared budget whose coverage-job timeouts exceed GitHub's job
    /// maximum, capped (#1228).
    fn notes(&self, cx: &Context<'_>) -> Result<Vec<String>> {
        let timeouts = jobs::budget_timeouts(cx)?;
        let mut notes: Vec<String> =
            crate::modules::ci_baseline::render::over_job_max_note(cx, &timeouts)
                .into_iter()
                .collect();
        notes.extend(diff_coverage::project_ci_notes(cx)?);
        Ok(notes)
    }
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>> {
        if text(cx.answers, "secrets_scanner", "gitleaks") == "betterleaks" {
            return refuse(format!(
                "Module {SECURITY}: secrets_scanner betterleaks refuses until SPEC-security.md Open question 1 is resolved and its pin exists; use gitleaks"
            ));
        }
        // `ci_jobs` cannot refuse; rendering the jobs here makes any reason they
        // would fail (an invalid stack-packs record, a missing pin) refuse the plan.
        jobs::contributed(cx)?;
        let item = |path: &str, class: Ownership, content: &str| Rendered {
            path: path.to_owned(),
            class,
            content: Some(content.to_owned()),
            scaffold: None,
        };
        let mut out = vec![
            item(INVENTORY, Ownership::Seed, INVENTORY_SEED),
            item(GITLEAKS_CONFIG, Ownership::Seed, GITLEAKS_SEED),
            item(OSV_CONFIG, Ownership::Seed, OSV_SEED),
            item(TRIVY_IGNORE, Ownership::Seed, TRIVY_SEED),
        ];
        if text(cx.answers, "sast", "semgrep") == "semgrep" {
            out.push(item(SEMGREP_IGNORE, Ownership::Seed, SEMGREP_SEED));
        }
        let workflows = cx.root.join(WORKFLOWS_DIR).is_dir();
        if let Some((path, seed)) =
            hook_seed(text(cx.answers, "hooks", "pre-commit-config"), workflows)
        {
            out.push(item(path, Ownership::Seed, &seed));
        }
        if pii(cx)? {
            out.push(item(PII_PATH, Ownership::Seed, PII_SEED));
            out.push(item(DSAR_PATH, Ownership::Seed, &dsar_runbook(cx.root)));
        }
        if let Some(coverage) = jobs::coverage(cx)? {
            out.push(item(
                exceptions::COVERAGE_RECORD,
                Ownership::Seed,
                &coverage.seed(),
            ));
        }
        if let Some(text) = diff_coverage::reusable(cx, &stack_packs::PinTable::embedded()?)? {
            out.push(item(diff_coverage::REUSABLE, Ownership::Managed, &text));
        }
        out.push(item(GUIDE_PATH, Ownership::Managed, GUIDE));
        // #854: lock-recorded, never written by the engine; `apply --remote` writes them.
        out.extend(REMOTE_ITEMS.iter().map(|id| Rendered {
            path: format!("github:{id}"),
            class: Ownership::Remote,
            content: None,
            scaffold: None,
        }));
        Ok(out)
    }
    fn manual_steps(&self, cx: &Context<'_>) -> Vec<ManualStep> {
        steps(cx.answers)
    }
    /// The desired state of `secret-scanning` and `private-vulnerability-reporting` (#854).
    fn remote_writes(&self, _cx: &Context<'_>) -> Result<Vec<RemoteWrite>> {
        Ok(remote_writes())
    }
    /// `security-gate` (never skippable), `deps-scan`, `coverage-ratchet` and,
    /// when `mutation_diff`, `mutation-diff` (skippable under `docs`).
    /// Empty only when `render` refuses in the same plan.
    fn ci_jobs(&self, cx: &Context<'_>) -> Vec<CiJob> {
        jobs::contributed(cx).unwrap_or_default()
    }
}
