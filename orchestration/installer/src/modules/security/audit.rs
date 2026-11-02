//! The static `security.*` rules (SPEC-security.md, "Auditor rules this module
//! enables" and "How `doctor` reports the static rules"): evaluated locally over
//! every workflow under `.github/workflows/`, owned or not, through the walker of
//! `auditor/workflows.rs`, and over the exception files through the T2 check
//! (`exceptions::check`), so `doctor` and `security-gate` cannot disagree, and
//! over the git index for `security.binary-artifacts` (#973). They are judged
//! by the auditor's registry from these findings at the levels the owner
//! allocated (#873, `auditor::catalogue::modules`): a failed rule is a
//! `WARNING: security.<rule-id>: <text>` finding, an unreadable file
//! `WARNING: security.<rule-id>: unverified: <file>: <reason>` for each rule it
//! feeds, a passed rule nothing. The remote halves (`secret-scanning` for the
//! secrets gate, the run log for full history, `SECURITY_BYPASS` ids) are
//! `unavailable` until host-adapter probes exist and are not reported here.
//! T10 (#798) adds `security.sast-gate` (a Semgrep or CodeQL job) and
//! `security.container-gate` (a Trivy or Grype scan where a Dockerfile exists).
use super::{
    SECURITY, diff_coverage,
    exceptions::{
        self, COVERAGE_RECORD, DEFAULT_BYPASS_MAX_DAYS, Entry, GITLEAKS_CONFIG, INVENTORY,
        Inventory, Kind, Shape, TRIVY_PLAIN,
    },
    jobs,
    pii::{self, DSAR_PATH, PII_PATH},
    pins::TRIVY_COMPROMISED,
};
use crate::profile::audit_fields;
use crate::{
    auditor::{
        LocalFiles,
        workflows::{
            Job, Step, Workflow, file_rule, pinned, read_all, repository_rule, unverified, warn,
        },
    },
    engine::answers,
    modules::stack_packs::{PackageManager, STACK_PACKS, packs},
};
use chrono::NaiveDate;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::Path,
};

const SECRETS_GATE: &str = "security.secrets-gate";
const FULL_HISTORY: &str = "security.secrets-full-history";
const DEPS_GATE: &str = "security.deps-gate";
const UNPINNED: &str = "security.scanner-unpinned";
const TRIVY_WINDOW: &str = "security.trivy-compromised-version";
const INVENTORY_VALID: &str = "security.bypass-inventory-valid";
const UNREGISTERED: &str = "security.bypass-unregistered";
const EXPIRED: &str = "security.bypass-expired";
const BINARY_ARTIFACTS: &str = "security.binary-artifacts";
const MUTATION_GATE: &str = "security.mutation-gate";

/// The prefix of an `allowlist` target that registers a tracked binary.
const BINARY_TARGET: &str = "binary-artifacts#";
/// How much of a tracked file `security.binary-artifacts` reads (Scorecard's bound).
const BINARY_HEAD: usize = 1024;
/// The executable and package magics (SPEC-security.md, `security.binary-artifacts`;
/// `ossf/scorecard` `checks/raw/binary_artifact.go` at `a604ed9`, the subset of
/// its detected types that are executables or packages, hand-written).
const BINARY_MAGICS: [(&[u8], &str); 11] = [
    (b"\x7fELF", "ELF"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "Java class or universal binary"),
    (b"MZ", "PE"),
    (b"\0asm", "WebAssembly"),
    (b"!<arch>\n", "ar archive"),
    (b"\xed\xab\xee\xdb", "RPM"),
    (b"dex\n", "DEX"),
];
/// Scorecard's 27 extensions (same source).
const BINARY_EXTENSIONS: [&str; 27] = [
    "crx", "deb", "dex", "dey", "elf", "o", "a", "so", "macho", "iso", "class", "jar", "bundle",
    "dylib", "lib", "msi", "dll", "drv", "efi", "exe", "ocx", "pyc", "pyo", "par", "rpm", "wasm",
    "whl",
];
const GRADLE_WRAPPER: &str = "gradle-wrapper.jar";
const WRAPPER_VALIDATION: [&str; 2] = [
    "gradle/actions/wrapper-validation",
    "gradle/wrapper-validation-action",
];
const SAST_GATE: &str = "security.sast-gate";
const CONTAINER_GATE: &str = "security.container-gate";
const PII_DECLARED: &str = "security.pii-declared";
pub const COVERAGE_RATCHET: &str = "security.coverage-ratchet";
pub const DIFF_COVERAGE_RULE: &str = "security.diff-coverage";

/// The scanner binaries the rules recognise in `run:` scripts.
const SCANNERS: [&str; 6] = [
    "gitleaks",
    "betterleaks",
    "trivy",
    "osv-scanner",
    "semgrep",
    "grype",
];
/// The scanner actions `security.scanner-unpinned` requires pinned by SHA.
const SCANNER_ACTIONS: [&str; 5] = [
    "aquasecurity/trivy-action",
    "aquasecurity/setup-trivy",
    "gitleaks/gitleaks-action",
    "semgrep/semgrep-action",
    "google/osv-scanner-action",
];
const TRIVY_ACTION: &str = "aquasecurity/trivy-action";
/// The first `trivy-action` tag after the March 2026 compromise.
const TRIVY_ACTION_SAFE: (u64, u64, u64) = (0, 35, 0);
/// Directories the lockfile and Dockerfile searches never enter.
const SKIPPED_DIRS: [&str; 3] = ["node_modules", "target", "vendor"];
const LOCKFILE_DEPTH: usize = 3;
/// The container build files `security.container-gate` looks for.
const DOCKERFILES: [&str; 2] = ["Dockerfile", "Containerfile"];
/// The `allowlist` target prefixes of the declared exclusions of the rules that
/// judge files a walk finds (#1171): the file is not judged, and `doctor`
/// prints an `EXCLUDED` line for it.
pub const CONTAINER_TARGET: &str = "container-gate#";
pub const SCREENSHOT_TARGET: &str = "screenshot-baseline-present#";

/// `doctor`'s `security.*` findings for the checkout at `root` on `today`, with
/// the recorded `bypass_max_days` when `security` has answers.
pub fn diagnose(root: &Path, today: NaiveDate) -> Vec<String> {
    let recorded = answers::recorded(root, SECURITY).ok().flatten();
    let answer = |id: &str| recorded.as_ref().and_then(|f| f.answers.get(id).cloned());
    let max_days = answer("bypass_max_days")
        .and_then(|d| d.as_u64())
        .and_then(|d| u32::try_from(d).ok())
        .unwrap_or(DEFAULT_BYPASS_MAX_DAYS);
    let mut out = findings(root, today, max_days);
    if answer("coverage_ratchet").and_then(|v| v.as_bool()) == Some(true) {
        out.extend(coverage_ratchet(root));
    }
    if answer("coverage_changed_lines").and_then(|v| v.as_bool()) != Some(false)
        && any_app_has_diff_report(root)
    {
        out.extend(diff_coverage(root));
    }
    out
}

/// Whether stack-packs' recorded answers name an app, wherever it lives, whose
/// pack has a per-file coverage report (rust, python-uv): where `diff-coverage`
/// applies (#1130; the root app only before).
fn any_app_has_diff_report(root: &Path) -> bool {
    let Some(file) = answers::recorded(root, STACK_PACKS).ok().flatten() else {
        return false;
    };
    file.answers.iter().any(|(key, value)| {
        key.starts_with("apps.")
            && key.ends_with(".stack")
            && value
                .as_str()
                .is_some_and(|s| ["rust", "python-uv"].contains(&s))
    })
}

/// `security.diff-coverage`, static (#978): a `diff-coverage` job that an
/// `if: always()` job of the same workflow needs, with a step that runs
/// `diff-cover` with `--fail-under` and a step that prints `Characterization first`.
pub fn diff_coverage(root: &Path) -> Vec<String> {
    let read: Vec<(String, Workflow)> = read_all(&LocalFiles::new(root))
        .into_iter()
        .filter_map(|(path, parsed)| Some((path, parsed.ok()?)))
        .collect();
    let judges = |wf: &Workflow| {
        wf.job(diff_coverage::DIFF_COVERAGE).is_some_and(|job| {
            let runs = |needle: &[&str]| {
                job.steps
                    .iter()
                    .any(|s| needle.iter().all(|n| run(s).contains(n)))
            };
            runs(&["diff-cover", "--fail-under"]) && runs(&["Characterization first"])
        })
    };
    let needed = |wf: &Workflow| {
        wf.jobs.iter().any(|gate| {
            gate.condition
                .as_deref()
                .is_some_and(|c| c.contains("always()"))
                && gate.needs.iter().any(|n| n == diff_coverage::DIFF_COVERAGE)
        })
    };
    // coverage_source project-ci (#1349): the reusable workflow judges, and the
    // project's workflow calls it as `diff-coverage` and gates on it.
    let reusable_judges = read
        .iter()
        .any(|(path, wf)| path == diff_coverage::REUSABLE && judges(wf));
    let calls_reusable = |wf: &Workflow| {
        wf.job(diff_coverage::DIFF_COVERAGE)
            .and_then(|job| job.uses.as_deref())
            .is_some_and(|uses| uses == format!("./{}", diff_coverage::REUSABLE))
    };
    let gated = read
        .iter()
        .any(|(_, wf)| needed(wf) && (judges(wf) || (reusable_judges && calls_reusable(wf))));
    if gated {
        Vec::new()
    } else {
        vec![warn(
            DIFF_COVERAGE_RULE,
            "No changed-line coverage gate: a pull request can ship code no test executes",
        )]
    }
}

/// `security.coverage-ratchet`'s static half, judged only when the ratchet is
/// answered: the record and a `coverage-ratchet` job exist. The latest
/// default-branch measurement is the remote half, unavailable here.
pub fn coverage_ratchet(root: &Path) -> Vec<String> {
    let text = |detail: &str| {
        warn(
            COVERAGE_RATCHET,
            format!("Coverage record absent or job red on main: {detail}"),
        )
    };
    let mut out = Vec::new();
    if !root.join(COVERAGE_RECORD).is_file() {
        out.push(text(&format!("{COVERAGE_RECORD} is absent")));
    }
    let job = read_all(&LocalFiles::new(root))
        .into_iter()
        .filter_map(|(_, parsed)| parsed.ok())
        .any(|wf| wf.jobs.iter().any(|j| j.id == jobs::COVERAGE_RATCHET));
    if !job {
        out.push(text(&format!(
            "no {} job in .github/workflows",
            jobs::COVERAGE_RATCHET
        )));
    }
    out
}

/// The `security.*` findings, in the spec's rule order then file order.
pub fn findings(root: &Path, today: NaiveDate, bypass_max_days: u32) -> Vec<String> {
    let read = read_all(&LocalFiles::new(root));
    let inventory = fs::read_to_string(root.join(INVENTORY))
        .ok()
        .and_then(|t| Inventory::parse(&t));
    let split = exception_findings(root, today, bypass_max_days);
    let binaries = binary_artifacts(root, &read, inventory.as_ref());
    let mut out = Vec::new();
    repository_rule(
        SECRETS_GATE,
        "No secrets gate: no gitleaks job and secret scanning off",
        &read,
        |wf| wf.jobs.iter().any(secrets_job),
        &mut out,
    );
    file_rule(FULL_HISTORY, &read, full_history, &mut out);
    if has_file(root, &lockfile_names(), 0) {
        repository_rule(
            DEPS_GATE,
            "No lockfile vulnerability scan in CI",
            &read,
            |wf| wf.jobs.iter().any(lockfile_scan_job),
            &mut out,
        );
    }
    file_rule(UNPINNED, &read, scanner_unpinned, &mut out);
    file_rule(TRIVY_WINDOW, &read, trivy_window, &mut out);
    out.extend(split.inventory_valid);
    out.extend(binaries.stale);
    out.extend(stale_exclusions(root, inventory.as_ref()));
    file_rule(
        UNREGISTERED,
        &read,
        |path, wf| workflow_bypasses(path, wf, inventory.as_ref()),
        &mut out,
    );
    out.extend(split.unregistered);
    out.extend(split.expired);
    out.extend(binaries.findings);
    repository_rule(
        SAST_GATE,
        "No static analysis job in CI",
        &read,
        |wf| wf.jobs.iter().any(sast_job),
        &mut out,
    );
    let judged = dockerfiles(root).into_iter().any(|path| {
        registration(inventory.as_ref(), &format!("{CONTAINER_TARGET}{path}")).is_none()
    });
    if judged {
        repository_rule(
            CONTAINER_GATE,
            "Dockerfile present and no container scan in CI",
            &read,
            |wf| wf.jobs.iter().any(container_scan_job),
            &mut out,
        );
    }
    out.extend(pii_declared(root));
    if mutation_diff(root) {
        repository_rule(
            MUTATION_GATE,
            "mutation_diff is true and no mutation-diff job is in the aggregate",
            &read,
            mutation_wired,
            &mut out,
        );
    }
    out
}

/// The bypass inventory at `root`, when it parses.
pub fn inventory(root: &Path) -> Option<Inventory> {
    fs::read_to_string(root.join(INVENTORY))
        .ok()
        .and_then(|t| Inventory::parse(&t))
}

/// The first `allowlist` entry registering `target`, in any state: an expired
/// one is `bypass-expired`'s, as for `binary-artifacts#` (#1171).
pub fn registration<'a>(inventory: Option<&'a Inventory>, target: &str) -> Option<&'a Entry> {
    inventory?.exceptions.iter().find(|e| {
        e.kind.as_deref() == Some(Kind::Allowlist.as_str()) && e.target.as_deref() == Some(target)
    })
}

/// The `doctor` line of a declared exclusion: information, never a finding.
pub fn exclusion_line(rule: &str, path: &str, entry: &Entry) -> String {
    format!(
        "EXCLUDED [{rule}] {path} — {} ({}, until {}): {}",
        entry.label(),
        entry.issue.as_deref().unwrap_or("no issue"),
        entry.expires.as_deref().unwrap_or("no expiry"),
        entry.reason.as_deref().unwrap_or("no reason"),
    )
}

/// The declared exclusions of `security.container-gate` at `root`, in path order.
pub fn excluded(root: &Path) -> Vec<String> {
    let inventory = inventory(root);
    dockerfiles(root)
        .into_iter()
        .filter_map(|path| {
            registration(inventory.as_ref(), &format!("{CONTAINER_TARGET}{path}"))
                .map(|entry| exclusion_line(CONTAINER_GATE, &path, entry))
        })
        .collect()
}

/// An exclusion entry whose path is not a file its rule judges is stale (#1171).
fn stale_exclusions(root: &Path, inventory: Option<&Inventory>) -> Vec<String> {
    let Some(inventory) = inventory else {
        return Vec::new();
    };
    let mut found: Option<(Vec<String>, Vec<String>)> = None;
    let mut out = Vec::new();
    for entry in &inventory.exceptions {
        if entry.kind.as_deref() != Some(Kind::Allowlist.as_str()) {
            continue;
        }
        let Some(target) = entry.target.as_deref() else {
            continue;
        };
        let (docker, specs) = found.get_or_insert_with(|| {
            (
                dockerfiles(root),
                crate::modules::qa::audit::screenshot_specs(root),
            )
        });
        let known = if let Some(path) = target.strip_prefix(CONTAINER_TARGET) {
            docker.iter().any(|p| p == path)
        } else if let Some(path) = target.strip_prefix(SCREENSHOT_TARGET) {
            specs.iter().any(|p| p == path)
        } else {
            continue;
        };
        if !known {
            out.push(warn(
                INVENTORY_VALID,
                format!(
                    "Exception {} registers {target}, which the rule does not find",
                    entry.label()
                ),
            ));
        }
    }
    out
}

/// The `Dockerfile`s and `Containerfile`s within three directory levels, in
/// path order: where `security.container-gate` looks.
fn dockerfiles(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &str, depth: usize, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(root.join(dir)) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            if kind.is_file() && DOCKERFILES.contains(&name.as_str()) {
                out.push(path);
            } else if kind.is_dir()
                && depth < LOCKFILE_DEPTH
                && !name.starts_with('.')
                && !SKIPPED_DIRS.contains(&name.as_str())
            {
                walk(root, &path, depth + 1, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", 0, &mut out);
    out.sort();
    out
}

/// `security.pii-declared` (T12, #800): under `personal-data-or-payments`,
/// the declaration exists in the seeded shape with at least one field and
/// passes the same check as the `pii-check` step, and the DSAR runbook exists.
/// Nothing is reported under any other criticality (the rule's `when`).
fn pii_declared(root: &Path) -> Vec<String> {
    // The profile is read for its `criticality` alone, so an unmanaged
    // repository's partial profile still answers (never `profile_for`).
    let criticality = fs::read_to_string(root.join(crate::PROFILE))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| audit_fields(&value).ok())
        .and_then(|fields| fields.criticality);
    if !pii::required(criticality) {
        return Vec::new();
    }
    let mut out = Vec::new();
    match pii::check(root, criticality) {
        Err(e) => out.push(unverified(PII_DECLARED, PII_PATH, &e.to_string())),
        Ok(report) => {
            if report.fields.is_none() || report.fields == Some(0) && report.passed() {
                out.push(warn(
                    PII_DECLARED,
                    "criticality is personal-data-or-payments and no pii.yaml declares the fields"
                        .to_owned(),
                ));
            }
            for finding in report.findings {
                if let Some((file, reason)) = finding.split_once(" is unverified: ") {
                    out.push(unverified(PII_DECLARED, file, reason));
                } else if !finding.ends_with("needs a PII declaration") {
                    out.push(warn(PII_DECLARED, finding));
                }
            }
        }
    }
    match fs::read_to_string(root.join(DSAR_PATH)) {
        Err(_) if !root.join(DSAR_PATH).is_file() => out.push(warn(
            PII_DECLARED,
            format!("criticality is personal-data-or-payments and {DSAR_PATH} is missing"),
        )),
        Err(e) => out.push(unverified(PII_DECLARED, DSAR_PATH, &e.to_string())),
        Ok(runbook) if seeded_before_the_fields(root, &runbook) => out.push(warn(
            PII_DECLARED,
            format!(
                "{DSAR_PATH} is still the runbook seeded before {PII_PATH} declared its fields; delete it and run install to re-seed it from the declaration"
            ),
        )),
        Ok(_) => {}
    }
    out
}

/// Whether `runbook` is byte-identical to the one seeded from the seed
/// declaration (or from an empty one) while `pii.yaml` now declares fields
/// that a re-seed would list, so the two can no longer be equal (#1236). The
/// engine never rewrites a seed, so this finding is the refresh path; an
/// edited runbook is the project's.
fn seeded_before_the_fields(root: &Path, runbook: &str) -> bool {
    let declares_fields = fs::read_to_string(root.join(PII_PATH))
        .ok()
        .is_some_and(|text| match pii::parse(&text) {
            Shape::Generated(d) => !d.fields.is_empty(),
            Shape::Unverified { .. } => false,
        });
    let seed = match pii::parse(super::PII_SEED) {
        Shape::Generated(d) => d,
        Shape::Unverified { .. } => pii::Declaration::default(),
    };
    declares_fields
        && (runbook == pii::runbook(&seed) || runbook == pii::runbook(&pii::Declaration::default()))
}

/// Whether the recorded `security` answers turn `mutation_diff` on (#979).
pub fn mutation_diff(root: &Path) -> bool {
    answers::recorded(root, SECURITY)
        .ok()
        .flatten()
        .and_then(|f| f.answers.get("mutation_diff").and_then(Value::as_bool))
        == Some(true)
}

/// A job `mutation-diff` that an `if: always()` job of the same workflow needs,
/// with a step that runs `cargo mutants … --in-diff` or `mutmut run`, in its
/// `run:` or in the `env:` the managed shell reads its command from. A line
/// counts only as a command: comments and `echo` lines (the managed shell names
/// both tools in its messages) never do.
fn mutation_wired(wf: &Workflow) -> bool {
    let runs_a_tool = |text: &str| {
        text.lines().map(str::trim).any(|line| {
            !line.starts_with('#')
                && !line.starts_with("echo ")
                && ((line.starts_with("cargo mutants") && line.contains("--in-diff"))
                    || line.contains("mutmut run"))
        })
    };
    let Some(job) = wf.job(super::jobs::MUTATION_DIFF) else {
        return false;
    };
    let aggregated = wf.jobs.iter().any(|gate| {
        gate.condition
            .as_deref()
            .is_some_and(|c| c.contains("always()"))
            && gate.needs.iter().any(|n| n == super::jobs::MUTATION_DIFF)
    });
    aggregated
        && job
            .steps
            .iter()
            .any(|s| runs_a_tool(run(s)) || s.env.values().any(|v| runs_a_tool(v)))
}

// --- recognising scanners -------------------------------------------------------

/// `word` in `text` with no ASCII letter or digit on either side.
fn mentions(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric())
            && !after.is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

fn first_scanner(text: &str) -> Option<&'static str> {
    SCANNERS.into_iter().find(|s| mentions(text, s))
}

/// The action of a `uses:` without its ref.
fn action(uses: &str) -> &str {
    uses.split_once('@').map_or(uses, |(name, _)| name)
}

/// `uses` is `prefix` or a path inside it (`google/osv-scanner-action/osv-scanner-action`).
fn uses_action(uses: &str, prefix: &str) -> bool {
    let name = action(uses);
    name == prefix
        || name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn step_uses(step: &Step, prefix: &str) -> bool {
    step.uses.as_deref().is_some_and(|u| uses_action(u, prefix))
}

fn run(step: &Step) -> &str {
    step.run.as_deref().unwrap_or("")
}

/// A job that runs gitleaks or betterleaks (by binary or action).
pub fn secrets_job(job: &Job) -> bool {
    job.steps.iter().any(|s| {
        step_uses(s, "gitleaks/gitleaks-action")
            || mentions(run(s), "gitleaks")
            || mentions(run(s), "betterleaks")
    })
}

/// An OSV-Scanner, Trivy filesystem or Grype scan.
fn lockfile_scan_job(job: &Job) -> bool {
    job.steps.iter().any(|s| {
        let trivy_fs = step_uses(s, TRIVY_ACTION)
            && matches!(
                s.with.get("scan-type").map(String::as_str),
                Some("fs" | "filesystem" | "repo")
            );
        let script = run(s);
        trivy_fs
            || step_uses(s, "google/osv-scanner-action")
            || step_uses(s, "anchore/scan-action")
            || mentions(script, "osv-scanner")
            || mentions(script, "grype")
            || ["trivy fs", "trivy filesystem", "trivy repo"]
                .iter()
                .any(|c| script.contains(c))
    })
}

/// A Semgrep run (binary, image or action) or a CodeQL action step.
fn sast_job(job: &Job) -> bool {
    job.steps.iter().any(|s| {
        step_uses(s, "github/codeql-action")
            || step_uses(s, "semgrep/semgrep-action")
            || step_uses(s, "returntocorp/semgrep-action")
            || mentions(run(s), "semgrep")
            || mentions(run(s), "codeql")
    })
}

/// A Trivy image, filesystem or config scan, or a Grype scan, by binary or action.
fn container_scan_job(job: &Job) -> bool {
    job.steps.iter().any(|s| {
        let script = run(s);
        step_uses(s, TRIVY_ACTION)
            || step_uses(s, "anchore/scan-action")
            || mentions(script, "grype")
            || [
                "trivy image",
                "trivy fs",
                "trivy filesystem",
                "trivy repo",
                "trivy config",
            ]
            .iter()
            .any(|c| script.contains(c))
    })
}

fn scanning_job(job: &Job) -> bool {
    job.steps
        .iter()
        .any(|s| SCANNER_ACTIONS.iter().any(|a| step_uses(s, a)) || first_scanner(run(s)).is_some())
}

// --- workflow rules ---------------------------------------------------------------

/// The static half: a secrets job in the managed shape prints `history: full`
/// on every run that is not a pull request; any other is read from the run log.
fn full_history(path: &str, wf: &Workflow) -> Vec<String> {
    wf.jobs
        .iter()
        .filter(|j| secrets_job(j) && !j.steps.iter().any(|s| run(s).contains("history: full")))
        .map(|j| {
            format!(
                "unverified: {path}: the secrets job {} is not the managed shape; its history is read from the run log (remote, unavailable)",
                j.id
            )
        })
        .collect()
}

/// `curl … | sh` or `wget … | bash`.
fn piped_to_shell(line: &str) -> bool {
    (line.contains("curl") || line.contains("wget"))
        && line.split('|').skip(1).any(|segment| {
            let command = segment.trim_start();
            let command = command.strip_prefix("sudo ").unwrap_or(command);
            ["sh", "bash"].iter().any(|shell| {
                command
                    .strip_prefix(shell)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
            })
        })
}

fn pip_install(line: &str) -> bool {
    ["pip install", "pip3 install", "pipx install"]
        .iter()
        .any(|c| line.contains(c))
}

/// A checksum is verified when the script runs `sha256sum` or `shasum`, as the
/// generated `install-tool.sh` does without `--check`.
fn checksummed(script: &str) -> bool {
    script.contains("sha256sum") || script.contains("shasum")
}

fn scanner_unpinned(path: &str, wf: &Workflow) -> Vec<String> {
    let text = |name: &str| format!("Scanner {name} in {path} is not pinned by SHA or checksum");
    let mut out = Vec::new();
    for step in wf.jobs.iter().flat_map(|j| &j.steps) {
        if let Some(uses) = &step.uses
            && let Some(name) = SCANNER_ACTIONS.iter().find(|a| uses_action(uses, a))
            && !pinned(uses)
        {
            out.push(text(name));
        }
        let script = run(step);
        for line in script.lines() {
            let Some(scanner) = first_scanner(line) else {
                continue;
            };
            let unpinned = piped_to_shell(line)
                || (pip_install(line) && !line.contains("--require-hashes"))
                || ((line.contains("curl") || line.contains("wget")) && !checksummed(script));
            if unpinned {
                out.push(text(scanner));
            }
        }
    }
    out
}

/// `v0.28.0` or `0.28.0` as numbers; `None` for a SHA or a branch.
fn version(reference: &str) -> Option<(u64, u64, u64)> {
    let mut parts = reference.strip_prefix('v').unwrap_or(reference).split('.');
    let mut next = || parts.next()?.parse::<u64>().ok();
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

/// A compromised Trivy version in `text`, not part of a longer version.
fn compromised_in(text: &str) -> Option<&'static str> {
    TRIVY_COMPROMISED.into_iter().find(|v| {
        text.match_indices(v).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let after = text[at + v.len()..].chars().next();
            !before.is_some_and(|c| c.is_ascii_digit() || c == '.')
                && !after.is_some_and(|c| c.is_ascii_digit() || c == '.')
        })
    })
}

fn trivy_window(_: &str, wf: &Workflow) -> Vec<String> {
    let text =
        |version: &str| format!("Trivy {version} is within the March 2026 compromise window");
    let mut out = Vec::new();
    for step in wf.jobs.iter().flat_map(|j| &j.steps) {
        if let Some(uses) = &step.uses
            && uses_action(uses, TRIVY_ACTION)
            && let Some((_, reference)) = uses.split_once('@')
            && version(reference).is_some_and(|v| v < TRIVY_ACTION_SAFE)
        {
            out.push(text(&format!("trivy-action@{reference}")));
        }
        let trivy = step_uses(step, TRIVY_ACTION) || step_uses(step, "aquasecurity/setup-trivy");
        if trivy && let Some(v) = step.with.get("version").and_then(|v| compromised_in(v)) {
            out.push(text(v));
        }
        let script = run(step);
        if mentions(script, "trivy")
            && let Some(v) = compromised_in(script)
        {
            out.push(text(v));
        }
    }
    out
}

/// Whether `inventory` has an entry of `kind` for one of `targets`, in any state:
/// an expired or invalid one is `bypass-expired`'s or `bypass-inventory-valid`'s.
fn registered(inventory: Option<&Inventory>, kind: Kind, targets: &[&str]) -> bool {
    inventory.is_some_and(|inv| {
        inv.exceptions.iter().any(|e| {
            e.kind.as_deref() == Some(kind.as_str())
                && e.target.as_deref().is_some_and(|t| targets.contains(&t))
        })
    })
}

/// The variable names a condition reads as `vars.<NAME>`.
fn variables(condition: &str) -> Vec<&str> {
    condition
        .match_indices("vars.")
        .filter(|(at, _)| {
            !condition[..*at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        })
        .map(|(at, prefix)| {
            let rest = &condition[at + prefix.len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            &rest[..end]
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// `continue-on-error` and `if: vars.*` on scanning jobs, unless registered as
/// `continue-on-error` (`<workflow>#<job>`) or `repo-variable` (the name).
fn workflow_bypasses(path: &str, wf: &Workflow, inventory: Option<&Inventory>) -> Vec<String> {
    let text =
        |target: &str| format!("Bypass {target} is not registered in security-exceptions.json");
    let file = path.rsplit('/').next().unwrap_or(path);
    let mut out = Vec::new();
    for job in wf.jobs.iter().filter(|j| scanning_job(j)) {
        let target = format!("{path}#{}", job.id);
        let short = format!("{file}#{}", job.id);
        if job.continue_on_error
            && !registered(inventory, Kind::ContinueOnError, &[&target, &short])
        {
            out.push(text(&target));
        }
        for name in job.condition.as_deref().map(variables).unwrap_or_default() {
            if !registered(inventory, Kind::RepoVariable, &[name]) {
                out.push(text(name));
            }
        }
    }
    out
}

// --- the exception files ----------------------------------------------------------

#[derive(Default)]
struct Split {
    inventory_valid: Vec<String>,
    unregistered: Vec<String>,
    expired: Vec<String>,
}

/// The findings of `exceptions::check`, the same as `security-gate` prints,
/// each under the rule the spec gives it: expiry and duration bound are
/// `bypass-expired`, registration and the plain `.trivyignore`
/// `bypass-unregistered`, the rest (parse, schema, fields, dates, issue)
/// `bypass-inventory-valid`. A file outside the generated shape is unverified
/// for the rules it feeds.
fn exception_findings(root: &Path, today: NaiveDate, bypass_max_days: u32) -> Split {
    let mut split = Split::default();
    let report = match exceptions::check(root, today, bypass_max_days) {
        Ok(report) => report,
        Err(e) => {
            let reason = e.to_string();
            split
                .inventory_valid
                .push(unverified(INVENTORY_VALID, INVENTORY, &reason));
            split
                .unregistered
                .push(unverified(UNREGISTERED, INVENTORY, &reason));
            split.expired.push(unverified(EXPIRED, INVENTORY, &reason));
            return split;
        }
    };
    for finding in report.findings {
        if let Some((file, reason)) = finding.split_once(" is unverified: ") {
            if file == GITLEAKS_CONFIG {
                split
                    .unregistered
                    .push(unverified(UNREGISTERED, file, reason));
            } else {
                split
                    .inventory_valid
                    .push(unverified(INVENTORY_VALID, file, reason));
                split.expired.push(unverified(EXPIRED, file, reason));
            }
        } else if finding.contains(" expired on ") || finding.contains(" allows at most ") {
            split.expired.push(warn(EXPIRED, finding));
        } else if finding.contains(" is not registered in ") || finding.starts_with(TRIVY_PLAIN) {
            split.unregistered.push(warn(UNREGISTERED, finding));
        } else {
            split.inventory_valid.push(warn(INVENTORY_VALID, finding));
        }
    }
    split
}

// --- binary artifacts (SPEC-security.md, `security.binary-artifacts`; #973) ------------

#[derive(Default)]
struct Binaries {
    /// `bypass-inventory-valid`: registrations of paths that are not tracked.
    stale: Vec<String>,
    findings: Vec<String>,
}

/// Scorecard's text test over the first bytes: no control character other than
/// tab, line feed or carriage return (every byte below space is a control
/// whatever the encoding, so bytes and decoded runes agree).
fn is_text(head: &[u8]) -> bool {
    head.iter()
        .all(|b| *b >= b' ' || matches!(b, b'\t' | b'\n' | b'\r'))
}

/// The type of a binary artifact: its magic's name, else its listed extension.
fn binary_type(path: &str, head: &[u8]) -> Option<String> {
    if head.is_empty() || is_text(head) {
        return None;
    }
    if let Some((_, name)) = BINARY_MAGICS.iter().find(|(m, _)| head.starts_with(m)) {
        return Some((*name).to_owned());
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    name.rsplit_once('.')
        .map(|(_, ext)| ext)
        .filter(|ext| BINARY_EXTENSIONS.contains(ext))
        .map(|ext| format!(".{ext}"))
}

/// The first [`BINARY_HEAD`] bytes of a tracked regular file; `None` for a
/// symlink or anything else `git` tracks that is not a file (never followed),
/// and for an index entry absent from the working tree (sparse checkout, a
/// pending `git rm`): nothing is in the checkout to judge.
fn head_of(root: &Path, path: &str) -> io::Result<Option<Vec<u8>>> {
    let full = root.join(path);
    let metadata = match fs::symlink_metadata(&full) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    let mut head = Vec::with_capacity(BINARY_HEAD);
    fs::File::open(&full)?
        .take(BINARY_HEAD as u64)
        .read_to_end(&mut head)?;
    Ok(Some(head))
}

/// A workflow step runs the wrapper validation action (the static half of
/// Scorecard's `gradle-wrapper.jar` exclusion).
fn wrapper_validated(read: &[(String, Result<Workflow, String>)]) -> bool {
    read.iter().any(|(_, parsed)| {
        parsed.as_ref().is_ok_and(|wf| {
            wf.jobs
                .iter()
                .flat_map(|j| &j.steps)
                .any(|s| WRAPPER_VALIDATION.iter().any(|action| step_uses(s, action)))
        })
    })
}

/// Every tracked file (`git ls-files -z`, the index, never a symlink's target)
/// whose first bytes are a compiled executable or package, sorted by path:
/// `gradle-wrapper.jar` passes when a workflow validates it, any other file when
/// an `allowlist` entry targets `binary-artifacts#<path>`; such an entry for a
/// path that is not tracked is stale under `bypass-inventory-valid`.
fn binary_artifacts(
    root: &Path,
    read: &[(String, Result<Workflow, String>)],
    inventory: Option<&Inventory>,
) -> Binaries {
    let mut out = Binaries::default();
    let listing = match crate::scope::git(root, &["ls-files", "-z"]) {
        Ok(listing) => listing,
        Err(e) => {
            out.findings
                .push(unverified(BINARY_ARTIFACTS, "git ls-files", &e.to_string()));
            return out;
        }
    };
    let mut tracked: Vec<&str> = listing.split('\0').filter(|p| !p.is_empty()).collect();
    tracked.sort_unstable();
    for entry in inventory
        .map(|inv| inv.exceptions.as_slice())
        .unwrap_or_default()
    {
        if entry.kind.as_deref() == Some(Kind::Allowlist.as_str())
            && let Some(path) = entry
                .target
                .as_deref()
                .and_then(|t| t.strip_prefix(BINARY_TARGET))
            && tracked.binary_search(&path).is_err()
        {
            out.stale.push(warn(
                INVENTORY_VALID,
                format!(
                    "Exception {} registers {BINARY_TARGET}{path}, which is not a tracked file",
                    entry.label()
                ),
            ));
        }
    }
    let mut validated = None;
    for path in tracked {
        let head = match head_of(root, path) {
            Ok(Some(head)) => head,
            Ok(None) => continue,
            Err(e) => {
                out.findings
                    .push(unverified(BINARY_ARTIFACTS, path, &e.to_string()));
                continue;
            }
        };
        let Some(kind) = binary_type(path, &head) else {
            continue;
        };
        if path.rsplit('/').next() == Some(GRADLE_WRAPPER)
            && *validated.get_or_insert_with(|| wrapper_validated(read))
        {
            continue;
        }
        if registered(
            inventory,
            Kind::Allowlist,
            &[&format!("{BINARY_TARGET}{path}")],
        ) {
            continue;
        }
        out.findings.push(warn(
            BINARY_ARTIFACTS,
            format!(
                "Binary artifact {path} ({kind}) is tracked; build it in CI or register it in security-exceptions.json"
            ),
        ));
    }
    out
}

// --- lockfiles ----------------------------------------------------------------------

/// The lockfile names the stack packs and the node package managers know.
fn lockfile_names() -> BTreeSet<&'static str> {
    packs::ALL
        .iter()
        .filter_map(|p| p.lockfile.map(|l| l.file))
        .chain(PackageManager::ALL.iter().map(|pm| pm.lockfile()))
        .collect()
}

/// A file named in `names` at `dir` or below, at most `LOCKFILE_DEPTH` levels
/// down, outside hidden and dependency directories.
fn has_file(dir: &Path, names: &BTreeSet<&str>, depth: usize) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_file() && names.contains(name.as_ref()) {
            return true;
        }
        if kind.is_dir() && !name.starts_with('.') && !SKIPPED_DIRS.contains(&name.as_ref()) {
            subdirs.push(entry.path());
        }
    }
    depth < LOCKFILE_DEPTH && subdirs.iter().any(|d| has_file(d, names, depth + 1))
}
