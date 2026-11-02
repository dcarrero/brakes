//! ci-baseline T6 (#776; SPEC-ci-baseline.md, Composition; SPEC-engine.md,
//! Contributed CI jobs in the context): other modules' jobs reach the workflow only
//! through `Module::ci_jobs`, collected by the plan and read by ci-baseline, which
//! inserts them, extends `required`'s `needs`, hands the docs-skippable ids to the
//! scope job and refuses a colliding id naming both modules.
mod support;
use brakes::engine::{self, CiJob, CiTier, Context, Module, PlanNote, Planned, Rendered};
use brakes::modules::StackPacks;
use brakes::modules::ci_baseline::{CiBaseline, REQUIRED_SH};
use brakes::{Result, Source, digest, profile_for};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};
use support::SetupCore;
use tempfile::TempDir;

const WORKFLOW: &str = ".github/workflows/ci.yml";

/// A contributor module: `id` contributes the given `(job id, skippable under docs)`.
struct Contributor {
    id: &'static str,
    jobs: Vec<(&'static str, bool)>,
}

impl Module for Contributor {
    fn id(&self) -> &'static str {
        self.id
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
        self.jobs
            .iter()
            .map(|(id, docs)| CiJob {
                id: (*id).to_owned(),
                yaml: format!(
                    "name: {id}\nneeds: scope\nruns-on: ubuntu-24.04\ntimeout-minutes: 10\nsteps:\n  - name: Run {id}\n    run: echo {id}\n"
                ),
                skippable_under: if *docs { vec![CiTier::Docs] } else { vec![] },
                app: None,
            })
            .collect()
    }
}

/// Records what its context hands it as contributed jobs, as notes.
struct Witness;
impl Module for Witness {
    fn id(&self) -> &'static str {
        "witness"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
        vec![CiJob {
            id: "own-job".to_owned(),
            yaml: "name: own-job\n".to_owned(),
            skippable_under: Vec::new(),
            app: None,
        }]
    }
    fn notes(&self, cx: &Context<'_>) -> Result<Vec<String>> {
        Ok(cx
            .contributed_jobs()
            .map(|(module, job)| format!("{module} {}", job.id))
            .collect())
    }
}

fn contributor(id: &'static str, jobs: &[(&'static str, bool)]) -> Contributor {
    Contributor {
        id,
        jobs: jobs.to_vec(),
    }
}

fn gate() -> Contributor {
    contributor("gatekeeper", &[("gate-job", false)])
}

fn scanner() -> Contributor {
    contributor("scanner", &[("scan-job", true)])
}

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// A personal repository with `setup-core` installed and `test` declared.
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args([
                "install",
                &root.to_string_lossy(),
                "--new-personal",
                "--apply",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let path = root.join(".agent-setup/project.json");
        let mut profile: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        profile["commands"]["test"] = "cargo test".into();
        fs::write(
            &path,
            serde_json::to_string_pretty(&profile).unwrap() + "\n",
        )
        .unwrap();
        // The deprecated generated `ci.yml` these tests read (#21), pinned until #25.
        let ci = root.join(".agent-setup/modules/ci-baseline.json");
        fs::create_dir_all(ci.parent().unwrap()).unwrap();
        fs::write(
            ci,
            r#"{"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "generate"}}"#,
        )
        .unwrap();
        Self { _temp: temp, root }
    }

    fn plan(&self, extra: &[&dyn Module]) -> Result<Planned> {
        let profile = profile_for(&self.root)?;
        let source = Source {
            documents: BTreeMap::new(),
            version: "0.1.0".to_owned(),
            revision: None,
            dirty: false,
        };
        let modules: Vec<&dyn Module> = [&SetupCore as &dyn Module, &StackPacks]
            .into_iter()
            .chain(extra.iter().copied())
            .chain([&CiBaseline as &dyn Module])
            .collect();
        engine::plan(&self.root, &source, &profile, &modules, &|_| true)
    }

    fn workflow(&self, extra: &[&dyn Module]) -> String {
        self.plan(extra).unwrap().changes[WORKFLOW].clone().unwrap()
    }

    fn refusal(&self, extra: &[&dyn Module]) -> String {
        self.plan(extra).unwrap_err().to_string()
    }
}

/// The lines of the job `id` in the workflow, from its key to the next job.
fn job<'a>(workflow: &'a str, id: &str) -> Vec<&'a str> {
    let key = format!("  {id}:");
    let mut lines = workflow.lines().skip_while(|l| *l != key);
    let first = lines.next().unwrap_or_else(|| panic!("no job {id}"));
    std::iter::once(first)
        .chain(lines.take_while(|l| !l.starts_with("  ") || l.starts_with("   ") || l.is_empty()))
        .collect()
}

/// The value of the `DOCS_SKIPPABLE` env entry, one id per line.
fn docs_skippable(workflow: &str) -> Vec<String> {
    let scope = job(workflow, "scope");
    let start = scope
        .iter()
        .position(|l| l.trim_start().starts_with("DOCS_SKIPPABLE:"))
        .unwrap();
    let header = scope[start];
    let indent = header.len() - header.trim_start().len();
    if !header.trim_end().ends_with('|') && !header.trim_end().ends_with("|-") {
        return vec![header.split(':').nth(1).unwrap().trim().to_owned()];
    }
    scope[start + 1..]
        .iter()
        .take_while(|l| l.len() - l.trim_start().len() > indent)
        .map(|l| l.trim().to_owned())
        .collect()
}

fn required_needs(workflow: &str) -> String {
    job(workflow, "required")
        .into_iter()
        .find(|l| l.trim_start().starts_with("needs:"))
        .unwrap()
        .trim()
        .to_owned()
}

#[test]
fn a_contributed_job_is_inserted_needed_by_required_and_handed_to_scope() {
    let repo = Repo::new();
    let workflow = repo.workflow(&[&gate(), &scanner()]);
    assert_eq!(
        job(&workflow, "scan-job"),
        [
            "  scan-job:",
            "    name: scan-job",
            "    needs: scope",
            "    runs-on: ubuntu-24.04",
            "    timeout-minutes: 10",
            "    steps:",
            "      - name: Run scan-job",
            "        run: echo scan-job",
        ]
    );
    assert_eq!(
        required_needs(&workflow),
        "needs: [scope, checks, heldout, workflow-lint, gate-job, scan-job]"
    );
    assert_eq!(docs_skippable(&workflow), ["checks", "heldout", "scan-job"]);
    // Contributed jobs come after the built-ins and before `required`, in module order.
    let order: Vec<usize> = ["workflow-lint:", "gate-job:", "scan-job:", "required:"]
        .iter()
        .map(|k| workflow.find(&format!("\n  {k}\n")).unwrap())
        .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{workflow}");
}

#[test]
fn a_non_skippable_contributor_never_appears_in_skippable() {
    let repo = Repo::new();
    let workflow = repo.workflow(&[&gate()]);
    assert!(job(&workflow, "gate-job").len() > 1);
    assert_eq!(docs_skippable(&workflow), ["checks", "heldout"]);
    assert!(required_needs(&workflow).contains("gate-job"));
}

#[test]
fn without_contributors_the_workflow_is_unchanged() {
    let repo = Repo::new();
    let quiet = contributor("quiet", &[]);
    assert_eq!(repo.workflow(&[&quiet]), repo.workflow(&[]));
}

#[test]
fn the_plan_notes_each_inserted_job() {
    let repo = Repo::new();
    let notes: Vec<String> = repo
        .plan(&[&gate(), &scanner()])
        .unwrap()
        .plan_notes
        .iter()
        .map(PlanNote::to_string)
        .filter(|n| n.contains("JOB"))
        .collect();
    assert_eq!(
        notes,
        [
            format!("NOTE [ci-baseline] JOB [gatekeeper] gate-job → {WORKFLOW}"),
            format!("NOTE [ci-baseline] JOB [scanner] scan-job → {WORKFLOW}"),
        ]
    );
}

#[test]
fn a_module_sees_the_other_modules_jobs_never_its_own() {
    let repo = Repo::new();
    let notes: Vec<String> = repo
        .plan(&[&gate(), &Witness])
        .unwrap()
        .plan_notes
        .iter()
        .filter(|n| n.module == "witness")
        .map(|n| n.text.clone())
        .collect();
    assert_eq!(notes, ["gatekeeper gate-job"]);
}

#[test]
fn two_contributors_with_the_same_id_refuse_naming_both() {
    let repo = Repo::new();
    let twin = contributor("twin", &[("scan-job", false)]);
    assert_eq!(
        repo.refusal(&[&scanner(), &twin]),
        "Module twin contributes CI job scan-job, which collides with module scanner"
    );
}

#[test]
fn a_contributed_built_in_id_refuses_naming_ci_baseline() {
    let repo = Repo::new();
    for id in [
        "scope",
        "checks",
        "workflow-lint",
        "required",
        "lint",
        "shard",
        "macos",
        "agentic-required",
    ] {
        let squatter = contributor("squatter", &[(id, false)]);
        assert_eq!(
            repo.refusal(&[&squatter]),
            format!(
                "Module squatter contributes CI job {id}, which collides with module ci-baseline"
            )
        );
    }
}

#[test]
fn a_non_kebab_id_refuses() {
    let repo = Repo::new();
    let odd = contributor("odd", &[("Scan_Job", false)]);
    assert_eq!(
        repo.refusal(&[&odd]),
        "Module odd contributes CI job Scan_Job, which is not kebab-case"
    );
}

#[test]
fn required_sh_is_unchanged_and_embedded_without_its_comment_lines() {
    // Re-pinned when the spec added rule 3, the protected-paths gate (#943), and
    // when rule 3 began reading who added the label (#1255); contributors never
    // change it.
    assert_eq!(
        digest(REQUIRED_SH),
        "f43422f29f025e02da9ae27e6e6ab990acfc51bff8c789b7a9531417bc20ad73"
    );
    let repo = Repo::new();
    let workflow = repo.workflow(&[&gate(), &scanner()]);
    // Embedded without its comment-only lines (#1088, amended by #1362).
    let indented: String = brakes::modules::security::embed::without_comment_lines(REQUIRED_SH)
        .lines()
        .map(|l| {
            if l.is_empty() {
                "\n".to_owned()
            } else {
                format!("          {l}\n")
            }
        })
        .collect();
    assert!(workflow.contains(&indented), "{workflow}");
}

#[test]
fn in_a_brownfield_repository_the_note_names_agentic_ci() {
    let repo = Repo::new();
    let own = repo.root.join(".github/workflows/build.yml");
    fs::create_dir_all(own.parent().unwrap()).unwrap();
    fs::write(&own, "name: build\non: push\njobs: {}\n").unwrap();
    let planned = repo.plan(&[&gate()]).unwrap();
    let notes: Vec<String> = planned.plan_notes.iter().map(PlanNote::to_string).collect();
    assert_eq!(
        notes,
        [
            "NOTE [ci-baseline] workflow generate is deprecated: it runs the declared commands in a workflow brakes owns; answer workflow=seed (the project owns its CI) or workflow=existing (decision 2026-11-02)",
            "NOTE [ci-baseline] JOB [gatekeeper] gate-job → .github/workflows/agentic-ci.yml"
        ]
    );
    let workflow = planned.changes[".github/workflows/agentic-ci.yml"]
        .as_ref()
        .unwrap();
    assert!(required_needs(workflow).contains("gate-job"), "{workflow}");
}

#[test]
fn missing_command_notes_come_before_the_job_notes() {
    let repo = Repo::new();
    let path = repo.root.join(".agent-setup/modules/ci-baseline.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let file = serde_json::json!({
        "module": "ci-baseline", "version": "1.0.0",
        "answers": {"workflow": "generate", "commands": ["lint", "test"]},
    });
    fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
    let notes: Vec<String> = repo
        .plan(&[&gate(), &scanner()])
        .unwrap()
        .plan_notes
        .iter()
        .map(PlanNote::to_string)
        .collect();
    assert_eq!(
        notes,
        [
            "NOTE [ci-baseline] workflow generate is deprecated: it runs the declared commands in a workflow brakes owns; answer workflow=seed (the project owns its CI) or workflow=existing (decision 2026-11-02)".to_owned(),
            "NOTE [ci-baseline] Verification command missing: commands.lint is null in .agent-setup/project.json; the workflow renders without its step until it is declared".to_owned(),
            format!("NOTE [ci-baseline] JOB [gatekeeper] gate-job → {WORKFLOW}"),
            format!("NOTE [ci-baseline] JOB [scanner] scan-job → {WORKFLOW}"),
        ]
    );
}

/// #940, split by "CI hardening for agent workflows" (#969): `agent-guardrails`'s
/// `cross-review-model` and `cross-review` join `required` in that order and are
/// skippable under `docs`, nothing more.
#[test]
fn agent_guardrails_contributes_cross_review_to_required() {
    use brakes::modules::{AgentGuardrails, RepoBaseline};
    let repo = Repo::new();
    let planned = repo.plan(&[&RepoBaseline, &AgentGuardrails]).unwrap();
    let workflow = planned.changes[WORKFLOW].clone().unwrap();
    assert_eq!(
        required_needs(&workflow),
        "needs: [scope, checks, heldout, workflow-lint, cross-review-model, cross-review]"
    );
    assert_eq!(
        docs_skippable(&workflow),
        ["checks", "heldout", "cross-review-model", "cross-review"]
    );
    assert_eq!(
        job(&workflow, "cross-review-model")[1],
        "    name: cross-review-model"
    );
    assert_eq!(job(&workflow, "cross-review")[1], "    name: cross-review");
    let notes: Vec<String> = planned.plan_notes.iter().map(PlanNote::to_string).collect();
    for id in ["cross-review-model", "cross-review"] {
        assert!(
            notes.contains(&format!(
                "NOTE [ci-baseline] JOB [agent-guardrails] {id} → {WORKFLOW}"
            )),
            "{notes:?}"
        );
    }
}

// --- a contributed job for one app (#1097) ---------------------------------------------

/// Contributes `<app>-qa` for each of `apps`, naming its app.
struct PerApp {
    apps: Vec<&'static str>,
}
impl Module for PerApp {
    fn id(&self) -> &'static str {
        "per-app"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn render(&self, _: &Context<'_>) -> Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn ci_jobs(&self, _: &Context<'_>) -> Vec<CiJob> {
        self.apps
            .iter()
            .map(|app| {
                let id = format!("{app}-qa");
                CiJob {
                    yaml: format!(
                        "name: {id}\nneeds: scope\nif: contains(fromJSON(needs.scope.outputs.skippable), '{id}') == false\nruns-on: ubuntu-24.04\ntimeout-minutes: 10\nsteps:\n  - name: Run {id}\n    run: echo {id}\n"
                    ),
                    id,
                    skippable_under: vec![CiTier::Docs],
                    app: Some((*app).to_owned()),
                }
            })
            .collect()
    }
}

impl Repo {
    /// Two rust apps, `api` and `web`, each with its own profile: monorepo mode.
    fn monorepo() -> Self {
        let repo = Self::new();
        for app in ["api", "web"] {
            for file in ["Cargo.toml", "Cargo.lock"] {
                let path = repo.root.join(app).join(file);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, "").unwrap();
            }
            let profile = repo.root.join(app).join(".agent-setup/project.json");
            fs::create_dir_all(profile.parent().unwrap()).unwrap();
            fs::write(profile, r#"{"commands": {"test": "cargo test"}}"#).unwrap();
        }
        let answers = repo.root.join(".agent-setup/modules/stack-packs.json");
        fs::create_dir_all(answers.parent().unwrap()).unwrap();
        fs::write(
            answers,
            r#"{"module": "stack-packs", "version": "1.0.0", "answers": {"apps.api.path": "api", "apps.api.stack": "rust", "apps.api.container": false, "apps.web.path": "web", "apps.web.stack": "rust", "apps.web.container": false}}"#,
        )
        .unwrap();
        repo
    }
}

/// The `env:` value `key` of the scope step, one line per entry.
fn scope_env(workflow: &str, key: &str) -> Option<Vec<String>> {
    let scope = job(workflow, "scope");
    let start = scope
        .iter()
        .position(|l| l.trim_start().starts_with(&format!("{key}:")))?;
    let header = scope[start];
    let indent = header.len() - header.trim_start().len();
    let value = header.split_once(':').unwrap().1.trim();
    if value != "|-" && value != "|" {
        return Some(vec![value.trim_matches('"').to_owned()]);
    }
    Some(
        scope[start + 1..]
            .iter()
            .take_while(|l| l.len() - l.trim_start().len() > indent)
            .map(|l| l.trim().to_owned())
            .collect(),
    )
}

#[test]
fn a_contributed_app_job_reaches_scope_as_an_app_job_pair() {
    let repo = Repo::monorepo();
    let workflow = repo.workflow(&[&PerApp {
        apps: vec!["api", "web"],
    }]);
    assert_eq!(
        scope_env(&workflow, "APP_JOBS").unwrap(),
        ["api-qa=api", "web-qa=web"]
    );
    let scope = job(&workflow, "scope").join("\n");
    assert!(scope.contains("done <<< \"${APP_JOBS:-}\""), "{scope}");
    assert!(
        required_needs(&workflow).ends_with("api-qa, web-qa]"),
        "{workflow}"
    );
    assert_eq!(
        docs_skippable(&workflow)
            .iter()
            .rev()
            .take(2)
            .collect::<Vec<_>>(),
        ["web-qa", "api-qa"]
    );
}

#[test]
fn without_an_app_job_the_scope_has_no_app_jobs_and_is_unchanged() {
    let repo = Repo::monorepo();
    let plain = repo.workflow(&[]);
    assert_eq!(scope_env(&plain, "APP_JOBS"), None);
    assert!(!plain.contains("APP_JOBS"), "{plain}");
    let with_docs_job = repo.workflow(&[&scanner()]);
    assert!(!with_docs_job.contains("APP_JOBS"), "{with_docs_job}");
}

#[test]
fn an_app_outside_the_stack_packs_record_refuses() {
    let repo = Repo::monorepo();
    assert_eq!(
        repo.refusal(&[&PerApp {
            apps: vec!["api", "mobile"],
        }]),
        "Module per-app contributes CI job mobile-qa for app mobile, which is not a stack-packs app"
    );
}
