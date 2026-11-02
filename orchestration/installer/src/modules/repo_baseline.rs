//! repo-baseline (SPEC-repo-baseline.md): the server-side and repository-side
//! baseline every repository gets. T1 (#700) renders the default-branch ruleset
//! and the service card schema as `managed` data files; T2 (#701) declares the
//! three questions on the engine's answers and routes them into the ruleset and
//! the seed selection; T3 (#702) adds the issue forms and the chooser's
//! `config.yml` as `managed` files; T4 (#703) adds the PR template as a
//! `managed-block` with its seed skeleton. T6 (#707) adds the RFC template as
//! `managed` and declares the GitHub-side changes as `remote` items with probes
//! plus the `check-reported` manual step (`steps.rs`, decision #848). T5 (#705)
//! adds the seeds: service card, `SECURITY.md`, `CODEOWNERS` when answered and
//! the dependency-update configuration the answer selects. T7 (#710) registers
//! it in `modules::all()`: inactive until `install --module repo-baseline
//! [--profile P1|P2|P3]` records it in the lock, the profile read from the
//! engine (`Context::tier`) and the declared-checks finding printed as a plan note.
use crate::{
    Result,
    auditor::rules::Criticality,
    block_content,
    engine::{
        Context, Module, Rendered,
        answers::{self, Kind, Question, Schema},
        lock::Ownership,
        manual::ManualStep,
    },
    host::desired::RemoteWrite,
    modules::{
        ci_baseline::CI_BASELINE,
        qa,
        security::exceptions::{self, INVENTORY, Inventory, Kind as ExceptionKind},
        stack_packs,
    },
    profile::{Profile, audit_fields},
    refuse,
};
use serde_json::{Value, json};
use std::path::Path;
use yaml_rust2::YamlLoader;

pub mod ruleset;
pub mod steps;

use ruleset::{Answers, Approvals, Tier};

pub const REPO_BASELINE: &str = "repo-baseline";
pub const REPO_BASELINE_VERSION: &str = "1.0.0";
/// The ruleset for the default branch; a local edit is a policy change and goes
/// through `configure`, so the engine refuses an edited copy.
pub const RULESET_PATH: &str = ".github/rulesets/main.json";
/// The review ruleset, rendered only when `bypass_actors` declares a bypass:
/// the approval rule alone, with the bypass (decision 2026-10-31, #1218).
pub const REVIEW_RULESET_PATH: &str = ".github/rulesets/main-review.json";
/// The schema the auditor validates the seeded service card against.
pub const SERVICE_SCHEMA_PATH: &str = ".agent-setup/service.schema.json";
pub const SERVICE_SCHEMA: &str =
    include_str!("../../../../templates/repo-baseline/service.schema.json");

/// The service schema with its `$id` under `base`: the configured
/// `schema_base_url`, else the product's own templates.
pub fn service_schema(base: Option<&str>) -> String {
    SERVICE_SCHEMA.replace(
        "{{schema_base_url}}",
        base.unwrap_or(crate::config::PRODUCT_SCHEMA_BASE_URL),
    )
}

/// The issue forms and the chooser's `config.yml` (SPEC-repo-baseline.md, Data
/// model: Issue forms): `managed` because they carry `task.md`'s shape and the
/// labels the auditor counts. Forms a project owns at other names are untouched.
pub const ISSUE_FORM_PATHS: [&str; 5] = [
    ".github/ISSUE_TEMPLATE/task.yml",
    ".github/ISSUE_TEMPLATE/checkpoint.yml",
    ".github/ISSUE_TEMPLATE/incident.yml",
    ".github/ISSUE_TEMPLATE/post-mortem-action.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
];
const ISSUE_FORMS: [&str; 5] = [
    include_str!("../../../../templates/repo-baseline/ISSUE_TEMPLATE/task.yml"),
    include_str!("../../../../templates/repo-baseline/ISSUE_TEMPLATE/checkpoint.yml"),
    include_str!("../../../../templates/repo-baseline/ISSUE_TEMPLATE/incident.yml"),
    include_str!("../../../../templates/repo-baseline/ISSUE_TEMPLATE/post-mortem-action.yml"),
    include_str!("../../../../templates/repo-baseline/ISSUE_TEMPLATE/config.yml"),
];

/// The PR template (SPEC-repo-baseline.md, Data model: PR template block): the
/// five Definition-of-done lines are a `managed-block`; the rest of the file is
/// the skeleton written only when the file is absent, and the project's afterwards.
pub const PR_TEMPLATE_PATH: &str = ".github/pull_request_template.md";
const PR_TEMPLATE: &str =
    include_str!("../../../../templates/repo-baseline/pull_request_template.md");

/// The RFC template (SPEC-repo-baseline.md, Data model: RFC template): `managed`,
/// same lifecycle as setup-core's `adr-template.md`, which stays unchanged.
pub const RFC_TEMPLATE_PATH: &str = "docs/agent-setup/rfc-template.md";
const RFC_TEMPLATE: &str = include_str!("../../../../templates/repo-baseline/rfc-template.md");

// ---- seeds (T5, #705) ---------------------------------------------------------
// Written only when absent, never digested (SPEC-repo-baseline.md, Data model).

/// The service card: owner data the auditor validates against the schema.
pub const SERVICE_CARD_PATH: &str = ".agent-setup/service.yaml";
const SERVICE_CARD: &str = include_str!("../../../../templates/repo-baseline/service.yaml");
/// What `{{repo}}` renders when the engine finds no `origin` repository.
pub const REPO_PLACEHOLDER: &str = "<owner>/<name>";
pub const SECURITY_PATH: &str = ".github/SECURITY.md";
const SECURITY: &str = include_str!("../../../../templates/repo-baseline/SECURITY.md");
/// Rendered only when the `codeowners` answer is true.
pub const CODEOWNERS_PATH: &str = ".github/CODEOWNERS";
const CODEOWNERS: &str = include_str!("../../../../templates/repo-baseline/CODEOWNERS");
const DEPENDABOT: &str = include_str!("../../../../templates/repo-baseline/dependabot.yml");
const DEPENDABOT_ENTRY: &str =
    include_str!("../../../../templates/repo-baseline/dependabot-entry.yml");
const RENOVATE: &str = include_str!("../../../../templates/repo-baseline/renovate.json");

/// `dependabot.yml`: `github-actions` at `/` monthly, then one weekly entry per
/// (ecosystem, directory) of the active stack-packs apps, in app order.
fn dependabot(cx: &Context<'_>) -> Result<String> {
    let entry = |ecosystem: &str, directory: &str, interval: &str| {
        DEPENDABOT_ENTRY
            .replace("{{ecosystem}}", ecosystem)
            .replace("{{directory}}", directory)
            .replace("{{interval}}", interval)
    };
    let mut seen = vec![("github-actions".to_owned(), "/".to_owned())];
    let mut updates = entry("github-actions", "/", "monthly");
    for (app, pack) in stack_packs::active_packs(cx)? {
        let directory = match app.path.as_str() {
            "." => "/".to_owned(),
            path => format!("/{path}"),
        };
        let key = (pack.dependabot_ecosystem.to_owned(), directory);
        if !seen.contains(&key) {
            updates.push_str(&entry(&key.0, &key.1, "weekly"));
            seen.push(key);
        }
    }
    Ok(DEPENDABOT.replace("{{updates}}\n", &updates))
}

/// The held-out test directory CODEOWNERS protects: `ci-baseline`'s `heldout_dir`
/// answer when that module is active (a soft read: repo-baseline does not require
/// it), else the spec's default. Written without a leading `./` or slashes.
fn heldout_dir(cx: &Context<'_>) -> String {
    let answer = cx
        .answers_if_active(CI_BASELINE)
        .and_then(|answers| answers.get("heldout_dir"))
        .and_then(Value::as_str)
        .map(|dir| dir.trim_start_matches("./").trim_matches('/'))
        .filter(|dir| !dir.is_empty());
    answer.unwrap_or(DEFAULT_HELDOUT_DIR).to_owned()
}

/// `ci-baseline`'s default `heldout_dir` (SPEC-ci-baseline.md, Questions).
const DEFAULT_HELDOUT_DIR: &str = "tests/heldout";

/// The criticality the card is seeded with: the profile's declared one, the
/// single source the auditor reads (#1236), else `internal`.
fn card_criticality(cx: &Context<'_>) -> Result<&'static str> {
    Ok(audit_fields(&cx.profile.value)?
        .criticality
        .unwrap_or(Criticality::Internal)
        .name())
}

/// `doctor`'s finding when the card's `criticality` differs from the profile's
/// (an undeclared one compared as `internal`, as the auditor audits it); a
/// missing card, one that does not parse or one without `criticality` is the
/// auditor's schema check, not this finding (#1236).
pub fn card_criticality_finding(root: &Path, profile: &Value) -> Result<Option<String>> {
    let Some(text) = crate::read(root, SERVICE_CARD_PATH)? else {
        return Ok(None);
    };
    let Some(card) = YamlLoader::load_from_str(&text).ok().and_then(|docs| {
        docs.first()
            .and_then(|d| d["criticality"].as_str().map(str::to_owned))
    }) else {
        return Ok(None);
    };
    // An invalid profile value is the profile's own finding.
    let Ok(fields) = audit_fields(profile) else {
        return Ok(None);
    };
    let declared = fields.criticality;
    if card == declared.unwrap_or(Criticality::Internal).name() {
        return Ok(None);
    }
    let profile = declared.map_or("undeclared, audited as internal", Criticality::name);
    Ok(Some(format!(
        "WARNING: Service card criticality differs from the project profile: {SERVICE_CARD_PATH} says {card}, {} says {profile}; project.json decides the required level, align the card",
        crate::PROFILE
    )))
}

/// The seeds for `choices`: the card, the policy, CODEOWNERS when answered and
/// the dependency-update file the answer selects.
fn seeds(cx: &Context<'_>, choices: &Choices) -> Result<Vec<Rendered>> {
    let owner = cx.previous.personal_owner.as_str();
    let seed = |path: &str, content: String| Rendered {
        path: path.to_owned(),
        class: Ownership::Seed,
        content: Some(content),
        scaffold: None,
    };
    let mut seeds = vec![
        seed(
            SERVICE_CARD_PATH,
            SERVICE_CARD
                .replace("{{repo}}", cx.repository().unwrap_or(REPO_PLACEHOLDER))
                .replace("{{owner}}", owner)
                .replace("{{criticality}}", card_criticality(cx)?),
        ),
        seed(SECURITY_PATH, SECURITY.to_owned()),
    ];
    if choices.ruleset.codeowners {
        // qa's web directories (T8, #1005), one line each, after the held-out one.
        let mut text = CODEOWNERS
            .replace("{{heldout_dir}}", &heldout_dir(cx))
            .replace("{{owner}}", owner);
        for line in qa::protected::codeowners_lines(cx, owner) {
            text.push_str(&line);
            text.push('\n');
        }
        seeds.push(seed(CODEOWNERS_PATH, text));
    }
    let path = choices.dependency_updates.seed_path();
    seeds.push(match choices.dependency_updates {
        DependencyUpdates::Dependabot => seed(path, dependabot(cx)?),
        DependencyUpdates::Renovate => seed(path, RENOVATE.to_owned()),
    });
    Ok(seeds)
}

/// The `dependency_updates` answer: which tool's configuration is seeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyUpdates {
    Dependabot,
    Renovate,
}

impl DependencyUpdates {
    pub const ALL: &'static [DependencyUpdates] =
        &[DependencyUpdates::Dependabot, DependencyUpdates::Renovate];
    pub fn parse(text: &str) -> Option<DependencyUpdates> {
        Self::ALL.iter().copied().find(|d| d.as_str() == text)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            DependencyUpdates::Dependabot => "dependabot",
            DependencyUpdates::Renovate => "renovate",
        }
    }
    /// The one seed this answer selects.
    pub fn seed_path(self) -> &'static str {
        match self {
            DependencyUpdates::Dependabot => ".github/dependabot.yml",
            DependencyUpdates::Renovate => "renovate.json",
        }
    }
}

/// The module's answers as typed values: what the ruleset reads, and which
/// dependency-update seed is rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choices {
    pub ruleset: Answers,
    pub dependency_updates: DependencyUpdates,
}

impl Choices {
    /// Reads the engine's validated answers (defaults already filled). The
    /// schema has no `when`, so every question is answered.
    pub fn from_answers(answers: &answers::Answers) -> Result<Choices> {
        let text = |id: &str| answers.get(id).and_then(Value::as_str);
        let Some(approvals) = text("approvals").and_then(Approvals::parse) else {
            return refuse("Module repo-baseline: answer `approvals` is missing or invalid");
        };
        let Some(dependency_updates) =
            text("dependency_updates").and_then(DependencyUpdates::parse)
        else {
            return refuse(
                "Module repo-baseline: answer `dependency_updates` is missing or invalid",
            );
        };
        let Some(codeowners) = answers.get("codeowners").and_then(Value::as_bool) else {
            return refuse("Module repo-baseline: answer `codeowners` is missing or invalid");
        };
        let Some(bypass_actors) = answers
            .get("bypass_actors")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<String>>>()
            })
        else {
            return refuse("Module repo-baseline: answer `bypass_actors` is missing or invalid");
        };
        Ok(Choices {
            ruleset: Answers {
                approvals,
                codeowners,
                bypass_actors,
            },
            dependency_updates,
        })
    }
}

/// The spec's questions (SPEC-repo-baseline.md, Data model: Questions), with the
/// per-profile defaults of `Answers::defaults`. No `when`, no secret.
pub fn questions_schema() -> Schema {
    let by_tier = |pick: fn(Answers) -> Value| {
        json!({
            "P1": pick(Answers::defaults(Tier::P1)),
            "P2": pick(Answers::defaults(Tier::P2)),
            "P3": pick(Answers::defaults(Tier::P3)),
        })
    };
    let question = |id: &str, kind: Kind, default: Value, description: &str| Question {
        default: Some(default),
        description: description.to_owned(),
        ..Question::new(id, kind)
    };
    Schema {
        questions: vec![
            question(
                "approvals",
                Kind::Enum(
                    Approvals::ALL
                        .iter()
                        .map(|a| a.as_str().to_owned())
                        .collect(),
                ),
                by_tier(|a| json!(a.approvals.as_str())),
                "checks-only: 0 approvals, no bypass actor (follows 'Never merge on red', administrators included). checks-only-owner-bypass: 0 approvals, repository admin bypasses; the auditor records it as a standing exception. one-approval: 1 approval, approval of the last push required, stale approvals dismissed, no bypass; agent identities are never bypass actors. review-app: like one-approval, the required check of a review App replaces the human approval; not available until the agent App exists (later slice).",
            ),
            question(
                "dependency_updates",
                Kind::Enum(
                    DependencyUpdates::ALL
                        .iter()
                        .map(|d| d.as_str().to_owned())
                        .collect(),
                ),
                json!(DependencyUpdates::Dependabot.as_str()),
                "The dependency-update tool whose configuration is seeded: dependabot (.github/dependabot.yml) or renovate (renovate.json), both with a 7-day cooldown.",
            ),
            question(
                "codeowners",
                Kind::Boolean,
                by_tier(|a| json!(a.codeowners)),
                "P1 default false: with 0 approvals and agents pushing under the owner's token, CODEOWNERS only requests the owner to review the owner's PRs.",
            ),
            question(
                "bypass_actors",
                Kind::ArrayOfString,
                json!([]),
                "Declared ruleset bypass actors as actor_type:actor_id:bypass_mode (decision 2026-10-31, #1218): OrganizationAdmin, RepositoryRole or Team; pull_request or always; each registered as a ruleset-bypass-actor entry of .agent-setup/security-exceptions.json.",
            ),
        ],
    }
}

/// The module. The maturity profile it renders for is the engine's
/// (`Context::tier`: `install --profile`, recorded with the answers; P1 by
/// default until the auditor derives it).
#[derive(Clone, Copy, Debug, Default)]
pub struct RepoBaseline;

/// The context's maturity profile as the ruleset reads it.
fn tier(cx: &Context<'_>) -> Result<Tier> {
    match Tier::parse(cx.tier()) {
        Some(tier) => Ok(tier),
        None => refuse(format!("Unknown profile: {}; use P1, P2 or P3", cx.tier())),
    }
}

impl RepoBaseline {
    /// What the plan reports about the rendered ruleset for `project` and the
    /// recorded `answers` (defaults for `tier` fill what is unanswered): today the
    /// declared-checks finding when the profile lists contexts other than `required`.
    pub fn findings(
        &self,
        tier: Tier,
        project: &Profile,
        answers: &answers::Answers,
    ) -> Result<Vec<String>> {
        let answers = self
            .questions()
            .validate(REPO_BASELINE, answers, tier.as_str())?;
        let choices = Choices::from_answers(&answers)?;
        Ok(ruleset::ruleset(tier, &choices.ruleset, project, &ruleset::default_checks())?.findings)
    }
}

/// The contexts the ruleset requires unless the project declares others:
/// ci-baseline's required checks when it is active (#1159), else `required`;
/// they replace the declared ones when ci-baseline's switch will (#1299).
fn standard_checks(cx: &Context<'_>) -> Result<ruleset::Standard> {
    use crate::modules::ci_baseline::model;
    let Some(checks) = model::required_checks(cx)? else {
        return Ok(ruleset::default_checks());
    };
    Ok(ruleset::Standard {
        checks,
        replaces_declared: model::switches_required_check(cx)?,
    })
}

/// Every declared bypass actor has a `ruleset-bypass-actor` entry of the
/// inventory whose target is the actor or its `actor_type:actor_id` prefix,
/// with the eight fields valid (decision 2026-10-31, #1218, point 4). The
/// expiry is `doctor`'s: rendering has no clock.
fn registered(root: &std::path::Path, actors: &[String]) -> Result<()> {
    if actors.is_empty() {
        return Ok(());
    }
    let inventory = match crate::read(root, INVENTORY)? {
        None => None,
        Some(text) => match Inventory::parse(&text) {
            Some(inventory) => Some(inventory),
            None => {
                return refuse(format!(
                    "Module repo-baseline: {INVENTORY} does not parse, so the declared bypass actors cannot be matched"
                ));
            }
        },
    };
    for actor in actors {
        let prefix = actor.rsplit_once(':').map_or(actor.as_str(), |(p, _)| p);
        let entries: Vec<_> = inventory
            .iter()
            .flat_map(|i| &i.exceptions)
            .filter(|e| e.kind.as_deref() == Some(ExceptionKind::RulesetBypassActor.as_str()))
            .filter(|e| {
                e.target
                    .as_deref()
                    .is_some_and(|t| t == actor || t == prefix)
            })
            .collect();
        if entries.iter().any(|e| exceptions::defects(e).is_empty()) {
            continue;
        }
        match entries.first() {
            None => {
                return refuse(format!(
                    "Module repo-baseline: bypass actor `{actor}` has no ruleset-bypass-actor entry in {INVENTORY}; add one with an issue and an expiry"
                ));
            }
            Some(entry) => {
                return refuse(format!(
                    "Module repo-baseline: bypass actor `{actor}` is registered by an invalid entry: {}",
                    exceptions::defects(entry).join("; ")
                ));
            }
        }
    }
    Ok(())
}

/// The rendered rulesets: the text of `.github/rulesets/main.json`, and of
/// `.github/rulesets/main-review.json` when a bypass is declared (#1218).
/// What `render` writes and what the `ruleset-main` and `ruleset-review`
/// remote items declare as their desired state, read back.
struct RulesetFiles {
    main: String,
    review: Option<String>,
}

fn ruleset_files(cx: &Context<'_>, choices: &Choices) -> Result<RulesetFiles> {
    registered(cx.root, &choices.ruleset.bypass_actors)?;
    let ruleset = ruleset::ruleset(
        tier(cx)?,
        &choices.ruleset,
        cx.profile,
        &standard_checks(cx)?,
    )?;
    let text =
        |value: &Value| -> Result<String> { Ok(serde_json::to_string_pretty(value)? + "\n") };
    Ok(RulesetFiles {
        main: text(&ruleset.value)?,
        review: ruleset.review.as_ref().map(text).transpose()?,
    })
}

impl Module for RepoBaseline {
    fn id(&self) -> &'static str {
        REPO_BASELINE
    }
    fn version(&self) -> &'static str {
        REPO_BASELINE_VERSION
    }
    /// The capability map names `engine` and `host-adapter`: the engine's content
    /// is the module `setup-core`; the host adapter is not a module but the runner
    /// of this module's remote probes (T6).
    /// Without the `setup-core` feature the engine's content is not a module and
    /// nothing is required (product-boundary T7a).
    fn requires(&self) -> &'static [&'static str] {
        #[cfg(feature = "setup-core")]
        return &["setup-core"];
        #[cfg(not(feature = "setup-core"))]
        return &[];
    }
    /// The spec's questions; the engine resolves their per-profile defaults
    /// with the profile the module is installed for.
    fn questions(&self) -> Schema {
        questions_schema()
    }
    /// The ruleset reads `approvals` and `codeowners`; refusals (owner bypass
    /// outside P1, `review-app`) surface here, so `configure` refuses before
    /// anything is recorded.
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>> {
        let choices = Choices::from_answers(cx.answers)?;
        let managed = |path: &str, content: String| Rendered {
            path: path.to_owned(),
            class: Ownership::Managed,
            content: Some(content),
            scaffold: None,
        };
        let files = ruleset_files(cx, &choices)?;
        let split = files.review.is_some();
        let mut rendered = vec![managed(RULESET_PATH, files.main)];
        if let Some(review) = files.review {
            rendered.push(managed(REVIEW_RULESET_PATH, review));
        }
        rendered.push(managed(
            SERVICE_SCHEMA_PATH,
            service_schema(crate::config::schema_base_url()),
        ));
        for (path, form) in ISSUE_FORM_PATHS.iter().zip(ISSUE_FORMS) {
            rendered.push(managed(path, crate::setup_core_text(form)?));
        }
        let Some(block) = block_content(PR_TEMPLATE)? else {
            return refuse("Module repo-baseline: the PR template has no managed block");
        };
        rendered.push(Rendered {
            path: PR_TEMPLATE_PATH.to_owned(),
            class: Ownership::ManagedBlock,
            content: Some(block.to_owned()),
            scaffold: Some(PR_TEMPLATE.to_owned()),
        });
        // T6 (#707): the RFC template and the remote items of `steps.rs`.
        rendered.push(managed(
            RFC_TEMPLATE_PATH,
            crate::setup_core_text(RFC_TEMPLATE)?,
        ));
        if steps::labels().is_empty() {
            return refuse(
                "Module repo-baseline: templates/repo-baseline/labels.json is not a label list",
            );
        }
        rendered.extend(steps::remote_items(split));
        // T5 (#705): the seeds.
        rendered.extend(seeds(cx, &choices)?);
        Ok(rendered)
    }
    /// `check-reported` and the probes of the remote items; the ruleset's
    /// contexts are those `render` writes into `.github/rulesets/main.json`.
    fn manual_steps(&self, cx: &Context<'_>) -> Vec<ManualStep> {
        // A ci-baseline that cannot load refuses the render; the steps keep `required`.
        let standard = standard_checks(cx).unwrap_or_else(|_| ruleset::default_checks());
        // An answer that cannot be read refuses the render; the steps keep one ruleset.
        let split = Choices::from_answers(cx.answers)
            .is_ok_and(|choices| !choices.ruleset.bypass_actors.is_empty());
        steps::steps(
            cx.root,
            &ruleset::required_checks(cx.profile, &standard),
            split,
        )
    }
    /// The desired state of the remote items (#902); the ruleset is the text
    /// `render` writes to `.github/rulesets/main.json`, read back.
    fn remote_writes(&self, cx: &Context<'_>) -> Result<Vec<RemoteWrite>> {
        let choices = Choices::from_answers(cx.answers)?;
        let files = ruleset_files(cx, &choices)?;
        steps::remote_writes(
            cx.root,
            &files.main,
            files.review.as_deref(),
            crate::modules::ci_baseline::model::supersession(cx)?,
        )
    }
    /// The ruleset's findings after the plan: today the declared-checks finding
    /// (assumption 3), so the owner sees it before `--apply`.
    fn notes(&self, cx: &Context<'_>) -> Result<Vec<String>> {
        let choices = Choices::from_answers(cx.answers)?;
        Ok(ruleset::ruleset(
            tier(cx)?,
            &choices.ruleset,
            cx.profile,
            &standard_checks(cx)?,
        )?
        .findings)
    }
}
