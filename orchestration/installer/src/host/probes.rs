//! The remote probe registry (SPEC-host-adapter.md, "Probe registry", #683):
//! id → (argument schema, runner). The engine refuses at module load a step
//! whose id or arguments [`check`] rejects; `doctor --remote` answers the rest
//! through [`HostRunner`]. Probes only read. Every evidence and reason is one
//! line through `remote::plain`, so GitHub text cannot forge a doctor line.
use super::{
    Availability, Host, HostError, HostErrorKind, RepoId, SecretScope, Visibility,
    github::declared_ruleset,
    types::{DeploymentBranchPolicy, Ruleset, SecurityToggle},
};
use crate::engine::manual::{ProbeResult, RemoteRunner};
use crate::remote::plain;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

type Args = BTreeMap<String, Value>;
type Answer = Result<ProbeResult, HostError>;

/// The JSON shape an argument takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    Text,
    TextList,
    Object,
    ObjectList,
}

impl ArgKind {
    fn accepts(self, value: &Value) -> bool {
        match self {
            ArgKind::Text => value.is_string(),
            ArgKind::TextList => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            ArgKind::Object => value.is_object(),
            ArgKind::ObjectList => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_object)),
        }
    }
    fn described(self) -> &'static str {
        match self {
            ArgKind::Text => "a text",
            ArgKind::TextList => "a list of texts",
            ArgKind::Object => "an object",
            ArgKind::ObjectList => "a list of objects",
        }
    }
}

/// One argument of a probe; an optional one may be left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arg {
    pub name: &'static str,
    pub kind: ArgKind,
    pub required: bool,
}

/// A registered probe: its id and its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema {
    pub id: &'static str,
    pub args: &'static [Arg],
}

const fn req(name: &'static str, kind: ArgKind) -> Arg {
    Arg {
        name,
        kind,
        required: true,
    }
}
const fn opt(name: &'static str, kind: ArgKind) -> Arg {
    Arg {
        name,
        kind,
        required: false,
    }
}

use ArgKind::{Object, ObjectList, Text, TextList};

/// The registry, sorted by id.
const REGISTRY: &[Schema] = &[
    Schema {
        id: "actions-pull-requests",
        args: &[],
    },
    Schema {
        id: "app-installed",
        args: &[opt("slug", Text)],
    },
    Schema {
        id: "automated-security-fixes",
        args: &[],
    },
    Schema {
        id: "check-run-reported",
        args: &[req("contexts", TextList), req("branch", Text)],
    },
    Schema {
        id: "classic-protection-absent",
        args: &[req("branch", Text)],
    },
    Schema {
        id: "code-scanning-default-setup",
        args: &[],
    },
    Schema {
        id: "default-branch",
        args: &[opt("expected", Text)],
    },
    Schema {
        id: "dependabot-alerts",
        args: &[],
    },
    Schema {
        id: "endpoint-answers",
        args: &[req("env", Text)],
    },
    Schema {
        id: "environment-main-only",
        args: &[opt("environment", Text)],
    },
    Schema {
        id: "feature-available",
        args: &[req("feature", Text)],
    },
    Schema {
        id: "labels-present",
        args: &[req("labels", ObjectList)],
    },
    Schema {
        id: "org-2fa-required",
        args: &[req("org", Text)],
    },
    Schema {
        id: "private-vulnerability-reporting",
        args: &[],
    },
    Schema {
        id: "repo-settings",
        args: &[req("fields", Object)],
    },
    Schema {
        id: "repository-visibility",
        args: &[req("expected", Text)],
    },
    Schema {
        id: "required-check",
        args: &[req("branch", Text), req("check", Text)],
    },
    Schema {
        id: "reusable-workflow-reachable",
        args: &[req("callee", Text)],
    },
    Schema {
        id: "ruleset-present",
        args: &[req("name", Text), req("branch", Text), req("path", Text)],
    },
    Schema {
        id: "ruleset-required-checks",
        args: &[req("branch", Text), req("checks", TextList)],
    },
    Schema {
        id: "secret-exists",
        args: &[req("name", Text), req("environment", Text)],
    },
    Schema {
        id: "secret-present",
        args: &[req("name", Text), req("scope", Text)],
    },
    Schema {
        id: "secret-scanning",
        args: &[],
    },
    Schema {
        id: "workflow-lockfile",
        args: &[],
    },
];

/// The `Features` fields `feature-available` accepts, in field order.
const FEATURES: &[&str] = &[
    "rulesets",
    "environments",
    "branch_protection",
    "required_reviewers",
    "dependabot_alerts",
    "secret_scanning",
    "workflow_lockfile",
    "merge_queue",
];

/// The `PATCH repos/{r}` keys `repo-settings` compares.
const SETTINGS: &[&str] = &[
    "allow_squash_merge",
    "allow_merge_commit",
    "allow_rebase_merge",
    "delete_branch_on_merge",
    "allow_auto_merge",
    "allow_update_branch",
    "has_wiki",
    "has_projects",
    "web_commit_signoff_required",
];

/// The registered ids, sorted.
pub fn ids() -> impl Iterator<Item = &'static str> {
    REGISTRY.iter().map(|s| s.id)
}

/// The schema of `id`, or `None` when the registry cannot run it.
pub fn schema(id: &str) -> Option<&'static Schema> {
    REGISTRY.iter().find(|s| s.id == id)
}

/// Whether the registry can run `id` with `args`: a known id, every required
/// argument, no unknown one, each of its kind, and the values a probe
/// enumerates. The error is one sentence naming the probe.
pub fn check(id: &str, args: &Args) -> Result<(), String> {
    let Some(schema) = schema(id) else {
        return Err(format!(
            "remote probe `{id}` is not in the host-adapter registry"
        ));
    };
    if let Some(unknown) = args
        .keys()
        .find(|k| !schema.args.iter().any(|a| a.name == k.as_str()))
    {
        return Err(format!("remote probe `{id}` has no argument `{unknown}`"));
    }
    for arg in schema.args {
        match args.get(arg.name) {
            None if arg.required => {
                return Err(format!("remote probe `{id}` needs argument `{}`", arg.name));
            }
            Some(value) if !arg.kind.accepts(value) => {
                return Err(format!(
                    "remote probe `{id}`: argument `{}` must be {}",
                    arg.name,
                    arg.kind.described()
                ));
            }
            _ => {}
        }
    }
    let invalid = |name: &str, rule: String| {
        Err(format!(
            "remote probe `{id}`: argument `{name}` must {rule}"
        ))
    };
    match id {
        "repository-visibility" if visibility(text(args, "expected")).is_none() => {
            invalid("expected", "be private, public or internal".to_owned())
        }
        "secret-present" if scope(text(args, "scope")).is_none() => invalid(
            "scope",
            "be repository, organization, dependabot or environment:<name>".to_owned(),
        ),
        "reusable-workflow-reachable" if RepoId::parse(text(args, "callee")).is_err() => {
            invalid("callee", "be owner/name".to_owned())
        }
        "feature-available" if !FEATURES.contains(&text(args, "feature")) => {
            invalid("feature", format!("be one of {}", FEATURES.join(", ")))
        }
        "repo-settings"
            if !args["fields"].as_object().is_some_and(|fields| {
                fields
                    .iter()
                    .all(|(k, v)| SETTINGS.contains(&k.as_str()) && v.is_boolean())
            }) =>
        {
            Err(format!(
                "remote probe `{id}`: argument `fields` may hold only {}, each true or false",
                SETTINGS.join(", ")
            ))
        }
        "labels-present"
            if !args["labels"].as_array().is_some_and(|labels| {
                labels
                    .iter()
                    .all(|l| l["name"].is_string() && l["color"].is_string())
            }) =>
        {
            invalid(
                "labels",
                "list objects with a text name and color".to_owned(),
            )
        }
        _ => Ok(()),
    }
}

/// Runs probe `id` against `repo`; see [`run_detailed`].
pub fn run(host: &dyn Host, repo: &RepoId, id: &str, args: &Args) -> ProbeResult {
    run_detailed(host, repo, id, args).0
}

/// Runs probe `id` against `repo` and maps the answer to the engine states,
/// with the host error kind behind a `failed` or `unavailable` answer (so the
/// CLI can tell a rate-limited read from a refusal). An unknown id or invalid
/// arguments are `unavailable` and read nothing.
pub fn run_detailed(
    host: &dyn Host,
    repo: &RepoId,
    id: &str,
    args: &Args,
) -> (ProbeResult, Option<HostErrorKind>) {
    if let Err(reason) = check(id, args) {
        return (ProbeResult::Unavailable(plain(&reason)), None);
    }
    let probe = Probe { host, repo, args };
    let answer = match id {
        "required-check" => probe.required_check(),
        "ruleset-required-checks" => probe.ruleset_required_checks(),
        "ruleset-present" => probe.ruleset_present(),
        "check-run-reported" => probe.check_run_reported(),
        "classic-protection-absent" => probe.classic_protection_absent(),
        "labels-present" => probe.labels_present(),
        "repo-settings" => probe.repo_settings(),
        "dependabot-alerts" => probe.toggle(SecurityToggle::VulnerabilityAlerts),
        "automated-security-fixes" => probe.toggle(SecurityToggle::AutomatedSecurityFixes),
        "private-vulnerability-reporting" => probe.private_vulnerability_reporting(),
        "secret-scanning" => probe.secret_scanning(),
        "code-scanning-default-setup" => probe.code_scanning_default_setup(),
        "environment-main-only" => probe.environment_main_only(),
        "secret-present" => probe.secret_present(),
        "actions-pull-requests" => probe.actions_pull_requests(),
        "workflow-lockfile" => probe.workflow_lockfile(),
        "default-branch" => probe.default_branch(),
        "org-2fa-required" => probe.org_2fa_required(),
        "repository-visibility" => probe.repository_visibility(),
        "feature-available" => probe.feature_available(),
        "reusable-workflow-reachable" => probe.reusable_workflow_reachable(),
        // The generic probes of the "configure new" contract (#725) and the
        // agents' App (#750): declared so the steps load; no runner reads them yet.
        "endpoint-answers" | "secret-exists" | "app-installed" => Ok(ProbeResult::Unavailable(
            format!("remote probe `{id}` has no runner yet"),
        )),
        // `check` accepted it, so the registry and this match disagree.
        _ => Ok(ProbeResult::Unavailable(format!(
            "remote probe `{id}` has no runner in the host-adapter registry"
        ))),
    };
    match answer {
        Ok(result) => (single_line(result), None),
        Err(error) => {
            let message = plain(&error.message);
            let result = match error.kind {
                HostErrorKind::Unsupported => ProbeResult::Unavailable(message),
                HostErrorKind::Unauthenticated => {
                    ProbeResult::Unavailable(format!("gh not authenticated: {message}"))
                }
                _ => ProbeResult::Failed(message),
            };
            (result, Some(error.kind))
        }
    }
}

fn single_line(result: ProbeResult) -> ProbeResult {
    match result {
        ProbeResult::Verified(t) => ProbeResult::Verified(plain(&t)),
        ProbeResult::Pending(t) => ProbeResult::Pending(plain(&t)),
        ProbeResult::Failed(t) => ProbeResult::Failed(plain(&t)),
        ProbeResult::Unavailable(t) => ProbeResult::Unavailable(plain(&t)),
        ProbeResult::NotApplicable(t) => ProbeResult::NotApplicable(plain(&t)),
    }
}

/// Answers `doctor --remote`'s remote probes for one repository through `host`.
pub struct HostRunner<'a> {
    host: &'a dyn Host,
    repo: RepoId,
}

impl<'a> HostRunner<'a> {
    pub fn new(host: &'a dyn Host, repo: RepoId) -> Self {
        Self { host, repo }
    }
    /// The host the probes read.
    pub fn host(&self) -> &'a dyn Host {
        self.host
    }
    /// The repository the probes read.
    pub fn repo(&self) -> &RepoId {
        &self.repo
    }
}

impl RemoteRunner for HostRunner<'_> {
    fn run(&self, id: &str, args: &Args) -> ProbeResult {
        run(self.host, &self.repo, id, args)
    }
}

// ---- argument readers (after `check`) ----------------------------------------------

fn text<'a>(args: &'a Args, name: &str) -> &'a str {
    args.get(name).and_then(Value::as_str).unwrap_or_default()
}
fn text_or<'a>(args: &'a Args, name: &str, default: &'a str) -> &'a str {
    args.get(name).and_then(Value::as_str).unwrap_or(default)
}
fn texts(args: &Args, name: &str) -> BTreeSet<String> {
    args.get(name)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
fn visibility(name: &str) -> Option<Visibility> {
    match name {
        "private" => Some(Visibility::Private),
        "public" => Some(Visibility::Public),
        "internal" => Some(Visibility::Internal),
        _ => None,
    }
}
fn visibility_name(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Private => "private",
        Visibility::Public => "public",
        Visibility::Internal => "internal",
    }
}
fn scope(name: &str) -> Option<SecretScope> {
    match name {
        "repository" => Some(SecretScope::Repository),
        "organization" => Some(SecretScope::Organization),
        "dependabot" => Some(SecretScope::Dependabot),
        _ => name
            .strip_prefix("environment:")
            .filter(|e| !e.is_empty())
            .map(|e| SecretScope::Environment(e.to_owned())),
    }
}
fn joined(items: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    let items: Vec<String> = items.into_iter().map(|i| i.as_ref().to_owned()).collect();
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}
fn named(ruleset: &Ruleset) -> String {
    match ruleset.id {
        Some(id) => format!("ruleset {id} \"{}\"", ruleset.name),
        None => format!("ruleset \"{}\"", ruleset.name),
    }
}

// ---- the probes --------------------------------------------------------------------

struct Probe<'a> {
    host: &'a dyn Host,
    repo: &'a RepoId,
    args: &'a Args,
}

impl Probe<'_> {
    fn default_branch_name(&self) -> Result<String, HostError> {
        Ok(self.host.repository(self.repo)?.default_branch)
    }

    /// The active branch rulesets that apply to `branch`; see [`applying`].
    fn applying(&self, branch: &str) -> Result<Vec<Ruleset>, HostError> {
        applying(self.host, self.repo, branch)
    }

    fn required_check(&self) -> Answer {
        let (branch, check) = (text(self.args, "branch"), text(self.args, "check"));
        let requiring: Vec<Ruleset> = self
            .applying(branch)?
            .into_iter()
            .filter(|r| r.required_status_checks.iter().any(|c| c == check))
            .collect();
        if let Some(ruleset) = requiring.iter().find(|r| r.bypass_actors.is_empty()) {
            return Ok(ProbeResult::Verified(format!(
                "{} requires \"{check}\"",
                named(ruleset)
            )));
        }
        let classic = self
            .host
            .branch_protection(self.repo, branch)?
            .filter(|p| p.required_status_checks.iter().any(|c| c == check));
        Ok(match (requiring.first(), classic) {
            (_, Some(p)) if p.enforce_admins == Some(true) => ProbeResult::Verified(format!(
                "classic protection of {branch} requires \"{check}\" for administrators too"
            )),
            (Some(ruleset), _) => ProbeResult::Pending(format!(
                "{} requires \"{check}\" but has bypass actors",
                named(ruleset)
            )),
            (None, Some(_)) => ProbeResult::Pending(format!(
                "classic protection of {branch} requires \"{check}\" but not for administrators"
            )),
            (None, None) => ProbeResult::Pending(format!(
                "no ruleset or classic protection requires \"{check}\" on {branch}"
            )),
        })
    }

    fn ruleset_required_checks(&self) -> Answer {
        let branch = text(self.args, "branch");
        let expected = texts(self.args, "checks");
        let mut required: BTreeSet<String> = self
            .applying(branch)?
            .into_iter()
            .flat_map(|r| r.required_status_checks)
            .collect();
        if let Some(classic) = self.host.branch_protection(self.repo, branch)? {
            required.extend(classic.required_status_checks);
        }
        Ok(if required == expected {
            ProbeResult::Verified(format!("required on {branch}: {}", joined(&required)))
        } else {
            ProbeResult::Pending(format!(
                "required on {branch}: {}; expected: {}",
                joined(&required),
                joined(&expected)
            ))
        })
    }

    fn ruleset_present(&self) -> Answer {
        let (name, branch, path) = (
            text(self.args, "name"),
            text(self.args, "branch"),
            text(self.args, "path"),
        );
        let rulesets = self.host.rulesets(self.repo)?;
        let Some(found) = rulesets.iter().find(|r| r.name == name) else {
            return Ok(ProbeResult::Pending(format!("no ruleset named \"{name}\"")));
        };
        let Some(file) = self.host.file_contents(self.repo, path, branch)? else {
            return Ok(ProbeResult::Pending(format!(
                "{path} is absent on {branch}"
            )));
        };
        let what = format!("{path} on {branch} of {}", self.repo);
        let body: Value = serde_json::from_str(&file.text).map_err(|e| {
            HostError::new(
                HostErrorKind::Shape,
                format!("{what} is not JSON: {}", plain(&e.to_string())),
            )
        })?;
        let declared = declared_ruleset(&body, &what)?;
        let differs = differences(found, &declared);
        if !differs.is_empty() {
            return Ok(ProbeResult::Pending(format!(
                "{} differs from {path} in {}",
                named(found),
                differs.join(", ")
            )));
        }
        let default = if found.include.iter().any(|p| p == "~DEFAULT_BRANCH") {
            Some(self.default_branch_name()?)
        } else {
            None
        };
        Ok(if applies(found, branch, default.as_deref()) {
            ProbeResult::Verified(format!(
                "{} is active on {branch} and equals {path}",
                named(found)
            ))
        } else {
            ProbeResult::Pending(format!(
                "{} equals {path} but is not active on {branch}",
                named(found)
            ))
        })
    }

    fn check_run_reported(&self) -> Answer {
        let branch = text(self.args, "branch");
        let contexts = texts(self.args, "contexts");
        let mut missing = contexts.clone();
        for sha in self.host.recent_commits(self.repo, branch, 10)? {
            if missing.is_empty() {
                break;
            }
            for run in self.host.check_runs(self.repo, &sha)? {
                missing.remove(&run.name);
            }
        }
        Ok(if missing.is_empty() {
            ProbeResult::Verified(format!(
                "reported on the last 10 commits of {branch}: {}",
                joined(&contexts)
            ))
        } else {
            ProbeResult::Pending(format!(
                "not reported on the last 10 commits of {branch}: {}",
                joined(&missing)
            ))
        })
    }

    fn classic_protection_absent(&self) -> Answer {
        let branch = text(self.args, "branch");
        Ok(match self.host.branch_protection(self.repo, branch)? {
            None => ProbeResult::Verified(format!("no classic protection on {branch}")),
            Some(p) => {
                let mut contexts = p.required_status_checks;
                contexts.sort();
                ProbeResult::Pending(format!(
                    "classic protection of {branch} is in force (requires: {})",
                    joined(&contexts)
                ))
            }
        })
    }

    fn labels_present(&self) -> Answer {
        let present: BTreeMap<String, String> = self
            .host
            .labels(self.repo)?
            .into_iter()
            .map(|l| (l.name.to_lowercase(), l.color.to_lowercase()))
            .collect();
        let declared = self.args["labels"].as_array().cloned().unwrap_or_default();
        let (mut missing, mut recolored) = (Vec::new(), Vec::new());
        for label in &declared {
            let name = label["name"].as_str().unwrap_or_default();
            let color = label["color"].as_str().unwrap_or_default().to_lowercase();
            match present.get(&name.to_lowercase()) {
                None => missing.push(name),
                Some(found) if *found != color => recolored.push(name),
                Some(_) => {}
            }
        }
        Ok(if missing.is_empty() && recolored.is_empty() {
            ProbeResult::Verified(format!(
                "{} labels present with their colors",
                declared.len()
            ))
        } else {
            ProbeResult::Pending(format!(
                "missing: {}; recolored: {}",
                joined(&missing),
                joined(&recolored)
            ))
        })
    }

    fn repo_settings(&self) -> Answer {
        let settings = self.host.repository(self.repo)?;
        let observed = |key: &str| match key {
            "allow_squash_merge" => settings.allow_squash_merge,
            "allow_merge_commit" => settings.allow_merge_commit,
            "allow_rebase_merge" => settings.allow_rebase_merge,
            "delete_branch_on_merge" => settings.delete_branch_on_merge,
            "allow_auto_merge" => settings.allow_auto_merge,
            "allow_update_branch" => settings.allow_update_branch,
            "has_wiki" => settings.has_wiki,
            "has_projects" => settings.has_projects,
            "web_commit_signoff_required" => settings.web_commit_signoff_required,
            _ => None,
        };
        let empty = Map::new();
        let fields = self.args["fields"].as_object().unwrap_or(&empty);
        let differs: Vec<String> = fields
            .iter()
            .filter_map(|(key, expected)| {
                let expected = expected.as_bool()?;
                match observed(key) {
                    Some(value) if value == expected => None,
                    Some(value) => Some(format!("{key} is {value}, expected {expected}")),
                    None => Some(format!("{key} is not visible, expected {expected}")),
                }
            })
            .collect();
        Ok(if differs.is_empty() {
            ProbeResult::Verified(format!("{} settings as declared", fields.len()))
        } else {
            ProbeResult::Pending(differs.join("; "))
        })
    }

    fn toggle(&self, toggle: SecurityToggle) -> Answer {
        Ok(if self.host.security_toggle(self.repo, toggle)? {
            ProbeResult::Verified("enabled".to_owned())
        } else {
            ProbeResult::Pending("disabled".to_owned())
        })
    }

    /// GitHub answers 404 where the feature does not exist (private
    /// repositories): the step is `not-applicable` there (#846).
    fn private_vulnerability_reporting(&self) -> Answer {
        match self.toggle(SecurityToggle::PrivateVulnerabilityReporting) {
            Err(e) if e.kind == HostErrorKind::NotFound => {
                Ok(ProbeResult::NotApplicable(e.message))
            }
            answer => answer,
        }
    }

    /// Secret scanning and push protection enabled. On a repository that is
    /// not public they need Secret Protection, which the installer never
    /// assumes (decision 2026-10-28, point 11; `security.secret-scanning`
    /// records the risk, #801): the step is `not-applicable` there unless
    /// both are already enabled, so `apply --remote` never writes it and
    /// GitHub's 422 "Secret scanning is not available for this repository."
    /// is not met (#1136).
    fn secret_scanning(&self) -> Answer {
        let settings = self.host.repository(self.repo)?;
        let status = |s: &Option<String>| s.clone().unwrap_or_else(|| "not reported".to_owned());
        let evidence = format!(
            "secret scanning {}, push protection {}",
            status(&settings.secret_scanning),
            status(&settings.secret_scanning_push_protection)
        );
        let enabled = |s: &Option<String>| s.as_deref() == Some("enabled");
        Ok(
            if enabled(&settings.secret_scanning)
                && enabled(&settings.secret_scanning_push_protection)
            {
                ProbeResult::Verified(evidence)
            } else if settings.visibility != Visibility::Public {
                // The risk id is the auditor rule's (`SECRET_SCANNING_RISK`); a test ties them.
                ProbeResult::NotApplicable(format!(
                    "{evidence}; a {} repository needs Secret Protection (Team or Enterprise), which the installer never assumes (risk secret-scanning-unavailable-on-plan)",
                    visibility_name(settings.visibility)
                ))
            } else {
                ProbeResult::Pending(evidence)
            },
        )
    }

    /// `GET repos/{r}/code-scanning/default-setup` answers 200 in any state
    /// where Code Security is available (SPEC-security.md, `code-security`);
    /// the 403 plan message is `failed` with that message through the generic
    /// mapping.
    fn code_scanning_default_setup(&self) -> Answer {
        let setup = self.host.code_scanning_default_setup(self.repo)?;
        Ok(ProbeResult::Verified(format!(
            "code scanning available; default setup {}",
            setup.state
        )))
    }

    fn environment_main_only(&self) -> Answer {
        let name = text_or(self.args, "environment", "production");
        let environments = self.host.environments(self.repo)?;
        let Some(environment) = environments.iter().find(|e| e.name == name) else {
            return Ok(ProbeResult::Pending(format!(
                "environment \"{name}\" is absent"
            )));
        };
        let label = match environment.id {
            Some(id) => format!("environment {id} \"{name}\""),
            None => format!("environment \"{name}\""),
        };
        Ok(match &environment.deployment_branch_policy {
            DeploymentBranchPolicy::ProtectedBranches => {
                ProbeResult::Verified(format!("{label} deploys from protected branches"))
            }
            DeploymentBranchPolicy::Unrestricted => {
                ProbeResult::Pending(format!("{label} deploys from any branch"))
            }
            DeploymentBranchPolicy::Custom { patterns } => {
                let default = self.default_branch_name()?;
                if patterns.len() == 1 && patterns[0] == default {
                    ProbeResult::Verified(format!("{label} deploys from {default} only"))
                } else {
                    ProbeResult::Pending(format!("{label} deploys from {}", joined(patterns)))
                }
            }
        })
    }

    /// The repository lets workflow tokens open pull requests (#946).
    fn actions_pull_requests(&self) -> Answer {
        Ok(if self.host.actions_pull_requests_allowed(self.repo)? {
            ProbeResult::Verified("GitHub Actions may create pull requests".to_owned())
        } else {
            ProbeResult::Pending(
                "GitHub Actions may not create pull requests (can_approve_pull_request_reviews is false)"
                    .to_owned(),
            )
        })
    }

    fn secret_present(&self) -> Answer {
        let name = text(self.args, "name");
        let scope = scope(text(self.args, "scope")).unwrap_or(SecretScope::Repository);
        let listed = self.host.secret_names(self.repo, &scope)?;
        Ok(match listed.iter().find(|s| s.name == name) {
            Some(secret) => ProbeResult::Verified(match &secret.updated_at {
                Some(at) => format!("{name} updated {at}"),
                None => format!("{name} listed"),
            }),
            None => {
                let place = match &scope {
                    SecretScope::Repository => "the repository".to_owned(),
                    SecretScope::Organization => "the organization".to_owned(),
                    SecretScope::Dependabot => "the Dependabot secrets".to_owned(),
                    SecretScope::Environment(e) => format!("environment {e}"),
                };
                ProbeResult::Pending(format!("{name} is not listed in {place}"))
            }
        })
    }

    fn workflow_lockfile(&self) -> Answer {
        const LOCK: &str = ".github/workflows/actions.lock";
        let default = self.default_branch_name()?;
        Ok(match self.host.file_exists(self.repo, LOCK, &default)? {
            Some(sha) => ProbeResult::Verified(format!("blob {sha}")),
            None => ProbeResult::Pending(format!("{LOCK} is absent on {default}")),
        })
    }

    fn default_branch(&self) -> Answer {
        let expected = text_or(self.args, "expected", "main");
        let observed = self.default_branch_name()?;
        Ok(if observed == expected {
            ProbeResult::Verified(observed)
        } else {
            ProbeResult::Pending(format!("{observed}, expected {expected}"))
        })
    }

    fn org_2fa_required(&self) -> Answer {
        let org = text(self.args, "org");
        Ok(
            match self.host.org_settings(org)?.two_factor_requirement_enabled {
                Some(true) => ProbeResult::Verified("required".to_owned()),
                Some(false) => ProbeResult::Pending("not required".to_owned()),
                None => ProbeResult::Unavailable(format!(
                    "two-factor requirement of {org} is not visible to this token (needs an organization owner)"
                )),
            },
        )
    }

    fn repository_visibility(&self) -> Answer {
        let expected = text(self.args, "expected");
        let observed = visibility_name(self.host.repository(self.repo)?.visibility);
        Ok(if observed == expected {
            ProbeResult::Verified(observed.to_owned())
        } else {
            ProbeResult::Pending(format!("{observed}, expected {expected}"))
        })
    }

    /// Whether this repository can call the reusable workflows of `callee`
    /// (#785; GitHub "Sharing actions and workflows"): a public callee, or a
    /// private one of the same owner whose Actions access lets that owner's
    /// repositories in. Reads the callee only, never writes.
    fn reusable_workflow_reachable(&self) -> Answer {
        let name = text(self.args, "callee");
        let callee = RepoId::parse(name)
            .map_err(|e| HostError::new(HostErrorKind::Shape, plain(&e.to_string())))?;
        let visibility = self.host.repository(&callee)?.visibility;
        if visibility == Visibility::Public {
            return Ok(ProbeResult::Verified(format!("{callee} is public")));
        }
        let shown = visibility_name(visibility);
        if callee.owner != self.repo.owner {
            return Ok(ProbeResult::Pending(format!(
                "{callee} is {shown} and owned by {}; a repository of {} cannot call it",
                callee.owner, self.repo.owner
            )));
        }
        let access = self.host.actions_access(&callee)?;
        Ok(match access.as_str() {
            "user" | "organization" | "enterprise" => ProbeResult::Verified(format!(
                "{callee} is {shown} and lets repositories of {} call its workflows (access level {access})",
                callee.owner
            )),
            _ => ProbeResult::Pending(format!(
                "{callee} is {shown} with access level {access}: no other repository can call its workflows"
            )),
        })
    }

    fn feature_available(&self) -> Answer {
        let feature = text(self.args, "feature");
        let features = self.host.features(self.repo)?;
        let availability = match feature {
            "rulesets" => features.rulesets,
            "environments" => features.environments,
            "branch_protection" => features.branch_protection,
            "required_reviewers" => features.required_reviewers,
            "dependabot_alerts" => features.dependabot_alerts,
            "secret_scanning" => features.secret_scanning,
            "workflow_lockfile" => features.workflow_lockfile,
            _ => features.merge_queue,
        };
        Ok(match availability {
            Availability::Available => ProbeResult::Verified(availability.to_string()),
            Availability::Unavailable { .. } => ProbeResult::Pending(availability.to_string()),
            Availability::Unknown { .. } => ProbeResult::Unavailable(availability.to_string()),
        })
    }
}

/// The active branch rulesets of `repo` that apply to `branch`. The default
/// branch is read only when a ruleset names `~DEFAULT_BRANCH`.
pub(crate) fn applying(
    host: &dyn Host,
    repo: &RepoId,
    branch: &str,
) -> Result<Vec<Ruleset>, HostError> {
    let rulesets = host.rulesets(repo)?;
    let default = if rulesets.iter().any(|r| {
        r.include
            .iter()
            .chain(&r.exclude)
            .any(|p| p == "~DEFAULT_BRANCH")
    }) {
        Some(host.repository(repo)?.default_branch)
    } else {
        None
    };
    Ok(rulesets
        .into_iter()
        .filter(|r| applies(r, branch, default.as_deref()))
        .collect())
}

/// Whether an active branch ruleset applies to `branch`; `default` is the
/// repository's default branch when a pattern needs it.
pub(crate) fn applies(ruleset: &Ruleset, branch: &str, default: Option<&str>) -> bool {
    let names = |patterns: &[String]| {
        patterns.iter().any(|p| {
            p == "~ALL"
                || p.strip_prefix("refs/heads/") == Some(branch)
                || (p == "~DEFAULT_BRANCH" && default == Some(branch))
        })
    };
    ruleset.enforcement == "active"
        && ruleset.target == "branch"
        && names(&ruleset.include)
        && !names(&ruleset.exclude)
}

/// The fields in which two rulesets differ, order-insensitive for lists.
pub(crate) fn differences(found: &Ruleset, declared: &Ruleset) -> Vec<&'static str> {
    let sorted = |items: &[String]| items.iter().cloned().collect::<BTreeSet<String>>();
    let mut differs = Vec::new();
    for (name, same) in [
        ("target", found.target == declared.target),
        ("enforcement", found.enforcement == declared.enforcement),
        (
            "include",
            sorted(&found.include) == sorted(&declared.include),
        ),
        (
            "exclude",
            sorted(&found.exclude) == sorted(&declared.exclude),
        ),
        ("rules", sorted(&found.rules) == sorted(&declared.rules)),
        (
            "required_status_checks",
            sorted(&found.required_status_checks) == sorted(&declared.required_status_checks),
        ),
        (
            "required_approving_review_count",
            found.required_approving_review_count == declared.required_approving_review_count,
        ),
        (
            "bypass_actors",
            sorted(&found.bypass_actors) == sorted(&declared.bypass_actors),
        ),
    ] {
        if !same {
            differs.push(name);
        }
    }
    differs
}
