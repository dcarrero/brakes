//! The desired state of a remote item (#902; SPEC-engine.md, Desired state of a
//! remote item): what a module declares each `github:<id>` must reach, as data
//! the writer of `apply --remote` (#903) consumes, each kind mapped to one
//! `Host` write. `change` names the verb a pending item gets with at most one
//! read and never writes; `write` is the dispatch of `apply --remote` (#903).
use super::{
    Host, HostError, HostErrorKind, RepoId, WriteToken,
    github::declared_ruleset,
    probes::applying,
    types::{
        BranchProtectionSpec, EnvironmentSpec, Label, RepositorySettingsPatch, Ruleset, WriteReport,
    },
};
use crate::{Result, refuse, remote::plain};
use serde_json::{Value, json};

/// One kind of desired state, with the `Host` write that reaches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Desired {
    /// `put_ruleset`: create or update by name.
    Ruleset(Ruleset),
    /// `ensure_labels`.
    Labels(Vec<Label>),
    /// `set_repository_settings`, Dependabot alerts and security updates included.
    Settings(RepositorySettingsPatch),
    /// `put_environment`.
    Environment(EnvironmentSpec),
    /// `put_branch_protection`.
    BranchProtection {
        branch: String,
        spec: BranchProtectionSpec,
    },
    /// `retire_branch_protection`; what the aggregate check supersedes decides
    /// which classic contexts count as covered (decision 2026-10-30, #1149).
    RetireProtection {
        branch: String,
        superseded_by: Supersession,
    },
    /// The required checks of `branch`, in the ruleset that applies to it, else
    /// in its classic protection: exactly `checks`, or `checks` added to the
    /// others when `keep_others`.
    RequiredChecks {
        branch: String,
        checks: Vec<String>,
        keep_others: bool,
    },
}

/// Whether the aggregate check of the generated workflow supersedes the
/// required checks of the classic protection a retirement removes (decision
/// 2026-10-30, #1149).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Supersession {
    /// No aggregate replaces them: each classic context must be required by
    /// an active ruleset that applies to the branch.
    #[default]
    None,
    /// The aggregate named here runs every declared command, so an active
    /// ruleset that requires it covers every classic context.
    By(String),
    /// The aggregate does not supersede them; the text, which says why and
    /// how to fold the missing command in, is added to the refusal.
    Short(String),
}

/// The desired state of the remote item `github:<id>` of the declaring module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteWrite {
    pub id: String,
    pub desired: Desired,
}

/// What the write of a pending item does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Create,
    Update,
    Remove,
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Change::Create => "create",
            Change::Update => "update",
            Change::Remove => "remove",
        })
    }
}

/// A committed ruleset file (GitHub's JSON, no `id`) read into the adapter's
/// model, as `put_ruleset` sends it; `what` names the file in a refusal.
pub fn ruleset_from_file(text: &str, what: &str) -> Result<Ruleset> {
    let body = match serde_json::from_str(text) {
        Ok(body) => body,
        Err(error) => return refuse(format!("{what} is not JSON: {error}")),
    };
    Ok(declared_ruleset(&body, what)?)
}

/// The verb of a pending item of `repo` whose desired state is `desired`.
pub fn change(
    host: &dyn Host,
    repo: &RepoId,
    desired: &Desired,
) -> std::result::Result<Change, HostError> {
    let created_unless = |exists: bool| {
        if exists {
            Change::Update
        } else {
            Change::Create
        }
    };
    Ok(match desired {
        Desired::Ruleset(ruleset) => {
            created_unless(host.rulesets(repo)?.iter().any(|r| r.name == ruleset.name))
        }
        Desired::Labels(labels) => {
            let present = host.labels(repo)?;
            created_unless(labels.iter().any(|label| {
                present
                    .iter()
                    .any(|p| p.name.eq_ignore_ascii_case(&label.name))
            }))
        }
        Desired::Environment(environment) => created_unless(
            host.environments(repo)?
                .iter()
                .any(|e| e.name == environment.name),
        ),
        Desired::BranchProtection { branch, .. } => {
            created_unless(host.branch_protection(repo, branch)?.is_some())
        }
        Desired::Settings(_) | Desired::RequiredChecks { .. } => Change::Update,
        Desired::RetireProtection { .. } => Change::Remove,
    })
}

/// The one `Host` write that reaches `write.desired`, through `token`
/// (SPEC-host-adapter.md, the dispatch of `apply --remote`, #903).
pub fn write(
    host: &dyn Host,
    token: &WriteToken,
    write: &RemoteWrite,
) -> std::result::Result<WriteReport, HostError> {
    match &write.desired {
        Desired::Ruleset(ruleset) => host.put_ruleset(token, ruleset),
        Desired::Labels(labels) => host.ensure_labels(token, labels),
        Desired::Settings(patch) => host.set_repository_settings(token, patch),
        Desired::Environment(environment) => host.put_environment(token, environment),
        Desired::BranchProtection { branch, spec } => {
            host.put_branch_protection(token, branch, spec)
        }
        Desired::RetireProtection {
            branch,
            superseded_by,
        } => {
            let aggregate = match superseded_by {
                Supersession::By(check) => Some(check.as_str()),
                Supersession::None | Supersession::Short(_) => None,
            };
            host.retire_branch_protection(token, branch, aggregate)
                .map_err(|mut error| {
                    if let (HostErrorKind::WriteRefused, Supersession::Short(why)) =
                        (&error.kind, superseded_by)
                    {
                        error.message = format!("{}; {why}", error.message);
                    }
                    error
                })
        }
        Desired::RequiredChecks {
            branch,
            checks,
            keep_others,
        } => {
            let ruleset = requiring_ruleset(host, token, branch)?;
            host.put_ruleset(token, &with_checks(ruleset, checks, *keep_others))
        }
    }
}

/// The one active ruleset with a `required_status_checks` rule that applies to
/// `branch`. Classic protection is never rewritten for its checks: the adapter
/// reads it only in part, and `PUT …/protection` would reset the rest.
fn requiring_ruleset(
    host: &dyn Host,
    token: &WriteToken,
    branch: &str,
) -> std::result::Result<Ruleset, HostError> {
    let repo = token.repo();
    let branch_name = plain(branch);
    let refused = |why: String| {
        HostError::new(
            HostErrorKind::WriteRefused,
            format!(
                "Remote write refused: the required checks of branch {branch_name} in {repo} {why}"
            ),
        )
    };
    let mut requiring: Vec<Ruleset> = applying(host, repo, branch)?
        .into_iter()
        .filter(|r| r.rule_parameters.contains_key(CHECKS_RULE))
        .collect();
    match requiring.len() {
        1 => Ok(requiring.remove(0)),
        0 if host.branch_protection(repo, branch)?.is_some() => Err(refused(
            "live in classic protection, which the adapter reads only in part (not restrictions, conversation resolution, signed commits, stale-review dismissal, code-owner reviews, branch lock); rewriting it would reset those, so change its checks by hand with the item's instructions".to_owned(),
        )),
        0 => Err(refused(format!(
            "cannot change: no ruleset or classic protection requires checks on {branch_name}"
        ))),
        _ => Err(refused(format!(
            "are required by several rulesets ({}); change them by hand",
            requiring
                .iter()
                .map(|r| format!("\"{}\"", plain(&r.name)))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

const CHECKS_RULE: &str = "required_status_checks";

/// `ruleset` with its required checks set to `checks`, or extended by them
/// when `keep_others`; a kept check keeps its entry (and `integration_id`).
fn with_checks(mut ruleset: Ruleset, checks: &[String], keep_others: bool) -> Ruleset {
    let parameters = ruleset
        .rule_parameters
        .entry(CHECKS_RULE.to_owned())
        .or_insert_with(|| json!({}));
    let current: Vec<Value> = parameters[CHECKS_RULE]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let entry = |check: &String| {
        current
            .iter()
            .find(|c| c["context"] == check.as_str())
            .cloned()
            .unwrap_or_else(|| json!({ "context": check }))
    };
    let mut entries: Vec<Value> = if keep_others {
        current.clone()
    } else {
        Vec::new()
    };
    for check in checks {
        if !entries.iter().any(|c| c["context"] == check.as_str()) {
            entries.push(entry(check));
        }
    }
    ruleset.required_status_checks = entries
        .iter()
        .filter_map(|c| c["context"].as_str().map(str::to_owned))
        .collect();
    parameters[CHECKS_RULE] = Value::Array(entries);
    ruleset
}
