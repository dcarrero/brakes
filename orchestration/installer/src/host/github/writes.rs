//! The writes of the GitHub host adapter: labels, issues and comments (#684)
//! and repository settings (#876). Each takes the repository from its
//! `WriteToken` only, goes through `send` (host and read gates, rate-limit
//! floor, call budget, secret-body refusal) and maps GitHub's answer to a
//! `HostError` naming the operation. Environments with their deployment
//! branch policies are #877, rulesets #878, classic branch protection #879.
use super::{GitHub, HostResult, features::names_plan, issue, number, opt_text, text};
use crate::{
    host::{
        Availability, Host, HostError, HostErrorKind, WriteToken,
        probes::{applies, differences},
        types::{
            BranchProtectionSpec, DeploymentBranchPolicy, EnvironmentSpec, IssueMeta, Label,
            NewIssue, RepositorySettings, RepositorySettingsPatch, Ruleset, SecurityToggle,
            WriteReport, bypass_actor_json, bypass_actor_refusal,
        },
    },
    remote::{HttpError, plain, refuse_secret_body, segment},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

impl GitHub<'_> {
    /// One write to the token's repository: `path` is relative to `repos/{r}`
    /// (empty for `repos/{r}` itself); `None` sends no body.
    fn send(
        &self,
        token: &WriteToken,
        what: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> HostResult<Value> {
        let base = self.base(token.repo())?;
        let path = if path.is_empty() {
            base
        } else {
            format!("{base}/{path}")
        };
        if let Some(body) = &body {
            refuse_secret_body(body)
                .map_err(|e| HostError::new(HostErrorKind::WriteRefused, e.to_string()))?;
        }
        self.admit(what, "written")?;
        self.api
            .send(method, &path, body.as_ref())
            .map_err(|e| self.write_error(what, e))
    }

    /// The HTTP mapping of a write; GitHub's status and message close the sentence.
    fn write_error(&self, what: &str, error: Box<dyn std::error::Error>) -> HostError {
        if let Some(host) = error.downcast_ref::<HostError>() {
            return host.clone();
        }
        let Some(http) = error.downcast_ref::<HttpError>() else {
            return HostError::new(
                HostErrorKind::Transport,
                format!("{what} failed: {}", plain(&error.to_string())),
            );
        };
        let limit = self.api.rate_limit();
        let exhausted = limit.is_some_and(|l| l.remaining == 0);
        let kind = match http.status {
            401 => HostErrorKind::Unauthenticated,
            429 | 403 if http.status == 429 || exhausted => HostErrorKind::RateLimited {
                reset_epoch: limit.and_then(|l| l.reset_epoch),
            },
            403 => HostErrorKind::Forbidden,
            404 => HostErrorKind::NotFound,
            _ => HostErrorKind::Transport,
        };
        HostError::new(
            kind,
            format!("{what} failed ({}: {})", http.status, plain(&http.message)),
        )
    }

    /// `GET repos/{r}/labels`, then `POST` each missing label and `PATCH` each
    /// whose colour or declared description differs. Names compare without
    /// case, as GitHub does; colours without case and without `#`. A label
    /// without a declared description keeps the one it has.
    pub(super) fn write_labels(
        &self,
        token: &WriteToken,
        labels: &[Label],
    ) -> HostResult<WriteReport> {
        let repo = token.repo();
        let base = self.base(repo)?;
        let existing = self.list(
            &format!("labels of {repo}"),
            &format!("{base}/labels"),
            None,
        )?;
        let mut report = WriteReport::default();
        for wanted in labels {
            let color = wanted.color.trim_start_matches('#').to_lowercase();
            let current = existing.iter().find(|l| {
                l["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(&wanted.name))
            });
            let mut body = Map::new();
            body.insert("color".into(), json!(color));
            if let Some(description) = &wanted.description {
                body.insert("description".into(), json!(description));
            }
            match current {
                None => {
                    body.insert("name".into(), json!(wanted.name));
                    let what = format!("creating label {} in {repo}", wanted.name);
                    self.send(token, &what, "POST", "labels", Some(Value::Object(body)))?;
                    report.created.push(wanted.name.clone());
                }
                Some(current) => {
                    let same_color = current["color"]
                        .as_str()
                        .is_some_and(|c| c.eq_ignore_ascii_case(&color));
                    let same_description = wanted.description.as_ref().is_none_or(|d| {
                        opt_text(&current["description"]).unwrap_or_default() == *d
                    });
                    if same_color && same_description {
                        report.unchanged.push(wanted.name.clone());
                        continue;
                    }
                    let name = text(current, "name", &format!("labels of {repo}"))?;
                    let what = format!("updating label {} in {repo}", wanted.name);
                    let path = format!("labels/{}", segment(&name));
                    self.send(token, &what, "PATCH", &path, Some(Value::Object(body)))?;
                    report.updated.push(wanted.name.clone());
                }
            }
        }
        Ok(report)
    }

    /// `POST repos/{r}/issues`; the title, body and labels are the caller's.
    pub(super) fn write_issue(&self, token: &WriteToken, new: &NewIssue) -> HostResult<IssueMeta> {
        let what = format!("creating an issue in {}", token.repo());
        let body = json!({"title": new.title, "body": new.body, "labels": new.labels});
        let created = self.send(token, &what, "POST", "issues", Some(body))?;
        issue(&created, &what)
    }

    /// `POST repos/{r}/issues/{n}/comments`; returns the comment id.
    pub(super) fn write_comment(
        &self,
        token: &WriteToken,
        issue_number: u64,
        body: &str,
    ) -> HostResult<u64> {
        let what = format!("commenting on #{issue_number} in {}", token.repo());
        let path = format!("issues/{issue_number}/comments");
        let created = self.send(token, &what, "POST", &path, Some(json!({"body": body})))?;
        number(&created, "id", &what)
    }

    /// Validates the whole patch, then reads `GET repos/{r}` (only when a
    /// `PATCH` key is declared) and sends one `PATCH repos/{r}` with the keys
    /// that differ, then reads each declared toggle and `PUT`s it when it is
    /// off, alerts before security fixes (GitHub needs alerts on for fixes),
    /// private vulnerability reporting last (its 404 is the read's error). A
    /// key GitHub does not show is written. Matching keys are reported
    /// `unchanged` and cost no write.
    pub(super) fn write_settings(
        &self,
        token: &WriteToken,
        patch: &RepositorySettingsPatch,
    ) -> HostResult<WriteReport> {
        let repo = token.repo();
        let refused = |key: &str, why: String| {
            HostError::new(
                HostErrorKind::WriteRefused,
                format!("Remote write refused: setting {key} of {repo} {why}"),
            )
        };
        type Flag = fn(&RepositorySettings) -> Option<bool>;
        type Status = fn(&RepositorySettings) -> &Option<String>;
        let flags: [(&str, Option<bool>, Flag); 9] = [
            ("allow_squash_merge", patch.allow_squash_merge, |c| {
                c.allow_squash_merge
            }),
            ("allow_merge_commit", patch.allow_merge_commit, |c| {
                c.allow_merge_commit
            }),
            ("allow_rebase_merge", patch.allow_rebase_merge, |c| {
                c.allow_rebase_merge
            }),
            (
                "delete_branch_on_merge",
                patch.delete_branch_on_merge,
                |c| c.delete_branch_on_merge,
            ),
            ("allow_auto_merge", patch.allow_auto_merge, |c| {
                c.allow_auto_merge
            }),
            ("allow_update_branch", patch.allow_update_branch, |c| {
                c.allow_update_branch
            }),
            ("has_wiki", patch.has_wiki, |c| c.has_wiki),
            ("has_projects", patch.has_projects, |c| c.has_projects),
            (
                "web_commit_signoff_required",
                patch.web_commit_signoff_required,
                |c| c.web_commit_signoff_required,
            ),
        ];
        let statuses: [(&str, &Option<String>, Status); 2] = [
            ("secret_scanning", &patch.secret_scanning, |c| {
                &c.secret_scanning
            }),
            (
                "secret_scanning_push_protection",
                &patch.secret_scanning_push_protection,
                |c| &c.secret_scanning_push_protection,
            ),
        ];
        let toggles = [
            (
                "vulnerability_alerts",
                SecurityToggle::VulnerabilityAlerts,
                patch.vulnerability_alerts,
            ),
            (
                "automated_security_fixes",
                SecurityToggle::AutomatedSecurityFixes,
                patch.automated_security_fixes,
            ),
            (
                "private_vulnerability_reporting",
                SecurityToggle::PrivateVulnerabilityReporting,
                patch.private_vulnerability_reporting,
            ),
        ];
        for (key, status, _) in statuses {
            if let Some(status) = status
                && status != "enabled"
                && status != "disabled"
            {
                let status = plain(status);
                return Err(refused(
                    key,
                    format!("is `{status}`, not enabled or disabled"),
                ));
            }
        }
        for (key, _, wanted) in toggles {
            if wanted == Some(false) {
                return Err(refused(
                    key,
                    "can only be enabled; disabling it needs DELETE, which the host adapter does not send".into(),
                ));
            }
        }
        let mut report = WriteReport::default();
        let declared = flags.iter().any(|(_, wanted, _)| wanted.is_some())
            || statuses.iter().any(|(_, wanted, _)| wanted.is_some());
        if declared {
            let current = self.repository(repo)?;
            let mut body = Map::new();
            for (key, wanted, observed) in flags {
                let Some(wanted) = wanted else { continue };
                if observed(&current) == Some(wanted) {
                    report.unchanged.push(key.into());
                } else {
                    body.insert(key.into(), json!(wanted));
                    report.updated.push(key.into());
                }
            }
            let mut security = Map::new();
            for (key, wanted, observed) in statuses {
                let Some(wanted) = wanted else { continue };
                if observed(&current).as_ref() == Some(wanted) {
                    report.unchanged.push(key.into());
                } else {
                    security.insert(key.into(), json!({"status": wanted}));
                    report.updated.push(key.into());
                }
            }
            if !security.is_empty() {
                body.insert("security_and_analysis".into(), Value::Object(security));
            }
            if !body.is_empty() {
                let what = format!("updating the settings of {repo}");
                self.send(token, &what, "PATCH", "", Some(Value::Object(body)))?;
            }
        }
        for (key, toggle, wanted) in toggles {
            if wanted.is_none() {
                continue;
            }
            if self.security_toggle(repo, toggle)? {
                report.unchanged.push(key.into());
                continue;
            }
            let what = format!("enabling {} in {repo}", toggle.title());
            self.send(token, &what, "PUT", toggle.endpoint(), None)?;
            report.updated.push(key.into());
        }
        Ok(report)
    }

    /// One environment as declared (SPEC-host-adapter.md, "As implemented
    /// (#877)"): reviewers on a plan that refuses them (`required_reviewers`
    /// unavailable) skip the environment; then one `PUT` when the environment is missing
    /// or differs, and one `POST` per custom pattern it lacks. An empty
    /// reviewer list or an undeclared timer keeps what the environment has.
    pub(super) fn write_environment(
        &self,
        token: &WriteToken,
        spec: &EnvironmentSpec,
    ) -> HostResult<WriteReport> {
        let repo = token.repo();
        let refused = |why: String| {
            HostError::new(
                HostErrorKind::WriteRefused,
                format!(
                    "Remote write refused: environment {} of {repo} {why}",
                    plain(&spec.name)
                ),
            )
        };
        if spec.name.trim().is_empty() {
            return Err(refused("has an empty name".into()));
        }
        if let Some(team) = spec.reviewers.iter().find(|r| r.contains('/')) {
            let team = plain(team);
            return Err(refused(format!(
                "names reviewer {team}, a team; only user logins are written"
            )));
        }
        let mut report = WriteReport::default();
        if !spec.reviewers.is_empty() {
            let available = self.features(repo)?.required_reviewers;
            // Only a plan refusal skips; `Unknown` is attempted and GitHub's
            // answer, refusal included, is the write's result.
            if let Availability::Unavailable { .. } = available {
                report.skipped.insert(
                    spec.name.clone(),
                    format!(
                        "required reviewers are {available}, so the environment was not written"
                    ),
                );
                return Ok(report);
            }
        }
        let environments = self.environments(repo)?;
        let current = environments
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(&spec.name));
        let lower = |names: &[String]| -> std::collections::BTreeSet<String> {
            names.iter().map(|n| n.to_lowercase()).collect()
        };
        let matches = current.is_some_and(|c| {
            std::mem::discriminant(&c.deployment_branch_policy)
                == std::mem::discriminant(&spec.deployment_branch_policy)
                && spec
                    .wait_timer_minutes
                    .is_none_or(|w| c.wait_timer_minutes.unwrap_or(0) == w)
                && (spec.reviewers.is_empty() || lower(&c.reviewers) == lower(&spec.reviewers))
        });
        let name = current.map_or(spec.name.as_str(), |c| c.name.as_str());
        let path = format!("environments/{}", segment(name));
        if !matches {
            let mut body = Map::new();
            if let Some(minutes) = spec.wait_timer_minutes {
                body.insert("wait_timer".into(), json!(minutes));
            }
            if !spec.reviewers.is_empty() {
                let reviewers = spec
                    .reviewers
                    .iter()
                    .map(|login| {
                        let what = format!("user {}", plain(login));
                        let user = self.get(&what, &format!("users/{}", segment(login)))?;
                        Ok(json!({"type": "User", "id": number(&user, "id", &what)?}))
                    })
                    .collect::<HostResult<Vec<_>>>()?;
                body.insert("reviewers".into(), json!(reviewers));
            }
            body.insert(
                "deployment_branch_policy".into(),
                policy_body(&spec.deployment_branch_policy),
            );
            let what = format!("writing environment {} in {repo}", plain(name));
            self.send(token, &what, "PUT", &path, Some(Value::Object(body)))?;
        }
        let mut posted = false;
        if let DeploymentBranchPolicy::Custom { patterns } = &spec.deployment_branch_policy {
            let existing = match current.map(|c| &c.deployment_branch_policy) {
                Some(DeploymentBranchPolicy::Custom { patterns }) => patterns.as_slice(),
                _ => &[],
            };
            for pattern in patterns.iter().filter(|p| !existing.contains(p)) {
                let (kind, bare) = match pattern.strip_prefix("tag:") {
                    Some(tag) => ("tag", tag),
                    None => ("branch", pattern.as_str()),
                };
                let what = format!(
                    "adding branch policy {} to environment {} in {repo}",
                    plain(pattern),
                    plain(name)
                );
                let policies = format!("{path}/deployment-branch-policies");
                self.send(
                    token,
                    &what,
                    "POST",
                    &policies,
                    Some(json!({"name": bare, "type": kind})),
                )?;
                posted = true;
            }
            for extra in existing.iter().filter(|p| !patterns.contains(p)) {
                report.skipped.insert(
                    format!("{} branch policy {}", spec.name, plain(extra)),
                    "the environment has it but it is not declared; removing it needs DELETE, which the host adapter does not send".into(),
                );
            }
        }
        let entry = spec.name.clone();
        if current.is_none() {
            report.created.push(entry);
        } else if !matches || posted {
            report.updated.push(entry);
        } else {
            report.unchanged.push(entry);
        }
        Ok(report)
    }

    /// One ruleset, created or updated by exact name (SPEC-host-adapter.md,
    /// "As implemented (#878)"). The bypass list and rule parameters are
    /// checked before any call; a plan that refuses rulesets skips it.
    pub(super) fn write_ruleset(
        &self,
        token: &WriteToken,
        ruleset: &Ruleset,
    ) -> HostResult<WriteReport> {
        let repo = token.repo();
        let refused = |why: String| {
            HostError::new(
                HostErrorKind::WriteRefused,
                format!(
                    "Remote write refused: ruleset \"{}\" of {repo} {why}",
                    plain(&ruleset.name)
                ),
            )
        };
        if ruleset.name.trim().is_empty() {
            return Err(refused("has an empty name".into()));
        }
        // Decision 2026-10-31 (#1218), amending 2026-10-28 point 7: only the
        // declared actors, each within the bypass policy, sent verbatim.
        let mut actors = Vec::new();
        for actor in &ruleset.bypass_actors {
            if let Err(why) = bypass_actor_refusal(actor) {
                let actor = plain(actor);
                return Err(refused(format!("declares bypass actor {actor}: {why}")));
            }
            actors.push(bypass_actor_json(actor));
        }
        for kind in ["pull_request", "required_status_checks"] {
            if ruleset.rules.iter().any(|r| r == kind)
                && !ruleset.rule_parameters.contains_key(kind)
            {
                return Err(refused(format!(
                    "has a {kind} rule without its parameters, which the adapter does not invent"
                )));
            }
        }
        if let Some(kind) = ruleset
            .rule_parameters
            .keys()
            .find(|k| !ruleset.rules.contains(k))
        {
            let kind = plain(kind);
            return Err(refused(format!(
                "has parameters for {kind}, a rule it does not list"
            )));
        }
        let mut report = WriteReport::default();
        let existing = match self.rulesets(repo) {
            Ok(existing) => existing,
            Err(e) => {
                match plan_refusal(&e) {
                    Some(detail) => {
                        report.skipped.insert(
                            ruleset.name.clone(),
                            format!("rulesets are unavailable ({detail}), so the ruleset was not written"),
                        );
                        return Ok(report);
                    }
                    None => return Err(e),
                }
            }
        };
        // Found by its name, else by a former name, which the update renames (#1067).
        let current = existing
            .iter()
            .find(|r| r.name == ruleset.name)
            .or_else(|| {
                existing
                    .iter()
                    .find(|r| crate::renamed_ruleset(&r.name) == Some(ruleset.name.as_str()))
            });
        let body = json!({
            "name": ruleset.name,
            "target": ruleset.target,
            "enforcement": ruleset.enforcement,
            "conditions": {"ref_name": {"include": ruleset.include, "exclude": ruleset.exclude}},
            // Checked above: every declared actor is within the policy.
            "bypass_actors": actors,
            "rules": ruleset.rules.iter().map(|kind| match ruleset.rule_parameters.get(kind) {
                Some(parameters) => json!({"type": kind, "parameters": parameters}),
                None => json!({"type": kind}),
            }).collect::<Vec<_>>(),
        });
        let name = plain(&ruleset.name);
        match current {
            None => {
                let what = format!("creating ruleset \"{name}\" in {repo}");
                self.send(token, &what, "POST", "rulesets", Some(body))?;
                report.created.push(ruleset.name.clone());
            }
            Some(found)
                if found.name == ruleset.name
                    && differences(found, ruleset).is_empty()
                    && parameters_match(found, ruleset) =>
            {
                report.unchanged.push(ruleset.name.clone());
            }
            Some(found) => {
                let id = found.id.ok_or_else(|| {
                    HostError::new(
                        HostErrorKind::Shape,
                        format!("ruleset \"{name}\" of {repo} has no id"),
                    )
                })?;
                let what = format!("updating ruleset \"{name}\" in {repo}");
                self.send(token, &what, "PUT", &format!("rulesets/{id}"), Some(body))?;
                report.updated.push(ruleset.name.clone());
            }
        }
        Ok(report)
    }

    /// The classic protection of `branch` as declared (SPEC-host-adapter.md,
    /// "As implemented (#879)"): one `PUT` when it is absent or differs.
    pub(super) fn write_branch_protection(
        &self,
        token: &WriteToken,
        branch: &str,
        spec: &BranchProtectionSpec,
    ) -> HostResult<WriteReport> {
        let repo = token.repo();
        if branch.trim().is_empty() {
            return Err(HostError::new(
                HostErrorKind::WriteRefused,
                format!("Remote write refused: branch protection of {repo} names an empty branch"),
            ));
        }
        if !spec.required_status_checks.is_empty() && !spec.enforce_admins {
            return Err(HostError::new(
                HostErrorKind::WriteRefused,
                format!(
                    "Remote write refused: protection of branch {} in {repo} requires checks with enforce_admins off; administrators must pass them too (Never merge on red)",
                    plain(branch)
                ),
            ));
        }
        let mut report = WriteReport::default();
        let current = match self.branch_protection(repo, branch) {
            Ok(current) => current,
            Err(e) => match plan_refusal(&e) {
                Some(detail) => {
                    report.skipped.insert(
                        branch.to_owned(),
                        format!(
                            "branch protection is unavailable ({detail}), so it was not written"
                        ),
                    );
                    return Ok(report);
                }
                None => return Err(e),
            },
        };
        let checks: BTreeSet<&String> = spec.required_status_checks.iter().collect();
        let matches = current.as_ref().is_some_and(|c| {
            c.required_status_checks.iter().collect::<BTreeSet<_>>() == checks
                && (checks.is_empty() || c.strict == Some(spec.strict))
                && c.enforce_admins == Some(spec.enforce_admins)
                && c.required_approving_review_count == spec.required_approving_review_count
                && c.required_linear_history == Some(spec.required_linear_history)
                && c.allow_force_pushes == Some(spec.allow_force_pushes)
                && c.allow_deletions == Some(spec.allow_deletions)
        });
        if matches {
            report.unchanged.push(branch.to_owned());
            return Ok(report);
        }
        let body = json!({
            "required_status_checks": if checks.is_empty() {
                Value::Null
            } else {
                json!({"strict": spec.strict, "contexts": checks})
            },
            "enforce_admins": spec.enforce_admins,
            "required_pull_request_reviews": spec.required_approving_review_count.map(|n| {
                json!({"required_approving_review_count": n})
            }),
            "restrictions": null,
            "required_linear_history": spec.required_linear_history,
            "allow_force_pushes": spec.allow_force_pushes,
            "allow_deletions": spec.allow_deletions,
        });
        let what = format!("protecting branch {} in {repo}", plain(branch));
        let path = format!("branches/{}/protection", segment(branch));
        self.send(token, &what, "PUT", &path, Some(body))?;
        if current.is_some() {
            report.updated.push(branch.to_owned());
        } else {
            report.created.push(branch.to_owned());
        }
        Ok(report)
    }

    /// `DELETE` the classic protection of `branch`, only while the active
    /// rulesets that apply to it require every context it requires, or require
    /// `superseded_by`, the aggregate check its declaring module says runs
    /// every declared command (decision 2026-10-30, #1149), so the branch is
    /// never left less protected.
    pub(super) fn remove_branch_protection(
        &self,
        token: &WriteToken,
        branch: &str,
        superseded_by: Option<&str>,
    ) -> HostResult<WriteReport> {
        let repo = token.repo();
        let mut report = WriteReport::default();
        let Some(current) = self.branch_protection(repo, branch)? else {
            report.unchanged.push(branch.to_owned());
            return Ok(report);
        };
        let rulesets = self.rulesets(repo)?;
        let default = if rulesets.iter().any(|r| {
            r.include
                .iter()
                .chain(&r.exclude)
                .any(|p| p == "~DEFAULT_BRANCH")
        }) {
            Some(self.repository(repo)?.default_branch)
        } else {
            None
        };
        let applying: Vec<_> = rulesets
            .iter()
            .filter(|r| applies(r, branch, default.as_deref()))
            .collect();
        let required: BTreeSet<&String> = applying
            .iter()
            .flat_map(|r| &r.required_status_checks)
            .collect();
        let superseded = superseded_by.is_some_and(|check| required.iter().any(|r| *r == check));
        let missing: Vec<&str> = current
            .required_status_checks
            .iter()
            .filter(|c| !superseded && !required.contains(c))
            .map(|c| c.as_str())
            .collect();
        let branch_text = plain(branch);
        let why = if applying.is_empty() {
            Some(format!("no active ruleset applies to {branch_text}"))
        } else if !missing.is_empty() {
            Some(format!(
                "no active ruleset that applies to {branch_text} requires {}",
                plain(&missing.join(", "))
            ))
        } else {
            None
        };
        if let Some(why) = why {
            return Err(HostError::new(
                HostErrorKind::WriteRefused,
                format!(
                    "Remote write refused: classic protection of branch {branch_text} in {repo} is not retired, because {why}"
                ),
            ));
        }
        let what = format!("retiring the classic protection of branch {branch_text} in {repo}");
        let path = format!("branches/{}/protection", segment(branch));
        self.send(token, &what, "DELETE", &path, None)?;
        report.removed.push(branch.to_owned());
        Ok(report)
    }
}

/// GitHub's `status: message` when `error` is a 403 that names a plan, the
/// answer that makes a `features` field `Unavailable`.
fn plan_refusal(error: &HostError) -> Option<&str> {
    if error.kind != HostErrorKind::Forbidden || !names_plan(&error.message) {
        return None;
    }
    // "Reading {what} is forbidden ({status}: {message})"
    let detail = error
        .message
        .split_once(" (")
        .map_or(error.message.as_str(), |(_, d)| d);
    Some(detail.strip_suffix(')').unwrap_or(detail))
}

/// Every declared parameter key equals GitHub's; keys GitHub adds are ignored.
fn parameters_match(found: &Ruleset, declared: &Ruleset) -> bool {
    declared.rule_parameters.iter().all(|(kind, wanted)| {
        let have = &found.rule_parameters.get(kind);
        wanted.as_object().is_some_and(|wanted| {
            wanted
                .iter()
                .all(|(key, value)| have.is_some_and(|h| h.get(key) == Some(value)))
        })
    })
}

/// The `deployment_branch_policy` of an environment `PUT`; custom patterns
/// are sent one `POST` each after it.
fn policy_body(policy: &DeploymentBranchPolicy) -> Value {
    match policy {
        DeploymentBranchPolicy::Unrestricted => Value::Null,
        DeploymentBranchPolicy::ProtectedBranches => {
            json!({"protected_branches": true, "custom_branch_policies": false})
        }
        DeploymentBranchPolicy::Custom { .. } => {
            json!({"protected_branches": false, "custom_branch_policies": true})
        }
    }
}
