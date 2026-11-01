//! `features` of the GitHub host adapter (#680): each field is decided by the
//! answer of its own endpoint, never by the plan name, which is read only as a
//! hint. 401, 429 and the rate limit stop the probe; every other answer becomes
//! a verdict carrying GitHub's status and message.
use super::{GitHub, HostResult, opt_text, text, visibility};
use crate::{
    host::{Availability, Features, HostErrorKind, RepoId},
    remote::{HttpError, plain, segment},
};
use serde_json::Value;

/// What one feature probe answered: the body, or GitHub's status and message.
enum Answer {
    Body(Value),
    Http(u16, String),
}
impl Answer {
    /// A body is `Available`; an HTTP answer is `Unavailable` when GitHub's
    /// message names a plan, `Unknown` otherwise, both with `status: message`.
    fn verdict(&self) -> Availability {
        match self {
            Self::Body(_) => Availability::Available,
            Self::Http(status, message) => {
                let reason = format!("{status}: {message}");
                if names_plan(message) {
                    Availability::Unavailable { reason }
                } else {
                    Availability::Unknown { reason }
                }
            }
        }
    }
    /// `verdict`, with a 404 also `Available`: the feature exists, switched off or absent.
    fn available_on_404(&self) -> Availability {
        match self {
            Self::Http(404, _) => Availability::Available,
            answer => answer.verdict(),
        }
    }
    /// `Available` when the body has an item `found` admits, else `Unknown`
    /// with `not_observed`; an HTTP answer keeps its own verdict.
    fn observed(&self, found: impl Fn(&Value) -> bool, not_observed: String) -> Availability {
        match self {
            Self::Body(body) if found(body) => Availability::Available,
            Self::Body(_) => Availability::Unknown {
                reason: format!("200: {not_observed}, so the feature was not observed"),
            },
            answer => answer.verdict(),
        }
    }
}

/// GitHub refuses a plan-gated feature with "Upgrade to GitHub Pro …" or a
/// message naming the plan; that is the only use of a plan name here.
pub(crate) fn names_plan(message: &str) -> bool {
    let message = message.to_lowercase();
    message.contains("upgrade")
        || ["github pro", "github team", "github enterprise"]
            .iter()
            .any(|plan| message.contains(plan))
}

/// Whether `items` (a list, or the list under `key`) has an item of `type` `kind`.
fn has_type(items: &Value, kind: &str) -> bool {
    items
        .as_array()
        .into_iter()
        .flatten()
        .any(|i| i["type"] == kind)
}

impl GitHub<'_> {
    pub(super) fn probe_features(&self, repo: &RepoId) -> HostResult<Features> {
        let base = self.base(repo)?;
        let v = self.get(&format!("repository {repo}"), &base)?;
        let what = format!("features of {repo}");
        let default_branch = text(&v, "default_branch", &what)?;
        let branch = segment(&default_branch);
        let plan_hint = self.plan_hint(&v["owner"], &what)?;

        let rulesets = self.probe(&what, &format!("{base}/rulesets"))?;
        let environments = self.probe(&what, &format!("{base}/environments"))?;
        let required_reviewers = environments.observed(
            |body| {
                body["environments"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|e| has_type(&e["protection_rules"], "required_reviewers"))
            },
            "no environment has a required_reviewers rule".to_owned(),
        );
        let branch_protection =
            match self.probe(&what, &format!("{base}/branches/{branch}/protection"))? {
                Answer::Http(404, message) if message.contains("Branch not protected") => {
                    Availability::Available
                }
                answer => answer.verdict(),
            };
        // 204 enabled, 404 disabled: either way the repository has the feature.
        let dependabot_alerts = self
            .probe(&what, &format!("{base}/vulnerability-alerts"))?
            .available_on_404();
        let security = &v["security_and_analysis"];
        let secret_scanning = if security["secret_scanning"]["status"].is_string() {
            Availability::Available
        } else if security.is_object() {
            Availability::Unavailable {
                reason: "200: security_and_analysis carries no secret_scanning status".to_owned(),
            }
        } else {
            Availability::Unknown {
                reason: "200: security_and_analysis is not visible to this token".to_owned(),
            }
        };
        // Present or absent, a read that answers says the repository supports it.
        let workflow_lockfile = self
            .probe(
                &what,
                &format!("{base}/contents/.github/workflows/actions.lock?ref={branch}"),
            )?
            .available_on_404();
        // A merge queue is a ruleset rule: observed through the rules of the
        // default branch, read only when rulesets answer.
        let merge_queue = match &rulesets {
            Answer::Body(_) => self
                .probe(&what, &format!("{base}/rules/branches/{branch}"))?
                .observed(
                    |rules| has_type(rules, "merge_queue"),
                    format!(
                        "no rule of branch {} is a merge_queue rule",
                        plain(&default_branch)
                    ),
                ),
            answer => answer.verdict(),
        };
        Ok(Features {
            visibility: visibility(&v, &what)?,
            plan_hint,
            rulesets: rulesets.verdict(),
            environments: environments.verdict(),
            branch_protection,
            required_reviewers,
            dependabot_alerts,
            secret_scanning,
            workflow_lockfile,
            merge_queue,
        })
    }

    /// One probe GET through the adapter's HTTP mapping: what it maps to
    /// `Unauthenticated`, `RateLimited` or a non-HTTP error stops the probe;
    /// any other HTTP answer is kept with its status and message.
    fn probe(&self, what: &str, path: &str) -> HostResult<Answer> {
        let error = match self.fetch(what, path) {
            Ok(v) => return Ok(Answer::Body(v)),
            Err(error) => error,
        };
        let http = error
            .downcast_ref::<HttpError>()
            .map(|h| (h.status, plain(&h.message)));
        let mapped = self.error(what, error);
        match (http, &mapped.kind) {
            (
                Some((status, message)),
                HostErrorKind::Forbidden | HostErrorKind::NotFound | HostErrorKind::Transport,
            ) => Ok(Answer::Http(status, message)),
            _ => Err(mapped),
        }
    }

    /// The owner's plan name when the token can see it: `GET user` for the
    /// authenticated user's own repositories, `GET orgs/{o}` for an organization.
    fn plan_hint(&self, owner: &Value, what: &str) -> HostResult<Option<String>> {
        let Some(login) = owner["login"].as_str() else {
            return Ok(None);
        };
        let path = match owner["type"].as_str() {
            Some("Organization") => format!("orgs/{}", segment(login)),
            Some("User") => "user".to_owned(),
            _ => return Ok(None),
        };
        Ok(match self.probe(what, &path)? {
            Answer::Body(v)
                if path != "user"
                    || v["login"]
                        .as_str()
                        .is_some_and(|l| l.eq_ignore_ascii_case(login)) =>
            {
                opt_text(&v["plan"]["name"])
            }
            _ => None,
        })
    }
}
