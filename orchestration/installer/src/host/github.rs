//! The GitHub implementation of `Host` over `remote::Api` (`gh api`, hostname
//! `github.com`). #676 carries the HTTP mapping, pagination, the call budget
//! and the repository-state and people reads; #678 the CI and delivery reads;
//! #679 the security-alert, branch and contents reads; #680 `features`
//! (`github/features.rs`); #681 the fleet reads (`github/fleet.rs`); #684 the
//! label, issue and comment writes and #876–#878 the settings, environment
//! and ruleset writes and #879 classic branch protection (`github/writes.rs`).
use super::types::ORGANIZATION_ADMIN;
use super::{
    Host, HostError, HostErrorKind, HostKind, RepoId, SecretName, SecretScope, WriteToken,
    authorize,
    types::{
        BranchProtection, BranchProtectionSpec, CallBudget, CheckRun, Collaborator, Deployment,
        DeploymentBranchPolicy, DeploymentStatus, Environment, EnvironmentSpec, Features,
        IssueFilter, IssueMeta, Job, Label, NewIssue, OrgSettings, OwnerId, Partial, PullFile,
        PullFilter, PullMeta, RepoSummary, RepositorySettings, RepositorySettingsPatch, Ruleset,
        RunFilter, RunTiming, Visibility, WorkflowRun, WriteReport,
    },
};
// Security, branch and contents reads (#679)
use super::types::{
    Branch, CodeScanningSetup, DependabotAlert, DirEntry, EntryKind, FileContents, Release,
    SecretScanningAlert, SecurityToggle,
};
use crate::remote::{self, Api, HttpError, paginate, plain, segment};
use serde_json::Value;

mod features;
pub(crate) use features::names_plan;
mod fleet;
mod writes;

type HostResult<T> = std::result::Result<T, HostError>;

/// Full pages read before a list is reported `Truncated` (3 000 items).
pub const PAGE_CAP: u32 = 30;
/// The adapter stops when `x-ratelimit-remaining` drops under this many calls,
/// leaving headroom for the owner's other tools.
pub const RATE_LIMIT_FLOOR: u64 = 50;

/// `Host` for github.com over one transport and one call budget per invocation.
pub struct GitHub<'a> {
    api: &'a dyn Api,
    budget: CallBudget,
}

impl<'a> GitHub<'a> {
    /// One release read: its tag and publication date.
    fn release(&self, what: &str, path: &str) -> HostResult<Release> {
        let v = self.get(what, path)?;
        match (opt_text(&v["tag_name"]), opt_text(&v["published_at"])) {
            (Some(tag_name), Some(published_at)) => Ok(Release {
                tag_name,
                published_at,
            }),
            _ => Err(shape(what, "missing text field tag_name or published_at")),
        }
    }
    pub fn new(api: &'a dyn Api, budget: CallBudget) -> Self {
        Self { api, budget }
    }
    /// The budget, so a caller can report how many calls an invocation spent.
    pub fn budget(&self) -> &CallBudget {
        &self.budget
    }

    /// `repos/{owner}/{name}` after the host and read gates, before any call.
    fn base(&self, repo: &RepoId) -> HostResult<String> {
        if repo.host != HostKind::GitHub || repo.project.is_some() {
            return Err(HostError::new(
                HostErrorKind::Unsupported,
                format!(
                    "{repo} is not a GitHub repository, so the GitHub host adapter cannot read it"
                ),
            ));
        }
        authorize::read(repo)
            .map_err(|e| HostError::new(HostErrorKind::Forbidden, e.to_string()))?;
        Ok(format!(
            "repos/{}/{}",
            segment(&repo.owner),
            segment(&repo.name)
        ))
    }

    /// One GET: the rate-limit floor, then the budget, then the transport.
    fn get(&self, what: &str, path: &str) -> HostResult<Value> {
        self.fetch(what, path).map_err(|e| self.error(what, e))
    }
    /// `get` before the HTTP mapping, so a probe can keep GitHub's status.
    fn fetch(&self, what: &str, path: &str) -> crate::Result<Value> {
        self.admit(what, "read")?;
        self.api.get(path)
    }
    /// The rate-limit floor, then the call budget, before any read or write.
    fn admit(&self, what: &str, verb: &str) -> HostResult<()> {
        if let Some(limit) = self.api.rate_limit()
            && limit.remaining < RATE_LIMIT_FLOOR
        {
            return Err(HostError::new(
                HostErrorKind::RateLimited {
                    reset_epoch: limit.reset_epoch,
                },
                format!(
                    "GitHub rate limit is down to {} calls, under the floor of {RATE_LIMIT_FLOOR}, so {what} was not {verb}",
                    limit.remaining
                ),
            ));
        }
        self.budget.spend()
    }

    /// The HTTP mapping of SPEC-host-adapter.md ("Errors").
    fn error(&self, what: &str, error: Box<dyn std::error::Error>) -> HostError {
        if let Some(host) = error.downcast_ref::<HostError>() {
            return host.clone();
        }
        if let Some(http) = error.downcast_ref::<HttpError>() {
            let detail = format!("{}: {}", http.status, plain(&http.message));
            let limit = self.api.rate_limit();
            let exhausted = limit.is_some_and(|l| l.remaining == 0);
            let (kind, message) = match http.status {
                401 => (
                    HostErrorKind::Unauthenticated,
                    format!(
                        "GitHub CLI is not authenticated, so {what} could not be read ({detail})"
                    ),
                ),
                429 => rate_limited(limit, what, &detail),
                403 if exhausted => rate_limited(limit, what, &detail),
                403 => (
                    HostErrorKind::Forbidden,
                    format!("Reading {what} is forbidden ({detail})"),
                ),
                404 => (
                    HostErrorKind::NotFound,
                    format!("{what} was not found ({detail})"),
                ),
                _ => (
                    HostErrorKind::Transport,
                    format!("{what} could not be read ({detail})"),
                ),
            };
            return HostError::new(kind, message);
        }
        if error.downcast_ref::<serde_json::Error>().is_some()
            || error.downcast_ref::<std::str::Utf8Error>().is_some()
        {
            return shape(what, &plain(&error.to_string()));
        }
        HostError::new(
            HostErrorKind::Transport,
            format!("{what} could not be read: {}", plain(&error.to_string())),
        )
    }

    /// Every item of a paged list; `key` names the array inside an object
    /// response, `None` for a top-level array.
    fn list(&self, what: &str, path: &str, key: Option<&str>) -> HostResult<Vec<Value>> {
        self.list_until(what, path, key, |_| false)
    }
    fn list_until(
        &self,
        what: &str,
        path: &str,
        key: Option<&str>,
        done: impl Fn(&[Value]) -> bool,
    ) -> HostResult<Vec<Value>> {
        let (items, truncated) = paginate(
            path,
            PAGE_CAP,
            |page| {
                let value = self.get(what, page)?;
                let list = match key {
                    Some(key) => &value[key],
                    None => &value,
                };
                list.as_array()
                    .cloned()
                    .ok_or_else(|| shape(what, "the response is not a list"))
            },
            done,
        )?;
        if truncated {
            return Err(HostError::new(
                HostErrorKind::Truncated,
                format!(
                    "{what} has more than {} items, the page cap of this read",
                    PAGE_CAP * 100
                ),
            ));
        }
        Ok(items)
    }
}

fn rate_limited(
    limit: Option<remote::RateLimit>,
    what: &str,
    detail: &str,
) -> (HostErrorKind, String) {
    (
        HostErrorKind::RateLimited {
            reset_epoch: limit.and_then(|l| l.reset_epoch),
        },
        format!("GitHub rate limit reached while reading {what} ({detail})"),
    )
}
fn shape(what: &str, detail: &str) -> HostError {
    HostError::new(
        HostErrorKind::Shape,
        format!("{what} has an unexpected shape: {detail}"),
    )
}

// --- field readers: a missing required field is `Shape`, an absent optional is `None`

fn text(value: &Value, key: &str, what: &str) -> HostResult<String> {
    value[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| shape(what, &format!("missing text field {key}")))
}
fn number(value: &Value, key: &str, what: &str) -> HostResult<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| shape(what, &format!("missing number field {key}")))
}
fn flag(value: &Value, key: &str, what: &str) -> HostResult<bool> {
    value[key]
        .as_bool()
        .ok_or_else(|| shape(what, &format!("missing boolean field {key}")))
}
fn opt_text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}
fn texts(value: &Value) -> Vec<String> {
    crate::profile::strings(value)
        .into_iter()
        .map(str::to_owned)
        .collect()
}
fn visibility(value: &Value, what: &str) -> HostResult<Visibility> {
    match value["visibility"].as_str() {
        Some("public") => Ok(Visibility::Public),
        Some("private") => Ok(Visibility::Private),
        Some("internal") => Ok(Visibility::Internal),
        _ => Err(shape(what, "missing or unknown visibility")),
    }
}

/// A repository file path whose segments `segment` can encode without
/// leaving `contents/`: no empty, `.` or `..` segment.
fn file_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    parts
        .iter()
        .all(|p| !matches!(*p, "" | "." | ".."))
        .then(|| {
            parts
                .iter()
                .map(|p| segment(p))
                .collect::<Vec<_>>()
                .join("/")
        })
}

fn ruleset(detail: &Value, what: &str) -> HostResult<Ruleset> {
    let id = number(detail, "id", what)?;
    Ok(Ruleset {
        id: Some(id),
        ..declared_ruleset(detail, what)?
    })
}

/// A ruleset body in GitHub's JSON, as GitHub returns it or as a repository
/// commits it to be applied (no `id`), read into the adapter's model.
pub(crate) fn declared_ruleset(detail: &Value, what: &str) -> HostResult<Ruleset> {
    let rules = detail["rules"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let rule = |kind: &str| rules.iter().find(|r| r["type"] == kind);
    Ok(Ruleset {
        id: None,
        name: text(detail, "name", what)?,
        target: text(detail, "target", what)?,
        enforcement: text(detail, "enforcement", what)?,
        include: texts(&detail["conditions"]["ref_name"]["include"]),
        exclude: texts(&detail["conditions"]["ref_name"]["exclude"]),
        rules: rules.iter().filter_map(|r| opt_text(&r["type"])).collect(),
        required_status_checks: rule("required_status_checks")
            .and_then(|r| r["parameters"]["required_status_checks"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|c| opt_text(&c["context"]))
            .collect(),
        rule_parameters: rules
            .iter()
            .filter(|r| r["parameters"].is_object())
            .filter_map(|r| Some((opt_text(&r["type"])?, r["parameters"].clone())))
            .collect(),
        required_approving_review_count: rule("pull_request")
            .and_then(|r| r["parameters"]["required_approving_review_count"].as_u64())
            .and_then(|n| u32::try_from(n).ok()),
        bypass_actors: detail["bypass_actors"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|a| {
                let kind = a["actor_type"].as_str().unwrap_or("");
                // GitHub ignores the id of an organization admin; `1` is its
                // canonical form, so drift is never read on it (#1218).
                let id = if kind == ORGANIZATION_ADMIN {
                    "1".to_owned()
                } else {
                    a["actor_id"]
                        .as_u64()
                        .map(|n| n.to_string())
                        .unwrap_or_default()
                };
                format!("{kind}:{id}:{}", a["bypass_mode"].as_str().unwrap_or(""))
            })
            .collect(),
    })
}

/// The highest permission of a collaborator: `role_name` when GitHub sends it,
/// else the strongest `permissions` flag in GitHub's role names.
fn permission(collaborator: &Value) -> Option<String> {
    opt_text(&collaborator["role_name"]).or_else(|| {
        [
            ("admin", "admin"),
            ("maintain", "maintain"),
            ("push", "write"),
            ("triage", "triage"),
            ("pull", "read"),
        ]
        .into_iter()
        .find(|(key, _)| collaborator["permissions"][key] == true)
        .map(|(_, role)| role.to_owned())
    })
}

fn pull(p: &Value, what: &str) -> HostResult<PullMeta> {
    Ok(PullMeta {
        number: number(p, "number", what)?,
        title: text(p, "title", what)?,
        state: text(p, "state", what)?,
        head_sha: text(&p["head"], "sha", what)?,
        base: text(&p["base"], "ref", what)?,
        author: opt_text(&p["user"]["login"]),
        draft: p["draft"].as_bool(),
        created_at: opt_text(&p["created_at"]),
        merged_at: opt_text(&p["merged_at"]),
        closed_at: opt_text(&p["closed_at"]),
        merge_commit_sha: opt_text(&p["merge_commit_sha"]),
    })
}

// --- CI and delivery reads (#678) ---------------------------------------------------

/// `path?k=v&…` with each value already encoded; `path` alone when empty.
fn with_query(path: String, query: &[String]) -> String {
    if query.is_empty() {
        path
    } else {
        format!("{path}?{}", query.join("&"))
    }
}
/// `done` for a list read with an optional item limit, counting items `keep` admits.
fn reached(limit: Option<u32>, keep: fn(&Value) -> bool) -> impl Fn(&[Value]) -> bool {
    move |items| limit.is_some_and(|n| items.iter().filter(|i| keep(i)).count() >= n as usize)
}
fn max_items(limit: Option<u32>) -> usize {
    limit.map_or(usize::MAX, |n| n as usize)
}
fn run(r: &Value, what: &str) -> HostResult<WorkflowRun> {
    Ok(WorkflowRun {
        id: number(r, "id", what)?,
        name: text(r, "name", what)?,
        head_sha: text(r, "head_sha", what)?,
        head_branch: text(r, "head_branch", what)?,
        event: text(r, "event", what)?,
        status: text(r, "status", what)?,
        conclusion: opt_text(&r["conclusion"]),
        run_attempt: r["run_attempt"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok()),
        created_at: opt_text(&r["created_at"]),
        updated_at: opt_text(&r["updated_at"]),
        run_started_at: opt_text(&r["run_started_at"]),
        pull_requests: r["pull_requests"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p["number"].as_u64())
            .collect(),
    })
}
fn job(j: &Value, what: &str) -> HostResult<Job> {
    Ok(Job {
        id: number(j, "id", what)?,
        name: text(j, "name", what)?,
        status: text(j, "status", what)?,
        conclusion: opt_text(&j["conclusion"]),
        started_at: opt_text(&j["started_at"]),
        completed_at: opt_text(&j["completed_at"]),
        labels: texts(&j["labels"]),
    })
}
fn check_run(c: &Value, what: &str) -> HostResult<CheckRun> {
    Ok(CheckRun {
        id: number(c, "id", what)?,
        name: text(c, "name", what)?,
        status: text(c, "status", what)?,
        conclusion: opt_text(&c["conclusion"]),
        app: opt_text(&c["app"]["slug"]),
        completed_at: opt_text(&c["completed_at"]),
    })
}
fn deployment(d: &Value, what: &str) -> HostResult<Deployment> {
    Ok(Deployment {
        id: number(d, "id", what)?,
        environment: text(d, "environment", what)?,
        sha: text(d, "sha", what)?,
        reference: opt_text(&d["ref"]),
        created_at: opt_text(&d["created_at"]),
        state: None,
    })
}
fn deployment_status(s: &Value, what: &str) -> HostResult<DeploymentStatus> {
    Ok(DeploymentStatus {
        id: number(s, "id", what)?,
        state: text(s, "state", what)?,
        environment: opt_text(&s["environment"]),
        created_at: opt_text(&s["created_at"]),
    })
}
/// GitHub's issue list also returns pull requests, marked by `pull_request`.
fn is_issue(i: &Value) -> bool {
    i.get("pull_request").is_none()
}
fn issue(i: &Value, what: &str) -> HostResult<IssueMeta> {
    Ok(IssueMeta {
        number: number(i, "number", what)?,
        title: text(i, "title", what)?,
        state: text(i, "state", what)?,
        labels: i["labels"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|l| opt_text(&l["name"]))
            .collect(),
        author: opt_text(&i["user"]["login"]),
        created_at: opt_text(&i["created_at"]),
        updated_at: opt_text(&i["updated_at"]),
        closed_at: opt_text(&i["closed_at"]),
        url: opt_text(&i["html_url"]),
        body: opt_text(&i["body"]),
    })
}

// --- security, branch and contents reads (#679) ------------------------------------

/// Items the single-page reads (Dependabot alerts, branches) return before
/// they are `Truncated`.
pub const ONE_PAGE: usize = 100;
/// The largest file, in bytes, `file_contents` decodes: the workflow reader's
/// cap, so `--fleet` reads the workflows a checkout reads (256 KiB,
/// SPEC-security.md Open question 16).
pub const FILE_CAP: u64 = 256 * 1024;

fn truncated(what: &str, detail: &str) -> HostError {
    HostError::new(HostErrorKind::Truncated, format!("{what} {detail}"))
}

/// Standard base64 as GitHub sends file contents (wrapped lines); `None` on
/// any other character, a partial quantum or misplaced padding.
fn base64(text: &str) -> Option<Vec<u8>> {
    let symbols: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !symbols.len().is_multiple_of(4) {
        return None;
    }
    let quanta = symbols.len() / 4;
    let mut bytes = Vec::with_capacity(quanta * 3);
    for (i, quantum) in symbols.chunks(4).enumerate() {
        let padding = quantum.iter().rev().take_while(|&&b| b == b'=').count();
        if padding > 2 || (padding > 0 && i + 1 != quanta) {
            return None;
        }
        let mut bits = 0u32;
        for &symbol in &quantum[..4 - padding] {
            bits = bits << 6 | sextet(symbol)?;
        }
        bits <<= 6 * padding as u32;
        bytes.extend_from_slice(&bits.to_be_bytes()[1..4 - padding]);
    }
    Some(bytes)
}
fn sextet(symbol: u8) -> Option<u32> {
    Some(u32::from(match symbol {
        b'A'..=b'Z' => symbol - b'A',
        b'a'..=b'z' => symbol - b'a' + 26,
        b'0'..=b'9' => symbol - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    }))
}

impl GitHub<'_> {
    /// `GET contents/{path}?ref=`; `None` on 404. An empty `path` is the root
    /// only when `root` allows it.
    fn contents(
        &self,
        what: &str,
        repo: &RepoId,
        path: &str,
        reference: &str,
        root: bool,
    ) -> HostResult<Option<Value>> {
        let base = self.base(repo)?;
        let encoded = if root && path.is_empty() {
            String::new()
        } else {
            let encoded = file_path(path)
                .ok_or_else(|| shape(what, "the path is not a plain repository path"))?;
            format!("/{encoded}")
        };
        match self.get(
            what,
            &format!("{base}/contents{encoded}?ref={}", segment(reference)),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind == HostErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl Host for GitHub<'_> {
    fn kind(&self) -> HostKind {
        HostKind::GitHub
    }

    fn repository(&self, repo: &RepoId) -> HostResult<RepositorySettings> {
        let base = self.base(repo)?;
        let what = format!("repository {repo}");
        let v = self.get(&what, &base)?;
        let security = &v["security_and_analysis"];
        Ok(RepositorySettings {
            id: number(&v, "id", &what)?.to_string(),
            default_branch: text(&v, "default_branch", &what)?,
            visibility: visibility(&v, &what)?,
            archived: flag(&v, "archived", &what)?,
            fork: flag(&v, "fork", &what)?,
            description: opt_text(&v["description"]),
            pushed_at: opt_text(&v["pushed_at"]),
            allow_squash_merge: v["allow_squash_merge"].as_bool(),
            allow_merge_commit: v["allow_merge_commit"].as_bool(),
            allow_rebase_merge: v["allow_rebase_merge"].as_bool(),
            delete_branch_on_merge: v["delete_branch_on_merge"].as_bool(),
            allow_auto_merge: v["allow_auto_merge"].as_bool(),
            has_wiki: v["has_wiki"].as_bool(),
            has_projects: v["has_projects"].as_bool(),
            web_commit_signoff_required: v["web_commit_signoff_required"].as_bool(),
            secret_scanning: opt_text(&security["secret_scanning"]["status"]),
            secret_scanning_push_protection: opt_text(
                &security["secret_scanning_push_protection"]["status"],
            ),
            allow_update_branch: v["allow_update_branch"].as_bool(),
        })
    }

    /// Each field by its endpoint (SPEC-host-adapter.md, "Features"); see `features.rs`.
    fn features(&self, repo: &RepoId) -> HostResult<Features> {
        self.probe_features(repo)
    }

    fn branch_protection(
        &self,
        repo: &RepoId,
        branch: &str,
    ) -> HostResult<Option<BranchProtection>> {
        let base = self.base(repo)?;
        let what = format!("protection of branch {} in {repo}", plain(branch));
        let v = match self.get(
            &what,
            &format!("{base}/branches/{}/protection", segment(branch)),
        ) {
            Ok(v) => v,
            Err(e)
                if e.kind == HostErrorKind::NotFound
                    && e.message.contains("Branch not protected") =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if !v.is_object() {
            return Err(shape(&what, "the response is not an object"));
        }
        Ok(Some(BranchProtection {
            branch: branch.to_owned(),
            required_status_checks: remote::protection_contexts(&v)
                .into_iter()
                .map(str::to_owned)
                .collect(),
            strict: v["required_status_checks"]["strict"].as_bool(),
            enforce_admins: v["enforce_admins"]["enabled"].as_bool(),
            required_approving_review_count:
                v["required_pull_request_reviews"]["required_approving_review_count"]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok()),
            require_code_owner_reviews:
                v["required_pull_request_reviews"]["require_code_owner_reviews"].as_bool(),
            required_linear_history: v["required_linear_history"]["enabled"].as_bool(),
            allow_force_pushes: v["allow_force_pushes"]["enabled"].as_bool(),
            allow_deletions: v["allow_deletions"]["enabled"].as_bool(),
        }))
    }

    /// The list endpoint carries no rules, so each ruleset costs one more read.
    fn rulesets(&self, repo: &RepoId) -> HostResult<Vec<Ruleset>> {
        let base = self.base(repo)?;
        let what = format!("rulesets of {repo}");
        self.list(&what, &format!("{base}/rulesets"), None)?
            .iter()
            .map(|summary| {
                let id = number(summary, "id", &what)?;
                let detail = self.get(&what, &format!("{base}/rulesets/{id}"))?;
                ruleset(&detail, &what)
            })
            .collect()
    }

    fn environments(&self, repo: &RepoId) -> HostResult<Vec<Environment>> {
        let base = self.base(repo)?;
        let what = format!("environments of {repo}");
        self.list(&what, &format!("{base}/environments"), Some("environments"))?
            .iter()
            .map(|env| {
                let name = text(env, "name", &what)?;
                let policy = &env["deployment_branch_policy"];
                let deployment_branch_policy = if policy.is_null() {
                    DeploymentBranchPolicy::Unrestricted
                } else if policy["protected_branches"] == true {
                    DeploymentBranchPolicy::ProtectedBranches
                } else if policy["custom_branch_policies"] == true {
                    let path = format!(
                        "{base}/environments/{}/deployment-branch-policies",
                        segment(&name)
                    );
                    let policies = self.list(&what, &path, Some("branch_policies"))?;
                    DeploymentBranchPolicy::Custom {
                        patterns: policies
                            .iter()
                            .map(|p| {
                                let pattern = text(p, "name", &what)?;
                                // A tag pattern must never read as a branch.
                                Ok(if p["type"] == "tag" {
                                    format!("tag:{pattern}")
                                } else {
                                    pattern
                                })
                            })
                            .collect::<HostResult<_>>()?,
                    }
                } else {
                    return Err(shape(&what, "unknown deployment_branch_policy"));
                };
                let rules = env["protection_rules"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                Ok(Environment {
                    id: env["id"].as_u64(),
                    name,
                    deployment_branch_policy,
                    reviewers: rules
                        .iter()
                        .filter(|r| r["type"] == "required_reviewers")
                        .flat_map(|r| r["reviewers"].as_array().into_iter().flatten())
                        .filter_map(|r| {
                            opt_text(&r["reviewer"]["login"])
                                .or_else(|| opt_text(&r["reviewer"]["slug"]))
                        })
                        .collect(),
                    wait_timer_minutes: rules
                        .iter()
                        .find(|r| r["type"] == "wait_timer")
                        .and_then(|r| r["wait_timer"].as_u64())
                        .and_then(|n| u32::try_from(n).ok()),
                })
            })
            .collect()
    }

    fn actions_pull_requests_allowed(&self, repo: &RepoId) -> HostResult<bool> {
        let base = self.base(repo)?;
        let what = format!("workflow permissions of {repo}");
        let v = self.get(&what, &format!("{base}/actions/permissions/workflow"))?;
        flag(&v, "can_approve_pull_request_reviews", &what)
    }

    fn actions_access(&self, repo: &RepoId) -> HostResult<String> {
        let base = self.base(repo)?;
        let what = format!("Actions access of {repo}");
        let v = self.get(&what, &format!("{base}/actions/permissions/access"))?;
        text(&v, "access_level", &what)
    }

    /// Names and update times only; any other field of the response is dropped.
    fn secret_names(&self, repo: &RepoId, scope: &SecretScope) -> HostResult<Vec<SecretName>> {
        let base = self.base(repo)?;
        let (path, label) = match scope {
            SecretScope::Repository => (format!("{base}/actions/secrets"), "repository".to_owned()),
            SecretScope::Environment(name) => (
                format!("{base}/environments/{}/secrets", segment(name)),
                format!("environment {}", plain(name)),
            ),
            SecretScope::Organization => (
                format!("{base}/actions/organization-secrets"),
                "organization".to_owned(),
            ),
            SecretScope::Dependabot => (
                format!("{base}/dependabot/secrets"),
                "Dependabot".to_owned(),
            ),
        };
        let what = format!("{label} secret names of {repo}");
        self.list(&what, &path, Some("secrets"))?
            .iter()
            .map(|s| {
                Ok(SecretName {
                    name: text(s, "name", &what)?,
                    scope: scope.clone(),
                    updated_at: opt_text(&s["updated_at"]),
                })
            })
            .collect()
    }

    /// Newest first, as GitHub lists them; `created_since` becomes
    /// `created=>=…`; `limit` stops early without a `Truncated`.
    fn workflow_runs(&self, repo: &RepoId, filter: &RunFilter) -> HostResult<Vec<WorkflowRun>> {
        let base = self.base(repo)?;
        let what = format!("workflow runs of {repo}");
        let mut query = Vec::new();
        for (key, value) in [
            ("branch", &filter.branch),
            ("event", &filter.event),
            ("status", &filter.status),
        ] {
            if let Some(value) = value {
                query.push(format!("{key}={}", segment(value)));
            }
        }
        if let Some(since) = &filter.created_since {
            query.push(format!("created={}", segment(&format!(">={since}"))));
        }
        let path = with_query(format!("{base}/actions/runs"), &query);
        let items = self.list_until(
            &what,
            &path,
            Some("workflow_runs"),
            reached(filter.limit, |_| true),
        )?;
        items
            .iter()
            .take(max_items(filter.limit))
            .map(|r| run(r, &what))
            .collect()
    }
    fn run_timing(&self, repo: &RepoId, run_id: u64) -> HostResult<RunTiming> {
        let base = self.base(repo)?;
        let what = format!("timing of run {run_id} in {repo}");
        let v = self.get(&what, &format!("{base}/actions/runs/{run_id}/timing"))?;
        Ok(RunTiming {
            run_id,
            run_duration_ms: number(&v, "run_duration_ms", &what)?,
        })
    }
    /// The jobs of the run's latest attempt (GitHub's default `filter=latest`).
    fn jobs(&self, repo: &RepoId, run_id: u64) -> HostResult<Vec<Job>> {
        let base = self.base(repo)?;
        let what = format!("jobs of run {run_id} in {repo}");
        self.list(
            &what,
            &format!("{base}/actions/runs/{run_id}/jobs"),
            Some("jobs"),
        )?
        .iter()
        .map(|j| job(j, &what))
        .collect()
    }
    fn check_runs(&self, repo: &RepoId, sha: &str) -> HostResult<Vec<CheckRun>> {
        let base = self.base(repo)?;
        let what = format!("check runs of commit {} in {repo}", plain(sha));
        self.list(
            &what,
            &format!("{base}/commits/{}/check-runs", segment(sha)),
            Some("check_runs"),
        )?
        .iter()
        .map(|c| check_run(c, &what))
        .collect()
    }

    /// Login, permission and account type; never names or emails.
    fn collaborators(&self, repo: &RepoId) -> HostResult<Vec<Collaborator>> {
        let base = self.base(repo)?;
        let what = format!("collaborators of {repo}");
        self.list(&what, &format!("{base}/collaborators"), None)?
            .iter()
            .map(|c| {
                Ok(Collaborator {
                    login: text(c, "login", &what)?,
                    permission: permission(c).ok_or_else(|| shape(&what, "missing permission"))?,
                    kind: opt_text(&c["type"]),
                })
            })
            .collect()
    }

    /// Newest first; each deployment's state comes from `deployment_statuses`.
    fn deployments(&self, repo: &RepoId, environment: Option<&str>) -> HostResult<Vec<Deployment>> {
        let base = self.base(repo)?;
        let (what, query) = match environment {
            Some(env) => (
                format!("{} deployments of {repo}", plain(env)),
                vec![format!("environment={}", segment(env))],
            ),
            None => (format!("deployments of {repo}"), Vec::new()),
        };
        self.list(
            &what,
            &with_query(format!("{base}/deployments"), &query),
            None,
        )?
        .iter()
        .map(|d| deployment(d, &what))
        .collect()
    }
    fn deployment_statuses(
        &self,
        repo: &RepoId,
        deployment_id: u64,
    ) -> HostResult<Vec<DeploymentStatus>> {
        let base = self.base(repo)?;
        let what = format!("statuses of deployment {deployment_id} in {repo}");
        self.list(
            &what,
            &format!("{base}/deployments/{deployment_id}/statuses"),
            None,
        )?
        .iter()
        .map(|s| deployment_status(s, &what))
        .collect()
    }
    fn latest_deployments(&self, repo: &RepoId, environment: &str) -> HostResult<Vec<Deployment>> {
        let base = self.base(repo)?;
        let what = format!("{} deployments of {repo}", plain(environment));
        let path = format!(
            "{base}/deployments?environment={}&per_page={ONE_PAGE}&page=1",
            segment(environment)
        );
        self.get(&what, &path)?
            .as_array()
            .ok_or_else(|| shape(&what, "the response is not a list"))?
            .iter()
            .map(|d| deployment(d, &what))
            .collect()
    }
    /// Issues only: the pull requests GitHub mixes into this list are dropped
    /// and do not count towards `limit`. `since` is GitHub's (updated at or after).
    fn issues(&self, repo: &RepoId, filter: &IssueFilter) -> HostResult<Vec<IssueMeta>> {
        let base = self.base(repo)?;
        let what = format!("issues of {repo}");
        let mut query = Vec::new();
        if let Some(state) = &filter.state {
            query.push(format!("state={}", segment(state)));
        }
        if !filter.labels.is_empty() {
            let labels: Vec<String> = filter.labels.iter().map(|l| segment(l)).collect();
            query.push(format!("labels={}", labels.join(",")));
        }
        if let Some(since) = &filter.since {
            query.push(format!("since={}", segment(since)));
        }
        let path = with_query(format!("{base}/issues"), &query);
        let items = self.list_until(&what, &path, None, reached(filter.limit, is_issue))?;
        items
            .iter()
            .filter(|i| is_issue(i))
            .take(max_items(filter.limit))
            .map(|i| issue(i, &what))
            .collect()
    }

    /// Newest update first (`sort=updated&direction=desc`); `since` keeps pulls
    /// updated at or after it and stops paging past it; `limit` stops early
    /// without a `Truncated`.
    fn pulls(&self, repo: &RepoId, filter: &PullFilter) -> HostResult<Vec<PullMeta>> {
        let base = self.base(repo)?;
        let what = format!("pull requests of {repo}");
        let mut path = format!("{base}/pulls?");
        if let Some(state) = &filter.state {
            path.push_str(&format!("state={}&", segment(state)));
        }
        if let Some(branch) = &filter.base {
            path.push_str(&format!("base={}&", segment(branch)));
        }
        path.push_str("sort=updated&direction=desc");
        let since = filter.since.as_deref();
        let limit = filter.limit.map(|n| n as usize);
        let older =
            |p: &Value| since.is_some_and(|s| p["updated_at"].as_str().is_some_and(|u| u < s));
        let items = self.list_until(&what, &path, None, |items| {
            limit.is_some_and(|n| items.len() >= n) || items.last().is_some_and(older)
        })?;
        items
            .iter()
            .filter(|p| !older(p))
            .take(limit.unwrap_or(usize::MAX))
            .map(|p| pull(p, &what))
            .collect()
    }

    fn pulls_for_commit(&self, repo: &RepoId, sha: &str) -> HostResult<Vec<PullMeta>> {
        let base = self.base(repo)?;
        let what = format!("pull requests of commit {} in {repo}", plain(sha));
        self.list(
            &what,
            &format!("{base}/commits/{}/pulls", segment(sha)),
            None,
        )?
        .iter()
        .map(|p| pull(p, &what))
        .collect()
    }

    /// One page of 100: a full page is `Truncated` rather than a second call,
    /// since a pull request that large is not judged (SPEC-auditor.md, "Counters").
    fn pull_files(&self, repo: &RepoId, number: u64) -> HostResult<Vec<PullFile>> {
        let base = self.base(repo)?;
        let what = format!("files of pull request #{number} in {repo}");
        let files = self
            .get(
                &what,
                &format!("{base}/pulls/{number}/files?per_page={ONE_PAGE}&page=1"),
            )?
            .as_array()
            .cloned()
            .ok_or_else(|| shape(&what, "the response is not a list"))?;
        if files.len() >= ONE_PAGE {
            return Err(truncated(
                &what,
                &format!("has {ONE_PAGE} or more files, the cap of this read"),
            ));
        }
        files
            .iter()
            .map(|f| {
                Ok(PullFile {
                    filename: text(f, "filename", &what)?,
                    status: text(f, "status", &what)?,
                    previous_filename: opt_text(&f["previous_filename"]),
                })
            })
            .collect()
    }

    /// The blob sha of a file; `None` when GitHub answers 404 or the path is a
    /// directory.
    fn file_exists(
        &self,
        repo: &RepoId,
        path: &str,
        reference: &str,
    ) -> HostResult<Option<String>> {
        let base = self.base(repo)?;
        let what = format!("file {} at {} in {repo}", plain(path), plain(reference));
        let encoded = file_path(path)
            .ok_or_else(|| shape(&what, "the path is not a plain repository path"))?;
        match self.get(
            &what,
            &format!("{base}/contents/{encoded}?ref={}", segment(reference)),
        ) {
            Ok(v) if v.is_array() => Ok(None),
            Ok(v) => text(&v, "sha", &what).map(Some),
            Err(e) if e.kind == HostErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    // Security, branch and contents reads (#679)

    /// One page: this endpoint pages by `Link` cursors, which the transport does
    /// not expose, so a full page is `Truncated` instead of a guessed page 2.
    fn dependabot_alerts(&self, repo: &RepoId) -> HostResult<Vec<DependabotAlert>> {
        let base = self.base(repo)?;
        let what = format!("open Dependabot alerts of {repo}");
        let v = self.get(
            &what,
            &format!("{base}/dependabot/alerts?state=open&per_page=100"),
        )?;
        let alerts = v
            .as_array()
            .ok_or_else(|| shape(&what, "the response is not a list"))?;
        if alerts.len() >= ONE_PAGE {
            return Err(truncated(
                &what,
                &format!("has {ONE_PAGE} or more items, the cap of this read"),
            ));
        }
        alerts
            .iter()
            .map(|a| {
                Ok(DependabotAlert {
                    number: number(a, "number", &what)?,
                    severity: opt_text(&a["security_vulnerability"]["severity"])
                        .or_else(|| opt_text(&a["security_advisory"]["severity"]))
                        .ok_or_else(|| shape(&what, "missing severity"))?,
                    package: opt_text(&a["dependency"]["package"]["name"]),
                    ecosystem: opt_text(&a["dependency"]["package"]["ecosystem"]),
                    manifest_path: opt_text(&a["dependency"]["manifest_path"]),
                    created_at: text(a, "created_at", &what)?,
                })
            })
            .collect()
    }

    /// `hide_secret=true` asks GitHub not to send the literal secret, and
    /// `SecretScanningAlert` has no field that could hold one.
    fn secret_scanning_alerts(&self, repo: &RepoId) -> HostResult<Vec<SecretScanningAlert>> {
        let base = self.base(repo)?;
        let what = format!("open secret-scanning alerts of {repo}");
        self.list(
            &what,
            &format!("{base}/secret-scanning/alerts?state=open&hide_secret=true"),
            None,
        )?
        .iter()
        .map(|a| {
            Ok(SecretScanningAlert {
                number: number(a, "number", &what)?,
                secret_type: text(a, "secret_type", &what)?,
                secret_type_display_name: opt_text(&a["secret_type_display_name"]),
                validity: opt_text(&a["validity"]),
                push_protection_bypassed: a["push_protection_bypassed"].as_bool(),
                created_at: text(a, "created_at", &what)?,
            })
        })
        .collect()
    }

    /// `branch_heads`, then one `commit_date` per branch.
    fn branches(&self, repo: &RepoId) -> HostResult<Vec<Branch>> {
        self.branch_heads(repo)?
            .into_iter()
            .map(|branch| {
                let committed_at = self.commit_date(repo, &branch.sha)?;
                Ok(Branch {
                    committed_at,
                    ..branch
                })
            })
            .collect()
    }

    /// One page of 100, page 2 only to tell exactly 100 from more.
    fn branch_heads(&self, repo: &RepoId) -> HostResult<Vec<Branch>> {
        let base = self.base(repo)?;
        let what = format!("branches of {repo}");
        let page = |n: u32| {
            self.get(&what, &format!("{base}/branches?per_page=100&page={n}"))?
                .as_array()
                .cloned()
                .ok_or_else(|| shape(&what, "the response is not a list"))
        };
        let branches = page(1)?;
        if branches.len() >= ONE_PAGE && !page(2)?.is_empty() {
            return Err(truncated(
                &what,
                &format!("has more than {ONE_PAGE} items, the cap of this read"),
            ));
        }
        branches
            .iter()
            .map(|b| {
                Ok(Branch {
                    name: text(b, "name", &what)?,
                    sha: text(&b["commit"], "sha", &what)?,
                    protected: b["protected"].as_bool(),
                    committed_at: None,
                })
            })
            .collect()
    }

    /// `git/commits/{sha}`: its `committer.date`.
    fn commit_date(&self, repo: &RepoId, sha: &str) -> HostResult<Option<String>> {
        let base = self.base(repo)?;
        let what = format!("branches of {repo}");
        let commit = self.get(&what, &format!("{base}/git/commits/{}", segment(sha)))?;
        Ok(opt_text(&commit["committer"]["date"]))
    }

    /// `None` on 404 or a directory; GitHub's `size` decides the cap before
    /// anything is decoded.
    fn file_contents(
        &self,
        repo: &RepoId,
        path: &str,
        reference: &str,
    ) -> HostResult<Option<FileContents>> {
        let what = format!("file {} at {} in {repo}", plain(path), plain(reference));
        let v = match self.contents(&what, repo, path, reference, false)? {
            Some(v) if !v.is_array() => v,
            _ => return Ok(None),
        };
        if v["type"] != "file" {
            return Err(shape(&what, "the path is not a regular file"));
        }
        let too_big = |size: u64| {
            truncated(
                &what,
                &format!("is {size} bytes, over the {FILE_CAP}-byte cap of this read"),
            )
        };
        let size = number(&v, "size", &what)?;
        if size > FILE_CAP {
            return Err(too_big(size));
        }
        let encoding = v["encoding"].as_str().unwrap_or("missing");
        if encoding != "base64" {
            return Err(shape(
                &what,
                &format!("unsupported encoding {}", plain(encoding)),
            ));
        }
        let bytes = base64(&text(&v, "content", &what)?)
            .ok_or_else(|| shape(&what, "the content is not base64"))?;
        if bytes.len() as u64 > FILE_CAP {
            return Err(too_big(bytes.len() as u64));
        }
        Ok(Some(FileContents {
            path: text(&v, "path", &what)?,
            sha: text(&v, "sha", &what)?,
            size,
            text: String::from_utf8(bytes)
                .map_err(|_| shape(&what, "the content is not UTF-8 text"))?,
        }))
    }

    fn list_directory(
        &self,
        repo: &RepoId,
        path: &str,
        reference: &str,
    ) -> HostResult<Option<Vec<DirEntry>>> {
        let shown = if path.is_empty() { "/" } else { path };
        let what = format!(
            "directory {} at {} in {repo}",
            plain(shown),
            plain(reference)
        );
        let Some(v) = self.contents(&what, repo, path, reference, true)? else {
            return Ok(None);
        };
        let entries = v
            .as_array()
            .ok_or_else(|| shape(&what, "the path is not a directory"))?;
        entries
            .iter()
            .map(|e| {
                let kind = match e["type"].as_str() {
                    Some("file") => EntryKind::File,
                    Some("dir") => EntryKind::Dir,
                    Some("symlink") => EntryKind::Symlink,
                    Some("submodule") => EntryKind::Submodule,
                    other => {
                        return Err(shape(
                            &what,
                            &format!("unknown entry type {}", plain(other.unwrap_or("missing"))),
                        ));
                    }
                };
                Ok(DirEntry {
                    name: text(e, "name", &what)?,
                    kind,
                    sha: text(e, "sha", &what)?,
                })
            })
            .collect::<HostResult<_>>()
            .map(Some)
    }

    // Reads the probe registry adds (#683)

    fn labels(&self, repo: &RepoId) -> HostResult<Vec<Label>> {
        let base = self.base(repo)?;
        let what = format!("labels of {repo}");
        self.list(&what, &format!("{base}/labels"), None)?
            .iter()
            .map(|l| {
                Ok(Label {
                    name: text(l, "name", &what)?,
                    color: text(l, "color", &what)?,
                    description: opt_text(&l["description"]),
                })
            })
            .collect()
    }

    /// One page of `commits?sha=`: the newest `limit` commits, no more.
    fn recent_commits(&self, repo: &RepoId, branch: &str, limit: u32) -> HostResult<Vec<String>> {
        let base = self.base(repo)?;
        let what = format!("commits of branch {} in {repo}", plain(branch));
        let v = self.get(
            &what,
            &format!("{base}/commits?sha={}&per_page={limit}", segment(branch)),
        )?;
        v.as_array()
            .ok_or_else(|| shape(&what, "the response is not a list"))?
            .iter()
            .map(|c| text(c, "sha", &what))
            .collect()
    }

    /// 204 (`null`) or `enabled: true` is enabled; GitHub documents 404 as
    /// disabled for the two Dependabot settings, so only those map it.
    fn security_toggle(&self, repo: &RepoId, toggle: SecurityToggle) -> HostResult<bool> {
        let base = self.base(repo)?;
        let what = format!("{} of {repo}", toggle.title());
        match self.get(&what, &format!("{base}/{}", toggle.endpoint())) {
            Ok(Value::Null) => Ok(toggle == SecurityToggle::VulnerabilityAlerts),
            Ok(v) => flag(&v, "enabled", &what),
            Err(e)
                if e.kind == HostErrorKind::NotFound
                    && toggle != SecurityToggle::PrivateVulnerabilityReporting =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    fn code_scanning_default_setup(&self, repo: &RepoId) -> HostResult<CodeScanningSetup> {
        let base = self.base(repo)?;
        let what = format!("code scanning default setup of {repo}");
        let value = self.get(&what, &format!("{base}/code-scanning/default-setup"))?;
        match opt_text(&value["state"]) {
            Some(state) => Ok(CodeScanningSetup { state }),
            None => Err(shape(&what, "missing text field state")),
        }
    }
    fn repo_variable(&self, repo: &RepoId, name: &str) -> HostResult<Option<String>> {
        let what = format!("variable {name} of {repo}");
        let valid =
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !valid {
            return Err(shape(&what, "the name is not a variable name"));
        }
        let base = self.base(repo)?;
        match self.get(&what, &format!("{base}/actions/variables/{name}")) {
            Ok(v) => match opt_text(&v["value"]) {
                Some(value) => Ok(Some(value)),
                None => Err(shape(&what, "missing text field value")),
            },
            Err(e) if e.kind == HostErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn latest_release(&self, repo: &RepoId) -> HostResult<Release> {
        let base = self.base(repo)?;
        self.release(
            &format!("latest release of {repo}"),
            &format!("{base}/releases/latest"),
        )
    }
    fn release_by_tag(&self, repo: &RepoId, tag: &str) -> HostResult<Release> {
        let base = self.base(repo)?;
        let what = format!("release {tag} of {repo}");
        if tag.is_empty()
            || !tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(shape(&what, "the tag is not a release tag"));
        }
        self.release(&what, &format!("{base}/releases/tags/{tag}"))
    }
    fn job_log(&self, repo: &RepoId, job_id: u64) -> HostResult<String> {
        let base = self.base(repo)?;
        let what = format!("log of job {job_id} of {repo}");
        match self.get(&what, &format!("{base}/actions/jobs/{job_id}/logs"))? {
            Value::String(text) => Ok(text),
            _ => Err(shape(&what, "the log is not text")),
        }
    }

    /// `GET users/{name}`; see `fleet.rs` for the four fleet reads.
    fn owner(&self, name: &str) -> HostResult<OwnerId> {
        self.read_owner(name)
    }
    fn list_repositories(&self, owner: &OwnerId) -> HostResult<Partial<RepoSummary>> {
        self.repositories(owner)
    }
    fn org_rulesets(&self, org: &str) -> HostResult<Vec<Ruleset>> {
        self.organization_rulesets(org)
    }
    fn org_settings(&self, org: &str) -> HostResult<OrgSettings> {
        self.organization_settings(org)
    }
    fn org_owners(&self, org: &str) -> HostResult<Vec<String>> {
        self.organization_owners(org)
    }

    /// See `writes.rs` for the writes of #684 and #876–#879.
    fn ensure_labels(&self, token: &WriteToken, labels: &[Label]) -> HostResult<WriteReport> {
        self.write_labels(token, labels)
    }
    fn create_issue(&self, token: &WriteToken, issue: &NewIssue) -> HostResult<IssueMeta> {
        self.write_issue(token, issue)
    }
    fn comment(&self, token: &WriteToken, number: u64, body: &str) -> HostResult<u64> {
        self.write_comment(token, number, body)
    }
    fn set_repository_settings(
        &self,
        token: &WriteToken,
        settings: &RepositorySettingsPatch,
    ) -> HostResult<WriteReport> {
        self.write_settings(token, settings)
    }
    fn put_ruleset(&self, token: &WriteToken, ruleset: &Ruleset) -> HostResult<WriteReport> {
        self.write_ruleset(token, ruleset)
    }
    fn put_environment(
        &self,
        token: &WriteToken,
        environment: &EnvironmentSpec,
    ) -> HostResult<WriteReport> {
        self.write_environment(token, environment)
    }
    fn put_branch_protection(
        &self,
        token: &WriteToken,
        branch: &str,
        protection: &BranchProtectionSpec,
    ) -> HostResult<WriteReport> {
        self.write_branch_protection(token, branch, protection)
    }
    fn retire_branch_protection(
        &self,
        token: &WriteToken,
        branch: &str,
        superseded_by: Option<&str>,
    ) -> HostResult<WriteReport> {
        self.remove_branch_protection(token, branch, superseded_by)
    }
}
