//! Read-only GitHub observations; absence of evidence is always a finding.
use crate::{
    Result,
    host::{HostError, HostErrorKind, github::names_plan},
    profile, refuse, scope,
};
use chrono::DateTime;
use serde_json::Value;
use std::{
    cell::Cell,
    collections::BTreeSet,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The transport under the host adapter: one `gh api` call per method call.
/// `get` is the only required method, so a fake that serves reads alone
/// still compiles; `send` and `rate_limit` have conservative defaults.
pub trait Api {
    fn get(&self, path: &str) -> Result<Value>;
    /// A non-GET request. The default refuses with `HostErrorKind::Unsupported`
    /// naming the method, so a read-only transport can never write.
    fn send(&self, method: &str, path: &str, _body: Option<&Value>) -> Result<Value> {
        Err(HostError::new(
            HostErrorKind::Unsupported,
            format!("{method} {path} is not supported by this read-only transport"),
        )
        .into())
    }
    /// The `x-ratelimit-*` headers of the last response, when the transport saw any.
    fn rate_limit(&self) -> Option<RateLimit> {
        None
    }
}

/// The last `x-ratelimit-remaining` and `x-ratelimit-reset` a response carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub remaining: u64,
    pub reset_epoch: Option<i64>,
}
#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub message: String,
}
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GitHub read failed (HTTP {})", self.status)
    }
}
impl std::error::Error for HttpError {}

/// `gh api` with the environment hygiene of the installer; it remembers the
/// rate-limit headers of the last response it read.
#[derive(Debug, Default)]
pub struct Gh {
    last_rate_limit: Cell<Option<RateLimit>>,
}
impl Api for Gh {
    fn rate_limit(&self) -> Option<RateLimit> {
        self.last_rate_limit.get()
    }
    fn get(&self, path: &str) -> Result<Value> {
        self.call("GET", path, None)
    }
    /// A write: the body goes through stdin (`--input -`) after
    /// `refuse_secret_body`, so a secret value never reaches a `gh` process.
    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        if let Some(body) = body {
            refuse_secret_body(body)?;
        }
        self.call(method, path, body)
    }
}
impl Gh {
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let mut args = vec![
            "api",
            "--include",
            "--hostname",
            "github.com",
            "--method",
            method,
            path,
        ];
        if body.is_some() {
            args.extend(["--input", "-"]);
        }
        let mut child = Command::new("gh")
            .args(args)
            .env_remove("GH_REPO")
            .env_remove("GH_HOST")
            .env_remove("GH_DEBUG")
            .stdin(if body.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        if let Some(body) = body {
            let mut stdin = child.stdin.take().expect("piped stdin");
            let bytes = serde_json::to_vec(body)?;
            std::thread::spawn(move || stdin.write_all(&bytes));
        }
        let stdout = child.stdout.take().expect("piped stdout");
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return refuse(if method == "GET" {
                    "GitHub read timed out"
                } else {
                    "GitHub write timed out"
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let bytes = reader.join().map_err(|_| "GitHub reader failed")??;
        if bytes.len() > 4 * 1024 * 1024 {
            return refuse("GitHub read failed");
        }
        if let Some(limit) = rate_limit_headers(&bytes) {
            self.last_rate_limit.set(Some(limit));
        }
        decode_response(status.success(), &bytes)
    }
}

/// The key GitHub's secrets API takes a secret value in; no body may carry it.
const SECRET_VALUE_KEY: &str = "encrypted_value";

/// Refuses a request body that carries `SECRET_VALUE_KEY` at any depth
/// (case-insensitive). The installer never sends a secret value
/// (SPEC-host-adapter.md, Secrets).
pub fn refuse_secret_body(body: &Value) -> Result<()> {
    let found = match body {
        Value::Object(map) => map.iter().any(|(key, child)| {
            key.eq_ignore_ascii_case(SECRET_VALUE_KEY) || refuse_secret_body(child).is_err()
        }),
        Value::Array(items) => items.iter().any(|child| refuse_secret_body(child).is_err()),
        _ => false,
    };
    if found {
        return refuse(format!(
            "Remote write refused: the request body carries a secret value field ({SECRET_VALUE_KEY}), which the installer never sends"
        ));
    }
    Ok(())
}

pub(crate) fn decode_response(success: bool, bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes)?;
    let (headers, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or("GitHub response has no HTTP headers")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("HTTP/"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("GitHub response has no HTTP status")?;
    // A text body (a job log, #801) is a string; the byte-order mark the
    // blob store prepends is dropped.
    let text_body = headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("content-type")
                && value.trim().to_ascii_lowercase().starts_with("text/plain")
        })
    });
    // 204 No Content (`vulnerability-alerts` when enabled) carries no body.
    let value: Value = if status == 204 && body.trim().is_empty() {
        Value::Null
    } else if text_body && (200..300).contains(&status) {
        Value::String(body.trim_start_matches('\u{feff}').to_owned())
    } else {
        serde_json::from_str(body)?
    };
    if !success || !(200..300).contains(&status) {
        return Err(HttpError {
            status,
            message: value["message"].as_str().unwrap_or("").to_owned(),
        }
        .into());
    }
    Ok(value)
}

/// The `x-ratelimit-remaining` and `x-ratelimit-reset` headers of a `gh api --include`
/// response; header names compare without case, values elsewhere never match.
fn rate_limit_headers(bytes: &[u8]) -> Option<RateLimit> {
    let text = String::from_utf8_lossy(bytes);
    let headers = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))?
        .0;
    let header = |wanted: &str| {
        headers.lines().skip(1).find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_owned())
        })
    };
    Some(RateLimit {
        remaining: header("x-ratelimit-remaining")?.parse().ok()?,
        reset_epoch: header("x-ratelimit-reset").and_then(|v| v.parse().ok()),
    })
}

/// Reads a list `path` page by page (`per_page=100&page=N`, never `--paginate`)
/// until a page holds fewer than 100 items, `done` says the caller has enough,
/// or `cap` pages were full; the flag is `true` only in that last case.
pub(crate) fn paginate<E>(
    path: &str,
    cap: u32,
    mut page: impl FnMut(&str) -> std::result::Result<Vec<Value>, E>,
    done: impl Fn(&[Value]) -> bool,
) -> std::result::Result<(Vec<Value>, bool), E> {
    let separator = if path.contains('?') { '&' } else { '?' };
    let mut items = Vec::new();
    for number in 1..=cap {
        let batch = page(&format!("{path}{separator}per_page=100&page={number}"))?;
        let full = batch.len() >= 100;
        items.extend(batch);
        if !full || done(&items) {
            return Ok((items, false));
        }
    }
    Ok((items, true))
}

pub fn repository(root: &Path) -> Result<String> {
    // Origin identifies this checkout; other allowed remotes still pass the scope guard.
    if let Ok(url) = scope::git(root, &["remote", "get-url", "origin"]) {
        return scope::remote_identity(&url);
    }
    let identities: BTreeSet<_> = scope::remote_urls(root)?
        .iter()
        .map(|u| scope::remote_identity(u))
        .collect::<Result<_>>()?;
    if identities.len() != 1 {
        return refuse("Remote diagnosis needs one repository or an origin remote");
    }
    Ok(identities.into_iter().next().expect("one identity"))
}

/// `owner/name` of a repository the personal scope allows; anything else is never read.
pub(crate) fn in_scope(repository: &str) -> bool {
    repository.split('/').count() == 2
        && repository
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
        && scope::remote_identity(&format!("https://github.com/{repository}")).is_ok()
}

pub(crate) fn segment(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub(crate) fn plain(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub struct Report {
    pub findings: Vec<String>,
    pub note: Option<String>,
}

pub fn inspect(api: &dyn Api, repository: &str, ci: &Value) -> Vec<String> {
    inspect_report(api, repository, ci).findings
}

/// What the remote diagnosis compares the repository with (#1109).
pub enum Policy<'a> {
    /// The profile's `ci` block, as declared: required checks, shards, cycle
    /// budget and tiers. A repository without `ci-baseline`.
    Declared(&'a Value),
    /// What `ci-baseline` and `repo-baseline` render, for a repository that
    /// has `ci-baseline`: the retired `ci.*` keys are never read.
    CiBaseline(CiBaselinePolicy),
}

/// The CI policy of a repository with `ci-baseline` (SPEC-auditor.md,
/// "Baseline block", #1109).
#[derive(Debug, Clone, PartialEq)]
pub struct CiBaselinePolicy {
    /// The contexts the rendered ruleset requires, else the `aggregate_check`.
    pub required: Vec<String>,
    /// `ci.shards.count` when the profile declares more than one shard.
    pub shards: Option<u64>,
    /// `ci.cycle_budget_minutes` when the profile declares it.
    pub cycle_budget_minutes: Option<f64>,
}

/// The policy `doctor --remote` judges `root` by: `CiBaseline` when
/// `ci-baseline` is installed (recorded in the lock, or its answers recorded),
/// with its defaults where no answers file exists (#1126: an install that keeps
/// every default writes none); else the declared `ci` block.
pub fn policy_for(root: &std::path::Path, ci: &Value) -> Result<Option<CiBaselinePolicy>> {
    const CI_BASELINE: &str = "ci-baseline";
    let answers = crate::engine::answers::recorded(root, CI_BASELINE)?;
    let in_lock = std::fs::read_to_string(root.join(crate::LOCK))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .is_some_and(|lock| lock["modules"].get(CI_BASELINE).is_some());
    if answers.is_none() && !in_lock {
        return Ok(None);
    }
    let ruleset: Vec<String> = std::fs::read_to_string(root.join(".github/rulesets/main.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .map(|v| ruleset_contexts(&v["rules"]))
        .unwrap_or_default();
    let required = if ruleset.is_empty() {
        vec![
            answers
                .as_ref()
                .and_then(|file| file.answers.get("aggregate_check"))
                .and_then(Value::as_str)
                .unwrap_or(crate::modules::ci_baseline::AGGREGATE_CHECK)
                .to_owned(),
        ]
    } else {
        ruleset
    };
    Ok(Some(CiBaselinePolicy {
        required,
        shards: ci["shards"]["count"].as_u64().filter(|n| *n > 1),
        cycle_budget_minutes: ci["cycle_budget_minutes"].as_f64(),
    }))
}

/// The `required_status_checks` contexts of a list of ruleset rules, as a
/// rendered ruleset or `rules/branches/{branch}` carries them.
fn ruleset_contexts(rules: &Value) -> Vec<String> {
    rules
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["type"] == "required_status_checks")
        .flat_map(|r| {
            r["parameters"]["required_status_checks"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c["context"].as_str())
        })
        .map(str::to_owned)
        .collect()
}

/// A bounded sample of the latest workflow cycles, never a claim about every historical run.
pub fn inspect_report(api: &dyn Api, repository: &str, ci: &Value) -> Report {
    inspect_policy(api, repository, &Policy::Declared(ci))
}

/// [`inspect_report`] against `policy`.
pub fn inspect_policy(api: &dyn Api, repository: &str, policy: &Policy<'_>) -> Report {
    let mut findings = Vec::new();
    if !in_scope(repository) {
        return Report {
            findings: vec![
                "Remote diagnosis refuses repositories outside the authorized personal scope."
                    .to_owned(),
            ],
            note: None,
        };
    }
    let base = format!("repos/{repository}");
    let metadata = match api.get(&base) {
        Ok(v) if v["default_branch"].as_str().is_some_and(|s| !s.is_empty()) => v,
        _ => {
            return Report {
                findings: vec!["The repository default branch could not be read, so remote protection and CI are unverified.".to_owned()],
                note: None,
            }
        }
    };
    let branch = metadata["default_branch"].as_str().expect("default branch");
    let (count, budget, tiers) = match policy {
        Policy::Declared(ci) => {
            protection(api, &base, branch, ci, &mut findings);
            if !ci.is_object() {
                findings.push(
                    "The project has no declared CI policy to compare with recent runs.".to_owned(),
                );
                return Report {
                    findings,
                    note: None,
                };
            }
            let count = ci["shards"]["count"]
                .as_u64()
                .filter(|n| (1..=256).contains(n));
            if count.is_none()
                || !ci["shards"]["command"]
                    .as_str()
                    .is_some_and(profile::single_line)
            {
                findings.push(
                    "The CI shard policy needs a positive count up to 256 and a declared command."
                        .to_owned(),
                );
            }
            let budget = ci["cycle_budget_minutes"]
                .as_f64()
                .filter(|v| v.is_finite() && *v > 0.0);
            if budget.is_none() {
                findings.push("The CI cycle budget is missing or invalid.".to_owned());
            }
            let tiers = Tiers::parse(&ci["tiers"]);
            if tiers.is_none() {
                findings.push("The declared CI tiers cannot be evaluated; declare main paths as ['**'] and pull_request inert_paths and full_paths lists.".to_owned());
            }
            (count, budget, tiers)
        }
        Policy::CiBaseline(rendered) => {
            rendered_protection(api, &base, branch, &rendered.required, &mut findings);
            let count = rendered.shards.filter(|n| (2..=256).contains(n));
            if rendered.shards.is_some() && count.is_none() {
                findings.push(
                    "The CI shard policy needs a positive count up to 256 and a declared command."
                        .to_owned(),
                );
            }
            let budget = rendered
                .cycle_budget_minutes
                .filter(|v| v.is_finite() && *v > 0.0);
            if rendered.cycle_budget_minutes.is_some() && budget.is_none() {
                findings.push("The CI cycle budget is missing or invalid.".to_owned());
            }
            // ci-baseline's scope job and aggregate decide the tier (#1109).
            (count, budget, None)
        }
    };
    let tiers_supported = tiers.is_some();
    let runs = match api.get(&format!("{base}/actions/runs?per_page=100")) {
        Ok(v) if v["workflow_runs"].is_array() => v,
        _ => {
            findings.push(
                "Recent CI runs could not be read, so the declared CI policy is unverified."
                    .to_owned(),
            );
            return Report {
                findings,
                note: None,
            };
        }
    };
    let mut note = None;
    let runs = runs["workflow_runs"].as_array().expect("runs array");
    for (event, label) in [("push", "default-branch"), ("pull_request", "pull-request")] {
        let candidates: Vec<_> = runs
            .iter()
            .filter(|r| r["event"] == event && (event != "push" || r["head_branch"] == branch))
            .collect();
        let Some(&latest) = candidates
            .iter()
            .max_by_key(|r| r["created_at"].as_str().unwrap_or(""))
        else {
            findings.push(format!(
                "No recent {label} CI cycle is available to verify its declared tier."
            ));
            continue;
        };
        let Some(sha) = latest["head_sha"].as_str().filter(|s| !s.is_empty()) else {
            findings.push(format!(
                "The latest {label} CI cycle has no commit identity and cannot be verified."
            ));
            continue;
        };
        let mut workflow_ids = BTreeSet::new();
        let mut cycle: Vec<_> = candidates
            .into_iter()
            .filter(|r| r["head_sha"] == sha)
            .collect();
        // Re-runs replace earlier attempts of the same workflow, rather than duplicating shards.
        cycle.sort_by(|a, b| b["created_at"].as_str().cmp(&a["created_at"].as_str()));
        cycle.retain(|r| {
            workflow_ids.insert(
                r["workflow_id"]
                    .as_u64()
                    .unwrap_or_else(|| r["id"].as_u64().unwrap_or(0)),
            )
        });
        let mut starts = Vec::new();
        let mut incomplete = false;
        for run in &cycle {
            if run["status"] != "completed" {
                incomplete = true;
            }
            if run["conclusion"] != "success" && run["status"] == "completed" {
                findings.push(format!(
                    "A workflow in the latest {label} CI cycle did not succeed."
                ));
            }
            if let Some(start) = timestamp(&run["created_at"]) {
                starts.push(start);
            } else {
                incomplete = true;
            }
        }
        if incomplete {
            findings.push(format!("The latest {label} CI cycle is still incomplete."));
            if note.is_none() {
                note = Some(format!("Último ciclo {label}: en curso"));
            }
            continue;
        }
        let mut all_jobs = Vec::new();
        for run in &cycle {
            match run["id"]
                .as_u64()
                .ok_or("missing run identity")
                .map_err(Into::into)
                .and_then(|id| jobs(api, &base, id))
            {
                Ok(jobs) => all_jobs.extend(jobs),
                Err(_) => {
                    findings.push(format!(
                        "Jobs in the latest {label} CI cycle could not be read completely."
                    ));
                    incomplete = true;
                }
            }
        }
        if incomplete {
            if note.is_none() {
                note = Some(format!("Último ciclo {label}: en curso"));
            }
            continue;
        }
        if let Some(budget) = budget {
            cycle_budget(&all_jobs, &starts, false, budget, label, &mut findings);
        }
        let docs = if let Some(tiers) = tiers.as_ref().filter(|_| event == "pull_request") {
            match docs_only(api, &base, latest, tiers) {
                Ok(value) => value,
                Err(_) => {
                    findings.push("The latest pull request's changed files could not be read, so its CI tier is unverified.".to_owned());
                    false
                }
            }
        } else {
            false
        };
        if let Some(claim) = scope_tier(&all_jobs) {
            let expected = if event == "pull_request" && docs {
                "docs"
            } else {
                "full"
            };
            if claim != expected {
                findings.push(format!(
                    "The Scope job claims tier '{claim}' but the doctor computed '{expected}'."
                ));
            }
        }
        let event_findings_start = findings.len();
        if let Some(count) = count {
            shards(&all_jobs, count, docs, label, &mut findings);
        }
        if tiers_supported {
            lint_tier(&all_jobs, docs, label, &mut findings);
        }
        if docs
            && event == "pull_request"
            && findings.len() == event_findings_start
            && note.is_none()
        {
            note =
                Some("Último ciclo: solo documentación, sin tests de Rust (correcto)".to_owned());
        }
    }
    Report { findings, note }
}

const UNREADABLE: &str = "The default branch protection could not be read, so required checks and push restrictions are unverified.";

/// GitHub's message when `error` is a `403` naming an upgrade or a plan: the
/// plan does not allow protection on this private repository (#1164), the
/// refusal the posture rules and the merge guard recognise.
fn plan_refusal<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a str> {
    error
        .downcast_ref::<HttpError>()
        .filter(|e| e.status == 403 && names_plan(&e.message))
        .map(|e| e.message.as_str())
}

/// The finding of a plan refusal: the plan the rule needs, and that no
/// server-side barrier is left (SPEC-auditor.md, Baseline block, #1164).
fn plan_refused(message: &str) -> String {
    format!(
        "{PLAN_REFUSED_SUBJECT}requires plan Team: the plan refuses branch protection and rulesets on this private repository (HTTP 403: {}), so there is no server-side merge barrier and the session hook is the only barrier.",
        plain(message)
    )
}

/// The subject of [`plan_refused`]'s finding; without it, the finding is the
/// reason `baseline.branch-protection-matches` is unavailable.
pub const PLAN_REFUSED_SUBJECT: &str = "The default branch protection ";

fn protection(api: &dyn Api, base: &str, branch: &str, ci: &Value, findings: &mut Vec<String>) {
    let checks = ci["required_checks"].as_array();
    if !checks.is_some_and(|c| {
        !c.is_empty()
            && c.iter()
                .all(|v| v.as_str().is_some_and(profile::single_line))
    }) {
        findings.push("The project has no valid declared required CI checks.".to_owned());
    }
    let protection = match api.get(&format!("{base}/branches/{}/protection", segment(branch))) {
        Ok(v) if v.is_object() => v,
        Err(error)
            if error
                .downcast_ref::<HttpError>()
                .is_some_and(|e| e.status == 404 && e.message == "Branch not protected") =>
        {
            findings.push("Default branch is not protected.".to_owned());
            return;
        }
        Err(error) => {
            findings.push(plan_refusal(error.as_ref()).map_or(UNREADABLE.to_owned(), plan_refused));
            return;
        }
        Ok(_) => {
            findings.push(UNREADABLE.to_owned());
            return;
        }
    };
    let required: Vec<&str> = checks
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    classic(&protection, &required, findings);
}

/// Classic protection against the `required` checks: each required, force
/// pushes and deletion forbidden, administrators covered.
fn classic(protection: &Value, required: &[&str], findings: &mut Vec<String>) {
    let contexts = protection_contexts(protection);
    for check in required {
        if !contexts.contains(check) {
            findings.push(format!(
                "The default branch no longer requires CI check '{}'.",
                plain(check)
            ));
        }
    }
    for (field, description) in [
        ("allow_force_pushes", "force pushes"),
        ("allow_deletions", "branch deletion"),
    ] {
        if protection[field]["enabled"].as_bool() != Some(false) {
            findings.push(format!(
                "The default branch does not explicitly forbid {description}."
            ));
        }
    }
    if protection["enforce_admins"]["enabled"].as_bool() != Some(true) {
        findings.push("The default branch protection does not cover administrators.".to_owned());
    }
}

/// The protection of a repository with `ci-baseline` (#1109): classic
/// protection judged as ever against `required`; without it, the active rules
/// that apply to the branch must require them and forbid force pushes and
/// deletion (a ruleset's bypass actors are `posture.no-unlisted-bypass-actors`'s).
fn rendered_protection(
    api: &dyn Api,
    base: &str,
    branch: &str,
    required: &[String],
    findings: &mut Vec<String>,
) {
    let required: Vec<&str> = required.iter().map(String::as_str).collect();
    // GitHub's refusal when the plan does not allow classic protection here.
    let refused = match api.get(&format!("{base}/branches/{}/protection", segment(branch))) {
        Ok(v) if v.is_object() => return classic(&v, &required, findings),
        Err(error)
            if error
                .downcast_ref::<HttpError>()
                .is_some_and(|e| e.status == 404 && e.message == "Branch not protected") =>
        {
            None
        }
        Err(error) if plan_refusal(error.as_ref()).is_some() => Some(error),
        _ => {
            findings.push(UNREADABLE.to_owned());
            return;
        }
    };
    let refused = refused.as_ref().and_then(|e| plan_refusal(e.as_ref()));
    let rules = match api.get(&format!("{base}/rules/branches/{}", segment(branch))) {
        Ok(Value::Array(rules)) => rules,
        Err(error) if refused.is_some() && plan_refusal(error.as_ref()).is_some() => Vec::new(),
        _ => {
            findings.push(UNREADABLE.to_owned());
            return;
        }
    };
    if rules.is_empty() {
        findings.push(match refused {
            Some(message) => plan_refused(message),
            None => "Default branch is not protected.".to_owned(),
        });
        return;
    }
    let contexts = ruleset_contexts(&Value::Array(rules.clone()));
    for check in required {
        if !contexts.iter().any(|c| c == check) {
            findings.push(format!(
                "The default branch no longer requires CI check '{}'.",
                plain(check)
            ));
        }
    }
    for (rule, description) in [
        ("non_fast_forward", "force pushes"),
        ("deletion", "branch deletion"),
    ] {
        if !rules.iter().any(|r| r["type"] == rule) {
            findings.push(format!(
                "The default branch does not explicitly forbid {description}."
            ));
        }
    }
}

/// The required check names of a classic protection response: legacy
/// `contexts` plus `checks[].context`.
pub(crate) fn protection_contexts(protection: &Value) -> BTreeSet<&str> {
    profile::strings(&protection["required_status_checks"]["contexts"])
        .into_iter()
        .chain(
            protection["required_status_checks"]["checks"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v["context"].as_str()),
        )
        .collect()
}

fn jobs(api: &dyn Api, base: &str, id: u64) -> Result<Vec<Value>> {
    let mut jobs = Vec::new();
    for page in 1..=100 {
        let value = api.get(&format!(
            "{base}/actions/runs/{id}/jobs?per_page=100&page={page}"
        ))?;
        let items = value["jobs"].as_array().ok_or("invalid jobs list")?;
        let total = value["total_count"].as_u64().ok_or("missing job count")?;
        jobs.extend(items.clone());
        if jobs.len() as u64 == total {
            return Ok(jobs);
        }
        if items.len() < 100 || jobs.len() as u64 > total {
            return refuse("incomplete jobs list");
        }
    }
    refuse("jobs list exceeds observation limit")
}
fn docs_only(api: &dyn Api, base: &str, run: &Value, tiers: &Tiers<'_>) -> Result<bool> {
    let prs = run["pull_requests"]
        .as_array()
        .ok_or("missing pull request identity")?;
    if prs.len() != 1 {
        return refuse("ambiguous pull request identity");
    }
    let number = prs[0]["number"]
        .as_u64()
        .ok_or("missing pull request number")?;
    let pull_path = format!("{base}/pulls/{number}");
    let before = api.get(&pull_path)?;
    let head = before["head"]["sha"]
        .as_str()
        .ok_or("missing pull request head")?;
    let base_sha = before["base"]["sha"]
        .as_str()
        .ok_or("missing pull request base")?;
    if head.is_empty()
        || base_sha.is_empty()
        || run["head_sha"] != head
        || prs[0]["base"]["sha"]
            .as_str()
            .is_some_and(|sha| sha != base_sha)
    {
        return refuse("pull request no longer matches the CI run");
    }
    let mut count = 0;
    for page in 1..=30 {
        let value = api.get(&format!(
            "{base}/pulls/{number}/files?per_page=100&page={page}"
        ))?;
        let files = value.as_array().ok_or("invalid changed files")?;
        for file in files {
            let name = file["filename"]
                .as_str()
                .ok_or("invalid changed filename")?;
            if !tiers.inert(name)
                || file["previous_filename"]
                    .as_str()
                    .is_some_and(|s| !tiers.inert(s))
            {
                return Ok(false);
            }
            count += 1;
        }
        if files.len() < 100 {
            let after = api.get(&pull_path)?;
            if after["head"]["sha"] != head || after["base"]["sha"] != base_sha {
                return refuse("pull request moved while reading changed files");
            }
            return Ok(count > 0);
        }
    }
    // GitHub caps this endpoint at 3000 files; a truncated list cannot establish docs-only.
    refuse("changed-file list may be truncated")
}
struct Tiers<'a> {
    inert_paths: Vec<&'a str>,
    full_paths: Vec<&'a str>,
}
impl<'a> Tiers<'a> {
    fn parse(value: &'a Value) -> Option<Self> {
        if value["main"]["paths"] != serde_json::json!(["**"]) {
            return None;
        }
        let paths = |key| {
            value["pull_request"][key]
                .as_array()?
                .iter()
                .map(|v| v.as_str().filter(|s| valid_tier_path(s)))
                .collect::<Option<Vec<_>>>()
        };
        let inert_paths = paths("inert_paths")?;
        if inert_paths.is_empty() {
            return None;
        }
        Some(Self {
            inert_paths,
            full_paths: paths("full_paths")?,
        })
    }

    fn inert(&self, name: &str) -> bool {
        !self.full_paths.iter().any(|p| matches_tier_path(name, p))
            && self.inert_paths.iter().any(|p| matches_tier_path(name, p))
    }
}
fn valid_tier_path(path: &str) -> bool {
    if path == "**" {
        return true;
    }
    let path = if let Some(extension) = path.strip_prefix("*.") {
        if extension.contains('/') {
            return false;
        }
        extension
    } else {
        path
    };
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['*', '?', '\\'])
        && !path.chars().any(char::is_whitespace)
        && path
            .trim_end_matches('/')
            .split('/')
            .all(|p| !matches!(p, "" | "." | ".."))
}
fn matches_tier_path(name: &str, path: &str) -> bool {
    path == "**"
        || if let Some(extension) = path.strip_prefix('*') {
            name.ends_with(extension)
        } else if path.ends_with('/') {
            name.starts_with(path)
        } else {
            name == path
        }
}
fn timestamp(value: &Value) -> Option<i64> {
    DateTime::parse_from_rfc3339(value.as_str()?)
        .ok()
        .map(|d| d.timestamp())
}
/// The tier the Scope job claims: its `tier` output, or a step named `tier=<tier>`
/// or `Tier: <tier>` (the lines ci-baseline's scope.sh prints).
pub fn scope_tier(jobs: &[Value]) -> Option<String> {
    let job = jobs.iter().find(|j| {
        j["name"]
            .as_str()
            .is_some_and(|n| n.eq_ignore_ascii_case("scope"))
    })?;
    if let Some(tier) = job["outputs"]["tier"].as_str() {
        return Some(tier.to_owned());
    }
    job["steps"].as_array()?.iter().find_map(|s| {
        let name = s["name"].as_str()?;
        name.strip_prefix("tier=")
            .or_else(|| name.strip_prefix("Tier: "))
            .map(str::to_owned)
    })
}
fn docs_then_skipped(job: &Value, docs: bool) -> Option<bool> {
    if !docs {
        return None;
    }
    job["steps"]
        .as_array()
        .filter(|steps| !steps.is_empty())
        .map(|_| false)
}
fn cycle_budget(
    jobs: &[Value],
    starts: &[i64],
    incomplete: bool,
    budget: f64,
    label: &str,
    findings: &mut Vec<String>,
) {
    let ends: Option<Vec<_>> = jobs
        .iter()
        .filter(|j| j["conclusion"] != "skipped")
        .map(|j| timestamp(&j["completed_at"]))
        .collect();
    match (starts.iter().min(), ends.and_then(|v| v.into_iter().max())) {
        (Some(start), Some(end)) if end >= *start && !incomplete => {
            let minutes = (end - start) as f64 / 60.0;
            if minutes > budget { findings.push(format!("The latest {label} CI cycle took {minutes:.1} minutes and exceeds its {budget} minute budget.")); }
        }
        _ => findings.push(format!("The latest {label} CI cycle has incomplete timing evidence, so its cycle budget is unverified.")),
    }
}

fn executed(job: &Value, test: impl Fn(&str) -> bool) -> Option<bool> {
    if job["conclusion"] == "skipped" {
        return Some(false);
    }
    let steps: Vec<_> = job["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| s["name"].as_str().is_some_and(&test))
        .collect();
    if steps.is_empty() {
        return None;
    }
    if steps.iter().all(|s| s["conclusion"] == "skipped") {
        return Some(false);
    }
    if steps.iter().any(|s| s["conclusion"] == "success") {
        return Some(true);
    }
    None
}
fn shards(jobs: &[Value], count: u64, docs: bool, label: &str, findings: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for job in jobs {
        let name = job["name"].as_str().unwrap_or("");
        let Some(suffix) = name.split_once("shard ").map(|(_, s)| s) else {
            continue;
        };
        let pair = suffix.split_whitespace().next().unwrap_or("");
        let Some((index, total)) = pair.split_once('/') else {
            continue;
        };
        let (Ok(index), Ok(total)) = (index.parse::<u64>(), total.parse::<u64>()) else {
            continue;
        };
        if total != count || index == 0 || index > count || !seen.insert(index) {
            findings.push(format!("The latest {label} CI cycle reports shard names inconsistent with its declared count of {count}."));
        }
        let ran = executed(job, |name| {
            name.starts_with("Test ")
                || name.starts_with("cargo nextest")
                || name == "Run declared shard"
        })
        .or_else(|| docs_then_skipped(job, docs));
        if (docs && ran != Some(false)) || (!docs && ran != Some(true)) {
            findings.push(if docs { "A shard ran or lacks skip evidence in the latest documentation-only pull request.".to_owned() }
                else { format!("The shard {index}/{count} in the latest {label} CI cycle was skipped or has no test execution evidence.") });
        }
    }
    if seen.len() as u64 != count {
        findings.push(format!(
            "The latest {label} CI cycle reports {} of the {count} declared shards.",
            seen.len()
        ));
    }
}
fn lint_tier(jobs: &[Value], docs: bool, label: &str, findings: &mut Vec<String>) {
    let lint: Vec<_> = jobs
        .iter()
        .filter(|j| {
            j["name"]
                .as_str()
                .is_some_and(|s| s.to_lowercase().contains("lint"))
        })
        .collect();
    if lint.is_empty() {
        findings.push(format!(
            "The latest {label} CI cycle has no lint job to verify its tier."
        ));
    }
    for job in lint {
        let ran = executed(job, |s| {
            s.starts_with("Check lint")
                || s.starts_with("Check formatting")
                || s.starts_with("cargo clippy")
        })
        .or_else(|| docs_then_skipped(job, docs));
        if (docs && ran != Some(false)) || (!docs && ran != Some(true)) {
            findings.push(if docs {
                "Lint ran or lacks skip evidence in the latest documentation-only pull request."
                    .to_owned()
            } else {
                format!(
                    "Lint in the latest {label} CI cycle was skipped or has no execution evidence."
                )
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gh_response_keeps_http_status_and_error_message() {
        for (header, status) in [
            ("HTTP/2.0 404 Not Found", 404),
            ("HTTP/1.1 403 Forbidden", 403),
        ] {
            let response = format!(
                "{header}\r\nContent-Type: application/json\r\n\r\n{{\"message\":\"Branch not protected\"}}"
            );
            let error = decode_response(false, response.as_bytes()).unwrap_err();
            let error = error.downcast_ref::<HttpError>().unwrap();
            assert_eq!(error.status, status);
            assert_eq!(error.message, "Branch not protected");
        }
        assert_eq!(
            decode_response(
                true,
                b"HTTP/2.0 200 OK\nContent-Type: application/json\n\n{\"default_branch\":\"main\"}"
            )
            .unwrap(),
            serde_json::json!({"default_branch": "main"})
        );
        assert!(decode_response(false, b"not an HTTP response").is_err());
    }

    #[test]
    fn gh_response_with_a_text_body_reads_as_a_string() {
        // A job log: `gh` follows the redirect to the blob and prints its headers (#801).
        assert_eq!(
            decode_response(
                true,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n\u{feff}2026-10-29T20:23:15Z history: full\n".as_bytes()
            )
            .unwrap(),
            Value::String("2026-10-29T20:23:15Z history: full\n".to_owned())
        );
        assert_eq!(
            decode_response(
                true,
                b"HTTP/2.0 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\n\r\nline\n"
            )
            .unwrap(),
            Value::String("line\n".to_owned())
        );
        // JSON stays JSON; a non-JSON body without the text header stays an error.
        assert!(
            decode_response(
                true,
                b"HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\nline"
            )
            .is_err()
        );
    }

    #[test]
    fn gh_response_204_without_a_body_reads_as_null() {
        // `vulnerability-alerts` answers 204 No Content when the alerts are enabled.
        assert_eq!(
            decode_response(
                true,
                b"HTTP/2.0 204 No Content\r\nX-Github-Request-Id: x\r\n\r\n"
            )
            .unwrap(),
            Value::Null
        );
        assert!(decode_response(true, b"HTTP/2.0 200 OK\r\n\r\n").is_err());
    }

    #[test]
    fn rate_limit_headers_read_the_header_names_not_values_that_mention_them() {
        let response = b"HTTP/2.0 403 Forbidden\r\nAccess-Control-Expose-Headers: X-RateLimit-Remaining, X-RateLimit-Reset\r\nX-Ratelimit-Remaining: 0\r\nx-ratelimit-reset: 1793215725\r\n\r\n{}";
        assert_eq!(
            rate_limit_headers(response),
            Some(RateLimit {
                remaining: 0,
                reset_epoch: Some(1793215725)
            })
        );
        assert_eq!(
            rate_limit_headers(b"HTTP/2.0 200 OK\nContent-Type: application/json\n\n{}"),
            None
        );
        assert_eq!(rate_limit_headers(b"not an HTTP response"), None);
        assert_eq!(Gh::default().rate_limit(), None);
    }
}
