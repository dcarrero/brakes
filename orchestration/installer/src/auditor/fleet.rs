//! `doctor --fleet <org-or-user>` (SPEC-auditor.md, "Fleet"): lists every
//! repository of an organisation or user through the host adapter and audits
//! each one sequentially, read-only, with its own call budget and its own read
//! cache. There is no checkout: local-file rules read through the contents API
//! within the auditor's path allowlist ([`super::ContentsFiles`]). The output is
//! sorted by repository, so it does not depend on the listing order.
//!
//! `--publish-issue <owner/repo>` is the module's only write (#736): the target
//! mints a `WriteToken` before the listing, and after the audit one `POST
//! repos/{r}/issues` carries the report. A missing `fleet-audit` label is a
//! finding, never a label write; earlier issues are never updated or closed.
use super::{FLEET_CALL_BUDGET, audit_remote, report::Audited};
use crate::{
    Result,
    host::{
        CallBudget, Host, OwnerId, RepoId,
        authorize::{self, WriteToken},
        github::GitHub,
        types::NewIssue,
    },
    refuse,
    remote::{Api, Gh},
};
use chrono::NaiveDate;
use serde_json::json;
use std::{ffi::OsString, process::ExitCode};

pub const USAGE: &str = "Usage: brakes doctor --fleet <org-or-user> [--json] [--report <file.md>] [--include-archived] [--now <YYYY-MM-DD>] [--publish-issue <owner/repo>]";

/// The label the published issue carries when the target already has it.
pub const LABEL: &str = "fleet-audit";
/// GitHub's limit on an issue body, in characters.
pub const ISSUE_BODY_LIMIT: usize = 65_535;

/// The issue body for `markdown`: the report byte for byte when it fits,
/// otherwise cut on a character boundary and ending with a line that names the
/// `--report` file as the full version.
pub fn issue_body(markdown: &str, report: Option<&str>) -> String {
    if markdown.chars().count() <= ISSUE_BODY_LIMIT {
        return markdown.to_owned();
    }
    let note = match report {
        Some(path) => {
            format!("\n\nTruncated at 65 535 characters: the full report is {path}\n")
        }
        None => {
            "\n\nTruncated at 65 535 characters: pass --report <file.md> to keep the full report\n"
                .to_owned()
        }
    };
    let keep = ISSUE_BODY_LIMIT.saturating_sub(note.chars().count());
    markdown.chars().take(keep).chain(note.chars()).collect()
}

/// The issue `--publish-issue` created and what it found on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub repo: String,
    pub number: u64,
    pub url: String,
    pub findings: Vec<String>,
}

/// Reads the target's labels, then sends the one `POST repos/{r}/issues`
/// titled `Fleet audit <name> <date>` with `body`.
pub fn publish(
    api: &dyn Api,
    token: &WriteToken,
    fleet: &Fleet,
    body: String,
) -> Result<Published> {
    let host = GitHub::new(api, CallBudget::default());
    let repo = token.repo();
    let has_label = host.labels(repo)?.iter().any(|l| l.name == LABEL);
    let mut findings = Vec::new();
    if !has_label {
        findings.push(format!("label {LABEL} missing in {repo}"));
    }
    let issue = NewIssue {
        title: format!("Fleet audit {} {}", fleet.owner.name, fleet.now),
        body,
        labels: if has_label {
            vec![LABEL.to_owned()]
        } else {
            Vec::new()
        },
    };
    let created = host.create_issue(token, &issue)?;
    Ok(Published {
        repo: repo.to_string(),
        number: created.number,
        url: created
            .url
            .unwrap_or_else(|| format!("{repo}#{}", created.number)),
        findings,
    })
}

/// How a fleet is audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Audit archived repositories instead of listing them under "Not audited".
    pub include_archived: bool,
    /// Host calls each repository may spend; [`FLEET_CALL_BUDGET`] outside tests.
    pub call_budget: u32,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            include_archived: false,
            call_budget: FLEET_CALL_BUDGET,
        }
    }
}

/// A listed repository the fleet did not audit, and why. `error` is an audit
/// that failed (exit code 2), not a repository left out by choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAudited {
    pub repo: String,
    pub reason: String,
    pub error: bool,
}

/// One fleet audit: what the listing returned and the audit of each repository.
#[derive(Debug, Clone, PartialEq)]
pub struct Fleet {
    pub owner: OwnerId,
    /// The login the token reads as (`gh api user`), never the token.
    pub identity: String,
    pub now: NaiveDate,
    pub include_archived: bool,
    /// Sorted by repository.
    pub audited: Vec<Audited>,
    /// Sorted by repository.
    pub not_audited: Vec<NotAudited>,
    /// Counts the listing did not read (a stopped listing, refused identities),
    /// never their names.
    pub unread: Vec<String>,
}

impl Fleet {
    /// 0 when every repository would exit 0, otherwise the highest code among
    /// them; a repository whose audit failed counts as 2.
    pub fn exit_code(&self) -> i32 {
        let audited = self.audited.iter().map(|a| a.exit_code(true));
        let failed = self.not_audited.iter().filter(|n| n.error).map(|_| 2);
        audited.chain(failed).max().unwrap_or(0)
    }
}

/// Lists `name`'s repositories through `api` and audits each one at `now`.
/// Refused (exit 2) when the name is a denylisted identity, before any call, or
/// when the listing itself failed; a partial listing is audited and reported.
pub fn audit_fleet(api: &dyn Api, name: &str, now: NaiveDate, options: Options) -> Result<Fleet> {
    authorize::read_owner(name)?;
    let listing = GitHub::new(api, CallBudget::default());
    let owner = listing.owner(name)?;
    let listed = listing.list_repositories(&owner)?;
    let identity = api
        .get("user")
        .ok()
        .and_then(|me| me["login"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown (the token's user is not readable)".to_owned());
    let mut repositories = listed.items;
    repositories.sort_by(|a, b| a.id.cmp(&b.id));
    let mut unread = listed.unread;
    let mut audited = Vec::new();
    let mut not_audited = Vec::new();
    let mut refused = 0;
    let mut refused_word: Option<String> = None;
    for summary in &repositories {
        let repo = summary.id.to_string();
        // The host adapter already leaves them out; any host must.
        if authorize::read(&summary.id).is_err() {
            if let Ok(Some(word)) = crate::config::denied_word(&repo) {
                refused_word.get_or_insert(word);
            }
            refused += 1;
            continue;
        }
        if summary.archived && !options.include_archived {
            not_audited.push(NotAudited {
                repo,
                reason: "archived (pass --include-archived to audit it)".to_owned(),
                error: false,
            });
            continue;
        }
        let host = GitHub::new(api, CallBudget::new(options.call_budget));
        match audit_remote(
            &host,
            host.budget(),
            &summary.id,
            &summary.default_branch,
            now,
        ) {
            Ok(a) => audited.push(a),
            Err(e) => not_audited.push(NotAudited {
                repo,
                reason: format!("audit failed: {e}"),
                error: true,
            }),
        }
    }
    if refused > 0 {
        unread.push(format!(
            "{refused} repositories not audited: {} identities are refused by the read gate",
            refused_word.as_deref().unwrap_or("Denylisted")
        ));
    }
    Ok(Fleet {
        owner,
        identity,
        now,
        include_archived: options.include_archived,
        audited,
        not_audited,
        unread,
    })
}

/// `doctor --fleet` over `api`: the Markdown report on stdout (the JSON with
/// `--json`), the same Markdown written to `--report`, and the exit code.
pub fn command(args: &[&str], api: &dyn Api, today: NaiveDate) -> Result<(u8, String)> {
    let mut name = None;
    let mut json = false;
    let mut report = None;
    let mut now = None;
    let mut target = None;
    let mut options = Options::default();
    let mut args = args.iter();
    while let Some(&arg) = args.next() {
        match arg {
            "--fleet" if name.is_none() => {
                name = Some(*args.next().ok_or("--fleet needs an organisation or user")?)
            }
            "--json" => json = true,
            "--include-archived" => options.include_archived = true,
            // The fleet always reads through the host: `--remote` is implied.
            "--remote" => {}
            "--report" => report = Some(*args.next().ok_or("--report needs a file")?),
            "--publish-issue" if target.is_none() => {
                target = Some(*args.next().ok_or("--publish-issue needs an owner/repo")?)
            }
            "--now" => {
                now = Some(
                    args.next()
                        .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
                        .ok_or("--now needs a YYYY-MM-DD date")?,
                )
            }
            _ => return refuse(USAGE),
        }
    }
    let name = name.ok_or(USAGE)?;
    // The write gate runs before the listing: a refused target audits nothing.
    // `--publish-issue` is the explicit flag (decision 2026-10-28, #848).
    let token = target
        .map(|t| authorize::write(&RepoId::parse(t)?, true))
        .transpose()?;
    let fleet = audit_fleet(api, name, now.unwrap_or(today), options)?;
    let markdown = fleet.markdown();
    if let Some(path) = report {
        std::fs::write(path, &markdown)?;
    }
    let published = token
        .map(|token| publish(api, &token, &fleet, issue_body(&markdown, report)))
        .transpose()?;
    let out = if json {
        let mut value = fleet.json();
        if let Some(p) = &published {
            value["published"] =
                json!({"repo": p.repo, "number": p.number, "url": p.url, "findings": p.findings});
        }
        format!("{}\n", serde_json::to_string_pretty(&value)?)
    } else if let Some(p) = &published {
        let mut out = format!("{markdown}\n## Published\n\n{}\n", p.url);
        if !p.findings.is_empty() {
            out.push('\n');
            for finding in &p.findings {
                out.push_str(&format!("- {finding}\n"));
            }
        }
        out
    } else {
        markdown
    };
    Ok((u8::try_from(fleet.exit_code())?, out))
}

/// The entry point `main` dispatches `doctor … --fleet …` to.
pub fn cli(args: &[OsString]) -> ExitCode {
    let Some(args) = args.iter().map(|a| a.to_str()).collect::<Option<Vec<_>>>() else {
        eprintln!("REFUSED: {USAGE}");
        return ExitCode::from(2);
    };
    match command(&args, &Gh::default(), crate::today()) {
        Ok((code, out)) => {
            print!("{out}");
            ExitCode::from(code)
        }
        Err(error) => {
            eprintln!("REFUSED: {error}");
            ExitCode::from(2)
        }
    }
}
