//! `doctor --fleet` (SPEC-auditor.md "Fleet", #734): organisation and user
//! listing, pagination, archived repositories, the denylisted-identity refusal, one call
//! budget per repository, files read through the contents API, and output
//! independent of the listing order. No test calls `gh`: the fleet runs
//! `GitHub` over a recording fake transport that answers 404 to any path it
//! was not given and records every non-GET request, of which there are none
//! outside the `--publish-issue` tests (#736), which expect exactly one
//! `POST repos/{r}/issues`.
mod configured;

use brakes::{
    Result,
    auditor::{
        ContentsFiles, FLEET_CALL_BUDGET, Files,
        fleet::{Fleet, ISSUE_BODY_LIMIT, Options, audit_fleet, command, issue_body},
    },
    host::{CallBudget, RepoId, github::GitHub},
    remote::{Api, HttpError, RateLimit},
};
use chrono::NaiveDate;
use configured::{capitalised, denied};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn now() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 28).unwrap()
}
fn manifest(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

/// A recorded transport: `replies` maps a path to its status and body.
#[derive(Default)]
struct Fake {
    replies: BTreeMap<String, (u16, Value)>,
    gets: RefCell<Vec<String>>,
    sends: RefCell<Vec<String>>,
    /// The bodies of the non-GET requests, in order.
    bodies: RefCell<Vec<Value>>,
    /// The reply to `POST …/issues`; any other non-GET is refused.
    created: Option<Value>,
    /// The rate limit runs out once this many GETs were served.
    rate_after: Option<usize>,
}
impl Fake {
    /// `tests/fixtures/auditor/fleet/<name>`, plus the replies of the
    /// recordings it names under `recorded` (the example-app blocks).
    fn fixture(name: &str) -> Self {
        let read = |path: String| -> Value {
            serde_json::from_str(&fs::read_to_string(manifest(&path)).unwrap()).unwrap()
        };
        let fixture = read(format!("tests/fixtures/auditor/fleet/{name}"));
        let mut sets = vec![fixture["replies"].clone()];
        for block in fixture["recorded"].as_array().into_iter().flatten() {
            let block = block.as_str().unwrap();
            sets.push(read(format!("tests/fixtures/auditor/{block}.json"))["replies"].clone());
        }
        let mut fake = Fake::default();
        for set in sets {
            for (path, reply) in set.as_object().unwrap() {
                let status = reply["status"].as_u64().unwrap() as u16;
                fake.replies
                    .entry(path.clone())
                    .or_insert((status, reply["body"].clone()));
            }
        }
        fake
    }
    fn reply(mut self, path: &str, status: u16, body: Value) -> Self {
        self.replies.insert(path.to_owned(), (status, body));
        self
    }
    /// The listing of the user fixture, replaced by `repos`.
    fn listing(self, repos: Value) -> Self {
        self.reply(
            "user/repos?affiliation=owner&per_page=100&page=1",
            200,
            repos,
        )
    }
    fn calls(&self, prefix: &str) -> usize {
        self.gets
            .borrow()
            .iter()
            .filter(|p| p.starts_with(prefix))
            .count()
    }
}
impl Api for Fake {
    fn get(&self, path: &str) -> Result<Value> {
        self.gets.borrow_mut().push(path.to_owned());
        match self.replies.get(path) {
            Some((200, body)) => Ok(body.clone()),
            Some((status, body)) => Err(HttpError {
                status: *status,
                message: body["message"].as_str().unwrap_or("error").to_owned(),
            }
            .into()),
            None => Err(HttpError {
                status: 404,
                message: "Not Found".to_owned(),
            }
            .into()),
        }
    }
    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        self.sends.borrow_mut().push(format!("{method} {path}"));
        self.bodies
            .borrow_mut()
            .push(body.cloned().unwrap_or(Value::Null));
        match &self.created {
            Some(created) if method == "POST" && path.ends_with("/issues") => Ok(created.clone()),
            _ => Err(format!("{method} {path} refused by the fake").into()),
        }
    }
    fn rate_limit(&self) -> Option<RateLimit> {
        self.rate_after
            .filter(|after| self.gets.borrow().len() >= *after)
            .map(|_| RateLimit {
                remaining: 0,
                reset_epoch: None,
            })
    }
}

/// The fleet of `fake` with `options`, asserting that nothing but GET ran.
fn fleet(fake: &Fake, name: &str, options: Options) -> Fleet {
    let fleet = audit_fleet(fake, name, now(), options).unwrap();
    assert_eq!(*fake.sends.borrow(), Vec::<String>::new());
    fleet
}
fn user_fleet() -> (Fake, Fleet) {
    let fake = Fake::fixture("example-owner.json");
    let fleet = fleet(&fake, "example-owner", Options::default());
    (fake, fleet)
}
fn repos(fleet: &Fleet) -> Vec<&str> {
    fleet.audited.iter().map(|a| a.repo.as_str()).collect()
}
fn summary(name: &str, archived: bool) -> Value {
    json!({"full_name": name, "visibility": "private", "default_branch": "main",
        "archived": archived, "fork": false, "pushed_at": null, "language": null})
}

/// Compares `actual` with the golden file; `AUDITOR_BLESS=1` rewrites it.
fn golden(name: &str, actual: &str) {
    let path = manifest(&format!("tests/golden/auditor/{name}"));
    if std::env::var_os("AUDITOR_BLESS").is_some() {
        fs::write(&path, actual).unwrap();
    }
    let expected = fs::read_to_string(&path).unwrap();
    assert_eq!(
        actual,
        expected,
        "{} differs; review and rerun with AUDITOR_BLESS=1 when intended",
        path.display()
    );
}

// --- listing -------------------------------------------------------------------------------

#[test]
fn a_user_fleet_audits_every_readable_repository_sorted_by_name() {
    let (_, fleet) = user_fleet();
    assert_eq!(fleet.owner.name, "example-owner");
    assert_eq!(fleet.identity, "example-owner");
    assert_eq!(
        repos(&fleet),
        ["example-owner/brownfield", "example-owner/example"]
    );
}

#[test]
fn an_organisation_fleet_pages_through_the_listing() {
    let page = |first: usize, count: usize| {
        Value::Array(
            (first..first + count)
                .rev()
                .map(|i| summary(&format!("example-org/repo-{i:03}"), false))
                .collect(),
        )
    };
    let fake = Fake::default()
        .reply(
            "users/example-org",
            200,
            json!({"login": "Example-Org", "type": "Organization"}),
        )
        .reply(
            "orgs/example-org",
            200,
            json!({"login": "example-org", "public_repos": 101, "total_private_repos": 0}),
        )
        .reply("user", 200, json!({"login": "example-owner"}))
        .reply(
            "orgs/example-org/repos?type=all&per_page=100&page=1",
            200,
            page(1, 100),
        )
        .reply(
            "orgs/example-org/repos?type=all&per_page=100&page=2",
            200,
            page(101, 1),
        );
    let fleet = fleet(&fake, "example-org", Options::default());
    assert_eq!(fleet.audited.len(), 101);
    assert_eq!(fleet.audited[0].repo, "example-org/repo-001");
    assert_eq!(fleet.audited[100].repo, "example-org/repo-101");
    assert!(fleet.not_audited.is_empty() && fleet.unread.is_empty());
}

#[test]
fn archived_repositories_are_listed_under_not_audited_unless_included() {
    let (_, fleet) = user_fleet();
    assert_eq!(fleet.not_audited.len(), 1);
    assert_eq!(fleet.not_audited[0].repo, "example-owner/archived-notes");
    assert_eq!(
        fleet.not_audited[0].reason,
        "archived (pass --include-archived to audit it)"
    );
    assert!(fleet.markdown().contains(
        "- example-owner/archived-notes: archived (pass --include-archived to audit it)\n"
    ));

    let fake = Fake::fixture("example-owner.json");
    let included = fleet_with(&fake, true);
    assert_eq!(
        repos(&included),
        [
            "example-owner/archived-notes",
            "example-owner/brownfield",
            "example-owner/example"
        ]
    );
    assert!(included.not_audited.is_empty());
    // An archived repository is read at its own default branch.
    assert!(
        fake.calls(
            "repos/example-owner/archived-notes/contents/.agent-setup/project.json?ref=master"
        ) == 1
    );
}
fn fleet_with(fake: &Fake, include_archived: bool) -> Fleet {
    fleet(
        fake,
        "example-owner",
        Options {
            include_archived,
            ..Options::default()
        },
    )
}

#[test]
fn a_denylisted_repository_is_refused_unnamed_and_the_run_continues() {
    let (fake, fleet) = user_fleet();
    assert_eq!(fake.calls("repos/example-owner/example-corp-notes"), 0);
    assert_eq!(fleet.audited.len(), 2);
    assert_eq!(
        fleet.unread,
        ["1 repositories not read: Example-corp identities are refused by the read gate"]
    );
    let json = serde_json::to_string(&fleet.json()).unwrap();
    for out in [fleet.markdown(), json] {
        assert!(!out.contains("example-corp-notes"), "{out}");
        assert!(out.contains("Example-corp identities are refused"));
    }
}

#[test]
fn a_denylisted_owner_is_refused_before_any_call() {
    let word = capitalised(&denied());
    let owner = format!("{word}-Tech");
    let fake = Fake::default();
    let error = audit_fleet(&fake, &owner, now(), Options::default()).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "Remote read refused: {owner} is a {word} identity and the installer never reads one (decision 2026-10-28)"
        )
    );
    assert!(fake.gets.borrow().is_empty());
}

#[test]
fn a_listing_that_fails_is_refused() {
    let fake = Fake::default().reply("users/ghost", 404, json!({"message": "Not Found"}));
    let error = audit_fleet(&fake, "ghost", now(), Options::default()).unwrap_err();
    assert!(error.to_string().contains("owner ghost"), "{error}");
}

#[test]
fn a_partial_listing_is_audited_and_reported() {
    let fake = Fake::fixture("example-owner.json")
        .listing(Value::Array(
            (0..100)
                .map(|i| summary(&format!("example-owner/repo-{i:03}"), true))
                .collect(),
        ))
        .reply(
            "user",
            200,
            json!({"login": "example-owner", "public_repos": 150, "owned_private_repos": 0}),
        );
    // users/{u}, user and the first page are served; the second is not.
    let fake = Fake {
        rate_after: Some(3),
        ..fake
    };
    let fleet = fleet(&fake, "example-owner", Options::default());
    assert_eq!(fleet.not_audited.len(), 100);
    assert_eq!(fleet.unread.len(), 1);
    assert!(
        fleet.unread[0].starts_with("50 repositories not read"),
        "{:?}",
        fleet.unread
    );
    assert!(
        fleet
            .markdown()
            .contains(&format!("- {}\n", fleet.unread[0]))
    );
    assert_eq!(fleet.exit_code(), 0);
}

// --- per-repository audit ------------------------------------------------------------------

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn local_file_rules_read_through_the_contents_api() {
    let (fake, fleet) = user_fleet();
    assert_eq!(
        fake.calls("repos/example-owner/example/contents/.agent-setup/project.json?ref=main"),
        1,
        "each file is read once per audit"
    );
    assert_eq!(
        fake.calls("repos/example-owner/brownfield/contents/.agent-setup/project.json?ref=trunk"),
        1
    );
    let example = &fleet.audited[1];
    let rule = |id: &str| {
        example
            .audit
            .rules
            .iter()
            .find(|e| e.rule.id == id)
            .unwrap()
            .outcome
            .clone()
    };
    assert_eq!(
        rule("baseline.purpose-declared").status,
        brakes::auditor::rules::Status::Passed
    );
    assert_eq!(
        rule("governance.dependency-updates-with-cooldown").status,
        brakes::auditor::rules::Status::Passed
    );
    // The brownfield repository, never installed, is still audited.
    let brownfield = &fleet.audited[0];
    let setup = brownfield
        .audit
        .rules
        .iter()
        .find(|e| e.rule.id == "baseline.guides-installed")
        .unwrap();
    assert_eq!(setup.outcome.reason.as_deref(), Some("setup not installed"));
}

#[test]
fn contents_files_keep_the_auditor_allowlist() {
    let fake = Fake::default();
    let host = GitHub::new(&fake, CallBudget::default());
    let repo = RepoId::parse("example-owner/example").unwrap();
    let files = ContentsFiles::new(&host, &repo, "main");
    assert_eq!(
        files.read("src/main.rs").unwrap_err().to_string(),
        "Auditor file read refused: src/main.rs is outside the auditor's path allowlist"
    );
    assert_eq!(
        files.list("src").unwrap_err().to_string(),
        "Auditor listing refused: src is not one of .github/workflows, .github/ISSUE_TEMPLATE"
    );
    assert!(fake.gets.borrow().is_empty());
    assert_eq!(files.read("AGENTS.md").unwrap(), None);
    assert_eq!(
        files.list(".github/workflows").unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn each_repository_spends_its_own_budget_and_exhaustion_marks_rules_unavailable() {
    let fake = Fake::fixture("example-owner.json");
    let fleet = fleet(
        &fake,
        "example-owner",
        Options {
            call_budget: 8,
            ..Options::default()
        },
    );
    for audited in &fleet.audited {
        assert_eq!(audited.budget.limit, 8, "{}", audited.repo);
        assert_eq!(audited.budget.api_calls, 8, "{}", audited.repo);
        assert!(audited.budget.exhausted, "{}", audited.repo);
        let exhausted = audited
            .audit
            .rules
            .iter()
            .filter(|e| {
                e.outcome
                    .reason
                    .as_deref()
                    .is_some_and(|r| r.contains("budget exhausted"))
            })
            .count();
        assert!(exhausted > 0, "{}", audited.repo);
    }
    assert!(fleet.markdown().contains("8 of 8 calls, budget exhausted."));
    let (_, full) = user_fleet();
    for audited in &full.audited {
        assert_eq!(audited.budget.limit, FLEET_CALL_BUDGET);
        assert!(!audited.budget.exhausted, "{}", audited.repo);
    }
}

// --- output --------------------------------------------------------------------------------

fn organisation_fleet() -> Fleet {
    fleet(
        &Fake::fixture("example-org.json"),
        "example-org",
        Options::default(),
    )
}

/// The organisation fixture: example-app as recorded (posture, CI health, DORA),
/// a repository the installer never touched and an archived one.
#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "lists setup-core or its guides; product-boundary T7a"
)]
#[test]
fn the_report_and_json_match_the_golden_files_and_repeat_byte_for_byte() {
    let first = organisation_fleet();
    let second = organisation_fleet();
    assert_eq!(
        repos(&first),
        ["example-org/docs-site", "example-org/example-app"]
    );
    let json = |f: &Fleet| format!("{}\n", serde_json::to_string_pretty(&f.json()).unwrap());
    assert_eq!(first.markdown(), second.markdown());
    assert_eq!(json(&first), json(&second));
    golden("fleet.md", &first.markdown());
    golden("fleet.json", &json(&first));
}

#[test]
fn the_output_does_not_depend_on_the_listing_order() {
    let fake = Fake::fixture("example-owner.json");
    let mut listing = fake.replies["user/repos?affiliation=owner&per_page=100&page=1"]
        .1
        .clone();
    listing.as_array_mut().unwrap().reverse();
    let reversed = fleet(&fake.listing(listing), "example-owner", Options::default());
    let (_, fleet) = user_fleet();
    assert_eq!(reversed.markdown(), fleet.markdown());
    assert_eq!(reversed.json(), fleet.json());
}

#[test]
fn the_fleet_exits_with_the_highest_code_of_its_repositories() {
    let (_, fleet) = user_fleet();
    let codes: Vec<i32> = fleet.audited.iter().map(|a| a.exit_code(true)).collect();
    assert_eq!(fleet.exit_code(), *codes.iter().max().unwrap());
    assert_eq!(fleet.json()["exit_code"], json!(fleet.exit_code()));
}

#[test]
fn report_writes_the_markdown_printed_and_json_prints_the_fleet_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.md");
    let fake = Fake::fixture("example-owner.json");
    let (code, out) = command(
        &[
            "--fleet",
            "example-owner",
            "--report",
            path.to_str().unwrap(),
            "--now",
            "2026-10-28",
        ],
        &fake,
        NaiveDate::from_ymd_opt(2030, 1, 1).unwrap(),
    )
    .unwrap();
    let (_, fleet) = user_fleet();
    assert_eq!(out, fleet.markdown());
    assert_eq!(fs::read_to_string(&path).unwrap(), out);
    assert_eq!(i32::from(code), fleet.exit_code());

    let fake = Fake::fixture("example-owner.json");
    let (_, out) = command(
        &["--fleet", "example-owner", "--json", "--now", "2026-10-28"],
        &fake,
        now(),
    )
    .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), fleet.json());
    assert!(fake.sends.borrow().is_empty());
}

#[test]
fn command_refuses_unknown_flags_and_a_missing_name() {
    let fake = Fake::default();
    for args in [
        &["--fleet"][..],
        &["--fleet", "x", "--apply"][..],
        &["--json"][..],
    ] {
        let error = command(args, &fake, now()).unwrap_err().to_string();
        assert!(
            error.starts_with("--fleet needs") || error.starts_with("Usage: brakes doctor --fleet"),
            "{error}"
        );
    }
    assert!(fake.gets.borrow().is_empty());
}

#[test]
fn the_binary_dispatches_doctor_fleet_and_refuses_a_denylisted_owner_without_a_call() {
    let word = denied();
    let owner = format!("{word}-labs");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(["doctor", "--fleet", &owner, "--report", "unused.md"])
        .env("GH_HOST", "invalid.invalid")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!(
            "REFUSED: Remote read refused: {owner} is a {} identity and the installer never reads one (decision 2026-10-28)\n",
            capitalised(&word)
        )
    );
    assert!(!Path::new("unused.md").exists());
}

/// A repository whose Basic and Bronze rules pass on their own evidence
/// reaches Bronze under `--fleet`: the baseline rules that re-label today's
/// `doctor` are not required without a checkout (#734).
#[test]
fn a_fleet_repository_whose_rules_pass_reaches_bronze() {
    let fake = Fake::fixture("bronze.json");
    let fleet = fleet(&fake, "example-owner", Options::default());
    let audited = &fleet.audited[0];
    let open: Vec<String> = audited
        .audit
        .rules
        .iter()
        .filter(|e| e.required && e.rule.level <= brakes::auditor::rules::Level::Bronze)
        .filter(|e| {
            !matches!(
                e.outcome.status,
                brakes::auditor::rules::Status::Passed
                    | brakes::auditor::rules::Status::NotRequired
            )
        })
        .map(|e| {
            format!(
                "{} {:?} {:?} {:?}",
                e.rule.id, e.outcome.status, e.outcome.reason, e.outcome.evidence
            )
        })
        .collect();
    assert!(open.is_empty(), "{open:#?}");
    assert_eq!(
        audited.audit.reached,
        Some(brakes::auditor::rules::Level::Bronze)
    );
    let relabelled = audited
        .audit
        .rules
        .iter()
        .find(|e| e.rule.id == "baseline.profile-current")
        .unwrap();
    assert_eq!(
        relabelled.outcome.reason.as_deref(),
        Some("no checkout under --fleet")
    );
    assert_eq!(audited.exit_code(true), 0);
    assert_eq!(fleet.exit_code(), 0);
}

// --- --publish-issue (#736) ----------------------------------------------------------

const TARGET: &str = "example-owner/fleet-audits";
const LABELS: &str = "repos/example-owner/fleet-audits/labels?per_page=100&page=1";
const ISSUE_URL: &str = "https://github.com/example-owner/fleet-audits/issues/7";

/// The user fixture, plus the target's labels and the reply to the one `POST`.
fn publishing(labels: &[&str]) -> Fake {
    let labels: Vec<Value> = labels
        .iter()
        .map(|name| json!({"name": name, "color": "ededed", "description": null}))
        .collect();
    let mut fake = Fake::fixture("example-owner.json").reply(LABELS, 200, Value::Array(labels));
    fake.created = Some(
        json!({"number": 7, "title": "Fleet audit example-owner 2026-10-28",
        "state": "open", "labels": [], "html_url": ISSUE_URL}),
    );
    fake
}
fn publish(fake: &Fake, extra: &[&str]) -> Result<(u8, String)> {
    let mut args = vec!["--fleet", "example-owner", "--now", "2026-10-28"];
    args.extend_from_slice(extra);
    command(&args, fake, now())
}

#[test]
fn publish_issue_creates_one_issue_whose_body_is_the_report() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.md");
    let path = path.to_str().unwrap();
    let fake = publishing(&["bug", "fleet-audit"]);
    let (code, out) = publish(&fake, &["--report", path, "--publish-issue", TARGET]).unwrap();

    let report = fs::read_to_string(path).unwrap();
    assert_eq!(
        *fake.sends.borrow(),
        vec![format!("POST repos/{TARGET}/issues")]
    );
    let body = &fake.bodies.borrow()[0];
    assert_eq!(body["title"], "Fleet audit example-owner 2026-10-28");
    assert_eq!(body["body"].as_str().unwrap().as_bytes(), report.as_bytes());
    assert_eq!(body["labels"], json!(["fleet-audit"]));
    assert_eq!(out, format!("{report}\n## Published\n\n{ISSUE_URL}\n"));
    let (_, fleet) = user_fleet();
    assert_eq!(report, fleet.markdown());
    assert_eq!(i32::from(code), fleet.exit_code());
}

#[test]
fn a_missing_label_is_a_finding_and_never_a_label_write() {
    let fake = publishing(&["bug"]);
    let (_, out) = publish(&fake, &["--publish-issue", TARGET]).unwrap();
    assert_eq!(
        *fake.sends.borrow(),
        vec![format!("POST repos/{TARGET}/issues")]
    );
    assert_eq!(fake.bodies.borrow()[0]["labels"], json!([]));
    assert!(
        out.ends_with(&format!(
            "## Published\n\n{ISSUE_URL}\n\n- label fleet-audit missing in {TARGET}\n"
        )),
        "{out}"
    );

    let fake = publishing(&[]);
    let (_, out) = publish(&fake, &["--json", "--publish-issue", TARGET]).unwrap();
    let json: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        json["published"],
        json!({"repo": TARGET, "number": 7, "url": ISSUE_URL,
            "findings": [format!("label fleet-audit missing in {TARGET}")]})
    );
    assert_eq!(fake.sends.borrow().len(), 1);
}

#[test]
fn publish_issue_outside_the_write_scope_is_refused_before_any_call() {
    let word = denied();
    let denied_target = format!("example-owner/{word}-notes");
    let denied_sentence = format!(
        "{} repository refused, regardless of remote owner",
        capitalised(&word)
    );
    for (target, sentence) in [
        (
            "someone-else/reports",
            "Remote write refused: someone-else/reports is not in the authorized write allowlist; a new organization needs an owner decision in docs/decisions.md",
        ),
        (denied_target.as_str(), denied_sentence.as_str()),
        ("not-a-repository", "not-a-repository"),
    ] {
        let fake = publishing(&["fleet-audit"]);
        let error = publish(&fake, &["--publish-issue", target])
            .unwrap_err()
            .to_string();
        assert!(error.contains(sentence), "{error}");
        assert!(fake.gets.borrow().is_empty(), "{target}");
        assert!(fake.sends.borrow().is_empty(), "{target}");
    }
    let fake = Fake::default();
    let error = command(
        &["--fleet", "example-owner", "--publish-issue"],
        &fake,
        now(),
    )
    .unwrap_err()
    .to_string();
    assert_eq!(error, "--publish-issue needs an owner/repo");
}

#[test]
fn publish_issue_without_fleet_is_refused() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(["doctor", ".", "--publish-issue", TARGET])
        .env("GH_HOST", "invalid.invalid")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "REFUSED: --publish-issue is only available with doctor --fleet\n"
    );
}

#[test]
fn a_report_over_the_issue_body_limit_is_truncated_naming_the_report_file() {
    let short = "# Fleet audit x\n\nshort\n";
    assert_eq!(issue_body(short, Some("fleet.md")), short);

    // Multi-byte characters: the limit counts characters, not bytes.
    let long = "é".repeat(ISSUE_BODY_LIMIT + 10);
    let body = issue_body(&long, Some("/tmp/fleet.md"));
    assert_eq!(body.chars().count(), ISSUE_BODY_LIMIT);
    assert!(
        body.ends_with("\n\nTruncated at 65 535 characters: the full report is /tmp/fleet.md\n"),
        "{}",
        &body[body.len() - 100..]
    );
    assert!(long.starts_with(body.split("\n\nTruncated").next().unwrap()));

    let body = issue_body(&long, None);
    assert_eq!(body.chars().count(), ISSUE_BODY_LIMIT);
    assert!(body.ends_with(
        "\n\nTruncated at 65 535 characters: pass --report <file.md> to keep the full report\n"
    ));
}

/// Under `--fleet` the governance rules read their files through the contents
/// API, so they have a fleet allowance on top of their checkout one: on the
/// example-app fleet fixture none reports the budget exhausted (#935).
#[test]
fn governance_rules_keep_their_file_reads_under_fleet_on_example_app() {
    let fleet = organisation_fleet();
    for audited in &fleet.audited {
        let starved: Vec<String> = audited
            .audit
            .rules
            .iter()
            .filter(|e| e.rule.block == brakes::auditor::rules::Block::Governance)
            .filter_map(|e| {
                let reason = e.outcome.reason.as_deref()?;
                reason
                    .contains("exhausted")
                    .then(|| format!("{}: {reason}", e.rule.id))
            })
            .collect();
        assert!(starved.is_empty(), "{}: {starved:#?}", audited.repo);
    }
    let example_app = &fleet.audited[1];
    assert_eq!(example_app.repo, "example-org/example-app");
    assert!(example_app.budget.api_calls <= FLEET_CALL_BUDGET);
}

/// #1318: on the example-app fleet fixture the 60 calls ran out (55 spent,
/// the rest held back) and the minutes sample read 0 of 100 runs; within the
/// fleet budget no rule of any block reports the budget exhausted.
#[test]
fn no_rule_of_the_example_app_fleet_fixture_reports_the_budget_exhausted() {
    let fleet = organisation_fleet();
    let example_app = &fleet.audited[1];
    assert_eq!(example_app.repo, "example-org/example-app");
    let starved: Vec<String> = example_app
        .audit
        .rules
        .iter()
        .filter_map(|e| {
            let text = format!("{:?} {:?}", e.outcome.reason, e.outcome.evidence);
            text.contains("exhausted")
                .then(|| format!("{}: {text}", e.rule.id))
        })
        .collect();
    assert!(starved.is_empty(), "{starved:#?}");
    assert!(!example_app.budget.exhausted, "{:?}", example_app.budget);
    assert_eq!(example_app.budget.limit, FLEET_CALL_BUDGET);
}
