//! agent-guardrails T3 (#739) and T4 (#743): the module, its questions, the managed
//! paths and the three seeds against goldens, the deny-list and MCP refusals, and
//! ownership through the engine (plan, apply, seeds kept, remove). T5 (#744): the
//! module in the registry, the two registration steps, the `doctor` lines and the
//! proof that `install` and `doctor` never run `verify`, through the CLI. #872: the
//! maturity profile comes from the engine (`--profile`, recorded with the answers).
//!
//! The library fixture plans through `engine::plan` with an explicit list:
//! `setup-core`, `repo-baseline` and a stand-in `ci-baseline` that renders nothing.
//! The CLI fixture installs the real requirements.
mod configured;
mod support;
use brakes::auditor::rules::{Level, Profile};
use brakes::engine::answers::{self, Answers, AnswersFile};
use brakes::engine::{self, Context, Module, Note, Ownership, Planned, Rendered};
use brakes::modules::agent_guardrails::doctor::{DENY_UNREGISTERED, STOP_UNREGISTERED};
use brakes::modules::agent_guardrails::{
    AgentGuardrails, GUIDE_PATH, MAX_DENY_RULES, MCP_ALLOWLIST_PATH, MCP_JSON_PATH,
    OPENCODE_JSON_PATH, SETTINGS_FRAGMENT_PATH, SETTINGS_PATH, STOP_VERIFY_PATH,
    TECHNICAL_DEBT_PATH, WORKTREEINCLUDE_PATH, render_stop_hook,
};
use brakes::modules::agent_guardrails::{audit, identity};
use brakes::modules::merge_guard::{MergeGuard, hook_entry};
use brakes::modules::repo_baseline::RULESET_PATH;
use brakes::modules::repo_baseline::RepoBaseline;
use brakes::modules::{self};
use brakes::*;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
use support::SetupCore;
use tempfile::TempDir;

const VERIFY: &str = "cargo test --locked && python3 -m unittest";

struct CiBaselineStandIn;
impl Module for CiBaselineStandIn {
    fn id(&self) -> &'static str {
        "ci-baseline"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    /// The one answer agent-guardrails reads across modules (#945), with the real
    /// module's default; the real module validates it at plan time.
    fn questions(&self) -> answers::Schema {
        answers::Schema {
            questions: vec![answers::Question {
                default: Some(json!("tests/heldout")),
                ..answers::Question::new("heldout_dir", answers::Kind::String)
            }],
        }
    }
    fn render(&self, _cx: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
}

struct Fixture {
    _temp: TempDir,
    root: std::path::PathBuf,
    /// The maturity profile recorded with the answers, as `install --profile` does.
    profile: Option<&'static str>,
}
impl Fixture {
    /// A project whose profile declares `verify` (or not).
    fn new(verify: Option<&str>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir_all(root.join(".agent-setup")).unwrap();
        let mut profile = default_profile();
        profile["commands"]["verify"] = verify.map_or(Value::Null, |v| json!(v));
        fs::write(
            root.join(PROFILE),
            serde_json::to_string_pretty(&profile).unwrap() + "\n",
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            profile: None,
        }
    }
    /// A project whose agent-guardrails answers record `profile` and nothing else.
    fn profiled(verify: Option<&str>, profile: &'static str) -> Self {
        let f = Self {
            profile: Some(profile),
            ..Self::new(verify)
        };
        f.answer(json!({}));
        f
    }
    fn answer(&self, answers: Value) {
        let file = AnswersFile {
            module: "agent-guardrails".to_owned(),
            version: "1.0.0".to_owned(),
            profile: self.profile.map(str::to_owned),
            answers: serde_json::from_value(answers).unwrap(),
        };
        let path = self.root.join(answers::path("agent-guardrails"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, file.to_json_string().unwrap()).unwrap();
    }
    fn plan(&self, module: &AgentGuardrails) -> Result<Planned> {
        let profile = profile_for(&self.root)?;
        let (core, baseline, ci) = (SetupCore, RepoBaseline, CiBaselineStandIn);
        engine::plan(
            &self.root,
            &Source::embedded(),
            &profile,
            &[&core, &baseline, &ci, module],
            &|_| true,
        )
    }
    fn apply(&self, module: &AgentGuardrails) -> Planned {
        let planned = self.plan(module).unwrap();
        apply(&self.root, &planned.changes).unwrap();
        planned
    }
    fn remove(&self, module: &AgentGuardrails) -> Result<Planned> {
        let (core, baseline, ci) = (SetupCore, RepoBaseline, CiBaselineStandIn);
        engine::remove(
            &self.root,
            &[&core, &baseline, &ci, module],
            &|_| true,
            "agent-guardrails",
        )
    }
    fn write(&self, name: &str, content: &str) {
        let path = self.root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap()
    }
}

/// The paths this module owns in a plan, with their rendered content.
fn owned(planned: &Planned) -> Vec<(String, String)> {
    planned
        .tags
        .iter()
        .filter(|(_, (_, module))| module == "agent-guardrails")
        .map(|(path, _)| {
            let content = planned.changes[path].clone().expect("written, not deleted");
            (path.clone(), content)
        })
        .collect()
}

fn fragment(planned: &Planned) -> Value {
    serde_json::from_str(planned.changes[SETTINGS_FRAGMENT_PATH].as_deref().unwrap()).unwrap()
}

fn deny(planned: &Planned) -> Vec<String> {
    serde_json::from_value(fragment(planned)["permissions"]["deny"].clone()).unwrap()
}

/// The spec's deny list (SPEC-agent-guardrails.md, "Deny rules"), in its order.
fn spec_deny() -> Vec<String> {
    [
        "Read(//**/.env)",
        "Read(//**/.env.local)",
        "Read(//**/.env.development)",
        "Read(//**/.env.production)",
        "Read(//**/.env.test)",
        "Read(//**/.env.staging)",
        "Read(//**/secrets/**)",
        "Read(//**/*.pem)",
        "Read(//**/*.key)",
        "Read(//**/*.p12)",
        "Read(//**/id_rsa*)",
        "Read(//**/id_ed25519*)",
        "Read(//**/local.properties)",
        "Read(//**/keystore.properties)",
        "Edit(//**/.env)",
        "Edit(//**/.env.local)",
        "Edit(//**/secrets/**)",
        "Edit(//**/.agent-setup/lock.json)",
        // In every profile (owner, 2026-10-29; #945): ci-baseline's `heldout_dir`,
        // unreadable too since the 7 November scope (#982).
        "Edit(//**/tests/heldout/**)",
        "Read(//**/tests/heldout/**)",
    ]
    .map(str::to_owned)
    .to_vec()
}

// ---- the module -----------------------------------------------------------------

#[test]
fn module_is_registered_before_ci_baseline_with_its_requirements() {
    let module = AgentGuardrails;
    assert_eq!(module.id(), "agent-guardrails");
    assert_eq!(module.version(), "1.0.0");
    assert_eq!(
        modules::find("agent-guardrails").map(|m| m.version()),
        Some("1.0.0")
    );
    let ids: Vec<&str> = modules::all().iter().map(|m| m.id()).collect();
    assert_eq!(
        ids,
        crate::support::with_core(&[
            "stack-packs",
            "merge-guard",
            "repo-baseline",
            "agent-guardrails",
            "security",
            "qa",
            "ci-baseline"
        ])
    );
    assert_eq!(module.requires(), &["repo-baseline", "ci-baseline"]);
}

#[test]
fn questions_follow_the_spec_data_model() {
    let p1 = AgentGuardrails.questions();
    p1.check("agent-guardrails").unwrap();
    let ids: Vec<&str> = p1.questions.iter().map(|q| q.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "stop_verify",
            "verify_timeout",
            "protected_paths",
            "secret_paths",
            "spec_dir",
            "review_family",
            "review_blocking",
            "review_environment",
            "unattended",
            "unattended_label",
            "unattended_prompt",
            "unattended_max_turns",
            "agent_environments",
            "agent_app_slug",
            "mcp_servers",
            "mcp_custom.*.purpose",
            "mcp_custom.*.permissions",
            "mcp_custom.*.transport",
            "mcp_custom.*.command",
            "mcp_custom.*.args",
            "mcp_custom.*.url",
        ]
    );
    let resolved = p1
        .validate("agent-guardrails", &Default::default(), "P1")
        .unwrap();
    assert_eq!(
        Value::Object(resolved.into_iter().collect()),
        json!({
            "stop_verify": true,
            "verify_timeout": 600,
            "protected_paths": [".agent-setup/lock.json", "<heldout_dir>/**"],
            "secret_paths": [],
            "review_family": "codex",
            "review_blocking": "p0-p1",
            "unattended": false,
            "agent_environments": [],
            "mcp_servers": [],
        })
    );
    let protected = p1.question("protected_paths").unwrap();
    assert_eq!(
        protected.default_for("P1"),
        Some(json!([".agent-setup/lock.json", "<heldout_dir>/**"]))
    );
    for tier in ["P2", "P3"] {
        assert_eq!(
            protected.default_for(tier),
            Some(json!([
                ".agent-setup/lock.json",
                "<heldout_dir>/**",
                ".github/workflows/**"
            ])),
            "{tier}"
        );
    }
}

#[test]
fn answers_outside_the_subset_refuse_by_rule() {
    let schema = AgentGuardrails.questions();
    let refuse = |answers: Value| {
        schema
            .validate(
                "agent-guardrails",
                &serde_json::from_value(answers).unwrap(),
                "P1",
            )
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        refuse(json!({"verify_timeout": 10})),
        "Module agent-guardrails: answer `verify_timeout` must be at least 30"
    );
    assert_eq!(
        refuse(json!({"verify_timeout": 3601})),
        "Module agent-guardrails: answer `verify_timeout` must be at most 3600"
    );
    assert_eq!(
        refuse(json!({"mcp_servers": ["playwright"]})),
        "Module agent-guardrails: answer `mcp_servers` item 1 must be one of: docs"
    );
    assert_eq!(
        refuse(json!({"agent_environments": ["vm"]})),
        "Module agent-guardrails: answer `agent_environments` item 1 must be one of: copilot, codex, devcontainer"
    );
}

// ---- goldens --------------------------------------------------------------------

/// Compares every owned path with `tests/golden/agent-guardrails/<case>/<path>`;
/// `UPDATE_GOLDENS=1` rewrites them.
fn assert_golden(case: &str, planned: &Planned) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/agent-guardrails")
        .join(case);
    let rendered = owned(planned);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        let _ = fs::remove_dir_all(&dir);
        for (path, content) in &rendered {
            let file = dir.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, content).unwrap();
        }
    }
    let mut expected: Vec<String> = Vec::new();
    collect(&dir, &dir, &mut expected);
    expected.sort();
    let paths: Vec<&String> = rendered.iter().map(|(path, _)| path).collect();
    assert_eq!(paths, expected.iter().collect::<Vec<_>>(), "{case}: paths");
    for (path, content) in &rendered {
        let golden = fs::read_to_string(dir.join(path)).unwrap();
        assert_eq!(content, &golden, "{case}: {path} drifted from its golden");
    }
}

fn collect(base: &Path, dir: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(base, &path, out);
        } else {
            let relative = path.strip_prefix(base).unwrap();
            out.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn golden_case(case: &str, f: Fixture, answers: Option<Value>) {
    if let Some(answers) = answers {
        f.answer(answers);
    }
    let first = f.plan(&AgentGuardrails).unwrap();
    let second = f.plan(&AgentGuardrails).unwrap();
    assert_eq!(owned(&first), owned(&second), "{case}: not deterministic");
    assert_golden(case, &first);
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn golden_p1_defaults() {
    golden_case("p1-defaults", Fixture::new(Some(VERIFY)), None);
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn golden_p2_defaults() {
    golden_case("p2-defaults", Fixture::profiled(Some(VERIFY), "P2"), None);
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn golden_p3_defaults() {
    golden_case("p3-defaults", Fixture::profiled(Some(VERIFY), "P3"), None);
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn golden_p1_stop_verify_false() {
    let answers = json!({"stop_verify": false});
    golden_case(
        "p1-stop-verify-false",
        Fixture::new(Some(VERIFY)),
        Some(answers),
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn golden_p1_docs() {
    let answers = json!({"mcp_servers": ["docs"]});
    golden_case("p1-docs", Fixture::new(Some(VERIFY)), Some(answers));
}

/// The spec's golden: the catalogue server plus a custom `read-write` one.
#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn golden_p1_docs_and_custom_read_write() {
    let answers = json!({
        "mcp_servers": ["docs"],
        "mcp_custom.tracker.transport": "http",
        "mcp_custom.tracker.url": "https://tracker.example/mcp",
        "mcp_custom.tracker.permissions": "read-write",
        "mcp_custom.tracker.purpose": "File bugs in the in-house tracker, which has no CLI or API",
        "mcp_custom.browser.transport": "stdio",
        "mcp_custom.browser.command": "npx",
        "mcp_custom.browser.args": ["-y", "@playwright/mcp@0.0.41"],
        "mcp_custom.browser.purpose": "Drive the local web app in a browser",
    });
    golden_case(
        "p1-docs-custom-read-write",
        Fixture::new(Some(VERIFY)),
        Some(answers),
    );
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn golden_no_verify_declared() {
    golden_case("no-verify", Fixture::new(None), None);
}

// ---- the fragment ---------------------------------------------------------------

#[test]
fn p1_fragment_is_exactly_the_spec_deny_list_and_the_stop_entry() {
    let planned = Fixture::new(Some(VERIFY)).plan(&AgentGuardrails).unwrap();
    assert_eq!(
        fragment(&planned),
        json!({
            "permissions": { "deny": spec_deny() },
            "hooks": { "Stop": [ { "hooks": [ {
                "type": "command",
                "command": "sh \"$CLAUDE_PROJECT_DIR/.claude/hooks/stop_verify.sh\"",
                "timeout": 630,
                "statusMessage": "Running verify"
            } ] } ] }
        })
    );
    let deny = deny(&planned);
    assert!(!deny.iter().any(|rule| rule.contains(".env.example")
        || rule.contains(".env.template")
        || rule.contains(".env.*")));
}

/// A session reaches files outside its own directory, such as a git worktree
/// beside the main checkout (#1309): Claude Code reads `./path` against the
/// current directory and `//path` from the filesystem root, so every secret
/// rule is anchored at `//**/` (https://code.claude.com/docs/en/permissions#how-path-patterns-match:
/// `Read(//**/.env)` blocks "any `.env` anywhere on the filesystem"). `Write(path)`
/// rules never match there; the `Read` and `Edit` rules cover the Write tool.
#[test]
fn every_deny_rule_holds_anywhere_on_the_filesystem_and_no_write_rule_is_rendered() {
    for tier in ["P1", "P2", "P3"] {
        let f = Fixture::profiled(Some(VERIFY), tier);
        f.answer(json!({"secret_paths": ["config/.env.ci"], "spec_dir": "docs/specs"}));
        let deny = deny(&f.plan(&AgentGuardrails).unwrap());
        for name in [
            ".env",
            ".env.local",
            ".env.development",
            ".env.production",
            ".env.test",
            ".env.staging",
            "secrets/**",
            "*.pem",
            "*.key",
            "*.p12",
            "id_rsa*",
            "id_ed25519*",
            "local.properties",
            "keystore.properties",
            "config/.env.ci",
        ] {
            let rule = format!("Read(//**/{name})");
            assert!(deny.contains(&rule), "{tier}: {rule}");
            assert!(
                !deny.contains(&format!("Read(./**/{name})"))
                    && !deny.contains(&format!("Read(./{name})")),
                "{tier}: {name} anchored at the session directory"
            );
        }
        for name in [".env", ".env.local", "secrets/**", "config/.env.ci"] {
            assert!(
                deny.contains(&format!("Edit(//**/{name})")),
                "{tier}: {name}"
            );
        }
        assert!(
            !deny.iter().any(|rule| rule.starts_with("Write(")),
            "{tier}"
        );
        // Nor any other rule (#1314): the lock, the protected paths and the
        // held-out directory hold in a sibling worktree too.
        assert!(
            deny.iter().all(|rule| rule.contains("(//**/")),
            "{tier}: {deny:?}"
        );
    }
}

#[test]
fn p2_and_p3_add_the_workflows_and_nothing_else() {
    for tier in ["P2", "P3"] {
        let planned = Fixture::profiled(Some(VERIFY), tier)
            .plan(&AgentGuardrails)
            .unwrap();
        let mut expected = spec_deny();
        expected.push("Edit(//**/.github/workflows/**)".to_owned());
        assert_eq!(deny(&planned), expected, "{tier}");
        // Twenty-one defaults since the held-out `Read` entry (#982); the cap of
        // 25 leaves room for two secret paths, two rules each (spec, the fragment).
        assert_eq!(expected.len(), 21, "{tier}");
        assert_eq!(MAX_DENY_RULES, 25, "{tier}");
        let fragment = fragment(&planned);
        for key in ["allow", "defaultMode"] {
            assert!(fragment["permissions"].get(key).is_none(), "{key}");
        }
        assert!(fragment.get("sandbox").is_none());
    }
}

#[test]
fn stop_timeout_is_verify_timeout_plus_thirty_and_baked_into_the_hook() {
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({"verify_timeout": 45}));
    let planned = f.plan(&AgentGuardrails).unwrap();
    assert_eq!(
        fragment(&planned)["hooks"]["Stop"][0]["hooks"][0]["timeout"],
        75
    );
    assert_eq!(
        planned.changes[STOP_VERIFY_PATH].as_deref().unwrap(),
        render_stop_hook(Some(VERIFY), 45)
    );
}

#[test]
fn stop_verify_false_renders_no_hook_and_no_stop_entry() {
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({"stop_verify": false}));
    let planned = f.plan(&AgentGuardrails).unwrap();
    assert!(!planned.changes.contains_key(STOP_VERIFY_PATH));
    assert!(fragment(&planned).get("hooks").is_none());
    assert_eq!(deny(&planned), spec_deny());
}

/// The room the cap leaves (spec, the fragment; #965, #982): two `secret_paths`
/// entries fit in every profile, a third does not, and the refusal names the cap.
#[test]
fn two_secret_paths_fit_in_every_profile_and_a_third_refuses_with_the_cap() {
    assert_eq!(spec_deny().len(), 20, "P1 defaults");
    for (tier, defaults) in [("P1", 20), ("P2", 21), ("P3", 21)] {
        let f = Fixture::profiled(Some(VERIFY), tier);
        f.answer(json!({"secret_paths": ["config/.env.ci", "ops/vault.json"]}));
        let deny = deny(&f.plan(&AgentGuardrails).unwrap());
        assert_eq!(deny.len(), defaults + 4, "{tier}");
        assert!(deny.len() <= MAX_DENY_RULES, "{tier}: {}", deny.len());
        let f = Fixture::profiled(Some(VERIFY), tier);
        f.answer(json!({"secret_paths": ["config/.env.ci", "ops/vault.json", "ops/.npmrc"]}));
        assert_eq!(
            f.plan(&AgentGuardrails).unwrap_err().to_string(),
            format!(
                "Module agent-guardrails: the deny list would have {} entries; at most 25 are allowed",
                defaults + 6
            ),
            "{tier}"
        );
    }
}

#[test]
fn secret_paths_add_a_read_and_an_edit_each() {
    use brakes::modules::agent_guardrails::deny_rules;
    let answers = Answers::from([("secret_paths".to_owned(), json!(["config/.env.ci"]))]);
    let mut expected = spec_deny();
    expected.push("Read(//**/config/.env.ci)".to_owned());
    expected.push("Edit(//**/config/.env.ci)".to_owned());
    assert_eq!(deny_rules(&answers, "tests/heldout").unwrap(), expected);
}

#[test]
fn a_path_leaving_the_repository_refuses_naming_the_entry() {
    for (id, entry) in [
        ("protected_paths", "../other/repo/**"),
        ("protected_paths", "docs/../../x"),
        ("secret_paths", "/etc/passwd"),
    ] {
        let f = Fixture::new(Some(VERIFY));
        f.answer(json!({ id: [entry] }));
        let error = f.plan(&AgentGuardrails).unwrap_err().to_string();
        assert_eq!(
            error,
            format!("Module agent-guardrails: {id} entry `{entry}` leaves the repository")
        );
    }
}

#[test]
fn more_than_twenty_five_deny_entries_refuse() {
    let f = Fixture::new(Some(VERIFY));
    // 20 P1 entries + 2 per secret path + 1 per protected path: 20 + 4 + 2 = 26.
    f.answer(json!({
        "secret_paths": ["a.secret", "b.secret"],
        "protected_paths": ["docs/adr/**", "docs/specs/**"]
    }));
    let error = f.plan(&AgentGuardrails).unwrap_err().to_string();
    assert_eq!(
        error,
        "Module agent-guardrails: the deny list would have 26 entries; at most 25 are allowed"
    );
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({
        "secret_paths": ["a.secret", "b.secret"],
        "protected_paths": [".agent-setup/lock.json", "<heldout_dir>/**", "docs/adr/**"]
    }));
    assert_eq!(deny(&f.plan(&AgentGuardrails).unwrap()).len(), 25);
}

#[test]
fn in_p2_and_p3_two_secret_paths_fill_the_cap_and_a_twenty_sixth_entry_refuses() {
    for tier in ["P2", "P3"] {
        let f = Fixture::profiled(Some(VERIFY), tier);
        f.answer(json!({"secret_paths": ["config/.env.ci", "deploy/credentials.json"]}));
        let mut expected = spec_deny();
        expected.push("Edit(//**/.github/workflows/**)".to_owned());
        for path in ["config/.env.ci", "deploy/credentials.json"] {
            expected.push(format!("Read(//**/{path})"));
            expected.push(format!("Edit(//**/{path})"));
        }
        assert_eq!(deny(&f.plan(&AgentGuardrails).unwrap()), expected, "{tier}");
        assert_eq!(expected.len(), 25, "{tier}");

        let f = Fixture::profiled(Some(VERIFY), tier);
        f.answer(json!({
            "secret_paths": ["config/.env.ci", "deploy/credentials.json"],
            "protected_paths": [".github/workflows/**", "docs/adr/**"]
        }));
        assert_eq!(
            f.plan(&AgentGuardrails).unwrap_err().to_string(),
            "Module agent-guardrails: the deny list would have 26 entries; at most 25 are allowed",
            "{tier}"
        );
    }
}

// ---- #945: the held-out directory, denied to agents in every profile ----------

/// Records ci-baseline's answers, as `configure ci-baseline` does.
fn answer_ci_baseline(f: &Fixture, answers: Value) {
    let file = AnswersFile {
        module: "ci-baseline".to_owned(),
        version: "0.0.0".to_owned(),
        profile: None,
        answers: serde_json::from_value(answers).unwrap(),
    };
    let path = f.root.join(answers::path("ci-baseline"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, file.to_json_string().unwrap()).unwrap();
}

#[test]
fn the_heldout_entry_follows_ci_baselines_heldout_dir_once() {
    for tier in ["P1", "P2", "P3"] {
        let f = Fixture::profiled(Some(VERIFY), tier);
        answer_ci_baseline(&f, json!({"heldout_dir": "./qa/held-out/"}));
        let deny = deny(&f.plan(&AgentGuardrails).unwrap());
        let heldout: Vec<&String> = deny.iter().filter(|r| r.contains("held")).collect();
        assert_eq!(
            heldout,
            ["Edit(//**/qa/held-out/**)", "Read(//**/qa/held-out/**)"],
            "{tier}"
        );
        assert_eq!(
            deny[18], "Edit(//**/qa/held-out/**)",
            "{tier}: after the lock"
        );
        assert_eq!(
            deny[19], "Read(//**/qa/held-out/**)",
            "{tier}: beside the Edit"
        );
    }
}

#[test]
fn the_heldout_entry_stays_when_protected_paths_omit_it() {
    let f = Fixture::profiled(Some(VERIFY), "P2");
    f.answer(json!({"protected_paths": [".github/workflows/**"]}));
    let deny = deny(&f.plan(&AgentGuardrails).unwrap());
    for entry in ["Edit(//**/tests/heldout/**)", "Read(//**/tests/heldout/**)"] {
        assert!(deny.contains(&entry.to_owned()), "{entry}: {deny:?}");
    }
}

#[test]
fn a_heldout_dir_outside_the_repository_refuses_with_ci_baselines_message() {
    let f = Fixture::new(Some(VERIFY));
    answer_ci_baseline(&f, json!({"heldout_dir": "../elsewhere"}));
    assert_eq!(
        f.plan(&AgentGuardrails).unwrap_err().to_string(),
        "ci-baseline: heldout_dir ../elsewhere is not a relative path inside the repository"
    );
}

// ---- ownership through the engine ----------------------------------------------

#[test]
fn plan_tags_the_managed_paths_and_seeds_and_a_second_plan_is_empty() {
    let f = Fixture::new(Some(VERIFY));
    let module = AgentGuardrails;
    let planned = f.apply(&module);
    for path in MANAGED {
        assert_eq!(
            planned.tags[path],
            (Ownership::Managed, "agent-guardrails".to_owned()),
            "{path}"
        );
    }
    for path in SEEDS {
        assert_eq!(
            planned.tags[path],
            (Ownership::Seed, "agent-guardrails".to_owned()),
            "{path}"
        );
        assert!(f.root.join(path).is_file(), "{path} seeded");
    }
    // The PR template and its definition-of-done block are repo-baseline's (#703).
    assert_eq!(
        planned.tags[".github/pull_request_template.md"],
        (Ownership::ManagedBlock, "repo-baseline".to_owned())
    );
    assert!(f.read(GUIDE_PATH).contains("\nLast verified: "));
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    assert_eq!(lock["modules"]["agent-guardrails"]["version"], "1.0.0");
    let after = f.plan(&module).unwrap();
    assert!(after.changes.is_empty(), "{:?}", after.changes.keys());
}

#[test]
fn an_edited_hook_or_fragment_refuses_as_managed_content() {
    for path in [STOP_VERIFY_PATH, SETTINGS_FRAGMENT_PATH] {
        let f = Fixture::new(Some(VERIFY));
        let module = AgentGuardrails;
        f.apply(&module);
        fs::write(f.root.join(path), f.read(path) + "\n# local edit\n").unwrap();
        assert_eq!(
            f.plan(&module).unwrap_err().to_string(),
            format!("Locally changed or missing managed content: {path}")
        );
    }
}

#[test]
fn a_changed_verify_rewrites_the_hook() {
    let f = Fixture::new(Some(VERIFY));
    let module = AgentGuardrails;
    f.apply(&module);
    let mut profile: Value = serde_json::from_str(&f.read(PROFILE)).unwrap();
    profile["commands"]["verify"] = json!("make check");
    fs::write(f.root.join(PROFILE), profile.to_string()).unwrap();
    let planned = f.plan(&module).unwrap();
    assert!(!planned.changes.contains_key(SETTINGS_FRAGMENT_PATH));
    assert!(
        planned.changes[STOP_VERIFY_PATH]
            .as_deref()
            .unwrap()
            .contains("\nmake check\n")
    );
}

// ---- T4 (#743): the seeds and the MCP allowlist -----------------------------------

const MANAGED: [&str; 4] = [
    STOP_VERIFY_PATH,
    SETTINGS_FRAGMENT_PATH,
    GUIDE_PATH,
    MCP_ALLOWLIST_PATH,
];
const SEEDS: [&str; 3] = [MCP_JSON_PATH, WORKTREEINCLUDE_PATH, TECHNICAL_DEBT_PATH];

/// The plan line `main.rs` prints for a reported path: `SKIP <path> [seed:<module>]`.
fn note_line(planned: &Planned, path: &str) -> String {
    let (class, module) = &planned.tags[path];
    format!("{} {path} [{class}:{module}]", planned.notes[path])
}

fn json_at(planned: &Planned, path: &str) -> Value {
    serde_json::from_str(planned.changes[path].as_deref().unwrap()).unwrap()
}

#[test]
fn defaults_seed_an_empty_mcp_json_and_an_empty_allowlist() {
    let planned = Fixture::new(Some(VERIFY)).plan(&AgentGuardrails).unwrap();
    assert_eq!(json_at(&planned, MCP_JSON_PATH), json!({"mcpServers": {}}));
    assert_eq!(
        json_at(&planned, MCP_ALLOWLIST_PATH),
        json!({"schema": 1, "servers": []})
    );
}

#[test]
fn the_catalogue_is_docs_alone_pinned_and_hosted_tools_are_not_offered() {
    // Agents reach GitHub and Sentry through their CLI or API (docs/decisions.md,
    // 2026-10-28, #743): neither is a catalogue server.
    assert_eq!(brakes::modules::agent_guardrails::mcp::CATALOGUE, ["docs"]);
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({"mcp_servers": ["docs"]}));
    let planned = f.plan(&AgentGuardrails).unwrap();
    // Stdio servers run an exact pinned version, and the allowlist matches that form.
    assert_eq!(
        json_at(&planned, MCP_ALLOWLIST_PATH),
        json!({"schema": 1, "servers": [{
            "name": "docs",
            "purpose": "Library documentation lookup",
            "permissions": "read-only",
            "transport": "stdio",
            "match": {"command_in": ["npx"], "args_contains": "@upstash/context7-mcp@4.4.4"}
        }]})
    );
    assert_eq!(
        json_at(&planned, MCP_JSON_PATH),
        json!({"mcpServers": {"docs": {"command": "npx", "args": ["-y", "@upstash/context7-mcp@4.4.4"]}}})
    );
    for path in [MCP_JSON_PATH, MCP_ALLOWLIST_PATH] {
        let raw = planned.changes[path].as_deref().unwrap();
        for gone in [
            "githubcopilot",
            "sentry",
            "requires_header",
            "requires_query",
        ] {
            assert!(!raw.contains(gone), "{path} mentions {gone}");
        }
    }
}

/// Every string under a key that names a credential, anywhere in `value`.
fn credential_values<'a>(value: &'a Value, key: &str, out: &mut Vec<(String, &'a str)>) {
    let secretish = ["auth", "token", "key", "secret", "password", "pat"];
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                credential_values(v, k, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| credential_values(v, key, out)),
        Value::String(s) => {
            let lower = key.to_ascii_lowercase();
            if secretish.iter().any(|w| lower.contains(w)) {
                out.push((key.to_owned(), s));
            }
        }
        _ => {}
    }
}

#[test]
fn rendered_mcp_files_carry_no_credential_value() {
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({"mcp_servers": ["docs"]}));
    let planned = f.plan(&AgentGuardrails).unwrap();
    let mut found = Vec::new();
    for path in [MCP_JSON_PATH, MCP_ALLOWLIST_PATH] {
        let value = json_at(&planned, path);
        let mut fields = Vec::new();
        credential_values(&value, "", &mut fields);
        for (key, text) in fields {
            found.push(key.clone());
            assert!(
                text.contains("${"),
                "{path}: `{key}` must be a ${{ENV}} reference, found `{text}`"
            );
        }
        let raw = planned.changes[path].as_deref().unwrap();
        for prefix in ["ghp_", "github_pat_", "sntrys_", "ctx7sk"] {
            assert!(!raw.contains(prefix), "{path} carries a token-shaped value");
        }
    }
    assert!(
        found.is_empty(),
        "the catalogue renders no credential field: {found:?}"
    );
}

#[test]
fn an_unknown_mcp_server_refuses_naming_it() {
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({"mcp_servers": ["docs", "github-readonly"]}));
    let error = f.plan(&AgentGuardrails).unwrap_err().to_string();
    assert!(
        error.contains("`mcp_servers`") && error.contains("item 2"),
        "{error}"
    );
    assert!(error.starts_with("Module agent-guardrails: "), "{error}");
    // The catalogue lookup refuses on its own too, naming the server, for a caller
    // that bypasses the answers validator.
    let answers = serde_json::from_value(json!({"mcp_servers": ["sentry-readonly"]})).unwrap();
    assert_eq!(
        brakes::modules::agent_guardrails::mcp::allowlist(&answers)
            .unwrap_err()
            .to_string(),
        "Module agent-guardrails: mcp_servers entry `sentry-readonly` is not in the read-only catalogue (docs)"
    );
}

#[test]
fn worktreeinclude_lists_no_secret() {
    let planned = Fixture::new(Some(VERIFY)).plan(&AgentGuardrails).unwrap();
    let text = planned.changes[WORKTREEINCLUDE_PATH].as_deref().unwrap();
    let entries: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    for entry in entries {
        assert!(
            !entry.contains(".env") && !entry.starts_with("secrets"),
            "{entry}"
        );
    }
    assert!(text.contains(".gitignore"), "explains the syntax");
}

#[test]
fn technical_debt_seed_has_the_spec_sections() {
    let planned = Fixture::new(Some(VERIFY)).plan(&AgentGuardrails).unwrap();
    let text = planned.changes[TECHNICAL_DEBT_PATH].as_deref().unwrap();
    for heading in [
        "## Patterns not to imitate",
        "## Commands that work inside the container",
        "## Shortcuts with an expiry",
    ] {
        assert!(text.contains(heading), "{heading}");
    }
    for column in ["Where", "Why", "Instead", "Retiring issue", "Expires"] {
        assert!(text.contains(column), "{column}");
    }
    assert!(text.contains("None yet (2026-10-28)."), "a dated none yet");
}

#[test]
fn a_fresh_install_passes_guides_verified_with_the_seed() {
    // #1107: the seed sits under docs/agent-setup/, so setup-core's guide check
    // reads it right after install; it carries the guides' `Last verified` line.
    let repo = Repo::new("cargo test --locked");
    let out = repo.install(&["--apply"]);
    assert!(out.status.success(), "{out:?}");
    let doctor = repo.doctor();
    assert!(
        !doctor
            .iter()
            .any(|l| l.contains("technical-debt.md") && l.contains("verif")),
        "{doctor:#?}"
    );
    let seed = fs::read_to_string(repo.root.join(TECHNICAL_DEBT_PATH)).unwrap();
    assert!(brakes::last_verified(&seed).is_some(), "{seed}");
}

#[test]
fn existing_seeds_are_kept_and_reported_and_a_second_run_has_no_changes() {
    let f = Fixture::new(Some(VERIFY));
    let local = [
        (
            MCP_JSON_PATH,
            "{\"mcpServers\": {\"mine\": {\"command\": \"x\"}}}\n",
        ),
        (WORKTREEINCLUDE_PATH, "build/local.cfg\n"),
        (TECHNICAL_DEBT_PATH, "# Our debt\n"),
    ];
    for (path, content) in local {
        f.write(path, content);
    }
    let module = AgentGuardrails;
    let planned = f.apply(&module);
    for (path, content) in local {
        assert!(!planned.changes.contains_key(path), "{path}");
        assert_eq!(planned.notes[path], Note::Skip, "{path}");
        assert_eq!(
            note_line(&planned, path),
            format!("SKIP {path} [seed:agent-guardrails]")
        );
        assert_eq!(f.read(path), content, "{path} untouched");
    }
    assert!(planned.changes.contains_key(MCP_ALLOWLIST_PATH));
    let again = f.plan(&module).unwrap();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
    assert_eq!(f.read(MCP_JSON_PATH), local[0].1);
}

#[test]
fn an_edited_allowlist_refuses_as_managed_content() {
    let f = Fixture::new(Some(VERIFY));
    let module = AgentGuardrails;
    f.apply(&module);
    f.write(
        MCP_ALLOWLIST_PATH,
        "{\"schema\": 1, \"servers\": [{\"name\": \"mine\"}]}\n",
    );
    assert_eq!(
        f.plan(&module).unwrap_err().to_string(),
        format!("Locally changed or missing managed content: {MCP_ALLOWLIST_PATH}")
    );
}

#[test]
fn an_edited_seed_stays_the_projects() {
    let f = Fixture::new(Some(VERIFY));
    let module = AgentGuardrails;
    f.apply(&module);
    f.write(TECHNICAL_DEBT_PATH, "# Edited by the project\n");
    let planned = f.plan(&module).unwrap();
    assert!(planned.changes.is_empty(), "{:?}", planned.changes.keys());
    assert_eq!(planned.notes[TECHNICAL_DEBT_PATH], Note::Skip);
}

#[test]
fn remove_deletes_the_unchanged_managed_files_and_lists_the_three_seeds() {
    let f = Fixture::new(Some(VERIFY));
    let module = AgentGuardrails;
    f.apply(&module);
    f.write(TECHNICAL_DEBT_PATH, "# Edited by the project\n");
    let planned = f.remove(&module).unwrap();
    for path in MANAGED {
        assert_eq!(planned.changes.get(path), Some(&None), "{path} deleted");
    }
    for path in SEEDS {
        assert!(!planned.changes.contains_key(path), "{path}");
        assert_eq!(planned.notes[path], Note::Keep, "{path}");
        assert_eq!(
            note_line(&planned, path),
            format!("KEEP {path} [seed:agent-guardrails]")
        );
    }
    apply(&f.root, &planned.changes).unwrap();
    for path in MANAGED {
        assert!(!f.root.join(path).exists(), "{path}");
    }
    for path in SEEDS {
        assert!(f.root.join(path).is_file(), "{path} kept");
    }
    assert_eq!(f.read(TECHNICAL_DEBT_PATH), "# Edited by the project\n");
    let lock: Value = serde_json::from_str(&f.read(LOCK)).unwrap();
    assert!(lock["modules"].get("agent-guardrails").is_none());
}

#[test]
fn a_server_named_twice_is_listed_once() {
    let answers = serde_json::from_value(json!({"mcp_servers": ["docs", "docs"]})).unwrap();
    let allowlist = brakes::modules::agent_guardrails::mcp::allowlist(&answers).unwrap();
    assert_eq!(allowlist["servers"].as_array().unwrap().len(), 1);
}

#[test]
fn the_guide_sends_agents_to_the_cli_or_api_for_hosted_tools() {
    let planned = Fixture::new(Some(VERIFY)).plan(&AgentGuardrails).unwrap();
    let guide = planned.changes[GUIDE_PATH].as_deref().unwrap();
    let section = guide
        .split("## Hosted tools: CLI or API first")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("the guide has the hosted-tools section");
    for needle in [
        "`gh`",
        "sentry-cli",
        "SENTRY_AUTH_TOKEN",
        "mcp-allowlist.json",
        "`docs`",
    ] {
        assert!(section.contains(needle), "{needle}");
    }
}

// ---- registration, doctor and the CLI (T5, #744; #872) ----------------------------

const SETTINGS: &str = ".claude/settings.json";
/// This repository's own settings file: three hook groups the installer keeps.
const REPO_SETTINGS: &str = include_str!("../../../.claude/settings.json");
const ENTRIES_DRIFT: &str =
    "NOT READY: Managed entries drift: .claude/settings.json (module agent-guardrails)";
const REVIEW_STEP_UNAVAILABLE: &str = "STEP [unavailable:agent-guardrails] review-secret-present — remote probe `secret-present` runs only with doctor --remote";
const REVIEW_DEPENDABOT_STEP_UNAVAILABLE: &str = "STEP [unavailable:agent-guardrails] review-dependabot-secret-present — remote probe `secret-present` runs only with doctor --remote";
/// The agents' App, a step in every profile since #1255.
const AGENT_APP_STEP_UNAVAILABLE: &str = "STEP [unavailable:agent-guardrails] agent-app — remote probe `app-installed` runs only with doctor --remote";

/// A git checkout with setup-core installed, a Rust stack recorded for
/// stack-packs and the declared commands, driven through the binary.
struct Repo {
    _temp: TempDir,
    root: std::path::PathBuf,
}
impl Repo {
    fn new(verify: &str) -> Self {
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
        let repo = Self { _temp: temp, root };
        repo.ok(&["install", "<repo>", "--new-personal", "--apply"]);
        repo.declare(verify);
        for path in ["Cargo.toml", "Cargo.lock"] {
            fs::write(repo.root.join(path), "").unwrap();
        }
        let file = json!({"module": "stack-packs", "version": "1.0.0",
            "answers": {"apps.root.path": ".", "apps.root.stack": "rust"}});
        repo.write_json(&answers::path("stack-packs"), &file);
        repo
    }
    /// Pins ci-baseline to the deprecated generated `ci.yml` these tests read (#21).
    fn generate(&self) -> &Self {
        let file = json!({"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "generate"}});
        self.write_json(&answers::path("ci-baseline"), &file);
        self
    }
    /// Declares `verify` (and `test`, which ci-baseline runs) in project.json.
    fn declare(&self, verify: &str) {
        let mut profile = self.json(PROFILE);
        profile["commands"]["verify"] = json!(verify);
        profile["commands"]["test"] = json!(verify);
        self.write_json(PROFILE, &profile);
    }
    fn cli(&self, args: &[&str]) -> std::process::Output {
        let root = self.root.to_string_lossy().into_owned();
        Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(
                args.iter()
                    .map(|a| if *a == "<repo>" { root.as_str() } else { a }),
            )
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }
    /// `install --module` for this module and its requirements, plus `extra`.
    fn install(&self, extra: &[&str]) -> std::process::Output {
        let mut args = vec!["install", "<repo>"];
        for id in [
            "repo-baseline",
            "stack-packs",
            "ci-baseline",
            "agent-guardrails",
        ] {
            args.extend(["--module", id]);
        }
        args.extend(extra);
        self.cli(&args)
    }
    fn doctor(&self) -> Vec<String> {
        let out = self.cli(&["doctor", "<repo>"]);
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    fn json(&self, path: &str) -> Value {
        serde_json::from_str(&fs::read_to_string(self.root.join(path)).unwrap()).unwrap()
    }
    fn write_json(&self, path: &str, value: &Value) {
        let file = self.root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, serde_json::to_string_pretty(value).unwrap() + "\n").unwrap();
    }
    /// Overwrites `.claude/settings.json` with the project's own deny entry and
    /// hooks, plus the fragment's deny rules and/or Stop entry (and always its
    /// merge-guard entry): what a hand-edit that drops owned entries leaves.
    fn register(&self, deny: bool, stop: bool) {
        let fragment = self.json(SETTINGS_FRAGMENT_PATH);
        let mut rules = vec![json!("Bash(rm -rf:*)")];
        if deny {
            rules.extend(fragment["permissions"]["deny"].as_array().unwrap().clone());
        }
        let mut stops = vec![json!({"hooks": [{"type": "command", "command": "echo bye"}]})];
        if stop {
            stops.extend(fragment["hooks"]["Stop"].as_array().unwrap().clone());
        }
        let mut pre = vec![
            json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "sh .claude/hooks/merge_guard.sh"}]}),
        ];
        pre.extend(
            fragment["hooks"]["PreToolUse"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
        let settings = json!({
            "permissions": {"allow": ["Bash(git status)"], "deny": rules},
            "hooks": {"PreToolUse": pre, "Stop": stops}
        });
        self.write_json(SETTINGS, &settings);
    }
}

/// This module's lines among today's, before the audit section (which
/// re-labels them as rules since #730).
fn ours(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .map(String::as_str)
        .take_while(|l| !l.starts_with("AUDIT "))
        .filter(|l| {
            l.contains("agent-guardrails") || l.contains("Stop verify") || l.contains("Deny rules")
        })
        .collect()
}

#[test]
fn cli_install_module_alone_refuses_naming_its_requirement() {
    let repo = Repo::new("cargo test --locked");
    let out = repo.cli(&["install", "<repo>", "--module", "agent-guardrails"]);
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "REFUSED: Module agent-guardrails requires module repo-baseline, which is not installed; add it with --module repo-baseline"
    );
}

#[test]
fn cli_install_with_profile_p2_resolves_the_workflows_default_and_lists_the_steps() {
    let repo = Repo::new("cargo test --locked");
    let out = repo.install(&["--profile", "P2", "--apply"]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    for path in [
        STOP_VERIFY_PATH,
        SETTINGS_FRAGMENT_PATH,
        GUIDE_PATH,
        MCP_ALLOWLIST_PATH,
    ] {
        assert!(
            text.lines()
                .any(|l| l == format!("WRITE {path} [managed:agent-guardrails]")),
            "{text}"
        );
    }
    assert!(
        text.lines()
            .any(|l| l == "WRITE .claude/settings.json [managed-entries:agent-guardrails]"),
        "{text}"
    );
    assert!(!text.contains("-registered"), "{text}");
    assert_eq!(
        repo.json(&answers::path("agent-guardrails"))["profile"],
        "P2"
    );
    let deny = repo.json(SETTINGS_FRAGMENT_PATH)["permissions"]["deny"].clone();
    assert!(
        deny.as_array()
            .unwrap()
            .contains(&json!("Edit(//**/.github/workflows/**)")),
        "{deny}"
    );
    let again = repo.ok(&["install", "<repo>"]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
}

/// Since #748 the installer registers the entries itself: a fresh install
/// writes them, with merge-guard's hook entry, and `doctor` has no registration
/// warning or step left to print; the second install prints `No changes.`.
#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn install_registers_the_entries_and_doctor_prints_no_registration_warning_or_step() {
    let repo = Repo::new("cargo test --locked");
    let out = repo.install(&["--apply"]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.lines()
            .any(|l| l == "WRITE .claude/settings.json [managed-entries:agent-guardrails]"),
        "{text}"
    );
    let fragment = repo.json(SETTINGS_FRAGMENT_PATH);
    let settings = repo.json(SETTINGS);
    assert_eq!(settings, fragment);
    assert_eq!(settings["hooks"]["PreToolUse"], json!([hook_entry()]));
    assert!(
        settings["hooks"]["Stop"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("stop_verify.sh")
    );
    let lines = repo.doctor();
    assert_eq!(
        ours(&lines),
        [
            AGENT_APP_STEP_UNAVAILABLE,
            REVIEW_DEPENDABOT_STEP_UNAVAILABLE,
            REVIEW_STEP_UNAVAILABLE
        ],
        "{lines:#?}"
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("registered") || l == ENTRIES_DRIFT),
        "{lines:#?}"
    );
    let again = repo.ok(&["install", "<repo>"]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
}

/// This repository's `.claude/settings.json` as the project file: its three hook
/// groups stay as they are, the merge-guard entry is recognised (not added
/// twice) and the deny rules and Stop entry join them.
#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn install_keeps_this_repositorys_hooks_and_adds_the_merge_guard_entry_once() {
    let repo = Repo::new("cargo test --locked");
    fs::write(repo.root.join(SETTINGS), REPO_SETTINGS).unwrap();
    let before: Value = serde_json::from_str(REPO_SETTINGS).unwrap();
    assert!(repo.install(&["--apply"]).status.success());
    let after = repo.json(SETTINGS);
    assert_eq!(
        after["hooks"]["SessionStart"],
        before["hooks"]["SessionStart"]
    );
    assert_eq!(after["hooks"]["PreToolUse"], before["hooks"]["PreToolUse"]);
    assert_eq!(after["hooks"]["Stop"][0], before["hooks"]["Stop"][0]);
    assert_eq!(after["hooks"]["Stop"].as_array().unwrap().len(), 2);
    assert_eq!(
        after["permissions"]["deny"],
        repo.json(SETTINGS_FRAGMENT_PATH)["permissions"]["deny"]
    );
    let lines = repo.doctor();
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("registered") || l == ENTRIES_DRIFT),
        "{lines:#?}"
    );
    let again = repo.ok(&["install", "<repo>"]);
    assert!(again.lines().any(|l| l == "No changes."), "{again}");
}

#[test]
fn install_refuses_an_owned_entry_edited_by_hand() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    let mut settings = repo.json(SETTINGS);
    settings["hooks"]["Stop"][0]["hooks"][0]["timeout"] = json!(5);
    repo.write_json(SETTINGS, &settings);
    let out = repo.install(&[]);
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "REFUSED: Locally changed managed entry: .claude/settings.json at /hooks/Stop (sh \"$CLAUDE_PROJECT_DIR/.claude/hooks/stop_verify.sh\")"
    );
}

/// The project keeps its own entries beside the installer's: a hand-edit that
/// drops the owned ones is drift and the rule's warning until the next install
/// adds them again, after the project's.
#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn owned_entries_deleted_by_hand_are_drift_until_the_next_install_adds_them_after_the_projects() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    repo.register(false, false);
    let lines = repo.doctor();
    assert!(lines.iter().any(|l| l == STOP_UNREGISTERED), "{lines:#?}");
    assert!(lines.iter().any(|l| l == DENY_UNREGISTERED), "{lines:#?}");
    assert!(lines.iter().any(|l| l == ENTRIES_DRIFT), "{lines:#?}");
    assert!(repo.install(&["--apply"]).status.success());
    let settings = repo.json(SETTINGS);
    assert_eq!(
        settings["permissions"]["allow"],
        json!(["Bash(git status)"])
    );
    assert_eq!(settings["permissions"]["deny"][0], "Bash(rm -rf:*)");
    assert_eq!(
        settings["hooks"]["Stop"][0]["hooks"][0]["command"],
        "echo bye"
    );
    assert_eq!(
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "sh .claude/hooks/merge_guard.sh"
    );
    assert_eq!(settings["hooks"]["PreToolUse"][1], hook_entry());
    let lines = repo.doctor();
    assert_eq!(
        ours(&lines),
        [
            AGENT_APP_STEP_UNAVAILABLE,
            REVIEW_DEPENDABOT_STEP_UNAVAILABLE,
            REVIEW_STEP_UNAVAILABLE
        ],
        "{lines:#?}"
    );
    assert!(!lines.iter().any(|l| l == ENTRIES_DRIFT), "{lines:#?}");
}

/// Through the library: the entries are the fragment, byte for byte, as
/// `managed-entries` of `.claude/settings.json`; with merge-guard active they
/// carry its hook entry and merge-guard drops its registration step.
#[test]
fn settings_entries_are_the_fragment_and_carry_merge_guards_entry_when_active() {
    let f = Fixture::new(Some(VERIFY));
    let planned = f.plan(&AgentGuardrails).unwrap();
    assert_eq!(
        planned.tags[SETTINGS_PATH],
        (Ownership::ManagedEntries, "agent-guardrails".to_owned())
    );
    assert_eq!(
        planned.changes[SETTINGS_PATH],
        planned.changes[SETTINGS_FRAGMENT_PATH]
    );
    assert!(fragment(&planned)["hooks"].get("PreToolUse").is_none());
    assert!(!planned.steps.iter().any(|s| s.id.ends_with("-registered")));
    // No merge guard, no approval route: no ask rule (#1146).
    assert!(fragment(&planned)["permissions"].get("ask").is_none());
    let profile = profile_for(&f.root).unwrap();
    let (core, guard, baseline, ci) = (SetupCore, MergeGuard, RepoBaseline, CiBaselineStandIn);
    let planned = engine::plan(
        &f.root,
        &Source::embedded(),
        &profile,
        &[&core, &guard, &baseline, &ci, &AgentGuardrails],
        &|_| true,
    )
    .unwrap();
    assert_eq!(
        fragment(&planned)["hooks"]["PreToolUse"],
        json!([hook_entry()])
    );
    // The explicit ask rule the person's approval goes through (#1146), the one
    // `ask` entry the installer owns; the whole object is pinned by a golden.
    assert_eq!(
        fragment(&planned)["permissions"]["ask"],
        json!(["Bash(gh pr edit * --add-label human-approved)"])
    );
    let entries = planned.changes[SETTINGS_FRAGMENT_PATH].clone().unwrap();
    let golden = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/agent-guardrails/with-merge-guard/claude-settings.json");
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(golden.parent().unwrap()).unwrap();
        fs::write(&golden, &entries).unwrap();
    }
    assert_eq!(
        entries,
        fs::read_to_string(&golden).unwrap(),
        "{}",
        golden.display()
    );
    assert_eq!(
        planned.changes[SETTINGS_PATH],
        planned.changes[SETTINGS_FRAGMENT_PATH]
    );
    assert!(
        !planned.steps.iter().any(|s| s.id == "hook-registered"),
        "{:?}",
        planned.steps.iter().map(|s| &s.id).collect::<Vec<_>>()
    );
}

#[test]
fn doctor_with_one_entry_registered_prints_exactly_the_other_warning() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    repo.register(true, false);
    let lines = repo.doctor();
    assert!(lines.iter().any(|l| l == STOP_UNREGISTERED), "{lines:#?}");
    assert!(!lines.iter().any(|l| l == DENY_UNREGISTERED), "{lines:#?}");
    repo.register(false, true);
    let lines = repo.doctor();
    assert!(lines.iter().any(|l| l == DENY_UNREGISTERED), "{lines:#?}");
    assert!(!lines.iter().any(|l| l == STOP_UNREGISTERED), "{lines:#?}");
}

/// The rules an install before #1309 rendered hold only under the session's
/// directory: `doctor` reports them as unregistered so a re-install anchors them
/// at the filesystem root.
#[test]
fn doctor_warns_when_the_secret_rules_are_anchored_at_the_session_directory() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    repo.write_json(
        SETTINGS,
        &json!({"permissions": {"deny": ["Read(./**/.env)", "Read(./secrets/**)", "Edit(./.agent-setup/lock.json)"]}}),
    );
    let lines = repo.doctor();
    assert!(lines.iter().any(|l| l == DENY_UNREGISTERED), "{lines:#?}");
}

#[test]
fn doctor_reports_a_baked_command_that_differs_from_project_json_as_not_ready() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    repo.register(true, true);
    let stale = |lines: &[String]| -> Vec<String> {
        lines
            .iter()
            .filter(|l| l.starts_with("NOT READY: Stop verify hook"))
            .cloned()
            .collect()
    };
    assert!(stale(&repo.doctor()).is_empty());
    repo.declare("cargo nextest run --locked");
    assert_eq!(
        stale(&repo.doctor()),
        [
            "NOT READY: Stop verify hook .claude/hooks/stop_verify.sh runs `cargo test --locked` but project.json declares `cargo nextest run --locked`; re-run install"
        ]
    );
    // Re-installing bakes the new command in and the finding goes away.
    assert!(repo.install(&["--apply"]).status.success());
    assert!(stale(&repo.doctor()).is_empty());
}

/// `doctor --json` restricted to this module: its findings, steps and version.
#[test]
fn doctor_json_carries_the_steps_and_matches_the_golden_file() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    repo.register(true, false);
    repo.declare("cargo nextest run --locked");
    repo.write_json(
        MCP_JSON_PATH,
        &json!({"mcpServers": {"playwright": {"command": "npx", "args": ["@playwright/mcp"]}}}),
    );
    let out = repo.cli(&["doctor", "<repo>", "--json"]);
    let document: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(document["ready"], json!(false));
    let pick = |key: &str, keep: &dyn Fn(&Value) -> bool| -> Value {
        Value::Array(
            document[key]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| keep(v))
                .cloned()
                .collect(),
        )
    };
    let actual = serde_json::to_string_pretty(&json!({
        "findings": pick("findings", &|f| {
            let f = f.as_str().unwrap();
            f.contains("Stop verify") || f.contains("Deny rules") || f.contains(" agents.")
        }),
        "steps": pick("steps", &|s| s["module"] == "agent-guardrails"),
        "modules": pick("modules", &|m| m["id"] == "agent-guardrails"),
    }))
    .unwrap()
        + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/agent-guardrails/doctor.json"
    );
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(path, &actual).unwrap();
    }
    let expected = fs::read_to_string(path).unwrap();
    assert_eq!(actual, expected, "{path} drifted; actual:\n{actual}");
}

#[test]
fn install_plan_and_doctor_never_run_verify() {
    let marker = tempfile::tempdir().unwrap();
    let called = marker.path().join("verify-called");
    let verify = format!("touch '{}'", called.display());
    let repo = Repo::new(&verify);
    assert!(repo.install(&[]).status.success(), "plan");
    assert!(repo.install(&["--apply"]).status.success(), "apply");
    repo.cli(&["doctor", "<repo>"]);
    repo.cli(&["doctor", "<repo>", "--json"]);
    repo.ok(&["install", "<repo>"]);
    // The command is baked into the hook, to be run by the agent host only.
    let hook = fs::read_to_string(repo.root.join(STOP_VERIFY_PATH)).unwrap();
    assert!(hook.contains(&verify), "{hook}");
    assert!(!called.exists(), "verify was executed");
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn without_the_hook_only_the_deny_rules_and_the_merge_guard_entry_are_registered() {
    let repo = Repo::new("cargo test --locked");
    let file = json!({"module": "agent-guardrails", "version": "1.0.0", "answers": {"stop_verify": false}});
    repo.write_json(&answers::path("agent-guardrails"), &file);
    assert!(repo.install(&["--apply"]).status.success());
    assert!(!repo.root.join(STOP_VERIFY_PATH).exists());
    let settings = repo.json(SETTINGS);
    assert!(settings["hooks"].get("Stop").is_none(), "{settings}");
    assert_eq!(settings["hooks"]["PreToolUse"], json!([hook_entry()]));
    assert!(settings["permissions"]["deny"].as_array().unwrap().len() > 10);
    let lines = repo.doctor();
    assert_eq!(
        ours(&lines),
        [
            AGENT_APP_STEP_UNAVAILABLE,
            REVIEW_DEPENDABOT_STEP_UNAVAILABLE,
            REVIEW_STEP_UNAVAILABLE
        ],
        "{lines:#?}"
    );
}

// ---- T6 (#746): the remaining doctor and auditor rules ----

/// A bare git checkout (no setup) for the rules `doctor` evaluates everywhere.
fn checkout() -> TempDir {
    let temp = tempfile::tempdir().unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success()
    );
    temp
}

fn put(root: &Path, name: &str, content: &str) {
    let file = root.join(name);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, content).unwrap();
}

fn track(root: &Path, names: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["add", "-f", "--"])
        .args(names)
        .status()
        .unwrap();
    assert!(status.success());
}

fn rule_lines<'a>(lines: &'a [String], rule: &str) -> Vec<&'a str> {
    let prefix = format!("WARNING: {rule}: ");
    lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.starts_with(&prefix))
        .collect()
}

const UNKNOWN_SERVER: &str = "WARNING: agents.mcp-allowlist: .mcp.json server `playwright` is not in .agent-setup/mcp-allowlist.json; declare it with configure --set mcp_servers or remove it";

#[test]
fn rule_data_is_exported_for_the_auditor_as_the_spec_allocates_it() {
    let rows: Vec<(&str, Level, &[Profile], bool)> = audit::RULES
        .iter()
        .map(|r| (r.id, r.level, r.profiles, r.local))
        .collect();
    let all: &[Profile] = &[Profile::P1, Profile::P2, Profile::P3];
    let teams: &[Profile] = &[Profile::P2, Profile::P3];
    assert_eq!(
        rows,
        [
            ("agents.deny-secrets", Level::Basic, all, true),
            ("agents.stop-verify", Level::Bronze, all, true),
            ("agents.protected-paths", Level::Bronze, teams, true),
            ("agents.mcp-allowlist", Level::Bronze, all, true),
            ("agents.technical-debt", Level::Bronze, all, true),
            ("agents.readable-secrets", Level::Basic, all, true),
            ("agents.cross-review", Level::Silver, all, true),
            ("agents.unattended-gated", Level::Silver, all, true),
            ("agents.heldout-denied", Level::Silver, all, true),
            ("agents.workflow-caps", Level::Silver, all, true),
            ("agents.identity", Level::Silver, teams, true),
            ("agents.workflow-injection", Level::Bronze, all, true),
        ]
    );
}

#[test]
fn mcp_allowlist_passes_without_mcp_json_and_with_the_catalogue_server() {
    let repo = checkout();
    assert_eq!(
        rule_lines(&audit::diagnose(repo.path()), "agents.mcp-allowlist"),
        Vec::<&str>::new()
    );
    let answers = Answers::from([("mcp_servers".to_owned(), json!(["docs"]))]);
    let allow = brakes::modules::agent_guardrails::mcp::allowlist(&answers).unwrap();
    let servers = brakes::modules::agent_guardrails::mcp::mcp_json(&answers).unwrap();
    put(repo.path(), MCP_ALLOWLIST_PATH, &allow.to_string());
    put(repo.path(), MCP_JSON_PATH, &servers.to_string());
    assert_eq!(
        rule_lines(&audit::diagnose(repo.path()), "agents.mcp-allowlist"),
        Vec::<&str>::new()
    );
}

#[test]
fn mcp_allowlist_warns_on_a_server_outside_the_allowlist_naming_it() {
    let repo = checkout();
    put(
        repo.path(),
        MCP_JSON_PATH,
        r#"{"mcpServers": {"playwright": {"command": "npx", "args": ["@playwright/mcp"]}}}"#,
    );
    let lines = audit::diagnose(repo.path());
    assert_eq!(rule_lines(&lines, "agents.mcp-allowlist"), [UNKNOWN_SERVER]);
}

#[test]
fn mcp_allowlist_refuses_a_catalogue_name_running_another_version() {
    let repo = checkout();
    let answers = Answers::from([("mcp_servers".to_owned(), json!(["docs"]))]);
    let allow = brakes::modules::agent_guardrails::mcp::allowlist(&answers).unwrap();
    put(repo.path(), MCP_ALLOWLIST_PATH, &allow.to_string());
    put(
        repo.path(),
        MCP_JSON_PATH,
        r#"{"mcpServers": {"docs": {"command": "npx", "args": ["-y", "@upstash/context7-mcp@4.4.40"]}}}"#,
    );
    let lines = audit::diagnose(repo.path());
    assert_eq!(
        rule_lines(&lines, "agents.mcp-allowlist"),
        [
            "WARNING: agents.mcp-allowlist: .mcp.json server `docs` is not in .agent-setup/mcp-allowlist.json; declare it with configure --set mcp_servers or remove it"
        ]
    );
}

#[test]
fn a_read_write_allowlist_entry_is_a_silver_finding_with_its_purpose() {
    let repo = checkout();
    put(
        repo.path(),
        MCP_ALLOWLIST_PATH,
        r#"{"schema": 1, "servers": [{"name": "tracker", "purpose": "File bugs in the in-house tracker, which has no CLI", "permissions": "read-write", "transport": "http"}]}"#,
    );
    put(
        repo.path(),
        MCP_JSON_PATH,
        r#"{"mcpServers": {"tracker": {"type": "http", "url": "https://tracker.example/mcp"}}}"#,
    );
    let lines = audit::diagnose(repo.path());
    assert_eq!(
        rule_lines(&lines, "agents.mcp-allowlist"),
        [
            "WARNING: agents.mcp-allowlist: Silver: .agent-setup/mcp-allowlist.json server `tracker` is read-write; purpose: File bugs in the in-house tracker, which has no CLI"
        ]
    );
}

#[test]
fn an_unreadable_mcp_json_is_reported_as_unverified() {
    let repo = checkout();
    put(repo.path(), MCP_JSON_PATH, "{ not json");
    let lines = audit::diagnose(repo.path());
    assert_eq!(
        rule_lines(&lines, "agents.mcp-allowlist"),
        ["WARNING: agents.mcp-allowlist: unverified: .mcp.json: invalid JSON"]
    );
}

#[test]
fn readable_secrets_passes_on_examples_and_untracked_files() {
    let repo = checkout();
    put(repo.path(), ".env", "TOKEN=x\n");
    put(repo.path(), ".env.example", "TOKEN=\n");
    put(repo.path(), ".env.template", "TOKEN=\n");
    put(
        repo.path(),
        "gradle.properties",
        "org.gradle.jvmargs=-Xmx2g\nkeyAlias=upload\n# password=see the vault\n",
    );
    track(
        repo.path(),
        &[".env.example", ".env.template", "gradle.properties"],
    );
    put(
        repo.path(),
        WORKTREEINCLUDE_PATH,
        "# never .env here\nbuild/local-config.json\n",
    );
    assert_eq!(
        rule_lines(&audit::diagnose(repo.path()), "agents.readable-secrets"),
        Vec::<&str>::new()
    );
}

#[test]
fn readable_secrets_flags_tracked_secret_paths_without_printing_values() {
    let repo = checkout();
    for name in [
        ".env",
        "app/.env.production",
        "secrets/db.txt",
        "certs/server.pem",
        "deploy/id_rsa",
    ] {
        put(repo.path(), name, "s3cr3t-value\n");
    }
    put(
        repo.path(),
        "android/local.properties",
        "sdk.dir=/opt\nstorePassword=hunter2\n",
    );
    track(
        repo.path(),
        &[
            ".env",
            "app/.env.production",
            "secrets/db.txt",
            "certs/server.pem",
            "deploy/id_rsa",
            "android/local.properties",
        ],
    );
    let lines = audit::diagnose(repo.path());
    assert_eq!(
        rule_lines(&lines, "agents.readable-secrets"),
        [
            "WARNING: agents.readable-secrets: .env is tracked; secrets must not be readable in the checkout",
            "WARNING: agents.readable-secrets: android/local.properties is tracked; secrets must not be readable in the checkout",
            "WARNING: agents.readable-secrets: app/.env.production is tracked; secrets must not be readable in the checkout",
            "WARNING: agents.readable-secrets: certs/server.pem is tracked; secrets must not be readable in the checkout",
            "WARNING: agents.readable-secrets: deploy/id_rsa is tracked; secrets must not be readable in the checkout",
            "WARNING: agents.readable-secrets: secrets/db.txt is tracked; secrets must not be readable in the checkout",
            "WARNING: agents.readable-secrets: android/local.properties has a `storePassword` line; keep credentials out of tracked files",
        ]
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("hunter2") || l.contains("s3cr3t"))
    );
}

#[test]
fn readable_secrets_flags_a_password_line_in_any_tracked_properties_file() {
    let repo = checkout();
    put(
        repo.path(),
        "app/gradle.properties",
        "org.gradle.jvmargs=-Xmx2g\nsigning.key = abc\n",
    );
    track(repo.path(), &["app/gradle.properties"]);
    assert_eq!(
        rule_lines(&audit::diagnose(repo.path()), "agents.readable-secrets"),
        [
            "WARNING: agents.readable-secrets: app/gradle.properties has a `signing.key` line; keep credentials out of tracked files"
        ]
    );
}

#[test]
fn a_worktreeinclude_listing_a_secret_is_flagged() {
    let repo = checkout();
    put(
        repo.path(),
        WORKTREEINCLUDE_PATH,
        "# comment .env\nbuild/config.json\n.env.local\n/secrets/\n.env.example\n",
    );
    assert_eq!(
        rule_lines(&audit::diagnose(repo.path()), "agents.readable-secrets"),
        [
            "WARNING: agents.readable-secrets: .worktreeinclude lists .env.local; worktrees must not multiply secrets",
            "WARNING: agents.readable-secrets: .worktreeinclude lists /secrets/; worktrees must not multiply secrets",
        ]
    );
}

#[test]
fn technical_debt_is_a_silver_finding_while_it_equals_the_seed_and_passes_once_edited() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    let lines = repo.doctor();
    assert_eq!(
        rule_lines(&lines, "agents.technical-debt"),
        [
            "WARNING: agents.technical-debt: Silver: docs/agent-setup/technical-debt.md still equals the seed; record the patterns not to copy"
        ]
    );
    let today = brakes::today().format("%Y-%m-%d").to_string();
    let text = fs::read_to_string(repo.root.join(TECHNICAL_DEBT_PATH))
        .unwrap()
        .replace("None yet (2026-10-28).", &format!("None yet ({today})."));
    fs::write(repo.root.join(TECHNICAL_DEBT_PATH), text).unwrap();
    assert_eq!(
        rule_lines(&repo.doctor(), "agents.technical-debt"),
        Vec::<&str>::new()
    );
}

#[test]
fn technical_debt_none_yet_older_than_ninety_days_is_a_silver_finding() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    let text = fs::read_to_string(repo.root.join(TECHNICAL_DEBT_PATH))
        .unwrap()
        .replacen("None yet (2026-10-28).", "None yet (2020-01-01).", 1);
    fs::write(repo.root.join(TECHNICAL_DEBT_PATH), text).unwrap();
    assert_eq!(
        rule_lines(&repo.doctor(), "agents.technical-debt"),
        [
            "WARNING: agents.technical-debt: Silver: docs/agent-setup/technical-debt.md says \"None yet\" since 2020-01-01, more than 90 days ago; review it"
        ]
    );
}

/// #1172: a seed written before #1107 has no `Last verified` line and the
/// install never adds one (the file is the project's). It is
/// `agents.technical-debt`'s Bronze warning naming the project's edit, never
/// setup-core's `NOT READY` guide finding.
#[test]
fn a_technical_debt_seed_without_a_verified_date_is_its_own_warning_never_not_ready() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    let text = fs::read_to_string(repo.root.join(TECHNICAL_DEBT_PATH)).unwrap();
    let dated = text
        .lines()
        .find(|l| l.starts_with("Last verified:"))
        .unwrap()
        .to_owned();
    fs::write(
        repo.root.join(TECHNICAL_DEBT_PATH),
        text.replacen(&format!("{dated}\n\n"), "", 1),
    )
    .unwrap();
    let lines = repo.doctor();
    assert!(
        !lines.iter().any(|l| l.contains("technical-debt.md")
            && (l.starts_with("NOT READY") || l.contains("guides-verified"))),
        "{lines:?}"
    );
    assert_eq!(
        rule_lines(&lines, "agents.technical-debt"),
        [
            "WARNING: agents.technical-debt: docs/agent-setup/technical-debt.md has no Last verified date; re-read it and add Last verified: YYYY-MM-DD"
        ]
    );
}

/// #1172: a seed's date older than `guide_verification_days` is the same
/// warning, never a `NOT READY` guide finding.
#[test]
fn a_technical_debt_seed_verified_too_long_ago_is_its_own_warning() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    let text = fs::read_to_string(repo.root.join(TECHNICAL_DEBT_PATH)).unwrap();
    let dated = text
        .lines()
        .find(|l| l.starts_with("Last verified:"))
        .unwrap()
        .to_owned();
    fs::write(
        repo.root.join(TECHNICAL_DEBT_PATH),
        text.replacen(&dated, "Last verified: 2020-01-01", 1),
    )
    .unwrap();
    let days = (brakes::today() - chrono::NaiveDate::from_ymd_opt(2020, 1, 1).unwrap()).num_days();
    let lines = repo.doctor();
    assert!(
        !lines
            .iter()
            .any(|l| l.starts_with("NOT READY") && l.contains("technical-debt.md")),
        "{lines:?}"
    );
    assert_eq!(
        rule_lines(&lines, "agents.technical-debt"),
        [format!(
            "WARNING: agents.technical-debt: docs/agent-setup/technical-debt.md not verified for {days} days; re-read it and bump Last verified"
        )]
    );
}

#[test]
fn a_missing_technical_debt_file_is_a_finding() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    fs::remove_file(repo.root.join(TECHNICAL_DEBT_PATH)).unwrap();
    assert_eq!(
        rule_lines(&repo.doctor(), "agents.technical-debt"),
        [
            "WARNING: agents.technical-debt: docs/agent-setup/technical-debt.md is missing; re-run install to seed it"
        ]
    );
}

#[test]
fn protected_paths_in_p2_needs_the_workflows_deny_rule_merged() {
    let repo = Repo::new("cargo test --locked");
    assert!(
        repo.install(&["--profile", "P2", "--apply"])
            .status
            .success()
    );
    // Only the three rules the deny step probes, not the workflows one.
    repo.write_json(
        SETTINGS,
        &json!({"permissions": {"deny": ["Read(//**/.env)", "Read(//**/secrets/**)", "Edit(//**/.agent-setup/lock.json)"]}}),
    );
    let lines = repo.doctor();
    assert!(!lines.iter().any(|l| l == DENY_UNREGISTERED), "{lines:#?}");
    assert_eq!(
        rule_lines(&lines, "agents.protected-paths"),
        [
            "WARNING: agents.protected-paths: .claude/settings.json permissions.deny lacks Edit(//**/.github/workflows/**) (profile P2)"
        ]
    );
    repo.register(true, true);
    assert_eq!(
        rule_lines(&repo.doctor(), "agents.protected-paths"),
        Vec::<&str>::new()
    );
}

#[test]
fn protected_paths_is_not_required_in_p1() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    repo.register(true, true);
    assert_eq!(
        rule_lines(&repo.doctor(), "agents.protected-paths"),
        Vec::<&str>::new()
    );
}

#[test]
fn doctor_reports_an_unknown_mcp_server_through_the_cli() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    repo.write_json(
        MCP_JSON_PATH,
        &json!({"mcpServers": {"playwright": {"command": "npx", "args": ["@playwright/mcp"]}}}),
    );
    let lines = repo.doctor();
    assert!(lines.iter().any(|l| l == UNKNOWN_SERVER), "{lines:#?}");
}

// ---- custom MCP servers: mcp_custom.<name>.<field> (#746) ----

/// The refusal of planning with these answers.
fn custom_refusal(answers: Value) -> String {
    let f = Fixture::new(Some(VERIFY));
    f.answer(answers);
    f.plan(&AgentGuardrails).unwrap_err().to_string()
}

#[test]
fn a_custom_server_without_purpose_refuses_naming_it() {
    assert_eq!(
        custom_refusal(json!({
            "mcp_custom.tracker.transport": "http",
            "mcp_custom.tracker.url": "https://tracker.example/mcp",
        })),
        "Module agent-guardrails: mcp_custom server `tracker` has no purpose; set mcp_custom.tracker.purpose"
    );
    assert_eq!(
        custom_refusal(json!({
            "mcp_custom.tracker.transport": "http",
            "mcp_custom.tracker.url": "https://tracker.example/mcp",
            "mcp_custom.tracker.purpose": "",
        })),
        "Module agent-guardrails: answer `mcp_custom.tracker.purpose` must have at least 1 character"
    );
}

#[test]
fn a_custom_server_without_transport_refuses_naming_it() {
    assert_eq!(
        custom_refusal(json!({"mcp_custom.x.purpose": "Something with no CLI"})),
        "Module agent-guardrails: mcp_custom server `x` has no transport; set mcp_custom.x.transport to stdio or http"
    );
}

#[test]
fn custom_permissions_and_transport_are_enums() {
    let schema = AgentGuardrails.questions();
    let refuse = |answers: Value| {
        schema
            .validate(
                "agent-guardrails",
                &serde_json::from_value(answers).unwrap(),
                "P1",
            )
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        refuse(json!({"mcp_custom.x.permissions": "admin"})),
        "Module agent-guardrails: answer `mcp_custom.x.permissions` must be one of: read-only, read-write"
    );
    assert_eq!(
        refuse(json!({"mcp_custom.x.transport": "sse"})),
        "Module agent-guardrails: answer `mcp_custom.x.transport` must be one of: stdio, http"
    );
}

#[test]
fn a_stdio_server_must_run_a_pinned_version() {
    let stdio = |command: &str, args: Value| {
        json!({
            "mcp_custom.s.transport": "stdio",
            "mcp_custom.s.purpose": "A need with no CLI or API",
            "mcp_custom.s.command": command,
            "mcp_custom.s.args": args,
        })
    };
    for (command, args) in [
        ("npx", json!(["-y", "@playwright/mcp"])),
        ("npx", json!(["-y", "@playwright/mcp@latest"])),
        ("npx", json!(["-y", "@playwright/mcp@^0.0.41"])),
        ("uvx", json!(["mcp-server-fetch"])),
        ("docker", json!(["run", "-i", "--rm", "mcp/fetch:latest"])),
        ("playwright-mcp", json!([])),
    ] {
        let error = custom_refusal(stdio(command, args.clone()));
        assert!(
            error.starts_with("Module agent-guardrails: mcp_custom server `s` ")
                && error.contains("pinned"),
            "{command} {args}: {error}"
        );
    }
    for (command, args) in [
        ("npx", json!(["-y", "@playwright/mcp@0.0.41"])),
        ("pnpm", json!(["dlx", "some-mcp@1.2.3"])),
        ("uvx", json!(["mcp-server-fetch==2025.4.7"])),
        (
            "docker",
            json!(["run", "-i", "--rm", "mcp/fetch@sha256:0123456789abcdef"]),
        ),
        ("./tools/mcp-server", json!(["--stdio"])),
    ] {
        let f = Fixture::new(Some(VERIFY));
        f.answer(stdio(command, args.clone()));
        assert!(f.plan(&AgentGuardrails).is_ok(), "{command} {args}");
    }
}

#[test]
fn transport_fields_must_agree() {
    assert_eq!(
        custom_refusal(json!({
            "mcp_custom.s.transport": "stdio",
            "mcp_custom.s.purpose": "p",
        })),
        "Module agent-guardrails: mcp_custom server `s` is stdio and needs mcp_custom.s.command"
    );
    assert_eq!(
        custom_refusal(json!({
            "mcp_custom.h.transport": "http",
            "mcp_custom.h.purpose": "p",
        })),
        "Module agent-guardrails: mcp_custom server `h` is http and needs mcp_custom.h.url"
    );
    assert_eq!(
        custom_refusal(json!({
            "mcp_custom.h.transport": "http",
            "mcp_custom.h.purpose": "p",
            "mcp_custom.h.url": "https://x.example/mcp",
            "mcp_custom.h.command": "npx",
        })),
        "Module agent-guardrails: mcp_custom server `h` is http and takes no command or args"
    );
    assert_eq!(
        custom_refusal(json!({
            "mcp_custom.s.transport": "stdio",
            "mcp_custom.s.purpose": "p",
            "mcp_custom.s.command": "./bin/mcp",
            "mcp_custom.s.url": "https://x.example/mcp",
        })),
        "Module agent-guardrails: mcp_custom server `s` is stdio and takes no url"
    );
}

#[test]
fn an_http_url_carries_no_credential() {
    for url in [
        "https://x.example/mcp?token=abc",
        "https://user:pw@x.example/mcp",
        "http://x.example/mcp",
        "ftp://x.example/mcp",
    ] {
        let error = custom_refusal(json!({
            "mcp_custom.h.transport": "http",
            "mcp_custom.h.purpose": "p",
            "mcp_custom.h.url": url,
        }));
        assert!(
            error.starts_with("Module agent-guardrails: mcp_custom server `h` url "),
            "{url}: {error}"
        );
        assert!(!error.contains("abc") && !error.contains("pw@"), "{error}");
    }
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({
        "mcp_custom.h.transport": "http",
        "mcp_custom.h.purpose": "p",
        "mcp_custom.h.url": "http://localhost:8931/mcp",
    }));
    assert!(f.plan(&AgentGuardrails).is_ok());
}

#[test]
fn a_custom_server_cannot_take_a_catalogue_name() {
    assert_eq!(
        custom_refusal(json!({
            "mcp_custom.docs.transport": "stdio",
            "mcp_custom.docs.purpose": "p",
            "mcp_custom.docs.command": "./bin/docs",
        })),
        "Module agent-guardrails: mcp_custom server `docs` takes a catalogue name; choose another name or use mcp_servers"
    );
}

#[test]
fn a_custom_server_defaults_to_read_only_and_lands_in_both_files() {
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({
        "mcp_custom.local.transport": "stdio",
        "mcp_custom.local.purpose": "Query the local fixture store",
        "mcp_custom.local.command": "./tools/mcp",
    }));
    let planned = f.plan(&AgentGuardrails).unwrap();
    assert_eq!(
        json_at(&planned, MCP_ALLOWLIST_PATH),
        json!({"schema": 1, "servers": [{
            "name": "local", "purpose": "Query the local fixture store",
            "permissions": "read-only", "transport": "stdio",
            "match": {"command_in": ["./tools/mcp"]},
        }]})
    );
    assert_eq!(
        json_at(&planned, MCP_JSON_PATH),
        json!({"mcpServers": {"local": {"command": "./tools/mcp", "args": []}}})
    );
}

#[test]
fn recorded_custom_servers_pass_doctor_and_read_write_is_reported_at_silver() {
    let repo = Repo::new("cargo test --locked");
    let file = json!({"module": "agent-guardrails", "version": "1.0.0", "answers": {
        "mcp_servers": ["docs"],
        "mcp_custom.tracker.transport": "http",
        "mcp_custom.tracker.url": "https://tracker.example/mcp",
        "mcp_custom.tracker.permissions": "read-write",
        "mcp_custom.tracker.purpose": "File bugs in the in-house tracker, which has no CLI or API",
        "mcp_custom.browser.transport": "stdio",
        "mcp_custom.browser.command": "npx",
        "mcp_custom.browser.args": ["-y", "@playwright/mcp@0.0.41"],
        "mcp_custom.browser.purpose": "Drive the local web app in a browser",
    }});
    repo.write_json(&answers::path("agent-guardrails"), &file);
    assert!(repo.install(&["--apply"]).status.success());
    assert_eq!(
        rule_lines(&repo.doctor(), "agents.mcp-allowlist"),
        [
            "WARNING: agents.mcp-allowlist: Silver: .agent-setup/mcp-allowlist.json server `tracker` is read-write; purpose: File bugs in the in-house tracker, which has no CLI or API"
        ]
    );
    // Another URL under the same name is outside the allowlist.
    let mut servers = repo.json(MCP_JSON_PATH);
    servers["mcpServers"]["tracker"]["url"] = json!("https://evil.example/mcp");
    repo.write_json(MCP_JSON_PATH, &servers);
    assert!(
        repo.doctor()
            .iter()
            .any(|l| l.contains("server `tracker` is not in")),
        "url must match"
    );
}

#[test]
fn configure_set_records_a_custom_server() {
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    let out = repo.cli(&[
        "configure",
        "<repo>",
        "agent-guardrails",
        "--set",
        "mcp_custom.tracker.transport=http",
        "--set",
        "mcp_custom.tracker.url=https://tracker.example/mcp",
        "--set",
        "mcp_custom.tracker.purpose=File bugs in the in-house tracker",
        "--apply",
    ]);
    assert!(out.status.success(), "{out:?}");
    let recorded = repo.json(&answers::path("agent-guardrails"))["answers"].clone();
    assert_eq!(
        recorded["mcp_custom.tracker.url"],
        "https://tracker.example/mcp"
    );
    assert_eq!(
        repo.json(MCP_ALLOWLIST_PATH)["servers"][0]["name"],
        "tracker"
    );
    let missing = repo.cli(&[
        "configure",
        "<repo>",
        "agent-guardrails",
        "--set",
        "mcp_custom.x.transport=http",
        "--set",
        "mcp_custom.x.url=https://x.example/mcp",
    ]);
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("mcp_custom server `x` has no purpose"),
        "{missing:?}"
    );
}

// ---- T9 (#749): agent environment files -----------------------------------------

use brakes::modules::agent_guardrails::environments::{
    BASE_HOSTS, CODEX_SETUP_PATH, COPILOT_SETUP_PATH, DEVCONTAINER_DOCKERFILE_PATH,
    DEVCONTAINER_JSON_PATH, INIT_FIREWALL_PATH,
};
use brakes::modules::stack_packs::{StackId, StackPacks, packs::pack};

const ENVIRONMENT_PATHS: [&str; 5] = [
    COPILOT_SETUP_PATH,
    CODEX_SETUP_PATH,
    DEVCONTAINER_JSON_PATH,
    DEVCONTAINER_DOCKERFILE_PATH,
    INIT_FIREWALL_PATH,
];
const ENVIRONMENT_SEEDS: [&str; 4] = [
    CODEX_SETUP_PATH,
    DEVCONTAINER_JSON_PATH,
    DEVCONTAINER_DOCKERFILE_PATH,
    INIT_FIREWALL_PATH,
];

/// A Go module at the root, recorded as the one stack-packs app `svc`.
fn with_go_pack(f: &Fixture) {
    f.write("go.mod", "module example.com/svc\n\ngo 1.25\n");
    f.write("go.sum", "");
    let file = AnswersFile {
        module: "stack-packs".to_owned(),
        version: "1.0.0".to_owned(),
        profile: None,
        answers: serde_json::from_value(json!({
            "apps.svc.path": ".",
            "apps.svc.stack": "go",
            "apps.svc.container": false,
        }))
        .unwrap(),
    };
    let path = f.root.join(answers::path("stack-packs"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, file.to_json_string().unwrap()).unwrap();
}

fn plan_with_packs(f: &Fixture) -> Result<Planned> {
    let profile = profile_for(&f.root)?;
    let (core, packs, baseline, ci, module) = (
        SetupCore,
        StackPacks,
        RepoBaseline,
        CiBaselineStandIn,
        AgentGuardrails,
    );
    engine::plan(
        &f.root,
        &Source::embedded(),
        &profile,
        &[&core, &packs, &baseline, &ci, &module],
        &|_| true,
    )
}

fn remove_with_packs(f: &Fixture) -> Result<Planned> {
    let (core, packs, baseline, ci, module) = (
        SetupCore,
        StackPacks,
        RepoBaseline,
        CiBaselineStandIn,
        AgentGuardrails,
    );
    engine::remove(
        &f.root,
        &[&core, &packs, &baseline, &ci, &module],
        &|_| true,
        "agent-guardrails",
    )
}

fn all_environments() -> Value {
    json!({"agent_environments": ["copilot", "codex", "devcontainer"]})
}

fn rendered<'a>(planned: &'a Planned, path: &str) -> &'a str {
    planned.changes[path]
        .as_deref()
        .unwrap_or_else(|| panic!("{path} rendered"))
}

/// The hosts between `ALLOWED_HOSTS="` and the closing quote, one per line.
fn firewall_hosts(script: &str) -> Vec<String> {
    let start = script.find("ALLOWED_HOSTS=\"\n").expect("the host list") + 15;
    let end = start + script[start..].find("\n\"").expect("its end");
    script[start..end]
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg_attr(
    not(feature = "setup-core"),
    ignore = "asserts setup-core's own content or id; product-boundary T7b"
)]
#[test]
fn golden_p1_environments_with_one_stack_pack() {
    let f = Fixture::new(Some(VERIFY));
    with_go_pack(&f);
    f.answer(all_environments());
    let first = plan_with_packs(&f).unwrap();
    let second = plan_with_packs(&f).unwrap();
    assert_eq!(owned(&first), owned(&second), "not deterministic");
    assert_golden("p1-environments-go", &first);
}

/// One Claude Code pin (#971, coordinator): the dev container installs the version
/// of the pin table's `tools.claude-code`, the same the model jobs install.
#[test]
fn the_dev_container_and_the_model_jobs_install_one_claude_code_version() {
    let pins = PinTable::embedded().unwrap();
    let package = format!(
        "@anthropic-ai/claude-code@{}",
        pins.tool("claude-code").unwrap().version
    );
    let f = Fixture::new(Some(VERIFY));
    with_go_pack(&f);
    f.answer(all_environments());
    let planned = plan_with_packs(&f).unwrap();
    let dockerfile = planned.changes[".devcontainer/Dockerfile"]
        .as_deref()
        .unwrap();
    assert!(
        dockerfile.contains(&format!("npm install -g {package} ")),
        "{dockerfile}"
    );
    let implement = workflow_of(
        &plan_composed(&reviewed(unattended_answers()), true).unwrap(),
        WORKFLOW_PATH,
    );
    assert!(implement.contains(&format!("\"{package}\"")), "{implement}");
}

#[test]
fn nothing_is_rendered_for_an_empty_agent_environments() {
    let f = Fixture::new(Some(VERIFY));
    with_go_pack(&f);
    f.answer(json!({"agent_environments": []}));
    let planned = plan_with_packs(&f).unwrap();
    for path in ENVIRONMENT_PATHS {
        assert!(!planned.tags.contains_key(path), "{path}");
    }
}

#[test]
fn each_environment_renders_only_its_own_files_with_its_class() {
    let cases: [(&str, &[&str], Ownership); 3] = [
        ("copilot", &[COPILOT_SETUP_PATH], Ownership::Managed),
        ("codex", &[CODEX_SETUP_PATH], Ownership::Seed),
        (
            "devcontainer",
            &[
                DEVCONTAINER_JSON_PATH,
                DEVCONTAINER_DOCKERFILE_PATH,
                INIT_FIREWALL_PATH,
            ],
            Ownership::Seed,
        ),
    ];
    for (environment, paths, class) in cases {
        let f = Fixture::new(Some(VERIFY));
        with_go_pack(&f);
        f.answer(json!({ "agent_environments": [environment] }));
        let planned = plan_with_packs(&f).unwrap();
        for path in ENVIRONMENT_PATHS {
            if paths.contains(&path) {
                assert_eq!(
                    planned.tags[path],
                    (class, "agent-guardrails".to_owned()),
                    "{environment}: {path}"
                );
            } else {
                assert!(!planned.tags.contains_key(path), "{environment}: {path}");
            }
        }
    }
}

#[test]
fn copilot_setup_steps_is_one_job_with_the_pack_steps_and_never_verify() {
    let f = Fixture::new(Some(VERIFY));
    with_go_pack(&f);
    f.answer(json!({"agent_environments": ["copilot"]}));
    let planned = plan_with_packs(&f).unwrap();
    let text = rendered(&planned, COPILOT_SETUP_PATH);
    let docs = yaml_rust2::YamlLoader::load_from_str(text).unwrap();
    let workflow = &docs[0];
    let jobs = workflow["jobs"].as_hash().unwrap();
    assert_eq!(jobs.len(), 1, "a single job");
    let job = &workflow["jobs"]["copilot-setup-steps"];
    assert_eq!(job["runs-on"].as_str(), Some("ubuntu-latest"));
    assert_eq!(job["timeout-minutes"].as_i64(), Some(30));
    assert_eq!(job["permissions"]["contents"].as_str(), Some("read"));
    assert_eq!(job["permissions"].as_hash().unwrap().len(), 1);
    let steps = job["steps"].as_vec().unwrap();
    let names: Vec<&str> = steps.iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "Check out",
            "Set up Go",
            "Restore Go module and build caches",
            "Download and verify modules",
            "Save Go module and build caches",
        ]
    );
    assert_eq!(
        steps[0]["with"]["persist-credentials"].as_str(),
        Some("false")
    );
    // Every `uses:` is the pin table's SHA with the version as a comment.
    let pins = brakes::modules::stack_packs::PinTable::embedded().unwrap();
    for line in text
        .lines()
        .filter(|l| l.trim_start().starts_with("uses: "))
    {
        let value = line.trim_start().trim_start_matches("uses: ");
        let (repo, rest) = value.split_once('@').unwrap();
        assert_eq!(value, pins.action(repo).unwrap().uses(), "{line}");
        assert_eq!(rest.split(' ').next().unwrap().len(), 40, "{line}");
    }
    for step in steps {
        let run = step["run"].as_str().unwrap_or("");
        assert!(
            !run.contains("verify") || run.contains("go mod verify"),
            "{run}"
        );
        assert!(!run.contains(VERIFY), "{run}");
    }
    assert!(
        !text.contains("cargo test"),
        "never runs the declared verify"
    );
    actionlint(text);
}

/// Runs `actionlint` on the rendered workflow when the tool is on PATH; reports
/// the skip otherwise (issue #749).
fn actionlint(text: &str) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".github/workflows/copilot-setup-steps.yml");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(&file, text).unwrap();
    match Command::new("actionlint")
        .arg(&file)
        .current_dir(dir.path())
        .output()
    {
        Ok(out) => assert!(
            out.status.success(),
            "actionlint: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(_) => {
            eprintln!("SKIPPED: actionlint is not on PATH; copilot-setup-steps.yml not linted")
        }
    }
}

#[test]
fn codex_setup_runs_the_pack_run_steps_in_sh() {
    let f = Fixture::new(Some(VERIFY));
    with_go_pack(&f);
    f.answer(json!({"agent_environments": ["codex"]}));
    let planned = plan_with_packs(&f).unwrap();
    let script = rendered(&planned, CODEX_SETUP_PATH);
    assert!(script.starts_with("#!/bin/sh\n"));
    assert!(script.contains("\nset -eu\n"));
    assert!(
        script.contains(
            "(\n  export GOFLAGS='-mod=readonly'\n  go mod download && go mod verify\n)\n"
        ),
        "{script}"
    );
    assert!(!script.contains("cargo test"), "never runs verify");
    assert!(!script.contains("uses:"));
}

#[test]
fn devcontainer_is_non_root_with_the_firewall_capabilities_and_no_host_secrets() {
    let f = Fixture::new(Some(VERIFY));
    with_go_pack(&f);
    f.answer(json!({"agent_environments": ["devcontainer"]}));
    let planned = plan_with_packs(&f).unwrap();
    let json: Value = serde_json::from_str(rendered(&planned, DEVCONTAINER_JSON_PATH)).unwrap();
    assert_eq!(
        json["runArgs"],
        json!(["--cap-add=NET_ADMIN", "--cap-add=NET_RAW"])
    );
    assert_eq!(json["remoteUser"], "node");
    assert_eq!(json["build"]["dockerfile"], "Dockerfile");
    assert_eq!(
        json["postStartCommand"],
        "sudo /usr/local/bin/init-firewall.sh"
    );
    for mount in json["mounts"].as_array().unwrap() {
        let mount = mount.as_str().unwrap();
        assert!(mount.contains("type=volume"), "only named volumes: {mount}");
        assert!(
            !mount.contains("localEnv") && !mount.contains("${env:HOME}"),
            "{mount}"
        );
    }
    let dockerfile = rendered(&planned, DEVCONTAINER_DOCKERFILE_PATH);
    let pins = brakes::modules::stack_packs::PinTable::embedded().unwrap();
    let from = dockerfile.lines().find(|l| l.starts_with("FROM ")).unwrap();
    assert_eq!(
        from,
        format!("FROM {}", pins.image("node.build").unwrap().pinned())
    );
    assert_eq!(
        dockerfile.lines().rfind(|l| l.starts_with("USER ")),
        Some("USER node")
    );
    assert!(!dockerfile.contains("latest"));
}

#[test]
fn firewall_allowlist_is_exactly_the_declared_hosts() {
    let f = Fixture::new(Some(VERIFY));
    with_go_pack(&f);
    f.answer(json!({
        "agent_environments": ["devcontainer"],
        "mcp_servers": ["docs"],
        "mcp_custom.tracker.transport": "http",
        "mcp_custom.tracker.url": "https://tracker.example/mcp",
        "mcp_custom.tracker.purpose": "File bugs in the in-house tracker",
    }));
    let planned = plan_with_packs(&f).unwrap();
    let mut expected: Vec<String> = BASE_HOSTS.iter().map(|h| (*h).to_owned()).collect();
    expected.extend(
        pack(StackId::Go)
            .egress_hosts
            .iter()
            .map(|h| (*h).to_owned()),
    );
    expected.push("tracker.example".to_owned());
    assert_eq!(
        firewall_hosts(rendered(&planned, INIT_FIREWALL_PATH)),
        expected
    );
    assert_eq!(
        BASE_HOSTS,
        [
            "github.com",
            "api.github.com",
            "api.anthropic.com",
            "claude.ai",
            "platform.claude.com"
        ]
    );
    assert_eq!(
        pack(StackId::Go).egress_hosts,
        ["proxy.golang.org", "sum.golang.org"]
    );
}

#[test]
fn firewall_without_stack_packs_allows_the_base_hosts_only() {
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({"agent_environments": ["devcontainer"]}));
    let planned = f.plan(&AgentGuardrails).unwrap();
    assert_eq!(
        firewall_hosts(rendered(&planned, INIT_FIREWALL_PATH)),
        BASE_HOSTS
    );
}

#[test]
fn environment_seeds_are_skipped_when_present_and_listed_by_remove() {
    let f = Fixture::new(Some(VERIFY));
    with_go_pack(&f);
    f.answer(all_environments());
    for path in ENVIRONMENT_SEEDS {
        f.write(path, "# the project's\n");
    }
    let planned = plan_with_packs(&f).unwrap();
    apply(&f.root, &planned.changes).unwrap();
    for path in ENVIRONMENT_SEEDS {
        assert!(!planned.changes.contains_key(path), "{path}");
        assert_eq!(
            note_line(&planned, path),
            format!("SKIP {path} [seed:agent-guardrails]")
        );
        assert_eq!(f.read(path), "# the project's\n", "{path} untouched");
    }
    assert!(f.root.join(COPILOT_SETUP_PATH).is_file());
    let again = plan_with_packs(&f).unwrap();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());

    let removed = remove_with_packs(&f).unwrap();
    assert_eq!(removed.changes.get(COPILOT_SETUP_PATH), Some(&None));
    for path in ENVIRONMENT_SEEDS {
        assert!(!removed.changes.contains_key(path), "{path}");
        assert_eq!(
            note_line(&removed, path),
            format!("KEEP {path} [seed:agent-guardrails]")
        );
    }
}

#[test]
fn an_mcp_host_outside_dns_name_characters_refuses_the_firewall() {
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({
        "agent_environments": ["devcontainer"],
        "mcp_custom.evil.transport": "http",
        "mcp_custom.evil.url": "https://a$(id).example/mcp",
        "mcp_custom.evil.purpose": "Injection probe",
    }));
    assert_eq!(
        f.plan(&AgentGuardrails).unwrap_err().to_string(),
        "Module agent-guardrails: MCP server url `https://a$(id).example/mcp` has no DNS host name the devcontainer firewall can allow"
    );
}

// ---- T13 (#940): cross-family review as a required check ---------------------------

use brakes::engine::manual::{Owner, Probe};
use brakes::modules::agent_guardrails::pins::{CLAUDE, CODEX, DEEPSEEK, Fact, REVIEWERS, Reviewer};
use brakes::modules::agent_guardrails::review::{self, CROSS_REVIEW, CROSS_REVIEW_MODEL};
use brakes::modules::ci_baseline::CiBaseline;
use brakes::modules::stack_packs::PinTable;

const CI_YML: &str = ".github/workflows/ci.yml";
const SEPARATE_YML: &str = ".github/workflows/agentic-security.yml";
const REVIEW_GOLDENS: &str = "../../templates/agent-guardrails/goldens";

/// A project with `verify` and `test` declared, planned with the real `ci-baseline`.
fn reviewed(answers: Value) -> Fixture {
    let f = Fixture::new(Some(VERIFY));
    let mut profile: Value = serde_json::from_str(&f.read(PROFILE)).unwrap();
    profile["commands"]["test"] = json!("cargo test --locked");
    f.write(
        PROFILE,
        &(serde_json::to_string_pretty(&profile).unwrap() + "\n"),
    );
    f.answer(answers);
    // These goldens are the deprecated generated `ci.yml` (#21): pinned until it migrates (#25).
    if !f.root.join(answers::path("ci-baseline")).exists() {
        let file = json!({"module": "ci-baseline", "version": "1.0.0", "answers": {"workflow": "generate"}});
        f.write(
            &answers::path("ci-baseline"),
            &serde_json::to_string_pretty(&file).unwrap(),
        );
    }
    f
}

fn plan_composed(f: &Fixture, guardrails: bool) -> Result<Planned> {
    let profile = profile_for(&f.root)?;
    let (core, packs, baseline, module, ci) = (
        SetupCore,
        StackPacks,
        RepoBaseline,
        AgentGuardrails,
        CiBaseline,
    );
    let mut list: Vec<&dyn Module> = vec![&core, &packs, &baseline];
    if guardrails {
        list.push(&module);
    }
    list.push(&ci);
    engine::plan(&f.root, &Source::embedded(), &profile, &list, &|_| true)
}

fn workflow_of(planned: &Planned, path: &str) -> String {
    planned.changes[path]
        .clone()
        .expect("the workflow is written")
}

/// Compares with `templates/agent-guardrails/goldens/<name>`; `UPDATE_GOLDENS=1` rewrites it.
fn review_golden(name: &str, text: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(REVIEW_GOLDENS)
        .join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with UPDATE_GOLDENS=1", path.display()));
    assert!(text == expected, "{name} differs from the golden:\n{text}");
}

/// The parsed workflow and its `cross-review` job.
fn parsed(text: &str) -> brakes::auditor::workflows::Workflow {
    brakes::auditor::workflows::parse(text).unwrap()
}

/// The text of job `id` as it sits under `jobs:`, up to the next job header.
fn job_text(text: &str, id: &str) -> String {
    let header = |line: &str| {
        line.starts_with("  ")
            && !line.starts_with("   ")
            && line.ends_with(':')
            && !line.trim().contains(' ')
    };
    let mut lines = text.lines().skip_while(|l| *l != format!("  {id}:"));
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("job {id} in\n{text}"));
    let body: Vec<&str> = std::iter::once(first)
        .chain(lines.take_while(|l| !header(l)))
        .collect();
    body.join("\n") + "\n"
}

/// The contract of "CI hardening for agent workflows": the model job holds
/// `contents: read` only, no cache and the reviewer as its last step, and emits the
/// verdict as its output; the gate job runs no model, checks out nothing, holds no
/// vendor secret and only `pull-requests: write`; both are in the aggregate's `needs`.
fn assert_the_contract(text: &str, aggregate: &str, reviewer: &Reviewer, runner: &str) {
    use brakes::auditor::workflows::Permissions;
    let wf = parsed(text);
    assert_eq!(
        wf.permissions,
        Some(Permissions::Scopes(
            [("contents".to_owned(), "read".to_owned())].into()
        )),
        "top-level permissions stay contents: read"
    );
    let always: Vec<&str> = wf
        .jobs
        .iter()
        .filter(|j| j.condition.as_deref() == Some("always()"))
        .map(|j| j.id.as_str())
        .collect();
    assert_eq!(always, [aggregate], "no second required check");
    let needs = &wf.job(aggregate).unwrap().needs;
    assert!(
        needs.contains(&CROSS_REVIEW_MODEL.to_owned()),
        "{aggregate} needs {CROSS_REVIEW_MODEL}"
    );
    assert!(
        needs.contains(&CROSS_REVIEW.to_owned()),
        "{aggregate} needs {CROSS_REVIEW}"
    );
    let tier = Some("needs.scope.outputs.tier != 'docs'");
    let pins = PinTable::embedded().unwrap();

    // The model job.
    let model = wf
        .job(CROSS_REVIEW_MODEL)
        .expect("a cross-review-model job");
    assert_eq!(model.needs, ["scope"]);
    assert_eq!(model.timeout_minutes.as_deref(), Some("15"));
    assert_eq!(model.runs_on, [runner]);
    assert_eq!(model.condition.as_deref(), tier);
    assert_eq!(
        model.permissions,
        Some(Permissions::Scopes(
            [("contents".to_owned(), "read".to_owned())].into()
        )),
        "the model job holds no write scope"
    );
    let model_text = job_text(text, CROSS_REVIEW_MODEL);
    assert!(
        model_text.contains("\n    cache-mode: none\n"),
        "{model_text}"
    );
    assert!(!model_text.contains("pull-requests"), "{model_text}");
    let Fact::Confirmed(output) = reviewer.findings_output else {
        panic!("confirmed")
    };
    assert!(
        model_text.contains(&format!(
            "\n    outputs:\n      verdict: \"${{{{ steps.review.outputs['{output}'] }}}}\"\n"
        )),
        "{model_text}"
    );
    let checkout = &model.steps[1];
    assert_eq!(
        checkout.uses.as_deref(),
        Some(format!("actions/checkout@{}", pins.actions["actions/checkout"].sha).as_str())
    );
    assert_eq!(
        checkout.with["ref"],
        "${{ github.event.pull_request.head.sha }}"
    );
    assert_eq!(checkout.with["persist-credentials"], "false");
    // #971: the egress limit comes right after the checkout, then the restore.
    assert_eq!(
        model.steps[2].env.get("EGRESS_USER").map(String::as_str),
        Some("agent-model")
    );
    let restore = &model.steps[3];
    assert_eq!(restore.run.as_deref(), Some(review::RESTORE_SH));
    assert_eq!(
        restore.env["BASE_SHA"],
        "${{ github.event.pull_request.base.sha }}"
    );
    let last = model.steps.last().unwrap();
    assert_eq!(
        last.id.as_deref(),
        Some("review"),
        "the reviewer is the last step"
    );
    if reviewer.family == "codex" {
        let action = format!("{}@{}", reviewer.action, pins.actions[reviewer.action].sha);
        assert_eq!(
            last.uses.as_deref(),
            Some(action.as_str()),
            "the reviewer's action, pinned by the pin table's SHA, is the last step"
        );
        let Fact::Confirmed(input) = reviewer.secret_input else {
            panic!("confirmed")
        };
        // #1095: the action holds a dummy key; the runner's filtering proxy holds the secret.
        assert_eq!(
            last.with[input],
            brakes::modules::agent_guardrails::MODEL_DUMMY_TOKEN
        );
        let readers: Vec<&str> = model
            .steps
            .iter()
            .filter(|s| {
                s.env
                    .values()
                    .chain(s.with.values())
                    .any(|v| v.contains("secrets."))
            })
            .filter_map(|s| s.run.as_deref())
            .collect();
        assert_eq!(readers.len(), 1, "one step reads a secret");
        assert!(readers[0].contains("model-proxy.py"));
    } else if reviewer.family == "deepseek" {
        // #1134: OpenCode as the model's user, holding a dummy key; only the runner's
        // proxy step reads the secret, and the verdict is checked before it leaves.
        assert_eq!(last.uses, None);
        assert_eq!(
            last.env["DEEPINFRA_API_KEY"],
            brakes::modules::agent_guardrails::MODEL_DUMMY_TOKEN
        );
        let run = last.run.as_deref().unwrap();
        assert!(
            run.contains("opencode run --format json --agent review"),
            "{run}"
        );
        assert!(run.contains(review::OPENCODE_VERDICT_SH), "{run}");
        let readers: Vec<&str> = model
            .steps
            .iter()
            .filter(|s| s.env.values().any(|v| v.contains("secrets.")))
            .filter_map(|s| s.run.as_deref())
            .collect();
        assert_eq!(readers.len(), 1, "one step reads a secret");
        assert!(readers[0].contains("model-proxy.py"));
        assert!(readers[0].contains(" deepinfra "), "{}", readers[0]);
    } else {
        // #971: the Claude reviewer is the pinned CLI as the model's user, holding
        // a dummy token; only the runner's proxy step reads the secret.
        assert_eq!(last.uses, None);
        assert_eq!(
            last.env["CLAUDE_CODE_OAUTH_TOKEN"],
            brakes::modules::agent_guardrails::MODEL_DUMMY_TOKEN
        );
        assert!(last.run.as_deref().unwrap().contains("claude -p"));
        let readers: Vec<&str> = model
            .steps
            .iter()
            .filter(|s| s.env.values().any(|v| v.contains("secrets.")))
            .filter_map(|s| s.run.as_deref())
            .collect();
        assert_eq!(readers.len(), 1, "one step reads a secret");
        assert!(readers[0].contains("model-proxy.py"));
    }
    assert!(
        model
            .steps
            .iter()
            .all(|s| s.run.as_deref() != Some(review::GATE_SH)),
        "no gate in the model job"
    );

    // The gate job.
    let gate = wf.job(CROSS_REVIEW).expect("a cross-review job");
    assert_eq!(gate.needs, ["scope", CROSS_REVIEW_MODEL]);
    assert_eq!(gate.timeout_minutes.as_deref(), Some("5"));
    assert_eq!(gate.condition.as_deref(), tier);
    assert_eq!(
        gate.permissions,
        Some(Permissions::Scopes(
            [("pull-requests".to_owned(), "write".to_owned())].into()
        )),
        "the gate job holds pull-requests: write and nothing else"
    );
    let gate_text = job_text(text, CROSS_REVIEW);
    assert!(
        gate_text.contains("\n    cache-mode: none\n"),
        "{gate_text}"
    );
    assert!(
        !gate_text.contains("secrets."),
        "no vendor secret in the gate job"
    );
    assert!(
        !gate_text.contains("uses:"),
        "no checkout, no action in the gate job"
    );
    assert_eq!(gate.steps.len(), 1, "one step: the gate");
    let step = &gate.steps[0];
    assert_eq!(step.run.as_deref(), Some(review::GATE_SH));
    assert_eq!(
        step.env["FINDINGS"],
        format!("${{{{ needs.{CROSS_REVIEW_MODEL}.outputs.verdict }}}}")
    );
    assert_eq!(step.env["VERDICT_MAX_BYTES"], "60000");
    assert_eq!(step.env["GH_TOKEN"], "${{ github.token }}");

    // Every step of both jobs but the fork refusal is gated to pull requests.
    assert!(text.contains("if: github.event_name == 'pull_request'"));
    assert!(!text.contains("secrets.GITHUB_TOKEN"));
}

#[test]
fn golden_cross_review_codex_is_a_job_of_required() {
    let f = reviewed(json!({}));
    let planned = plan_composed(&f, true).unwrap();
    let text = workflow_of(&planned, CI_YML);
    review_golden("cross-review-codex.yml", &text);
    assert_the_contract(&text, "required", &CODEX, "ubuntu-24.04");
    let wf = parsed(&text);
    let step = wf
        .job(CROSS_REVIEW_MODEL)
        .unwrap()
        .steps
        .iter()
        .find(|s| {
            s.uses
                .as_deref()
                .is_some_and(|u| u.starts_with("openai/codex-action@"))
        })
        .unwrap();
    let pins = PinTable::embedded().unwrap();
    assert_eq!(
        step.with["codex-version"],
        pins.tool("codex").unwrap().version
    );
    assert_eq!(step.with["permission-profile"], ":read-only");
    assert!(
        text.contains(
            "DOCS_SKIPPABLE: |-\n            checks\n            heldout\n            cross-review-model\n            cross-review\n"
        ),
        "{text}"
    );
    assert!(text.contains("BLOCKING: P0 P1\n"));
    let notes: Vec<String> = planned.plan_notes.iter().map(|n| n.to_string()).collect();
    for id in [CROSS_REVIEW_MODEL, CROSS_REVIEW] {
        assert!(
            notes.contains(&format!(
                "NOTE [ci-baseline] JOB [agent-guardrails] {id} → {CI_YML}"
            )),
            "{notes:?}"
        );
    }
}

#[test]
fn golden_cross_review_claude_runs_on_the_answered_runner_with_its_turn_cap() {
    let f = reviewed(json!({"review_family": "claude", "review_blocking": "p0"}));
    let text = workflow_of(&plan_composed(&f, true).unwrap(), CI_YML);
    review_golden("cross-review-claude.yml", &text);
    assert_the_contract(
        &text,
        "required",
        &CLAUDE,
        &configured::linux_runner().label,
    );
    let wf = parsed(&text);
    // #971: the Claude reviewer is the CLI as agent-model; its caps and schema are
    // on the line the model's user runs, and it gets no GitHub token at all.
    let step = wf
        .job(CROSS_REVIEW_MODEL)
        .unwrap()
        .steps
        .iter()
        .find(|s| s.id.as_deref() == Some("review"))
        .unwrap();
    let run = step.run.as_deref().unwrap();
    assert!(run.contains("--max-turns 30 "), "{run}");
    assert!(run.contains("--json-schema \"$SCHEMA\""), "{run}");
    assert_eq!(step.env["SCHEMA"], review::SCHEMA.trim_end());
    assert!(!step.env.contains_key("GH_TOKEN") && !step.env.contains_key("GITHUB_TOKEN"));
    assert!(text.contains("BLOCKING: P0\n"));
}

/// #1301: OpenCode's `grep` and `glob` run ripgrep. OpenCode 1.19.5 takes `rg` from
/// `PATH`, else downloads ripgrep 15.1.0 from GitHub
/// (packages/core/src/ripgrep/binary.ts at v1.19.5); the runner images ship none
/// and the model's user cannot reach GitHub, so both tools failed on every review.
/// The job installs that exact ripgrep by checksum, as the runner, on `sudo`'s
/// `secure_path`, before the model starts; egress stays closed.
#[test]
fn deepseek_review_installs_the_ripgrep_opencode_would_download() {
    let f = reviewed(json!({"review_family": "deepseek"}));
    let text = workflow_of(&plan_composed(&f, true).unwrap(), CI_YML);
    let wf = parsed(&text);
    let job = wf.job(CROSS_REVIEW_MODEL).unwrap();
    let pins = PinTable::embedded().unwrap();
    let ripgrep = pins.tool("ripgrep").expect("ripgrep is pinned");
    assert_eq!(
        ripgrep.version, "15.1.0",
        "the version OpenCode 1.19.5 downloads"
    );
    let at = job
        .steps
        .iter()
        .position(|s| s.env.get("TOOL_NAME").map(String::as_str) == Some("ripgrep"))
        .expect("the ripgrep install");
    let install = &job.steps[at];
    let mut expected = pins.tool_binary("ripgrep").unwrap();
    expected.sort();
    for (key, value) in expected {
        assert_eq!(install.env.get(key), Some(&value), "{key}");
    }
    assert_eq!(
        install.env["TOOL_URL_AMD64"],
        "https://github.com/BurntSushi/ripgrep/releases/download/15.1.0/ripgrep-15.1.0-x86_64-unknown-linux-musl.tar.gz"
    );
    let run = install.run.as_deref().unwrap();
    assert!(
        run.contains(brakes::modules::security::INSTALL_TOOL.trim_end()),
        "{run}"
    );
    assert!(
        run.ends_with("sudo install -m 0755 \"${RUNNER_TEMP}/brakes-bin/rg\" /usr/local/bin/rg\n/usr/local/bin/rg --version\n"),
        "{run}"
    );
    let review = job
        .steps
        .iter()
        .position(|s| s.id.as_deref() == Some("review"))
        .unwrap();
    let egress = job
        .steps
        .iter()
        .rposition(|s| {
            s.run
                .as_deref()
                .is_some_and(|r| r.contains("egress-reject"))
        })
        .unwrap();
    assert!(
        at < egress && at < review,
        "installed before egress and the model"
    );
    // The other families run no OpenCode and install no ripgrep.
    for family in ["claude", "codex"] {
        let f = reviewed(json!({"review_family": family}));
        let text = workflow_of(&plan_composed(&f, true).unwrap(), CI_YML);
        assert!(!text.contains("TOOL_NAME: \"ripgrep\""), "{family}");
    }
}

#[test]
fn golden_cross_review_deepseek_runs_opencode_through_the_proxy() {
    let f = reviewed(json!({"review_family": "deepseek"}));
    let text = workflow_of(&plan_composed(&f, true).unwrap(), CI_YML);
    review_golden("cross-review-deepseek.yml", &text);
    assert_the_contract(
        &text,
        "required",
        &DEEPSEEK,
        &configured::linux_runner().label,
    );
    let wf = parsed(&text);
    let job = wf.job(CROSS_REVIEW_MODEL).unwrap();
    let pins = PinTable::embedded().unwrap();
    let install = job
        .steps
        .iter()
        .find(|s| s.run.as_deref().is_some_and(|r| r.contains("opencode-ai@")))
        .expect("the OpenCode install");
    assert_eq!(
        install.run.as_deref().unwrap(),
        format!(
            "sudo npm install -g --no-fund --no-audit \"opencode-ai@{}\"",
            pins.tool("opencode").unwrap().version
        )
    );
    let review = job.steps.last().unwrap();
    for (flag, value) in [
        ("OPENCODE_DISABLE_PROJECT_CONFIG", "1"),
        ("OPENCODE_DISABLE_MODELS_FETCH", "1"),
        ("OPENCODE_DISABLE_AUTOUPDATE", "1"),
        ("OPENCODE_DISABLE_LSP_DOWNLOAD", "1"),
        ("OPENCODE_DISABLE_DEFAULT_PLUGINS", "1"),
        ("OPENCODE_DISABLE_CLAUDE_CODE", "1"),
        ("OPENCODE_DISABLE_EXTERNAL_SKILLS", "1"),
    ] {
        assert_eq!(
            review.env.get(flag).map(String::as_str),
            Some(value),
            "{flag}"
        );
    }
    // The configuration: one provider at the proxy, the one model, the review agent's
    // caps and read-only permissions; the base URL is filled in at run time.
    let config: Value = serde_json::from_str(&review.env["OPENCODE_REVIEW_CONFIG"]).unwrap();
    assert_eq!(config["model"], "deepinfra/deepseek-ai/DeepSeek-V4-Pro");
    assert_eq!(config["small_model"], config["model"]);
    assert_eq!(config["enabled_providers"], json!(["deepinfra"]));
    assert_eq!(config["share"], "disabled");
    let provider = &config["provider"]["deepinfra"];
    assert_eq!(provider["npm"], "@ai-sdk/openai-compatible");
    assert_eq!(provider["options"]["apiKey"], "{env:DEEPINFRA_API_KEY}");
    assert_eq!(provider["options"]["baseURL"], "MODEL_PROXY_BASE_URL");
    let agent = &config["agent"]["review"];
    assert_eq!(agent["steps"], json!(review::MAX_TURNS));
    for permission in [&config["permission"], &agent["permission"]] {
        assert_eq!(permission["*"], "deny");
        for denied in ["webfetch", "websearch", "edit", "task"] {
            assert_eq!(permission[denied], "deny", "{denied}");
        }
        for allowed in ["read", "grep", "glob", "list"] {
            assert_eq!(permission[allowed], "allow", "{allowed}");
        }
        assert_eq!(
            permission["bash"],
            json!({"*": "deny", "git diff *": "allow", "git log *": "allow", "git show *": "allow"})
        );
        // #1144: the reviewer reads the pull request's description in its context
        // directory, and nothing else outside the checkout (measured: a review that
        // could not read it stopped without a verdict).
        // #1223: and the output OpenCode cut at its 2000-line / 50 KB limit, which it
        // saves under its data directory and tells the model to read with offset and
        // limit (packages/opencode/src/tool/truncate.ts at v1.19.5); the deny of every
        // other directory came later and so overrode OpenCode's own allow of it.
        assert_eq!(
            permission["external_directory"],
            json!({
                "*": "deny",
                "/home/agent-model/context/*": "allow",
                "/home/agent-model/.local/share/opencode/tool-output/*": "allow"
            })
        );
    }
    let run = review.run.as_deref().unwrap();
    assert!(
        run.contains("http://127.0.0.1:$MODEL_PROXY_PORT/v1/openai"),
        "{run}"
    );
    assert!(!review.env.contains_key("GH_TOKEN") && !review.env.contains_key("GITHUB_TOKEN"));
    // #1144: the proxy is given the verdict's schema, and the verdict step names it.
    let proxy_step = job
        .steps
        .iter()
        .find(|s| {
            s.run
                .as_deref()
                .is_some_and(|r| r.contains("model-proxy.py"))
        })
        .unwrap();
    assert!(
        proxy_step
            .run
            .as_deref()
            .unwrap()
            .contains("\"$port_file\" deepinfra \"$RUNNER_TEMP/cross-review/schema.json\" <<<"),
        "{}",
        proxy_step.run.as_deref().unwrap()
    );
    assert!(
        run.contains("VERDICT_SCHEMA_FILE=\"$RUNNER_TEMP/cross-review/schema.json\""),
        "{run}"
    );
    // #1240: the step budget follows the change, counted by the runner in its own
    // checkout between the event's base and head, from the floor to the hard cap; it
    // becomes the agent's `steps` and the verdict step's cap, so a run that used it
    // all is still marked incomplete (#1223).
    assert!(run.contains(review::OPENCODE_BUDGET_SH), "{run}");
    assert!(
        run.contains(&format!(
            "cap=$(REPO_DIR=\"$GITHUB_WORKSPACE\" OPENCODE_STEP_FLOOR={} OPENCODE_STEP_MAX={} bash \"$RUNNER_TEMP/opencode-budget.sh\")",
            review::OPENCODE_STEP_FLOOR,
            review::OPENCODE_STEP_MAX
        )),
        "{run}"
    );
    assert!(
        run.contains("--argjson steps \"$cap\" '.provider.deepinfra.options.baseURL = $url | .agent.review.steps = $steps'"),
        "{run}"
    );
    assert!(run.contains("OPENCODE_STEP_CAP=\"$cap\" "), "{run}");
    assert!(!run.contains("OPENCODE_STEP_CAP=30"), "{run}");
    assert_eq!(
        review.env.get("BASE_SHA").map(String::as_str),
        Some("${{ github.event.pull_request.base.sha }}")
    );
    assert_eq!(
        review.env.get("HEAD_SHA").map(String::as_str),
        Some("${{ github.event.pull_request.head.sha }}")
    );
    // #1141: the prompt asks for what the verdict step accepts.
    assert!(
        review.env["PROMPT"].contains(review::OPENCODE_ANSWER_SHAPE),
        "{}",
        review.env["PROMPT"]
    );
    // The model's user writes only its own directories: the runner's XDG_CONFIG_HOME
    // reached OpenCode in the first real run (#1137) and it stopped on EACCES.
    for dir in [
        "HOME=/home/agent-model ",
        "XDG_CONFIG_HOME=/home/agent-model/.config ",
        "XDG_DATA_HOME=/home/agent-model/.local/share ",
        "XDG_CACHE_HOME=/home/agent-model/.cache ",
        "XDG_STATE_HOME=/home/agent-model/.local/state ",
    ] {
        assert!(run.contains(dir), "{dir}: {run}");
    }
}

#[test]
fn golden_cross_review_under_workflow_existing_joins_agentic_required() {
    let f = reviewed(json!({}));
    f.write(
        ".github/workflows/orchestration.yml",
        "name: Orchestration\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  rust:\n    name: Rust (linux)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n      - run: echo verify\n",
    );
    f.write(
        &answers::path("ci-baseline"),
        &ci_baseline_answers(json!({"workflow": "existing", "aggregate_check": "Rust (linux)"})),
    );
    let planned = plan_composed(&f, true).unwrap();
    assert!(!planned.changes.contains_key(CI_YML));
    let text = workflow_of(&planned, SEPARATE_YML);
    review_golden("cross-review-existing.yml", &text);
    assert_the_contract(&text, "agentic-required", &CODEX, "ubuntu-24.04");
}

/// The answers file of `ci-baseline` with `answers`.
fn ci_baseline_answers(answers: Value) -> String {
    AnswersFile {
        module: "ci-baseline".to_owned(),
        version: "1.0.0".to_owned(),
        profile: None,
        answers: serde_json::from_value(answers).unwrap(),
    }
    .to_json_string()
    .unwrap()
}

/// "CI hardening for agent workflows": `cache-mode: none` is a key actionlint
/// 1.7.12 rejects (rhysd/actionlint#762), so ci-baseline's actionlint configuration
/// ignores exactly that message wherever a model job is rendered, on every runner;
/// the configured self-hosted label stays its other reason to exist, and without either reason
/// no configuration is rendered.
#[test]
fn the_actionlint_config_ignores_cache_mode_wherever_a_model_job_is_rendered() {
    const CONFIG: &str = ".github/actionlint.yaml";
    const IGNORE: &str = "paths:\n  .github/workflows/**/*.{yml,yaml}:\n    ignore:\n      # actionlint 1.7.12 rejects the `cache-mode` job key GitHub enforces\n      # (rhysd/actionlint#762); the ignore leaves with the actionlint bump that accepts it.\n      - 'unexpected key \"cache-mode\"'\n";
    let f = reviewed(json!({}));
    let self_hosted = plan_composed(&f, true).unwrap().changes[CONFIG]
        .clone()
        .unwrap();
    review_golden("cross-review-actionlint.yaml", &self_hosted);
    let label = configured::linux_runner().label;
    assert!(
        self_hosted.contains(&format!("self-hosted-runner:\n  labels:\n    - {label}\n")),
        "{self_hosted}"
    );
    assert!(self_hosted.ends_with(IGNORE), "{self_hosted}");
    assert_eq!(self_hosted.matches("cache-mode").count(), 2, "one ignore");

    let f = reviewed(json!({}));
    f.write(
        &answers::path("ci-baseline"),
        &ci_baseline_answers(json!({"runner": "github"})),
    );
    let github = plan_composed(&f, true).unwrap().changes[CONFIG]
        .clone()
        .unwrap();
    assert!(!github.contains("self-hosted-runner"), "{github}");
    assert!(github.ends_with(IGNORE), "{github}");

    let f = reviewed(json!({"review_family": "none"}));
    f.write(
        &answers::path("ci-baseline"),
        &ci_baseline_answers(json!({"runner": "github"})),
    );
    assert!(
        !plan_composed(&f, true)
            .unwrap()
            .changes
            .contains_key(CONFIG),
        "no reason to render the configuration"
    );
}

#[test]
fn review_family_none_renders_nothing() {
    let f = reviewed(json!({"review_family": "none"}));
    let with = plan_composed(&f, true).unwrap();
    let without = plan_composed(&f, false).unwrap();
    assert_eq!(workflow_of(&with, CI_YML), workflow_of(&without, CI_YML));
    assert!(!workflow_of(&with, CI_YML).contains(CROSS_REVIEW));
    assert!(!workflow_of(&with, CI_YML).contains(CROSS_REVIEW_MODEL));
    assert!(
        !with.steps.iter().any(|s| s.id == "review-secret-present"),
        "no secret step without a reviewer"
    );
}

#[test]
fn the_secret_steps_name_both_stores_and_probe_names_only() {
    for (answers, secret) in [
        (json!({}), "OPENAI_API_KEY"),
        (
            json!({"review_family": "claude"}),
            "CLAUDE_CODE_OAUTH_TOKEN",
        ),
        (json!({"review_family": "deepseek"}), "DEEPINFRA_API_KEY"),
    ] {
        let steps = review::steps(&serde_json::from_value::<Answers>(answers).unwrap());
        let ids: Vec<&str> = steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            ["review-secret-present", "review-dependabot-secret-present"]
        );
        let actions = format!("gh secret set {secret} --repo <owner>/<repo>");
        let dependabot = format!("gh secret set {secret} --app dependabot --repo <owner>/<repo>");
        for step in &steps {
            assert_eq!(step.owner, Owner::Owner);
            assert!(
                step.instructions.contains(&actions),
                "{}",
                step.instructions
            );
            assert!(
                step.instructions.contains(&dependabot),
                "{}",
                step.instructions
            );
        }
        for (step, scope) in steps.iter().zip(["repository", "dependabot"]) {
            assert_eq!(
                step.probe,
                Probe::Remote {
                    id: "secret-present".to_owned(),
                    args: [
                        ("name".to_owned(), json!(secret)),
                        ("scope".to_owned(), json!(scope)),
                    ]
                    .into(),
                }
            );
        }
    }
}

/// #1320 (owner, 2026-11-01): `review_environment` puts the model job in a GitHub
/// environment, so the reviewer's key is an environment secret, never a repository
/// one beside `production`. Unset, the workflow is the golden's, byte for byte.
#[test]
fn review_environment_puts_only_the_model_job_in_that_environment() {
    let q = AgentGuardrails.questions();
    let question = q.question("review_environment").unwrap();
    assert_eq!(question.default, None, "unset by default");
    assert_eq!(
        question.when,
        Some(answers::When::Ne(
            "review_family".to_owned(),
            "none".to_owned()
        ))
    );
    let f = reviewed(json!({"review_family": "deepseek", "review_environment": "ci-review"}));
    let text = workflow_of(&plan_composed(&f, true).unwrap(), CI_YML);
    let wf = parsed(&text);
    assert_eq!(
        wf.job(CROSS_REVIEW_MODEL).unwrap().environment.as_deref(),
        Some("ci-review")
    );
    assert_eq!(wf.job(CROSS_REVIEW).unwrap().environment, None);
    assert!(
        job_text(&text, CROSS_REVIEW_MODEL).contains("\n    environment: ci-review\n"),
        "{text}"
    );
    let unset = reviewed(json!({"review_family": "deepseek"}));
    let golden = workflow_of(&plan_composed(&unset, true).unwrap(), CI_YML);
    assert_eq!(
        text.replace("    environment: ci-review\n", ""),
        golden,
        "the answer adds one line and nothing else"
    );
}

#[test]
fn review_environment_moves_the_actions_secret_step_to_that_environment() {
    let answers: Answers = serde_json::from_value(
        json!({"review_family": "deepseek", "review_environment": "ci-review"}),
    )
    .unwrap();
    let steps = review::steps(&answers);
    let scopes: Vec<(&str, Value)> = steps
        .iter()
        .map(|s| match &s.probe {
            Probe::Remote { args, .. } => (s.id.as_str(), args["scope"].clone()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        scopes,
        [
            ("review-secret-present", json!("environment:ci-review")),
            ("review-dependabot-secret-present", json!("dependabot")),
        ]
    );
    for step in &steps {
        assert!(
            step.instructions
                .contains("gh secret set DEEPINFRA_API_KEY --env ci-review --repo <owner>/<repo>"),
            "{}",
            step.instructions
        );
        assert!(
            step.instructions
                .contains("gh secret set DEEPINFRA_API_KEY --app dependabot --repo <owner>/<repo>"),
            "{}",
            step.instructions
        );
    }
    assert_eq!(
        steps[0].title,
        "Create the DEEPINFRA_API_KEY secret for cross-review in the ci-review environment's secrets"
    );
}

#[test]
fn a_review_environment_that_could_break_the_workflow_refuses() {
    for name in [
        "ci review",
        "x\n  permissions: write-all",
        "${{ github.ref }}",
        "",
        &"e".repeat(256),
    ] {
        let f = reviewed(json!({"review_environment": name}));
        assert_eq!(
            plan_composed(&f, true).unwrap_err().to_string(),
            format!(
                "Module agent-guardrails: review_environment `{name}` must be 1 to 255 letters, digits and . _ -"
            ),
            "{name:?}"
        );
    }
}

#[test]
fn dependabot_is_the_one_bot_allowed_and_forks_fail_closed() {
    for answers in [
        json!({}),
        json!({"review_family": "claude"}),
        json!({"review_family": "deepseek"}),
    ] {
        let f = reviewed(answers.clone());
        let text = workflow_of(&plan_composed(&f, true).unwrap(), CI_YML);
        let wf = parsed(&text);
        let job = wf.job(CROSS_REVIEW_MODEL).unwrap();
        if answers.get("review_family").is_none() {
            let review = job
                .steps
                .iter()
                .find(|s| s.with.contains_key("prompt"))
                .unwrap();
            assert_eq!(review.with["allow-bot-users"], "dependabot[bot]");
        } else {
            // #971: the CLI has no actor check, so the job keeps the action's.
            let check = job
                .steps
                .iter()
                .find(|s| s.env.contains_key("ACTOR"))
                .expect("the actor check");
            assert_eq!(check.env["ALLOWED_BOT"], "dependabot[bot]");
            assert_eq!(check.env["ACTOR"], "${{ github.actor }}");
        }
        let fork = &job.steps[0];
        let run = fork.run.as_deref().unwrap();
        assert!(
            run.contains("::error::cross-review: pull requests from forks are not reviewed"),
            "{run}"
        );
        assert!(run.trim_end().ends_with("exit 1"), "{run}");
        assert!(text.contains(
            "if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository"
        ));
    }
}

#[test]
fn vendor_facts_are_dated_sourced_and_pinned() {
    let pins = PinTable::embedded().unwrap();
    assert_eq!(REVIEWERS.len(), 3);
    for reviewer in &REVIEWERS {
        // An action is pinned by SHA; a CLI the job installs, by exact version.
        assert!(
            pins.actions.contains_key(reviewer.action) || pins.tool(reviewer.action).is_ok(),
            "{}",
            reviewer.action
        );
        assert!(chrono::NaiveDate::parse_from_str(reviewer.verified, "%Y-%m-%d").is_ok());
        assert!(!reviewer.sources.is_empty());
        assert!(reviewer.sources.iter().all(|s| s.starts_with("https://")));
        review::confirmed(reviewer).unwrap();
    }
    assert_eq!(
        (CODEX.family, CODEX.action, CODEX.secret),
        ("codex", "openai/codex-action", "OPENAI_API_KEY")
    );
    assert_eq!(
        (CLAUDE.family, CLAUDE.action, CLAUDE.secret),
        (
            "claude",
            "anthropics/claude-code-action",
            "CLAUDE_CODE_OAUTH_TOKEN"
        )
    );
    // #1134: DeepSeek V4 Pro on DeepInfra, run by the pinned OpenCode CLI.
    assert_eq!(
        (DEEPSEEK.family, DEEPSEEK.action, DEEPSEEK.secret),
        ("deepseek", "opencode", "DEEPINFRA_API_KEY")
    );
    assert_eq!(pins.tool("opencode").unwrap().version, "1.19.5");
    assert_eq!(DEEPSEEK.fails_on_findings, Fact::Confirmed(false));
    assert_eq!(DEEPSEEK.turn_limit, Fact::Confirmed(Some("steps")));
    assert_eq!(DEEPSEEK.github_hosted, Fact::Confirmed(false));
    assert_eq!(DEEPSEEK.extra_read_scope, Fact::Confirmed(None));
    // Neither action fails the job on findings: the gate step parses their output.
    assert_eq!(CODEX.fails_on_findings, Fact::Confirmed(false));
    assert_eq!(CLAUDE.fails_on_findings, Fact::Confirmed(false));
    assert_eq!(CLAUDE.turn_limit, Fact::Confirmed(Some("--max-turns")));
    assert_eq!(CODEX.turn_limit, Fact::Confirmed(None));
    // Both prepare with `contents: read` alone (metadata reads only); a read scope
    // recorded here would be rendered into the model job, never a write scope.
    assert_eq!(CODEX.extra_read_scope, Fact::Confirmed(None));
    assert_eq!(CLAUDE.extra_read_scope, Fact::Confirmed(None));
    assert!(
        brakes::modules::agent_guardrails::pins::GITHUB_SOURCES
            .iter()
            .all(|s| s.starts_with("https://docs.github.com/"))
    );
}

/// A reviewer whose preparation needs one more read scope renders it, and only a
/// read: the model job never holds a write token.
#[test]
fn a_recorded_extra_read_scope_reaches_the_model_job_as_a_read() {
    let needy = Reviewer {
        extra_read_scope: Fact::Confirmed(Some("pull-requests")),
        ..CLAUDE
    };
    let pins = PinTable::embedded().unwrap();
    let jobs = review::jobs(&needy, "P0", "ubuntu-24.04", None, &pins).unwrap();
    assert_eq!(jobs[0].id, CROSS_REVIEW_MODEL);
    assert!(
        jobs[0]
            .yaml
            .contains("permissions:\n  contents: read\n  pull-requests: read\ncache-mode: none\n"),
        "{}",
        jobs[0].yaml
    );
    // No write scope: no `<scope>: write` line anywhere in the job (the actor check
    // and curl's --write-out mention the word, never as a scope).
    assert!(
        !jobs[0]
            .yaml
            .lines()
            .any(|l| l.trim_end().ends_with(": write")),
        "{}",
        jobs[0].yaml
    );
    assert!(
        jobs[1]
            .yaml
            .contains("permissions:\n  pull-requests: write\ncache-mode: none\n")
    );
}

#[test]
fn an_unconfirmed_vendor_fact_refuses_at_render_time() {
    let guessed = Reviewer {
        fails_on_findings: Fact::Unconfirmed,
        ..CODEX
    };
    let pins = PinTable::embedded().unwrap();
    assert_eq!(
        review::jobs(&guessed, "P0 P1", "ubuntu-24.04", None, &pins)
            .unwrap_err()
            .to_string(),
        "Module agent-guardrails: reviewer codex: fails_on_findings is not confirmed in the vendor facts; verify it against the vendor's documentation before rendering cross-review"
    );
    let guessed = Reviewer {
        secret_input: Fact::Unconfirmed,
        ..CLAUDE
    };
    assert!(
        review::jobs(&guessed, "P0", "ubuntu-24.04", None, &pins)
            .unwrap_err()
            .to_string()
            .contains("secret_input is not confirmed")
    );
}

// `agents.cross-review` (Silver, all profiles) and the secret step against a host.

#[test]
fn agents_cross_review_passes_with_the_job_in_the_aggregate() {
    let repo = Repo::new("cargo test --locked");
    repo.generate();
    assert!(repo.install(&["--apply"]).status.success());
    let ci = fs::read_to_string(repo.root.join(CI_YML)).unwrap();
    assert!(ci.contains("\n  cross-review-model:\n"), "{ci}");
    assert!(ci.contains("\n  cross-review:\n"), "{ci}");
    let lines = repo.doctor();
    assert_eq!(
        rule_lines(&lines, "agents.cross-review"),
        Vec::<&str>::new(),
        "{lines:#?}"
    );
}

#[test]
fn agents_cross_review_fails_without_a_reviewer() {
    let repo = Repo::new("cargo test --locked");
    let file = json!({"module": "agent-guardrails", "version": "1.0.0", "answers": {"review_family": "none"}});
    repo.write_json(&answers::path("agent-guardrails"), &file);
    assert!(repo.install(&["--apply"]).status.success());
    assert!(
        !fs::read_to_string(repo.root.join(CI_YML))
            .unwrap()
            .contains("cross-review")
    );
    assert_eq!(
        rule_lines(&repo.doctor(), "agents.cross-review"),
        [
            "WARNING: agents.cross-review: review_family is none; no other model family reviews pull requests (configure --set review_family=codex, claude or deepseek)"
        ]
    );
}

/// "CI hardening for agent workflows": the rule passes only when both ids are in
/// `needs`, and names the one that is missing.
#[test]
fn agents_cross_review_fails_when_the_aggregate_does_not_need_either_job() {
    for (from, to, missing) in [
        (", cross-review]", "]", "cross-review"),
        (", cross-review-model,", ",", "cross-review-model"),
    ] {
        let repo = Repo::new("cargo test --locked");
        repo.generate();
        assert!(repo.install(&["--apply"]).status.success());
        let path = repo.root.join(CI_YML);
        let ci = fs::read_to_string(&path).unwrap();
        let edited = ci.replace(from, to);
        assert_ne!(ci, edited, "{from}");
        fs::write(&path, edited).unwrap();
        assert_eq!(
            rule_lines(&repo.doctor(), "agents.cross-review"),
            [format!(
                "WARNING: agents.cross-review: no required or agentic-required job in .github/workflows needs {missing}; re-run install"
            )],
            "{from}"
        );
    }
}

/// Serves the secret names of the Actions or Dependabot store, and nothing else.
struct SecretNames(Vec<&'static str>);
impl brakes::remote::Api for SecretNames {
    fn get(&self, path: &str) -> brakes::Result<Value> {
        assert!(
            [
                "repos/example-owner/example/actions/secrets?per_page=100&page=1",
                "repos/example-owner/example/dependabot/secrets?per_page=100&page=1",
            ]
            .contains(&path),
            "{path}"
        );
        let secrets: Vec<Value> = self.0.iter().map(|n| json!({"name": n})).collect();
        Ok(json!({"total_count": secrets.len(), "secrets": secrets}))
    }
}

#[test]
fn review_secret_present_is_pending_until_the_secret_exists() {
    use brakes::engine::{ProbeResult, manual};
    use brakes::host::{CallBudget, RepoId, github::GitHub, probes::HostRunner};
    let f = Fixture::new(Some(VERIFY));
    let steps = review::steps(&Answers::new());
    let probe = |step: &brakes::engine::manual::ManualStep, names: Vec<&'static str>| {
        let api = SecretNames(names);
        let host = GitHub::new(&api, CallBudget::default());
        let runner = HostRunner::new(&host, RepoId::parse("example-owner/example").unwrap());
        manual::run(&f.root, &step.probe, &runner)
    };
    assert_eq!(
        probe(&steps[0], vec!["OTHER"]),
        ProbeResult::Pending("OPENAI_API_KEY is not listed in the repository".to_owned())
    );
    assert_eq!(
        probe(&steps[0], vec!["OPENAI_API_KEY"]),
        ProbeResult::Verified("OPENAI_API_KEY listed".to_owned())
    );
    assert_eq!(
        probe(&steps[1], vec![]),
        ProbeResult::Pending("OPENAI_API_KEY is not listed in the Dependabot secrets".to_owned())
    );
}

// ---- T14 (#946): unattended issue to pull request ----------------------------------

use brakes::modules::agent_guardrails::unattended::{self, WORKFLOW_PATH};

const UNATTENDED_PROMPT: &str = "Run /implement on the issue below.";

fn unattended_answers() -> Value {
    json!({"unattended": true, "unattended_prompt": UNATTENDED_PROMPT})
}

fn job<'a>(
    wf: &'a brakes::auditor::workflows::Workflow,
    id: &str,
) -> &'a brakes::auditor::workflows::Job {
    wf.job(id).unwrap_or_else(|| panic!("a job {id}"))
}

fn scopes(pairs: &[(&str, &str)]) -> Option<brakes::auditor::workflows::Permissions> {
    Some(brakes::auditor::workflows::Permissions::Scopes(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    ))
}

#[test]
fn golden_unattended_renders_agentic_implement_with_the_spec_caps() {
    let f = reviewed(unattended_answers());
    let planned = plan_composed(&f, true).unwrap();
    let text = workflow_of(&planned, WORKFLOW_PATH);
    review_golden("agentic-implement.yml", &text);
    assert_eq!(
        planned
            .tags
            .get(WORKFLOW_PATH)
            .map(|(c, m)| (*c, m.as_str())),
        Some((Ownership::Managed, "agent-guardrails"))
    );
    let wf = parsed(&text);
    assert_eq!(wf.triggers, ["issues"]);
    assert_eq!(wf.trigger_types["issues"], ["labeled"]);
    assert_eq!(wf.permissions, scopes(&[]), "nothing at the top level");
    assert_eq!(
        wf.concurrency.as_deref(),
        Some("agentic-implement-${{ github.event.issue.number }}")
    );
    let implement = job(&wf, "implement");
    assert_eq!(
        implement.condition.as_deref(),
        Some("github.event.label.name == 'agent:ready'")
    );
    assert_eq!(implement.timeout_minutes.as_deref(), Some("45"));
    assert_eq!(implement.runs_on, [configured::linux_runner().label]);
    // The agent's token reads only: it cannot push, label, approve or merge.
    assert_eq!(
        implement.permissions,
        scopes(&[("contents", "read"), ("issues", "read")])
    );
    // #971: the agent is the pinned Claude Code CLI as agent-model, not the action.
    assert!(
        implement.steps.iter().all(|s| !s
            .uses
            .as_deref()
            .is_some_and(|u| u.starts_with("anthropics/"))),
        "no Claude action"
    );
    let agent = implement
        .steps
        .iter()
        .find(|s| s.id.as_deref() == Some("agent"))
        .expect("the agent step");
    // #971: the agent holds a dummy token; the runner's proxy holds the secret.
    assert_eq!(
        agent.env["CLAUDE_CODE_OAUTH_TOKEN"],
        brakes::modules::agent_guardrails::MODEL_DUMMY_TOKEN
    );
    let run = agent.run.as_deref().unwrap();
    assert!(run.contains("--max-turns 60 "), "{run}");
    // No gh: the issue reaches the agent as it was when labelled, written by a step
    // before it, never later edits or comments; no write under .git.
    assert!(!run.contains("gh "), "{run}");
    // #1146: headless, so the human-approved prompt can never happen here: no
    // `gh` tool, no permission bypass, no prompt tool that could answer for a person.
    assert!(
        run.contains("claude -p ") || run.contains("--print"),
        "{run}"
    );
    for flag in [
        "Bash(gh",
        "--dangerously-skip-permissions",
        "bypassPermissions",
        "--permission-prompt-tool",
        "--permission-mode",
    ] {
        assert!(!run.contains(flag), "{flag} in {run}");
    }
    assert!(
        run.contains(
            "--disallowedTools \"Edit(./.git/**),Write(./.git/**),Read(//proc/**),Grep(//proc/**),Glob(//proc/**),Bash(git * --output*),Bash(git * -o *)\" --add-dir /home/agent-model/context"
        ),
        "{run}"
    );
    let snapshot = implement
        .steps
        .iter()
        .position(|s| {
            s.run
                .as_deref()
                .is_some_and(|r| r.contains("$RUNNER_TEMP/agentic-issue/issue.md"))
        })
        .expect("a step keeps the issue as labelled");
    let agent_at = implement
        .steps
        .iter()
        .position(|s| s.id.as_deref() == Some("agent"))
        .unwrap();
    assert!(snapshot < agent_at);
    assert!(text.contains("ISSUE_BODY: \"${{ github.event.issue.body }}\""));
    assert!(agent.env["PROMPT"].starts_with(&format!("{UNATTENDED_PROMPT}\n\nIssue #")));
    // The action's actor checks are kept, with no bot let past.
    let check = implement
        .steps
        .iter()
        .find(|s| s.env.contains_key("ACTOR"))
        .expect("the actor check");
    assert_eq!(check.env["ALLOWED_BOT"], "");
    assert!(text.contains("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: \"1\""));
    for checkout in wf.jobs.iter().flat_map(|j| &j.steps).filter(|s| {
        s.uses
            .as_deref()
            .is_some_and(|u| u.starts_with("actions/checkout@"))
    }) {
        assert_eq!(checkout.with["persist-credentials"], "false");
    }
    // Publish runs no agent and alone holds the write scopes.
    let publish = job(&wf, "publish");
    assert_eq!(publish.needs, ["implement"]);
    assert_eq!(
        publish.permissions,
        scopes(&[("contents", "write"), ("pull-requests", "write")])
    );
    assert!(publish.steps.iter().all(|s| {
        !s.uses
            .as_deref()
            .is_some_and(|u| u.starts_with("anthropics/") || u.starts_with("openai/"))
    }));
    let run = publish.steps.last().unwrap().run.as_deref().unwrap();
    assert!(run.contains("git merge-base --is-ancestor \"$BASE\" \"$head\""));
    assert!(run.contains("\"$head:refs/heads/$branch\""));
    assert!(run.contains("gh pr create"));
    assert!(!text.contains("pull_request_target"));
    assert!(!text.contains("secrets.GITHUB_TOKEN"));
    assert!(!text.contains("id-token"));
    assert_eq!(
        unattended::gated(WORKFLOW_PATH, &wf),
        Vec::<String>::new(),
        "the golden meets its own rule"
    );
}

/// #1079: `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` stays on, and Claude Code refuses to
/// start under it without bubblewrap, which the pinned action installs only for
/// non-write users. A step before the agent installs it (and socat) and lifts
/// Ubuntu 24.04's AppArmor limit on unprivileged user namespaces.
#[test]
fn agentic_implement_prepares_bubblewrap_before_the_agent_and_keeps_the_scrub() {
    let f = reviewed(unattended_answers());
    let text = workflow_of(&plan_composed(&f, true).unwrap(), WORKFLOW_PATH);
    let wf = parsed(&text);
    let implement = job(&wf, "implement");
    assert!(text.contains("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: \"1\""));
    let prepare = implement
        .steps
        .iter()
        .position(|s| {
            s.run.as_deref().is_some_and(|r| {
                // #971 (security review): an AppArmor profile for bwrap alone, never
                // the global userns sysctl.
                r.contains("sudo apt-get install -y --no-install-recommends bubblewrap socat")
                    && r.contains("profile agent-bwrap /usr/bin/bwrap")
                    && !r.contains("sysctl -w")
            })
        })
        .expect("a step installs bubblewrap and socat");
    let agent = implement
        .steps
        .iter()
        .position(|s| s.id.as_deref() == Some("agent"))
        .unwrap();
    assert!(
        prepare < agent,
        "bubblewrap is ready before the agent starts"
    );
}

/// "CI hardening for agent workflows", point 4 (#970): neither job of
/// agentic-implement restores or saves a cache entry. `cache-mode: none` sits on
/// each job, and no step uses `actions/cache` or passes a `cache:` input.
#[test]
fn agentic_implement_declares_cache_mode_none_on_both_jobs_and_no_cache() {
    let f = reviewed(unattended_answers());
    let text = workflow_of(&plan_composed(&f, true).unwrap(), WORKFLOW_PATH);
    for id in ["implement", "publish"] {
        let job = job_text(&text, id);
        assert_eq!(
            job.matches("\n    cache-mode: none\n").count(),
            1,
            "{id}:\n{job}"
        );
    }
    let wf = parsed(&text);
    for step in wf.jobs.iter().flat_map(|j| &j.steps) {
        assert!(
            !step
                .uses
                .as_deref()
                .is_some_and(|u| u.to_ascii_lowercase().starts_with("actions/cache")),
            "{:?}",
            step.uses
        );
        assert!(!step.with.contains_key("cache"), "{:?}", step.uses);
    }
}

/// #970: the guide states the approval-required state of the agent's pull-request
/// runs with GitHub's page and the date it was read, and that neither job caches.
#[test]
fn the_guide_states_the_approval_required_checks_with_source_and_date() {
    let planned = Fixture::new(Some(VERIFY)).plan(&AgentGuardrails).unwrap();
    let guide = planned.changes[GUIDE_PATH].as_deref().unwrap();
    let section = guide
        .split("## Unattended issue to pull request")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("the guide has the unattended section");
    for needle in [
        "approval-required",
        "Approve workflows to run",
        "https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow",
        "read 2026-10-29",
        "`opened`, `synchronize` and `reopened`",
        "`cache-mode: none`",
    ] {
        assert!(section.contains(needle), "{needle}");
    }
}

/// #970: with no reviewer, `agentic-implement.yml` is the only workflow with
/// `cache-mode`, so ci-baseline's actionlint configuration still ignores that one
/// message; without `unattended` it renders none on GitHub-hosted runners.
#[test]
fn the_actionlint_config_ignores_cache_mode_for_unattended_without_a_reviewer() {
    const CONFIG: &str = ".github/actionlint.yaml";
    let mut answers = unattended_answers();
    answers["review_family"] = json!("none");
    let f = reviewed(answers);
    f.write(
        &answers::path("ci-baseline"),
        &ci_baseline_answers(json!({"runner": "github"})),
    );
    let config = plan_composed(&f, true).unwrap().changes[CONFIG]
        .clone()
        .unwrap();
    assert!(!config.contains("self-hosted-runner"), "{config}");
    assert!(
        config.ends_with("      - 'unexpected key \"cache-mode\"'\n"),
        "{config}"
    );
}

#[test]
fn unattended_false_renders_no_workflow_and_no_step() {
    let f = reviewed(json!({}));
    let planned = plan_composed(&f, true).unwrap();
    assert!(!planned.changes.contains_key(WORKFLOW_PATH));
    assert!(
        !planned
            .steps
            .iter()
            .any(|s| s.id == "actions-open-pull-requests")
    );
}

#[test]
fn unattended_without_a_prompt_refuses_at_plan_time_naming_the_answer() {
    let f = reviewed(json!({"unattended": true}));
    assert_eq!(
        plan_composed(&f, true).unwrap_err().to_string(),
        "Module agent-guardrails: answer `unattended_prompt` is required and has no value"
    );
}

#[test]
fn a_label_or_prompt_that_could_inject_a_workflow_expression_refuses() {
    let f = reviewed(
        json!({"unattended": true, "unattended_prompt": UNATTENDED_PROMPT,
        "unattended_label": "x' || true || '"}),
    );
    assert_eq!(
        plan_composed(&f, true).unwrap_err().to_string(),
        "Module agent-guardrails: unattended_label `x' || true || '` may hold only letters, digits, spaces and : . _ / -"
    );
    let f = reviewed(json!({"unattended": true,
        "unattended_prompt": "Fix ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}"}));
    assert_eq!(
        plan_composed(&f, true).unwrap_err().to_string(),
        "Module agent-guardrails: unattended_prompt contains `${{`, a workflow expression; write the prompt as plain text"
    );
}

#[test]
fn a_custom_label_and_turn_cap_reach_the_workflow() {
    let f = reviewed(
        json!({"unattended": true, "unattended_prompt": "Use the implement skill.\nKeep the diff small.",
        "unattended_label": "agent: go", "unattended_max_turns": 25}),
    );
    let text = workflow_of(&plan_composed(&f, true).unwrap(), WORKFLOW_PATH);
    let wf = parsed(&text);
    assert_eq!(
        job(&wf, "implement").condition.as_deref(),
        Some("github.event.label.name == 'agent: go'")
    );
    let agent = job(&wf, "implement")
        .steps
        .iter()
        .find(|s| s.id.as_deref() == Some("agent"))
        .unwrap();
    assert!(agent.run.as_deref().unwrap().contains("--max-turns 25 "));
    assert!(
        agent.env["PROMPT"].starts_with("Use the implement skill.\nKeep the diff small.\n\n"),
        "{:?}",
        agent.env["PROMPT"]
    );
}

#[test]
fn unattended_steps_ask_for_the_secret_and_the_pull_request_setting() {
    let answers: Answers = serde_json::from_value(unattended_answers()).unwrap();
    let steps = unattended::steps(&answers);
    let ids: Vec<&str> = steps.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        ["unattended-secret-present", "actions-open-pull-requests"]
    );
    assert_eq!(
        steps[0].probe,
        Probe::Remote {
            id: "secret-present".to_owned(),
            args: [
                ("name".to_owned(), json!("CLAUDE_CODE_OAUTH_TOKEN")),
                ("scope".to_owned(), json!("repository")),
            ]
            .into(),
        }
    );
    assert_eq!(
        steps[1].probe,
        Probe::Remote {
            id: "actions-pull-requests".to_owned(),
            args: Default::default(),
        }
    );
    assert!(steps.iter().all(|s| s.owner == Owner::Owner));
    // The Claude reviewer already asks for the same secret in the same store.
    let mut claude = answers.clone();
    claude.insert("review_family".to_owned(), json!("claude"));
    let ids: Vec<String> = unattended::steps(&claude)
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(ids, ["actions-open-pull-requests"]);
}

// `agents.unattended-gated` (Silver, all profiles).

fn gated_findings(text: &str) -> Vec<String> {
    unattended::gated(WORKFLOW_PATH, &parsed(text))
}

fn golden_text() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(REVIEW_GOLDENS)
            .join("agentic-implement.yml"),
    )
    .unwrap()
}

#[test]
fn unattended_gated_fails_alongside_pull_request_target() {
    let text = golden_text().replace(
        "on:\n  issues:\n",
        "on:\n  pull_request_target:\n  issues:\n",
    );
    assert_eq!(
        gated_findings(&text),
        [
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: also triggers on pull_request_target; an unattended agent runs on issues.labeled alone"
        ]
    );
}

#[test]
fn unattended_gated_fails_without_caps() {
    let text = "name: hand-written\non:\n  issues:\n    types: [labeled, opened]\npermissions: write-all\njobs:\n  agent:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: anthropics/claude-code-action@d70510b174a1244958df0b03166a54912811f3e6\n        with:\n          prompt: go\n          allowed_non_write_users: \"*\"\n";
    assert_eq!(
        gated_findings(text),
        [
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job agent runs the agent on any issue event; gate it with if: github.event.label.name == '<label>'",
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job agent has no timeout-minutes of at most 45",
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job agent has no concurrency group per issue (github.event.issue.number)",
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job agent declares no permission scopes; declare them, read-only",
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job agent runs anthropics/claude-code-action without --max-turns",
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job agent sets allowed_non_write_users; only people with write access start the agent",
        ]
    );
}

#[test]
fn unattended_gated_flags_an_agent_job_that_writes() {
    let text = golden_text().replace(
        "      issues: read # the agent reads the issue it implements\n",
        "      issues: write\n      id-token: write\n",
    );
    assert_eq!(
        gated_findings(&text),
        [
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job implement grants id-token: write; the agent holds the job's token, so its job only reads and another job without an agent writes",
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job implement grants issues: write; the agent holds the job's token, so its job only reads and another job without an agent writes",
        ]
    );
}

#[test]
fn unattended_gated_ignores_workflows_out_of_scope() {
    // Another trigger, or issues without an agent action: not this rule's.
    for text in [
        "on:\n  issue_comment:\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@d70510b174a1244958df0b03166a54912811f3e6\n",
        "on:\n  issues:\n    types: [opened]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@d70510b174a1244958df0b03166a54912811f3e6\n",
        "on:\n  issues:\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo labeled\n",
    ] {
        assert_eq!(gated_findings(text), Vec::<String>::new(), "{text}");
    }
}

#[test]
fn doctor_reports_unattended_gated_in_any_checkout_and_passes_on_the_golden() {
    let repo = checkout();
    put(repo.path(), WORKFLOW_PATH, &golden_text());
    assert_eq!(
        rule_lines(&audit::diagnose(repo.path()), "agents.unattended-gated"),
        Vec::<&str>::new()
    );
    put(
        repo.path(),
        WORKFLOW_PATH,
        &golden_text().replace("timeout-minutes: 45", "timeout-minutes: 90"),
    );
    assert_eq!(
        rule_lines(&audit::diagnose(repo.path()), "agents.unattended-gated"),
        [
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job implement has no timeout-minutes of at most 45"
        ]
    );
}

#[test]
fn unattended_installed_without_its_workflow_is_a_finding() {
    let repo = Repo::new("cargo test --locked");
    let file =
        json!({"module": "agent-guardrails", "version": "1.0.0", "answers": unattended_answers()});
    repo.write_json(&answers::path("agent-guardrails"), &file);
    assert!(repo.install(&["--apply"]).status.success());
    assert!(repo.root.join(WORKFLOW_PATH).is_file());
    assert_eq!(
        rule_lines(&repo.doctor(), "agents.unattended-gated"),
        Vec::<&str>::new()
    );
    fs::remove_file(repo.root.join(WORKFLOW_PATH)).unwrap();
    assert!(
        rule_lines(&repo.doctor(), "agents.unattended-gated").contains(
            &"WARNING: agents.unattended-gated: unattended is true but .github/workflows/agentic-implement.yml is missing; re-run install"
        )
    );
}

#[test]
fn the_auditor_judges_unattended_gated_only_where_it_applies() {
    let status = |repo: &Repo| -> (String, Value) {
        let out = repo.cli(&["doctor", "<repo>", "--json"]);
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        let rule = report["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "agents.unattended-gated")
            .cloned()
            .expect("the rule is in the registry");
        (rule["status"].as_str().unwrap().to_owned(), rule)
    };
    let repo = Repo::new("cargo test --locked");
    assert!(repo.install(&["--apply"]).status.success());
    assert_eq!(
        status(&repo).0,
        "not-required",
        "unattended false, no workflow"
    );
    // A hand-written agent workflow on issues.labeled is judged, managed or not.
    fs::write(
        repo.root.join(".github/workflows/hand.yml"),
        "on:\n  issues:\n    types: [labeled]\n  workflow_dispatch:\npermissions: {}\njobs:\n  a:\n    if: github.event.label.name == 'go'\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    concurrency: agent-${{ github.event.issue.number }}\n    permissions:\n      contents: read\n    steps:\n      - uses: anthropics/claude-code-action@d70510b174a1244958df0b03166a54912811f3e6\n        with:\n          claude_args: --max-turns 10\n",
    )
    .unwrap();
    let (state, rule) = status(&repo);
    assert_eq!(state, "failed", "{rule}");
    assert_eq!(
        rule["evidence"],
        json!([
            ".github/workflows/hand.yml: also triggers on workflow_dispatch; an unattended agent runs on issues.labeled alone"
        ])
    );
    // The rendered workflow passes it.
    fs::remove_file(repo.root.join(".github/workflows/hand.yml")).unwrap();
    let file =
        json!({"module": "agent-guardrails", "version": "1.0.0", "answers": unattended_answers()});
    repo.write_json(&answers::path("agent-guardrails"), &file);
    assert!(repo.install(&["--apply"]).status.success());
    assert_eq!(status(&repo).0, "passed");
}

/// The rule's status and evidence in `doctor <repo> --json`.
fn unattended_gated_status(repo: &Repo) -> (String, Value) {
    let out = repo.cli(&["doctor", "<repo>", "--json"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let rule = report["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "agents.unattended-gated")
        .cloned()
        .expect("the rule is in the registry");
    (
        rule["status"].as_str().unwrap().to_owned(),
        rule["evidence"].clone(),
    )
}

#[test]
fn unattended_gated_applies_with_and_without_the_answers_file() {
    // #966: applicability comes from the workflows and from doctor's own finding,
    // never from the answers file the auditor's allowlist does not admit.
    let answers_path = answers::path("agent-guardrails");
    let with_unattended = json!({
        "module": "agent-guardrails", "version": "1.0.0", "answers": unattended_answers()
    });

    // With the answers file, unattended true: the rendered workflow passes, and a
    // deleted one fails with doctor's missing-workflow finding as evidence.
    let repo = Repo::new("cargo test --locked");
    repo.write_json(&answers_path, &with_unattended);
    assert!(repo.install(&["--apply"]).status.success());
    assert_eq!(unattended_gated_status(&repo).0, "passed");
    fs::remove_file(repo.root.join(WORKFLOW_PATH)).unwrap();
    let (state, evidence) = unattended_gated_status(&repo);
    assert_eq!(state, "failed", "{evidence}");
    assert_eq!(
        evidence,
        json!([
            "unattended is true but .github/workflows/agentic-implement.yml is missing; re-run install"
        ])
    );

    // With the answers file, unattended false and no workflow: not required.
    let repo = Repo::new("cargo test --locked");
    repo.write_json(
        &answers_path,
        &json!({"module": "agent-guardrails", "version": "1.0.0", "answers": {"unattended": false}}),
    );
    assert!(repo.install(&["--apply"]).status.success());
    assert_eq!(unattended_gated_status(&repo).0, "not-required");

    // Without the answers file: not required with no workflow in scope, judged
    // (and passed) once the rendered workflow is there.
    fs::remove_file(repo.root.join(&answers_path)).unwrap();
    assert_eq!(unattended_gated_status(&repo).0, "not-required");
    put(&repo.root, WORKFLOW_PATH, &golden_text());
    assert_eq!(unattended_gated_status(&repo).0, "passed");
}

#[test]
fn unattended_gated_reads_the_label_gate_strictly() {
    for condition in [
        "github.event.label.name != 'agent:ready'",
        "always() || github.event.label.name == 'agent:ready'",
        "github.event.label.name == 'agent:ready' || true",
        "!cancelled() && github.event.label.name == 'agent:ready'",
        "github.event.label.name == 'agent:ready' && (github.event.issue.locked || true)",
    ] {
        let text = golden_text().replace(
            "if: \"github.event.label.name == 'agent:ready'\"",
            &format!("if: \"{condition}\""),
        );
        assert_eq!(
            gated_findings(&text),
            [
                "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job implement runs the agent on any issue event; gate it with if: github.event.label.name == '<label>'"
            ],
            "{condition}"
        );
    }
    let text = golden_text().replace(
        "if: \"github.event.label.name == 'agent:ready'\"",
        "if: \"${{ github.event.label.name == 'agent:ready' && github.event.issue.state == 'open' }}\"",
    );
    assert_eq!(gated_findings(&text), Vec::<String>::new());
}

#[test]
fn unattended_gated_sees_agents_by_sub_path_case_and_cli() {
    let base = "on:\n  issues:\n    types: [labeled]\njobs:\n  a:\n    runs-on: x\n    steps:\n";
    for step in [
        "      - uses: Anthropics/Claude-Code-Action/base-action@d70510b174a1244958df0b03166a54912811f3e6\n",
        "      - run: npx @anthropic-ai/claude-code -p go\n",
        "      - run: codex exec go\n",
    ] {
        let findings = gated_findings(&format!("{base}{step}"));
        assert!(
            findings
                .iter()
                .any(|f| f.contains("job a runs the agent on any issue event")),
            "{step}: {findings:?}"
        );
    }
}

#[test]
fn unattended_gated_refuses_another_token_and_a_permission_bypass() {
    // #971: the golden runs the CLI; the bypass goes into its run line, and a
    // project's own action step carries the foreign token.
    let golden = golden_text();
    assert!(golden.contains("--max-turns 60 "));
    let text = golden
        .replace("--max-turns 60 ", "--max-turns 60 --dangerously-skip-permissions ")
        .replace(
            "      - id: bundle\n",
            "      - uses: anthropics/claude-code-action@d70510b174a1244958df0b03166a54912811f3e6\n        with:\n          github_token: \"${{ secrets.AGENT_PAT }}\"\n          claude_args: --max-turns 5\n          prompt: x\n      - id: bundle\n",
        );
    assert_eq!(
        gated_findings(&text),
        [
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job implement runs the agent with --dangerously-skip-permissions; its permission checks stay on",
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: job implement gives the agent github_token ${{ secrets.AGENT_PAT }}; only the job's own token, whose scopes this rule reads",
        ]
    );
}

#[test]
fn unattended_gated_flags_any_trigger_besides_issues() {
    let text = golden_text().replace("on:\n  issues:\n", "on:\n  issue_comment:\n  issues:\n");
    assert_eq!(
        gated_findings(&text),
        [
            "WARNING: agents.unattended-gated: .github/workflows/agentic-implement.yml: also triggers on issue_comment; an unattended agent runs on issues.labeled alone"
        ]
    );
}

#[test]
fn a_prompt_with_a_control_character_refuses() {
    let f = reviewed(
        json!({"unattended": true, "unattended_prompt": "Run /implement\r  injected: key"}),
    );
    assert_eq!(
        plan_composed(&f, true).unwrap_err().to_string(),
        "Module agent-guardrails: unattended_prompt contains a control character; only line breaks and tabs are kept"
    );
}

// ---- #945: `agents.heldout-denied` (Silver, all profiles) ----

const HELDOUT_DENIED: &str = "agents.heldout-denied";

/// A repository whose ci-baseline answers enable the held-out job over `dir`.
fn heldout_repo(dir: &str) -> Repo {
    let repo = Repo::new("cargo test --locked");
    let file = json!({"module": "ci-baseline", "version": "1.0.0", "answers": {
        "heldout_dir": dir, "heldout": true, "heldout_command": "cargo test --test heldout"}});
    repo.write_json(&answers::path("ci-baseline"), &file);
    assert!(repo.install(&["--apply"]).status.success());
    repo
}

/// A repository whose ci-baseline answers opt out of the held-out job, on by
/// default since #1362.
fn no_heldout_repo() -> Repo {
    let repo = Repo::new("cargo test --locked");
    let file = json!({"module": "ci-baseline", "version": "1.0.0", "answers": {"heldout": false}});
    repo.write_json(&answers::path("ci-baseline"), &file);
    assert!(repo.install(&["--apply"]).status.success());
    repo
}

/// The fragment as merged with the whole deny list but the held-out entries of
/// `tools` (`Edit`, `Read`): before #945 both were absent, before #982 `Read` was.
fn register_without_heldout_tools(repo: &Repo, dir: &str, tools: &[&str]) {
    repo.register(true, true);
    let mut settings = repo.json(SETTINGS);
    let entries: Vec<Value> = tools
        .iter()
        .map(|tool| json!(format!("{tool}(//**/{dir}/**)")))
        .collect();
    settings["permissions"]["deny"]
        .as_array_mut()
        .unwrap()
        .retain(|rule| !entries.contains(rule));
    repo.write_json(SETTINGS, &settings);
}

/// The fragment as merged before #945: every entry but the two held-out ones.
fn register_without_heldout(repo: &Repo, dir: &str) {
    register_without_heldout_tools(repo, dir, &["Edit", "Read"]);
}

const HELDOUT_EDIT_LACKING: &str = "WARNING: agents.heldout-denied: .claude/settings.json permissions.deny lacks Edit(//**/qa/heldout/**); agents can edit the held-out tests (re-run install)";
const HELDOUT_READ_LACKING: &str = "WARNING: agents.heldout-denied: .claude/settings.json permissions.deny lacks Read(//**/qa/heldout/**); agents can read and search the held-out tests (re-run install)";

/// Both entries present pass; `Edit` only, `Read` only and neither fail, and the
/// finding names each missing entry (#982).
#[test]
fn heldout_denied_requires_both_entries_and_names_the_missing_one() {
    let repo = heldout_repo("qa/heldout");
    let fragment = repo.json(SETTINGS_FRAGMENT_PATH)["permissions"]["deny"].clone();
    for entry in ["Edit(//**/qa/heldout/**)", "Read(//**/qa/heldout/**)"] {
        assert!(
            fragment.as_array().unwrap().contains(&json!(entry)),
            "{entry}"
        );
    }
    repo.register(true, true);
    assert_eq!(
        rule_lines(&repo.doctor(), HELDOUT_DENIED),
        Vec::<&str>::new(),
        "both present"
    );
    register_without_heldout_tools(&repo, "qa/heldout", &["Read"]);
    assert_eq!(
        rule_lines(&repo.doctor(), HELDOUT_DENIED),
        [HELDOUT_READ_LACKING],
        "Edit only"
    );
    register_without_heldout_tools(&repo, "qa/heldout", &["Edit"]);
    assert_eq!(
        rule_lines(&repo.doctor(), HELDOUT_DENIED),
        [HELDOUT_EDIT_LACKING],
        "Read only"
    );
    register_without_heldout(&repo, "qa/heldout");
    assert_eq!(
        rule_lines(&repo.doctor(), HELDOUT_DENIED),
        [HELDOUT_EDIT_LACKING, HELDOUT_READ_LACKING],
        "neither"
    );
}

#[test]
fn heldout_denied_is_silent_without_heldout() {
    let repo = no_heldout_repo();
    register_without_heldout(&repo, "tests/heldout");
    assert_eq!(
        rule_lines(&repo.doctor(), HELDOUT_DENIED),
        Vec::<&str>::new()
    );
}

#[test]
fn a_heldout_entry_deleted_by_hand_is_drift_until_the_next_install() {
    let repo = heldout_repo("tests/heldout");
    register_without_heldout(&repo, "tests/heldout");
    let lines = repo.doctor();
    assert!(lines.iter().any(|l| l == ENTRIES_DRIFT), "{lines:#?}");
    assert_eq!(rule_lines(&lines, HELDOUT_DENIED).len(), 2, "{lines:#?}");
    // The secrets are registered: agents.deny-secrets has nothing to say.
    assert!(!lines.iter().any(|l| l == DENY_UNREGISTERED), "{lines:#?}");
    assert!(repo.install(&["--apply"]).status.success());
    let lines = repo.doctor();
    assert!(!lines.iter().any(|l| l == ENTRIES_DRIFT), "{lines:#?}");
    assert_eq!(rule_lines(&lines, HELDOUT_DENIED), Vec::<&str>::new());
}

#[test]
fn the_auditor_judges_heldout_denied_only_where_heldout_is_true() {
    let status = |repo: &Repo| -> (String, Value) {
        let out = repo.cli(&["doctor", "<repo>", "--json"]);
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        let rule = report["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == HELDOUT_DENIED)
            .cloned()
            .expect("the rule is in the registry");
        (rule["status"].as_str().unwrap().to_owned(), rule)
    };
    let repo = no_heldout_repo();
    register_without_heldout(&repo, "tests/heldout");
    assert_eq!(status(&repo).0, "not-required", "heldout false");
    let repo = heldout_repo("tests/heldout");
    register_without_heldout(&repo, "tests/heldout");
    let (state, rule) = status(&repo);
    assert_eq!(state, "failed", "{rule}");
    repo.register(true, true);
    let (state, rule) = status(&repo);
    assert_eq!(state, "passed", "{rule}");
}

// ---- #986: `spec_dir`, the project's specification directory, denied to agents ----

#[test]
fn spec_dir_is_an_optional_question_without_a_default_that_names_no_tool() {
    let schema = AgentGuardrails.questions();
    let question = schema.question("spec_dir").unwrap();
    assert!(matches!(question.kind, answers::Kind::String));
    assert_eq!(question.default, None);
    assert!(!question.required);
    assert_eq!(question.min_length, Some(1));
    let description = question.description.to_lowercase();
    for name in ["skill", "spec kit", "spec-kit", "openspec"] {
        assert!(!description.contains(name), "{description}");
    }
    // Unanswered: no extra rule.
    let f = Fixture::new(Some(VERIFY));
    assert_eq!(deny(&f.plan(&AgentGuardrails).unwrap()), spec_deny());
}

#[test]
fn spec_dir_answered_renders_one_edit_deny_rule_after_the_protected_paths() {
    let f = Fixture::new(Some(VERIFY));
    f.answer(json!({"spec_dir": "docs/specs", "protected_paths": ["docs/adr/**"]}));
    let mut expected = spec_deny();
    expected.push("Edit(//**/docs/adr/**)".to_owned());
    expected.push("Edit(//**/docs/specs/**)".to_owned());
    assert_eq!(deny(&f.plan(&AgentGuardrails).unwrap()), expected);
    // A leading `./` and a trailing `/` are dropped; the same glob already in
    // `protected_paths` is not repeated.
    for dir in ["./docs/specs/", "docs/specs/", "docs/specs"] {
        let f = Fixture::new(Some(VERIFY));
        f.answer(json!({"spec_dir": dir, "protected_paths": ["docs/specs/**"]}));
        let mut expected = spec_deny();
        expected.push("Edit(//**/docs/specs/**)".to_owned());
        assert_eq!(deny(&f.plan(&AgentGuardrails).unwrap()), expected, "{dir}");
    }
}

#[test]
fn spec_dir_leaving_the_repository_refuses_and_the_entry_counts_toward_the_cap() {
    for dir in ["../specs", "/specs", "docs/../../x", "./"] {
        let f = Fixture::new(Some(VERIFY));
        f.answer(json!({"spec_dir": dir}));
        assert_eq!(
            f.plan(&AgentGuardrails).unwrap_err().to_string(),
            format!("Module agent-guardrails: spec_dir entry `{dir}` leaves the repository")
        );
    }
    // P2: twenty-one defaults, the spec directory and two secret paths (two rules each) are 26.
    let f = Fixture::profiled(Some(VERIFY), "P2");
    f.answer(json!({"spec_dir": "specs", "secret_paths": ["a.secret", "b.secret"]}));
    assert_eq!(
        f.plan(&AgentGuardrails).unwrap_err().to_string(),
        "Module agent-guardrails: the deny list would have 26 entries; at most 25 are allowed"
    );
    let f = Fixture::profiled(Some(VERIFY), "P2");
    f.answer(json!({"spec_dir": "specs", "secret_paths": ["a.secret"]}));
    assert_eq!(deny(&f.plan(&AgentGuardrails).unwrap()).len(), 24);
}

// ---- T10 (#750): the agent App step, spend caps and the Silver rules --------------

#[test]
fn agent_app_steps_name_the_permissions_the_secrets_and_never_all_repositories() {
    let steps = identity::steps(Some("acme-agent"), true);
    assert_eq!(
        steps.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["agent-app", "agent-app-id-present", "agent-app-key-present"]
    );
    assert!(steps.iter().all(|s| s.owner == Owner::Owner));
    let app = &steps[0];
    for needle in [
        "Contents",
        "Pull requests",
        "Issues",
        "Checks",
        "Commit statuses",
        "Actions read",
        "Metadata",
        "no Workflows",
        "no Administration",
        "no Secrets",
        "no Environments",
        "macOS Keychain",
        "templates/agent-identity/app-manifest.json",
        "templates/agent-identity/installation-token.sh",
        "selected repositories only, never all repositories",
        "AGENT_APP_ID",
        "AGENT_APP_PRIVATE_KEY",
        "bypass actor",
    ] {
        assert!(
            app.instructions.contains(needle),
            "{needle}: {}",
            app.instructions
        );
    }
    assert_eq!(
        app.probe,
        Probe::Remote {
            id: "app-installed".to_owned(),
            args: [("slug".to_owned(), json!("acme-agent"))].into(),
        }
    );
    // P1 (#1255): the App alone; its CI secrets are P2 and P3 steps.
    assert_eq!(
        identity::steps(None, false)
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        ["agent-app"]
    );
    assert_eq!(
        identity::steps(None, false)[0].probe,
        Probe::Remote {
            id: "app-installed".to_owned(),
            args: Default::default(),
        }
    );
    for (step, name) in steps[1..]
        .iter()
        .zip(["AGENT_APP_ID", "AGENT_APP_PRIVATE_KEY"])
    {
        assert_eq!(
            step.probe,
            Probe::Remote {
                id: "secret-present".to_owned(),
                args: [
                    ("name".to_owned(), json!(name)),
                    ("scope".to_owned(), json!("repository")),
                ]
                .into(),
            }
        );
        assert!(
            step.instructions.contains(&format!("gh secret set {name}")),
            "{}",
            step.instructions
        );
    }
}

/// #1255: agents act through the App in every profile, so P1 lists the `agent-app`
/// step too; the two repository secrets stay P2 and P3, where agent jobs run in CI.
#[test]
fn in_p2_doctor_lists_the_agent_app_steps_unavailable_and_p1_lists_the_app_alone() {
    let repo = Repo::new("cargo test --locked");
    assert!(
        repo.install(&["--profile", "P2", "--apply"])
            .status
            .success()
    );
    let lines = repo.doctor();
    for line in [
        "STEP [unavailable:agent-guardrails] agent-app — remote probe `app-installed` runs only with doctor --remote",
        "STEP [unavailable:agent-guardrails] agent-app-id-present — remote probe `secret-present` runs only with doctor --remote",
        "STEP [unavailable:agent-guardrails] agent-app-key-present — remote probe `secret-present` runs only with doctor --remote",
    ] {
        assert!(lines.iter().any(|l| l == line), "{line}\n{lines:#?}");
    }
    // The module's own workflows carry their caps and no PAT-like secret.
    assert_eq!(rule_lines(&lines, audit::WORKFLOW_CAPS), Vec::<&str>::new());
    assert_eq!(rule_lines(&lines, audit::IDENTITY), Vec::<&str>::new());
    let p1 = Repo::new("cargo test --locked");
    assert!(p1.install(&["--apply"]).status.success());
    let lines = p1.doctor();
    // The step, and the auditor's Bronze reading of it; no CI secret step.
    let app: Vec<&String> = lines.iter().filter(|l| l.contains("agent-app")).collect();
    assert_eq!(
        app,
        [
            AGENT_APP_STEP_UNAVAILABLE,
            "UNAVAILABLE [bronze:baseline.agent-guardrails.agent-app] remote probe `app-installed` runs only with doctor --remote"
        ],
        "{lines:#?}"
    );
}

#[test]
fn workflow_caps_flags_an_agent_job_without_timeout_concurrency_or_max_turns() {
    let repo = checkout();
    let root = repo.path();
    put(
        root,
        ".github/workflows/uncapped.yml",
        "on: push\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: review\n",
    );
    put(
        root,
        ".github/workflows/capped.yml",
        "on: push\nconcurrency: caps-${{ github.ref }}\njobs:\n  review:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: |\n            --max-turns 30\n  codex:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps:\n      - uses: openai/codex-action@v1\n  plain:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    );
    assert_eq!(
        rule_lines(&audit::diagnose(root), audit::WORKFLOW_CAPS),
        [
            "WARNING: agents.workflow-caps: .github/workflows/uncapped.yml: job review runs an agent without timeout-minutes",
            "WARNING: agents.workflow-caps: .github/workflows/uncapped.yml: job review runs an agent without a concurrency group",
            "WARNING: agents.workflow-caps: .github/workflows/uncapped.yml: job review runs anthropics/claude-code-action without --max-turns",
        ]
    );
}

#[test]
fn identity_reports_a_pat_like_secret_in_an_agent_job_as_a_heuristic() {
    let repo = checkout();
    let root = repo.path();
    put(
        root,
        ".github/workflows/agent.yml",
        "on: push\njobs:\n  agent:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        env:\n          GH_TOKEN: ${{ secrets.DEPLOY_PAT }}\n        with:\n          github_token: ${{ secrets.GITHUB_TOKEN }}\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh api x\n        env:\n          GH_TOKEN: ${{ secrets.RELEASE_PAT }}\n",
    );
    assert_eq!(
        rule_lines(&audit::diagnose(root), audit::IDENTITY),
        [
            "WARNING: agents.identity: .github/workflows/agent.yml: job agent references secrets.DEPLOY_PAT, named like a personal access token (a heuristic); agents act through the App of step agent-app"
        ]
    );
}

#[test]
fn the_rendered_ruleset_keeps_bypass_actors_empty() {
    let repo = Repo::new("cargo test --locked");
    assert!(
        repo.install(&["--profile", "P2", "--apply"])
            .status
            .success()
    );
    assert_eq!(repo.json(RULESET_PATH)["bypass_actors"], json!([]));
}

// ---- T11 (#751): Codex and OpenCode -------------------------------------------------

/// The host table has a column per host, each cell says enforced, configured or
/// documented, the vendor sources are cited, and no cell claims a verify-on-stop
/// guarantee for Codex or OpenCode.
#[test]
fn the_guide_marks_each_rule_per_host_with_sources_and_claims_no_stop_hook_elsewhere() {
    let guide = brakes::modules::agent_guardrails::GUIDE;
    assert!(guide.contains("| Rule | Claude Code | Codex | OpenCode |"));
    let rows: Vec<&str> = guide
        .lines()
        .skip_while(|l| !l.starts_with("| Rule | Claude Code | Codex | OpenCode |"))
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .collect();
    assert!(rows.len() >= 5, "{rows:#?}");
    for row in &rows {
        let cells: Vec<&str> = row.trim_matches('|').split(" | ").collect();
        assert_eq!(cells.len(), 4, "{row}");
        for cell in &cells[1..] {
            assert!(
                ["Enforced", "Configured", "Documented"]
                    .iter()
                    .any(|w| cell.trim().starts_with(w)),
                "{row}"
            );
        }
        if row.starts_with("| `verify` green") {
            assert!(cells[2].starts_with("Documented: not claimed"), "{row}");
            assert!(cells[3].starts_with("Documented: not claimed"), "{row}");
        }
    }
    for source in [
        "https://learn.chatgpt.com/docs/agent-approvals-security",
        "https://learn.chatgpt.com/docs/sandboxing",
        "https://learn.chatgpt.com/docs/hooks",
        "https://opencode.ai/docs/permissions/",
        "https://opencode.ai/docs/config/",
    ] {
        assert!(guide.contains(source), "{source}");
    }
}

/// OpenCode matches a permission pattern against the repository-relative path,
/// and `*` crosses `/` (observed in an OpenCode 1.18.35 session, #751): so a
/// Claude `//**/<path>` (#1309, #1314) becomes `<path>` and `*/<path>`, any
/// other `**` a `*`.
#[test]
fn opencode_patterns_translate_the_claude_deny_rules() {
    let translated = brakes::modules::agent_guardrails::opencode_permission(&[
        "Read(//**/.env)".to_owned(),
        "Read(//**/secrets/**)".to_owned(),
        "Read(//**/*.pem)".to_owned(),
        "Edit(//**/.agent-setup/lock.json)".to_owned(),
        "Edit(//**/tests/heldout/**)".to_owned(),
        "Read(//**/tests/heldout/**)".to_owned(),
    ]);
    assert_eq!(
        translated,
        json!({
            "edit": {
                ".agent-setup/lock.json": "deny", "*/.agent-setup/lock.json": "deny",
                "tests/heldout/*": "deny", "*/tests/heldout/*": "deny"
            },
            "read": {
                ".env": "deny", "*/.env": "deny",
                "secrets/*": "deny", "*/secrets/*": "deny",
                "*.pem": "deny", "*/*.pem": "deny",
                "tests/heldout/*": "deny", "*/tests/heldout/*": "deny"
            }
        })
    );
}

#[test]
fn opencode_json_owns_the_deny_patterns_as_managed_entries() {
    let f = Fixture::new(Some(VERIFY));
    let planned = f.plan(&AgentGuardrails).unwrap();
    assert_eq!(
        planned.tags[OPENCODE_JSON_PATH],
        (Ownership::ManagedEntries, "agent-guardrails".to_owned())
    );
    let config: Value =
        serde_json::from_str(planned.changes[OPENCODE_JSON_PATH].as_deref().unwrap()).unwrap();
    let keys: Vec<&String> = config.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["permission"]);
    let expected = brakes::modules::agent_guardrails::opencode_permission(&deny(&planned));
    assert_eq!(config["permission"], expected);
    assert_eq!(config["permission"]["read"][".env"], "deny");
    assert_eq!(
        config["permission"]["edit"][".agent-setup/lock.json"],
        "deny"
    );
}

/// An existing `opencode.json` keeps the project's keys and patterns; the
/// installer adds only its own, a second install changes nothing.
#[test]
fn an_existing_opencode_json_keeps_the_projects_entries_and_gains_the_deny_patterns() {
    let f = Fixture::new(Some(VERIFY));
    let own = json!({"$schema": "https://opencode.ai/config.json", "model": "anthropic/claude",
        "permission": {"bash": {"git *": "allow"}, "read": {"docs/*": "allow"}}});
    f.write(
        OPENCODE_JSON_PATH,
        &(serde_json::to_string_pretty(&own).unwrap() + "\n"),
    );
    f.apply(&AgentGuardrails);
    let after: Value = serde_json::from_str(&f.read(OPENCODE_JSON_PATH)).unwrap();
    assert_eq!(after["$schema"], own["$schema"]);
    assert_eq!(after["model"], own["model"]);
    assert_eq!(after["permission"]["bash"], own["permission"]["bash"]);
    assert_eq!(after["permission"]["read"]["docs/*"], "allow");
    assert_eq!(after["permission"]["read"][".env"], "deny");
    assert_eq!(after["permission"]["edit"]["tests/heldout/*"], "deny");
    let again = f.plan(&AgentGuardrails).unwrap();
    assert!(again.changes.is_empty(), "{:?}", again.changes.keys());
}

/// Growth of the deny list (a new `secret_paths` answer) lands in an installed
/// `opencode.json` on the next install, and a project-edited pattern refuses.
#[test]
fn deny_list_growth_reaches_opencode_json_and_an_edited_pattern_refuses() {
    let f = Fixture::new(Some(VERIFY));
    f.apply(&AgentGuardrails);
    f.answer(json!({"secret_paths": ["config/vault.yml"]}));
    let planned = f.apply(&AgentGuardrails);
    assert!(planned.changes.contains_key(OPENCODE_JSON_PATH));
    let after: Value = serde_json::from_str(&f.read(OPENCODE_JSON_PATH)).unwrap();
    assert_eq!(after["permission"]["read"]["config/vault.yml"], "deny");
    assert_eq!(after["permission"]["edit"]["config/vault.yml"], "deny");
    let mut edited = after.clone();
    edited["permission"]["read"][".env"] = json!("allow");
    f.write(
        OPENCODE_JSON_PATH,
        &(serde_json::to_string_pretty(&edited).unwrap() + "\n"),
    );
    assert_eq!(
        f.plan(&AgentGuardrails).unwrap_err().to_string(),
        "Locally changed managed entry: opencode.json at /permission/read/.env (.env)"
    );
}

// ---- T18 (#972): agents.workflow-injection (Bronze, static) -----------------------

use brakes::modules::agent_guardrails::injection;

const INJECTION_PATH: &str = ".github/workflows/agent.yml";
const CHECKOUT_PIN: &str = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
const CLAUDE_PIN: &str = "anthropics/claude-code-action@d70510b174a1244958df0b03166a54912811f3e6";
const CODEX_PIN: &str = "openai/codex-action@bdf19a4a223ec2549a3e2274a0cf61556bc07675";

/// A workflow that runs Claude Code and passes every check: read-only job token,
/// no cache, credentials not persisted, the issue title through `env:`.
fn injection_clean() -> String {
    format!(
        r#"name: agent
on:
  issues:
    types: [labeled]
permissions: {{}}
jobs:
  agent:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions:
      contents: read
    cache-mode: none
    steps:
      - uses: {CHECKOUT_PIN}
        with:
          persist-credentials: "false"
      - name: Keep the title
        env:
          TITLE: "${{{{ github.event.issue.title }}}}"
        run: printf '%s' "$TITLE" >"$RUNNER_TEMP/title.md"
      - id: agent
        uses: {CLAUDE_PIN}
        env:
          BODY: "${{{{ github.event.issue.body }}}}"
        with:
          github_token: "${{{{ github.token }}}}"
          claude_args: |
            --max-turns 30
            --allowedTools "Read,Grep,Bash(git add *)"
          prompt: "Issue #${{{{ github.event.issue.number }}}} at ${{{{ github.event.issue.html_url }}}}"
"#
    )
}

/// The same job running Codex as its last step.
fn injection_codex_clean() -> String {
    injection_clean().replace(
        &format!(
            "      - id: agent\n        uses: {CLAUDE_PIN}\n        env:\n          BODY: \"${{{{ github.event.issue.body }}}}\"\n        with:\n          github_token: \"${{{{ github.token }}}}\"\n          claude_args: |\n            --max-turns 30\n            --allowedTools \"Read,Grep,Bash(git add *)\"\n"
        ),
        &format!(
            "      - id: agent\n        uses: {CODEX_PIN}\n        with:\n          openai-api-key: \"${{{{ secrets.OPENAI_API_KEY }}}}\"\n          safety-strategy: drop-sudo\n"
        ),
    )
}

fn injection_findings(text: &str) -> Vec<String> {
    injection::findings(INJECTION_PATH, &parsed(text))
}

fn injected(check: &str) -> String {
    format!("WARNING: agents.workflow-injection: {INJECTION_PATH}#agent: {check}")
}

/// Replaces `from` once, failing loudly when the fixture does not contain it.
fn with(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "the fixture contains {from:?}");
    text.replacen(from, to, 1)
}

#[test]
fn workflow_injection_passes_the_clean_fixtures_and_env_routes() {
    assert_eq!(injection_findings(&injection_clean()), Vec::<String>::new());
    assert_eq!(
        injection_findings(&injection_codex_clean()),
        Vec::<String>::new()
    );
    // unprivileged-user is the other strategy kept.
    let unprivileged = with(
        &injection_codex_clean(),
        "safety-strategy: drop-sudo",
        "safety-strategy: unprivileged-user",
    );
    assert_eq!(injection_findings(&unprivileged), Vec::<String>::new());
    // No agent, no scope: the same job with the agent step removed is not judged.
    let no_agent = with(
        &with(&injection_clean(), "    cache-mode: none\n", ""),
        &format!("uses: {CLAUDE_PIN}"),
        &format!("uses: {CHECKOUT_PIN}"),
    );
    assert_eq!(injection_findings(&no_agent), Vec::<String>::new());
}

/// One failing fixture per check of "CI hardening for agent workflows", point 6.
#[test]
fn workflow_injection_reports_each_check_naming_file_job_and_check() {
    let clean = injection_clean();
    let codex = injection_codex_clean();
    let cases: Vec<(String, Vec<String>)> = vec![
        (
            with(&clean, "  issues:\n", "  pull_request_target:\n  issues:\n"),
            vec![injected(
                "triggers on pull_request_target; the agent would run on text and code from outside with this repository's token and secrets",
            )],
        ),
        (
            with(
                &clean,
                "  issues:\n",
                "  workflow_run:\n    workflows: [ci]\n  issues:\n",
            ),
            vec![injected(
                "triggers on workflow_run; the agent would run on text and code from outside with this repository's token and secrets",
            )],
        ),
        (
            with(
                &clean,
                "run: printf '%s' \"$TITLE\"",
                "run: printf '%s' \"${{ github.event.issue.title }}\"",
            ),
            vec![injected(
                "a run: interpolates ${{ github.event.issue.title }}; pass it through env:",
            )],
        ),
        (
            with(
                &clean,
                "prompt: \"Issue #",
                "prompt: \"${{ github.event.comment.body }} Issue #",
            ),
            vec![injected(
                "input prompt of the agent step interpolates ${{ github.event.comment.body }}; pass it through env: and a file",
            )],
        ),
        (
            with(
                &clean,
                "prompt: \"Issue #",
                "prompt: \"${{ github.head_ref }} Issue #",
            ),
            vec![injected(
                "input prompt of the agent step interpolates ${{ github.head_ref }}; pass it through env: and a file",
            )],
        ),
        (
            with(
                &clean,
                "prompt: \"Issue #",
                "prompt: \"${{ toJSON(github.event) }} Issue #",
            ),
            vec![injected(
                "input prompt of the agent step interpolates ${{ toJSON(github.event) }}; pass it through env: and a file",
            )],
        ),
        (
            with(
                &clean,
                "prompt: \"Issue #",
                "prompt: \"${{ github.event.pull_request.head.ref }} ${{ github.event.commits[0].message }} Issue #",
            ),
            vec![
                injected(
                    "input prompt of the agent step interpolates ${{ github.event.pull_request.head.ref }}; pass it through env: and a file",
                ),
                injected(
                    "input prompt of the agent step interpolates ${{ github.event.commits[0].message }}; pass it through env: and a file",
                ),
            ],
        ),
        (
            with(&clean, "      contents: read\n", "      contents: write\n"),
            vec![injected(
                "grants contents: write; the agent holds the job's token, so its job only reads",
            )],
        ),
        (
            with(
                &clean,
                "      contents: read\n",
                "      contents: read\n      id-token: write\n",
            ),
            vec![injected(
                "grants id-token: write; the agent holds the job's token, so its job only reads",
            )],
        ),
        (
            with(
                &with(&clean, "permissions: {}\n", ""),
                "    permissions:\n      contents: read\n",
                "",
            ),
            vec![injected(
                "declares no permissions at job or workflow level; the agent would hold the default token",
            )],
        ),
        (
            with(
                &with(&clean, "permissions: {}\n", "permissions: write-all\n"),
                "    permissions:\n      contents: read\n",
                "",
            ),
            vec![injected(
                "grants write-all; the agent holds the job's token, so its job only reads",
            )],
        ),
        (
            with(
                &clean,
                "          github_token:",
                "          allowed_non_write_users: \"octocat\"\n          github_token:",
            ),
            vec![injected(
                "sets allowed_non_write_users; only people with write access start the agent",
            )],
        ),
        (
            with(
                &clean,
                "          github_token:",
                "          allowed_bots: \"renovate[bot],*\"\n          github_token:",
            ),
            vec![injected(
                "sets allowed_bots to renovate[bot],*; name the actors, never all of them",
            )],
        ),
        (
            with(
                &codex,
                "          safety-strategy:",
                "          allow-users: \"*\"\n          safety-strategy:",
            ),
            vec![injected(
                "sets allow-users to *; name the actors, never all of them",
            )],
        ),
        (
            with(
                &codex,
                "          safety-strategy:",
                "          allow-bot-users: \"*\"\n          safety-strategy:",
            ),
            vec![injected(
                "sets allow-bot-users to *; name the actors, never all of them",
            )],
        ),
        (
            with(
                &codex,
                "          safety-strategy:",
                "          allow-bots: true\n          safety-strategy:",
            ),
            vec![injected(
                "sets allow-bots to true; name the actors, never all of them",
            )],
        ),
        (
            with(
                &clean,
                "github_token: \"${{ github.token }}\"",
                "github_token: \"${{ secrets.AGENT_PAT }}\"",
            ),
            vec![injected(
                "gives the agent github_token ${{ secrets.AGENT_PAT }}; only the job's own token",
            )],
        ),
        (
            with(
                &clean,
                "            --max-turns 30\n",
                "            --max-turns 30\n            --dangerously-skip-permissions\n",
            ),
            vec![injected(
                "runs the agent with --dangerously-skip-permissions; its permission checks stay on",
            )],
        ),
        (
            with(
                &clean,
                "            --max-turns 30\n",
                "            --max-turns 30\n            --permission-mode bypassPermissions\n",
            ),
            vec![injected(
                "runs the agent with bypassPermissions; its permission checks stay on",
            )],
        ),
        (
            with(
                &clean,
                "\"Read,Grep,Bash(git add *)\"",
                "\"Read,Grep,Bash\"",
            ),
            vec![injected(
                "allows Bash without a pattern in --allowedTools; name the commands, Bash(<command> *)",
            )],
        ),
        (
            with(
                &codex,
                "safety-strategy: drop-sudo",
                "safety-strategy: unsafe",
            ),
            vec![injected(
                "runs openai/codex-action with safety-strategy unsafe; keep drop-sudo or unprivileged-user",
            )],
        ),
        (
            format!("{codex}      - run: echo after\n"),
            vec![injected(
                "runs a step after openai/codex-action; Codex is the last step of its job",
            )],
        ),
        (
            with(&clean, "    cache-mode: none\n", ""),
            vec![injected(
                "has no cache-mode: none; no cache entry may reach the agent or leave it",
            )],
        ),
        (
            with(&clean, "    cache-mode: none\n", "    cache-mode: read\n"),
            vec![injected(
                "has no cache-mode: none; no cache entry may reach the agent or leave it",
            )],
        ),
        (
            with(
                &clean,
                "      - name: Keep the title\n",
                "      - uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684\n        with:\n          path: ~/.cache\n          key: k\n      - name: Keep the title\n",
            ),
            vec![injected(
                "uses actions/cache@5a3ec84eff668545956fd18022155c47e93e2684; no cache near an agent",
            )],
        ),
        (
            with(
                &clean,
                "      - name: Keep the title\n",
                "      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020\n        with:\n          cache: npm\n      - name: Keep the title\n",
            ),
            vec![injected(
                "passes cache: to actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020; no cache near an agent",
            )],
        ),
        (
            with(
                &clean,
                "        with:\n          persist-credentials: \"false\"\n",
                "",
            ),
            vec![injected("checks out without persist-credentials: false")],
        ),
        (
            with(
                &clean,
                "          github_token:",
                "          show_full_output: true\n          github_token:",
            ),
            vec![injected(
                "sets show_full_output: true; the agent's full output would reach the run log",
            )],
        ),
        (
            with(
                &clean,
                "      - name: Keep the title\n",
                "      - uses: anthropics/claude-code-base-action@e8132bc5e637a42c27763fc757faa37e1ee43b34\n        with:\n          prompt: hi\n      - name: Keep the title\n",
            ),
            vec![injected(
                "uses anthropics/claude-code-base-action; use anthropics/claude-code-action, which keeps the actor checks",
            )],
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(injection_findings(&text), expected, "{text}");
    }
}

/// A job whose only agent is the base action is in scope too: the check that
/// names it would otherwise never run (#972).
#[test]
fn workflow_injection_judges_a_job_whose_only_agent_is_the_base_action() {
    let text = with(
        &injection_clean(),
        CLAUDE_PIN,
        "anthropics/claude-code-base-action@e8132bc5e637a42c27763fc757faa37e1ee43b34",
    );
    assert_eq!(
        injection_findings(&text),
        [injected(
            "uses anthropics/claude-code-base-action; use anthropics/claude-code-action, which keeps the actor checks"
        )]
    );
}

/// The rendered workflows meet the rule: every cross-review golden and
/// agentic-implement.yml.
#[test]
fn workflow_injection_passes_the_rendered_goldens() {
    for name in [
        "cross-review-claude.yml",
        "cross-review-codex.yml",
        "cross-review-existing.yml",
        "agentic-implement.yml",
    ] {
        let text = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(REVIEW_GOLDENS)
                .join(name),
        )
        .unwrap();
        let wf = parsed(&text);
        assert!(injection::in_scope(&wf), "{name} runs an agent");
        assert_eq!(
            injection::findings(name, &wf),
            Vec::<String>::new(),
            "{name}"
        );
    }
}

fn workflow_injection_status(repo: &Repo) -> (String, Value) {
    let out = repo.cli(&["doctor", "<repo>", "--json"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let rule = report["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "agents.workflow-injection")
        .cloned()
        .expect("the rule is in the registry");
    assert_eq!(rule["level"], "Bronze", "{rule}");
    (
        rule["status"].as_str().unwrap().to_owned(),
        rule["evidence"].clone(),
    )
}

/// doctor's WARNING channel in any checkout, and the auditor's verdict:
/// `not-required` with no agent job, `failed` with the findings as evidence,
/// `passed` once fixed. Never `NOT READY`.
#[test]
fn workflow_injection_reaches_doctor_and_the_auditor() {
    let repo = Repo::new("cargo test --locked");
    assert_eq!(workflow_injection_status(&repo).0, "not-required");

    let bad = with(&injection_clean(), "    cache-mode: none\n", "");
    put(&repo.root, INJECTION_PATH, &bad);
    let out = repo.cli(&["doctor", "<repo>"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = injected("has no cache-mode: none; no cache entry may reach the agent or leave it");
    assert!(text.lines().any(|l| l == line), "{text}");
    assert!(
        !text.contains("NOT READY: agents.workflow-injection"),
        "{text}"
    );
    let (state, evidence) = workflow_injection_status(&repo);
    assert_eq!(state, "failed", "{evidence}");
    assert_eq!(
        evidence,
        json!([format!(
            "{INJECTION_PATH}#agent: has no cache-mode: none; no cache entry may reach the agent or leave it"
        )])
    );

    put(&repo.root, INJECTION_PATH, &injection_clean());
    assert_eq!(workflow_injection_status(&repo).0, "passed");

    // The module's own rendered ci.yml (cross-review by default) is in scope and passes.
    fs::remove_file(repo.root.join(INJECTION_PATH)).unwrap();
    assert!(repo.install(&["--apply"]).status.success());
    let (state, evidence) = workflow_injection_status(&repo);
    assert_eq!(state, "passed", "{evidence}");
}

/// This repository's own workflows meet the rule (#972 follow-up): the never-run
/// pins workflow keeps every `uses:` Dependabot reads, with the agent actions in a
/// job of their own (no cache, `cache-mode: none`, Codex last), which also meets
/// `agents.workflow-caps` (#750: a concurrency group, `--max-turns`).
#[test]
fn workflow_injection_passes_this_repository_s_workflows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let found = audit::diagnose(&root)
        .into_iter()
        .filter(|f| {
            f.starts_with("WARNING: agents.workflow-injection:")
                || f.starts_with("WARNING: agents.workflow-caps:")
        })
        .collect::<Vec<_>>();
    assert_eq!(found, Vec::<String>::new());
}

// ---- T17 (#971): the model as a user without sudo, egress closed for that uid ---
// After the security review of #1084: no model process holds a credential, the
// model's uid has no DNS and no host, and the limit is proved again before the model.

const MODEL_USER: &str = "agent-model";

type WStep = brakes::auditor::workflows::Step;

/// The steps of `job` in `text`, parsed.
fn steps_of(text: &str, job_id: &str) -> Vec<WStep> {
    parsed(text).job(job_id).unwrap().steps.clone()
}

fn is_checkout(s: &WStep) -> bool {
    s.uses
        .as_deref()
        .is_some_and(|u| u.starts_with("actions/checkout@"))
}

fn egress_sh() -> &'static str {
    brakes::modules::agent_guardrails::EGRESS_SH
}

fn codex_review() -> String {
    workflow_of(&plan_composed(&reviewed(json!({})), true).unwrap(), CI_YML)
}

fn claude_review() -> String {
    workflow_of(
        &plan_composed(&reviewed(json!({"review_family": "claude"})), true).unwrap(),
        CI_YML,
    )
}

/// `implement` with a rust stack pack answered, so its registries would be candidates.
fn implement_with_a_pack() -> String {
    let f = reviewed(unattended_answers());
    f.write(
        "Cargo.toml",
        "[package]\nname = \"p\"\nversion = \"0.1.0\"\n",
    );
    f.write("Cargo.lock", "version = 4\n");
    f.write(
        &answers::path("stack-packs"),
        &serde_json::to_string(&json!({"module": "stack-packs", "version": "1.0.0",
            "answers": {"apps.root.path": ".", "apps.root.stack": "rust"}}))
        .unwrap(),
    );
    workflow_of(&plan_composed(&f, true).unwrap(), WORKFLOW_PATH)
}

/// The model's step: the review's last step, or implement's `agent`.
fn model_at(steps: &[WStep]) -> usize {
    steps
        .iter()
        .position(|s| s.id.as_deref() == Some("agent"))
        .unwrap_or(steps.len() - 1)
}

/// Every model job: the egress step right after the checkout, with no host and no
/// probe (the model's uid reaches no host), and the proof again right before the
/// model, through the credential proxy for Claude.
#[test]
fn every_model_job_is_limited_after_its_checkout_and_proved_again_before_the_model() {
    for (text, job_id, probe) in [
        (codex_review(), "cross-review-model", "/v1/responses"),
        (claude_review(), "cross-review-model", "/v1/messages"),
        (implement_with_a_pack(), "implement", "/v1/messages"),
    ] {
        let steps = steps_of(&text, job_id);
        let checkout = steps.iter().position(is_checkout).expect("a checkout");
        let egress = &steps[checkout + 1];
        assert_eq!(
            egress.env.get("EGRESS_USER").map(String::as_str),
            Some(MODEL_USER)
        );
        assert_eq!(egress.env.get("EGRESS_HOSTS"), None, "{job_id}: no host");
        assert_eq!(egress.env.get("EGRESS_PROBE_URL"), None, "{job_id}");
        assert_eq!(egress.run.as_deref(), Some(egress_sh()));
        let model = model_at(&steps);
        let check = &steps[model - 1];
        assert_eq!(
            check.env.get("EGRESS_MODE").map(String::as_str),
            Some("check"),
            "{job_id}"
        );
        assert_eq!(check.run.as_deref(), Some(egress_sh()));
        assert_eq!(
            check.env.get("EGRESS_PROBE_URL").map(String::as_str),
            Some(format!("http://127.0.0.1:${{{{ env.MODEL_PROXY_PORT }}}}{probe}").as_str()),
            "{job_id}"
        );
    }
    assert!(
        steps_of(&implement_with_a_pack(), "publish")
            .iter()
            .all(|s| !s.env.contains_key("EGRESS_USER"))
    );
}

/// Claude is the pinned CLI as agent-model with a dummy token; the real one goes to
/// the loopback proxy the runner starts, through stdin, never to the model's uid.
#[test]
fn the_claude_model_holds_no_credential_and_reaches_the_api_through_the_runner_s_proxy() {
    let pins = PinTable::embedded().unwrap();
    let version = &pins.tool("claude-code").unwrap().version;
    for (text, job_id, turns) in [
        (claude_review(), "cross-review-model", "--max-turns 30 "),
        (implement_with_a_pack(), "implement", "--max-turns 60 "),
    ] {
        let steps = steps_of(&text, job_id);
        assert!(
            steps.iter().all(|s| !s
                .uses
                .as_deref()
                .is_some_and(|u| u.starts_with("anthropics/"))),
            "{job_id}: no Claude action"
        );
        let model = model_at(&steps);
        let proxy = steps
            .iter()
            .position(|s| {
                s.run
                    .as_deref()
                    .is_some_and(|r| r.contains("model-proxy.py"))
            })
            .expect("the proxy step");
        assert!(proxy < model, "{job_id}");
        let proxy_step = &steps[proxy];
        assert_eq!(
            proxy_step.env["CLAUDE_CODE_OAUTH_TOKEN"], "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}",
            "{job_id}: only the runner's proxy step reads the secret"
        );
        let run = proxy_step.run.as_deref().unwrap();
        assert!(run.contains("env -u CLAUDE_CODE_OAUTH_TOKEN"), "{run}");
        assert!(run.contains("MODEL_PROXY_PORT="), "{run}");
        assert!(
            run.contains(brakes::modules::agent_guardrails::MODEL_PROXY_PY),
            "the proxy verbatim"
        );
        // Nothing the model's step receives is a secret.
        let step = &steps[model];
        assert!(
            step.env.values().all(|v| !v.contains("secrets.")),
            "{job_id}: {:?}",
            step.env
        );
        assert_ne!(step.env.get("CLAUDE_CODE_OAUTH_TOKEN"), None);
        let run = step.run.as_deref().unwrap();
        for needle in [
            &format!("-u {MODEL_USER} "),
            "ANTHROPIC_BASE_URL=\"http://127.0.0.1:$MODEL_PROXY_PORT\"",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "claude -p",
            turns,
            "Read(//proc/**)",
            "Grep(//proc/**)",
            "Glob(//proc/**)",
            "Bash(git * --output*)",
            "Bash(git * -o *)",
            "::stop-commands::",
        ] {
            assert!(run.contains(needle), "{job_id}: {needle} in\n{run}");
        }
        let install = steps
            .iter()
            .position(|s| {
                s.run
                    .as_deref()
                    .is_some_and(|r| r.contains(&format!("@anthropic-ai/claude-code@{version}")))
            })
            .unwrap_or_else(|| panic!("{job_id}: the CLI at the pinned version"));
        let actor = steps
            .iter()
            .position(|s| s.env.contains_key("ACTOR"))
            .unwrap_or_else(|| panic!("{job_id}: the actor check"));
        assert!(install < model && actor < model, "{job_id}");
        // Bubblewrap through an AppArmor profile for bwrap alone, never the global sysctl.
        let prepare = steps
            .iter()
            .find(|s| {
                s.run
                    .as_deref()
                    .is_some_and(|r| r.contains("bubblewrap socat"))
            })
            .unwrap_or_else(|| panic!("{job_id}: bubblewrap is prepared"));
        let prepare = prepare.run.as_deref().unwrap();
        assert!(prepare.contains("apparmor_parser -r"), "{prepare}");
        // Re-review of #1084: modelled on bwrap-userns-restrict; whatever bwrap runs is
        // stacked against a profile without capabilities or further user namespaces,
        // and the step proves a nested user namespace is refused.
        for needle in [
            "allow pix /** -> &agent-bwrap//&agent-unpriv-bwrap,",
            "profile agent-unpriv-bwrap",
            "audit deny capability,",
            "audit deny userns,",
            "unshare -U true",
        ] {
            assert!(prepare.contains(needle), "{needle} in\n{prepare}");
        }
        assert!(!prepare.contains("flags=(unconfined)"), "{prepare}");
        assert!(
            prepare.contains("profile agent-bwrap /usr/bin/bwrap"),
            "{prepare}"
        );
        assert!(!prepare.contains("sysctl -w"), "{prepare}");
        assert!(
            text.contains(&format!("/home/{MODEL_USER}/context/")),
            "{job_id}"
        );
    }
    // The review's verdict is the CLI's structured_output.
    let review = steps_of(&claude_review(), "cross-review-model");
    let run = review.last().unwrap().run.as_deref().unwrap();
    assert!(
        run.contains("--output-format json") && run.contains("--json-schema"),
        "{run}"
    );
    assert!(run.contains(".structured_output"), "{run}");
}

#[test]
fn codex_runs_as_the_model_user_through_unprivileged_user() {
    let steps = steps_of(&codex_review(), "cross-review-model");
    let review = steps.last().unwrap();
    assert!(
        review
            .uses
            .as_deref()
            .unwrap()
            .starts_with("openai/codex-action@")
    );
    assert_eq!(review.with["safety-strategy"], "unprivileged-user");
    assert_eq!(review.with["codex-user"], MODEL_USER);
    assert_eq!(
        review.with["working-directory"],
        format!("/home/{MODEL_USER}/work")
    );
    assert_eq!(
        review.with["output-schema-file"],
        format!("/home/{MODEL_USER}/context/schema.json")
    );
    assert!(review.with["prompt"].contains(&format!("/home/{MODEL_USER}/context/pull-request.md")));
    // #1095: Codex reaches OpenAI only through the runner's filtering proxy.
    assert_eq!(
        review.with["openai-api-key"],
        brakes::modules::agent_guardrails::MODEL_DUMMY_TOKEN
    );
    assert_eq!(
        review.with["responses-api-endpoint"],
        "http://127.0.0.1:${{ env.MODEL_PROXY_PORT }}/v1/responses"
    );
    let proxy = steps
        .iter()
        .find(|s| {
            s.run
                .as_deref()
                .is_some_and(|r| r.contains("model-proxy.py"))
        })
        .expect("the proxy step");
    assert_eq!(proxy.env["OPENAI_API_KEY"], "${{ secrets.OPENAI_API_KEY }}");
    let run = proxy.run.as_deref().unwrap();
    assert!(run.contains("env -u OPENAI_API_KEY"), "{run}");
    assert!(run.contains("\"$port_file\" openai "), "{run}");
    assert!(run.contains(brakes::modules::agent_guardrails::MODEL_PROXY_PY));
}

/// The hand-over: the runner kills the model's processes until none is left, the
/// model bundles its own commits, and the runner takes only a regular file, not a
/// link, read as the model's user within a time and a size cap; it runs no git there.
#[test]
fn the_model_works_on_its_own_copy_and_bundles_its_own_commits() {
    let implement = implement_with_a_pack();
    let steps = steps_of(&implement, "implement");
    let copy = steps
        .iter()
        .position(|s| s.env.get("MODEL_USER").map(String::as_str) == Some(MODEL_USER))
        .expect("a copy step");
    assert!(copy < model_at(&steps));
    let bundle = steps
        .iter()
        .find(|s| s.id.as_deref() == Some("bundle"))
        .unwrap();
    let run = bundle.run.as_deref().unwrap();
    let (runner_before, rest) = run
        .split_once("<<'MODEL'\n")
        .expect("a heredoc for the model's user");
    let (_, runner_after) = rest.split_once("\nMODEL\n").expect("the heredoc ends");
    for line in runner_before.lines().chain(runner_after.lines()) {
        assert!(
            !line.trim_start().starts_with("git "),
            "the runner runs git: {line}"
        );
    }
    assert!(
        runner_before.contains(&format!("pgrep -u {MODEL_USER}")),
        "{runner_before}"
    );
    for needle in [
        &format!("[ -f /home/{MODEL_USER}/agent.bundle ]"),
        &format!("! -L /home/{MODEL_USER}/agent.bundle"),
        "timeout ",
        "head -c ",
        "BUNDLE_MAX_BYTES",
    ] {
        assert!(runner_after.contains(needle), "{needle} in\n{runner_after}");
    }
}

#[test]
fn the_guide_states_the_residual_egress_channels() {
    let planned = Fixture::new(Some(VERIFY)).plan(&AgentGuardrails).unwrap();
    let guide = planned.changes[GUIDE_PATH].as_deref().unwrap();
    for needle in [
        "agent-model",
        "no DNS",
        "proxy",
        "without sudo",
        "quota",
        "loopback",
        // Re-review of #1084 (N1): what the Claude proxy refuses, and the residual
        // risk of Codex's vendor proxy, which this setup does not filter.
        "server tools",
        "web search",
        "MCP",
        // #1095: Codex goes through the same filter; nothing is left unfiltered.
        "Codex's calls to OpenAI go through the same filter",
    ] {
        assert!(guide.contains(needle), "{needle}");
    }
    for stale in [
        "This setup does not filter it",
        "forwards what Codex sends to the OpenAI",
    ] {
        assert!(!guide.contains(stale), "{stale}");
    }
}

// ---- #1229: `<heldout_dir>` is settled in the recorded answers ----

const PLACEHOLDER_FINDING: &str = "WARNING: agents.protected-paths: protected_paths entry <heldout_dir>/** carries an unresolved placeholder; re-run install";

/// Records agent-guardrails' answers file with `answers`: what an installation
/// recorded before #1229 holds.
fn record_guardrails(repo: &Repo, answers: Value) {
    let file = json!({"module": "agent-guardrails",
        "version": brakes::modules::agent_guardrails::AGENT_GUARDRAILS_VERSION,
        "answers": answers});
    repo.write_json(&answers::path("agent-guardrails"), &file);
}

#[test]
fn configure_records_the_heldout_entry_resolved_never_the_placeholder() {
    let repo = heldout_repo("qa/heldout");
    let out = repo.cli(&[
        "configure",
        "<repo>",
        "agent-guardrails",
        "--set",
        "verify_timeout=900",
        "--apply",
    ]);
    assert!(out.status.success(), "{out:?}");
    let recorded = repo.json(&answers::path("agent-guardrails"))["answers"].clone();
    assert_eq!(
        recorded["protected_paths"],
        json!([".agent-setup/lock.json", "qa/heldout/**"])
    );
    assert!(repo.doctor().iter().all(|l| l != PLACEHOLDER_FINDING));
    let again = repo.install(&[]);
    assert!(again.status.success(), "{again:?}");
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("No changes."),
        "{again:?}"
    );
}

#[test]
fn an_installation_recorded_with_the_placeholder_is_migrated_by_the_next_install() {
    let repo = heldout_repo("qa/heldout");
    record_guardrails(
        &repo,
        json!({"protected_paths": [".agent-setup/lock.json", "<heldout_dir>/**", "docs/<heldout_dir>/**"], "verify_timeout": 900}),
    );
    assert!(
        repo.doctor().iter().any(|l| l == PLACEHOLDER_FINDING),
        "{:#?}",
        repo.doctor()
    );
    let plan = repo.install(&[]);
    assert!(plan.status.success(), "{plan:?}");
    let stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(
        stdout
            .contains("PLAN .agent-setup/modules/agent-guardrails.json [answers:agent-guardrails]"),
        "{stdout}"
    );
    assert!(repo.install(&["--apply"]).status.success());
    let recorded = repo.json(&answers::path("agent-guardrails"))["answers"].clone();
    assert_eq!(
        recorded["protected_paths"],
        json!([
            ".agent-setup/lock.json",
            "qa/heldout/**",
            "docs/qa/heldout/**"
        ])
    );
    assert_eq!(recorded["verify_timeout"], 900, "the other answers stay");
    assert!(
        repo.doctor()
            .iter()
            .all(|l| !l.contains("unresolved placeholder"))
    );
    let again = repo.install(&[]);
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("No changes."),
        "{again:?}"
    );
}

#[test]
fn doctor_flags_any_unresolved_placeholder_in_protected_paths() {
    let repo = heldout_repo("qa/heldout");
    record_guardrails(
        &repo,
        json!({"protected_paths": [".agent-setup/lock.json", "<spec_dir>/**"]}),
    );
    assert!(
        repo.doctor().iter().any(|l| l
            == "WARNING: agents.protected-paths: protected_paths entry <spec_dir>/** carries an unresolved placeholder; re-run install"),
        "{:#?}",
        repo.doctor()
    );
}

#[test]
fn settling_never_creates_an_answers_file_nor_rewrites_one_without_the_placeholder() {
    let f = Fixture::new(Some(VERIFY));
    let planned = f.plan(&AgentGuardrails).unwrap();
    assert!(
        !planned
            .changes
            .contains_key(&answers::path("agent-guardrails")),
        "no file is created"
    );
    let f = Fixture::profiled(Some(VERIFY), "P2");
    let planned = f.plan(&AgentGuardrails).unwrap();
    assert!(
        !planned
            .changes
            .contains_key(&answers::path("agent-guardrails")),
        "a file without the placeholder is left as recorded"
    );
}

#[test]
fn the_library_plan_records_the_settled_entry_in_the_answers_file() {
    let f = Fixture::profiled(Some(VERIFY), "P2");
    answer_ci_baseline(&f, json!({"heldout_dir": "./qa/held-out/"}));
    f.answer(json!({"protected_paths": ["<heldout_dir>/**", ".github/workflows/**"]}));
    let planned = f.plan(&AgentGuardrails).unwrap();
    let text = planned.changes[&answers::path("agent-guardrails")]
        .clone()
        .expect("written");
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        file["answers"]["protected_paths"],
        json!(["qa/held-out/**", ".github/workflows/**"])
    );
    assert_eq!(file["profile"], "P2");
}
