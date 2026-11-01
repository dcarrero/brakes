//! The minimal line-oriented TUI on `configure` (SPEC-questions.md, TUI
//! transcript and rendering rules; #719): scripted stdin against golden stdout
//! and the recorded file, which must equal the one `--set` writes for the same
//! answers; the interactivity rules of the CLI (`--interactive`, `--no-input`,
//! the refusal of a non-interactive run with an unanswered required question).
//!
//! Goldens live under `tests/golden/tui/<module>/<case>.{in,out,answers.json}`;
//! `UPDATE_GOLDENS=1` rewrites them.
use brakes::engine::answers::{self, Answers, Schema};
use brakes::engine::{Context, EnvVar, IntegrationContract, Module, Ownership, Rendered};
use brakes::questions::{self, Inputs, configure_new};
use brakes::{LOCK, Source, apply, profile_for};
use serde_json::json;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::{collections::BTreeMap, fs};

/// The fixture: one question of each scalar kind, labelled and helped by `x-ui`.
struct Survey;
impl Module for Survey {
    fn id(&self) -> &'static str {
        "survey"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        Schema::parse(&json!([
            {"id": "flavour", "type": "string", "enum": ["vanilla", "chocolate", "strawberry"],
             "default": "vanilla", "description": "The base flavour of every scoop.",
             "x-ui": {"label": "Flavour", "help": "Chocolate and strawberry cost one more."}},
            {"id": "cone", "type": "boolean", "default": false, "description": "Serve in a cone.",
             "x-ui": {"label": "Cone"}},
            {"id": "scoops", "type": "integer", "default": 2, "minimum": 1, "maximum": 4,
             "description": "How many scoops.", "x-ui": {"label": "Scoops"}},
            {"id": "name", "type": "string", "default": "demo", "minLength": 1, "maxLength": 8,
             "description": "The name on the order."},
        ]))
        .unwrap()
    }
    fn render(&self, cx: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(vec![Rendered {
            path: "docs/agent-setup/survey.json".to_owned(),
            class: Ownership::Managed,
            content: Some(serde_json::to_string(cx.answers)? + "\n"),
            scaffold: None,
        }])
    }
}

/// A required question with no default, and a pattern the TUI never asks.
struct Ticket;
impl Module for Ticket {
    fn id(&self) -> &'static str {
        "ticket"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        Schema::parse(&json!([
            {"id": "priority", "type": "integer", "default": 3, "description": "Priority."},
            {"id": "owner", "type": "string", "required": true, "description": "Who owns it."},
            {"id": "apps.*.port", "type": "integer", "minimum": 1, "description": "Port per app."},
        ]))
        .unwrap()
    }
    fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
}

/// Groups, an array of enum, a `when`-gated question, a plan-dependency note and
/// the `other` value with its "configure new" contract.
struct Order;
impl Module for Order {
    fn id(&self) -> &'static str {
        "order"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn questions(&self) -> Schema {
        Schema::parse(&json!([
            {"id": "size", "type": "string", "enum": ["small", "large", "other"], "default": "small",
             "description": "The cup size.", "x-ui": {"label": "Size", "group": "Cup"},
             "x-plan-dependency": {"feature": "big-cups", "values": ["large"]},
             "x-configure-new": {"contract": "order.size"}},
            {"id": "toppings", "type": "array",
             "items": {"type": "string", "enum": ["sprinkles", "nuts", "sauce"]},
             "default": ["sprinkles"], "minItems": 1, "maxItems": 2,
             "description": "What goes on top.", "x-ui": {"label": "Toppings", "group": "Cup"}},
            {"id": "delivery", "type": "boolean", "default": false, "description": "Deliver the order.",
             "x-ui": {"label": "Delivery", "group": "Cup"}},
            {"id": "address", "type": "string", "minLength": 1, "required": true, "when": "delivery",
             "description": "Where to deliver.", "x-ui": {"label": "Address", "group": "Delivery"}},
            {"id": "note", "type": "string", "default": "none", "description": "A note for the kitchen.",
             "x-ui": {"label": "Note", "group": "Delivery"}},
        ]))
        .unwrap()
    }
    fn render(&self, _: &Context<'_>) -> brakes::Result<Vec<Rendered>> {
        Ok(Vec::new())
    }
    fn configure_new(&self, question: &str, _: &Context<'_>) -> Option<IntegrationContract> {
        let seed = |path: &str, text: &str| Rendered {
            path: path.to_owned(),
            class: Ownership::Seed,
            content: Some(text.to_owned()),
            scaffold: None,
        };
        (question == "size").then(|| IntegrationContract {
            id: "order.size",
            env: vec![EnvVar {
                name: "CUP_URL".to_owned(),
                purpose: "Where the cup supplier answers.".to_owned(),
                example: "https://cups.example.org".to_owned(),
                required: true,
            }],
            seed: vec![seed(
                "order/cup.sh",
                "# TODO(configure-new): order the cup.\n",
            )],
            steps: vec![configure_new::endpoint_answers("CUP_URL")],
            guide: seed(
                "docs/agent-setup/integrations/order.size.md",
                "# Cup\n\nTODO(configure-new): name the supplier.\n",
            ),
        })
    }
}

struct Repo {
    _temp: tempfile::TempDir,
    root: PathBuf,
}
impl Repo {
    fn new() -> Self {
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
        Self { _temp: temp, root }
    }
    fn source() -> Source {
        Source {
            documents: BTreeMap::new(),
            version: "0.1.0".to_owned(),
            revision: None,
            dirty: false,
        }
    }
    fn configure(&self, module: &str, inputs: &Inputs) -> brakes::Result<questions::Configured> {
        let profile = profile_for(&self.root).unwrap();
        questions::configure(
            &self.root,
            &Self::source(),
            &profile,
            &[&Survey, &Ticket, &Order],
            &|_| true,
            module,
            inputs,
        )
    }
    /// The TUI over `stdin`; returns the patch (or the refusal) and the transcript.
    fn interview(
        &self,
        module: &str,
        inputs: &Inputs,
        stdin: &str,
    ) -> (brakes::Result<Answers>, String) {
        let mut output = Vec::new();
        let asked = questions::interview(
            &self.root,
            &Self::source(),
            &[&Survey, &Ticket, &Order],
            module,
            inputs,
            &mut stdin.as_bytes(),
            &mut output,
        );
        (asked, String::from_utf8(output).unwrap())
    }
    fn recorded(&self, module: &str) -> Option<String> {
        fs::read_to_string(self.root.join(answers::path(module))).ok()
    }
    /// `configure --set <sets>` applied: the recorded file the TUI must equal.
    fn by_set(module: &str, sets: &[&str]) -> String {
        let repo = Repo::new();
        let inputs = Inputs {
            sets: sets.iter().map(|s| (*s).to_owned()).collect(),
            ..Inputs::default()
        };
        let configured = repo.configure(module, &inputs).unwrap();
        apply(&repo.root, &configured.planned.changes).unwrap();
        repo.recorded(module).unwrap()
    }
}

fn golden_path(module: &str, case: &str, extension: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/tui")
        .join(module)
        .join(format!("{case}.{extension}"))
}

fn read_golden(module: &str, case: &str, extension: &str) -> String {
    let path = golden_path(module, case, extension);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with UPDATE_GOLDENS=1", path.display()))
}

/// Compares `text` with the golden byte for byte; `UPDATE_GOLDENS=1` rewrites it.
fn assert_golden(module: &str, case: &str, extension: &str, text: &str) {
    let path = golden_path(module, case, extension);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
    }
    let expected = read_golden(module, case, extension);
    assert!(
        text == expected,
        "{} differs from the golden:\n{text}",
        path.display()
    );
}

/// One fixture golden: `.in` through the TUI, the transcript against `.out`, the
/// recorded file against `.answers.json` and against what `--set <sets>` records.
/// Returns the transcript and the recorded file.
fn fixture_case(module: &str, case: &str, sets: &[&str]) -> (String, String) {
    let repo = Repo::new();
    let mut inputs = Inputs::default();
    let (asked, transcript) = repo.interview(module, &inputs, &read_golden(module, case, "in"));
    assert_golden(module, case, "out", &transcript);
    inputs.interactive = Some(asked.unwrap());
    let configured = repo.configure(module, &inputs).unwrap();
    apply(&repo.root, &configured.planned.changes).unwrap();
    let recorded = repo.recorded(module).unwrap();
    assert_golden(module, case, "answers.json", &recorded);
    assert_eq!(recorded, Repo::by_set(module, sets), "{case}: TUI vs --set");
    (transcript, recorded)
}

fn survey_case(case: &str, sets: &[&str]) {
    fixture_case("survey", case, sets);
}

#[test]
fn enter_on_every_question_records_the_defaults() {
    survey_case(
        "all-defaults",
        &["flavour=vanilla", "cone=false", "scoops=2", "name=demo"],
    );
}

#[test]
fn an_invalid_answer_reprompts_with_the_engines_message_then_takes_a_valid_one() {
    survey_case(
        "invalid-then-valid",
        &["flavour=chocolate", "cone=true", "scoops=3", "name=demo"],
    );
}

#[test]
fn a_question_mark_prints_the_help_and_reprompts() {
    survey_case(
        "help",
        &["flavour=vanilla", "cone=false", "scoops=2", "name=demo"],
    );
}

#[test]
fn an_enum_is_answered_by_its_number() {
    survey_case(
        "enum-number",
        &["flavour=strawberry", "cone=false", "scoops=2", "name=demo"],
    );
}

#[test]
fn an_enum_is_answered_by_its_value() {
    survey_case(
        "enum-text",
        &["flavour=chocolate", "cone=false", "scoops=4", "name=kiosk"],
    );
}

#[test]
fn eof_cancels_and_nothing_is_recorded() {
    let repo = Repo::new();
    let (asked, transcript) = repo.interview(
        "survey",
        &Inputs::default(),
        &read_golden("survey", "eof", "in"),
    );
    assert_golden("survey", "eof", "out", &transcript);
    assert_eq!(
        asked.unwrap_err().to_string(),
        "Cancelled; nothing recorded."
    );
    assert!(repo.recorded("survey").is_none());
}

#[test]
fn q_cancels_on_any_prompt() {
    let repo = Repo::new();
    let (asked, _) = repo.interview("survey", &Inputs::default(), "1\nq\n");
    assert_eq!(
        asked.unwrap_err().to_string(),
        "Cancelled; nothing recorded."
    );
}

#[test]
fn the_header_names_the_recorded_answers_and_the_preset_and_defaults_come_from_merged_answers() {
    let repo = Repo::new();
    let first = repo
        .configure(
            "survey",
            &Inputs {
                sets: vec!["scoops=3".to_owned(), "flavour=chocolate".to_owned()],
                ..Inputs::default()
            },
        )
        .unwrap();
    apply(&repo.root, &first.planned.changes).unwrap();
    let inputs = Inputs {
        sets: vec!["name=kiosk".to_owned()],
        ..Inputs::default()
    };
    let (asked, transcript) = repo.interview("survey", &inputs, "\n\n\n\n");
    assert!(
        transcript.starts_with(
            "survey 1.0.0 — 4 questions (profile P1; recorded answers: 4; preset: none)\n"
        ),
        "{transcript}"
    );
    assert!(
        transcript.contains("  2) chocolate  (default)\n"),
        "{transcript}"
    );
    assert!(transcript.contains("[3/4] Scoops  [3]\n"), "{transcript}");
    assert!(transcript.contains("[4/4] name  [kiosk]\n"), "{transcript}");
    assert_eq!(
        serde_json::to_value(asked.unwrap()).unwrap(),
        json!({"flavour": "chocolate", "cone": false, "scoops": 3, "name": "kiosk"})
    );
}

#[test]
fn interactive_answers_override_set_and_provenance_names_them() {
    let repo = Repo::new();
    let mut inputs = Inputs {
        sets: vec!["scoops=3".to_owned()],
        ..Inputs::default()
    };
    let (asked, _) = repo.interview("survey", &inputs, "\n\n4\n\n");
    inputs.interactive = Some(asked.unwrap());
    let configured = repo.configure("survey", &inputs).unwrap();
    assert_eq!(
        configured.provenance,
        "ANSWERS interactive cone, flavour, name, scoops"
    );
    apply(&repo.root, &configured.planned.changes).unwrap();
    assert_eq!(
        repo.recorded("survey").unwrap(),
        Repo::by_set("survey", &["scoops=4"])
    );
}

#[test]
fn a_required_question_without_a_value_reprompts_and_a_pattern_is_never_asked() {
    let repo = Repo::new();
    let (asked, transcript) = repo.interview("ticket", &Inputs::default(), "\n\nada\n");
    assert_eq!(
        transcript,
        "ticket 1.0.0 — 2 questions (profile P1; recorded answers: none; preset: none)\n\
         \n\
         [1/2] priority  [3]\n\
         > [2/2] owner\n\
         >   Module ticket: answer `owner` is required and has no value\n\
         > "
    );
    assert_eq!(
        serde_json::to_value(asked.unwrap()).unwrap(),
        json!({"priority": 3, "owner": "ada"})
    );
}

#[test]
fn a_non_interactive_run_with_an_unanswered_required_question_refuses_with_its_id() {
    let repo = Repo::new();
    assert_eq!(
        repo.configure("ticket", &Inputs::default())
            .unwrap_err()
            .to_string(),
        "Module ticket: question owner has no answer; pass --set owner=<value>, --answers <file> or --preset <name>"
    );
    assert!(repo.recorded("ticket").is_none());
    assert!(!repo.root.join(LOCK).exists());
}

// ---- #720: `when` gating, arrays of enum, groups, the plan-dependency note, `other` ----

const ORDER_DEFAULTS: &[&str] = &[
    "size=small",
    "toppings=sprinkles",
    "delivery=false",
    "note=none",
];

#[test]
fn a_gated_question_is_skipped_and_uncounted_and_a_group_header_waits_for_its_first_asked_question()
{
    let (transcript, _) = fixture_case("order", "all-defaults", ORDER_DEFAULTS);
    assert!(!transcript.contains("Address"), "{transcript}");
    assert_eq!(transcript.matches("Cup\n").count(), 1, "{transcript}");
    assert!(
        transcript.contains("> Delivery\n[4/4] Note  [none]\n"),
        "{transcript}"
    );
}

#[test]
fn an_answer_that_opens_a_gated_question_recounts_n_and_a_plan_dependency_never_blocks() {
    let (transcript, _) = fixture_case(
        "order",
        "when-opened",
        &[
            "size=large",
            "toppings=sprinkles",
            "delivery=true",
            "address=Main St 1",
            "note=none",
        ],
    );
    assert!(
        transcript.contains("  2) large  (needs GitHub feature big-cups: not checked)\n"),
        "{transcript}"
    );
    assert!(transcript.contains("[4/5] Address\n"), "{transcript}");
    assert!(transcript.contains("[5/5] Note  [none]\n"), "{transcript}");
}

#[test]
fn an_answer_that_closes_a_gated_question_recounts_n() {
    let repo = Repo::new();
    let first = repo
        .configure(
            "order",
            &Inputs {
                sets: vec!["delivery=true".to_owned(), "address=Main St 1".to_owned()],
                ..Inputs::default()
            },
        )
        .unwrap();
    apply(&repo.root, &first.planned.changes).unwrap();
    let (asked, transcript) = repo.interview("order", &Inputs::default(), "\n\nn\n\n");
    assert!(
        transcript.starts_with("order 1.0.0 — 5 questions "),
        "{transcript}"
    );
    assert!(
        transcript.contains("[3/5] Delivery  [Y/n]\n"),
        "{transcript}"
    );
    assert!(
        transcript.contains("> Delivery\n[4/4] Note  [none]\n"),
        "{transcript}"
    );
    assert_eq!(
        serde_json::to_value(asked.unwrap()).unwrap(),
        json!({"size": "small", "toppings": ["sprinkles"], "delivery": false, "note": "none"})
    );
}

#[test]
fn an_array_of_enum_takes_numbers_and_values_and_reprompts_with_the_engines_bounds() {
    let (transcript, _) = fixture_case(
        "order",
        "array",
        &[
            "size=small",
            "toppings=sauce,nuts",
            "delivery=false",
            "note=none",
        ],
    );
    for line in [
        "  Numbers separated by commas (1,3); at least 1, at most 2.\n",
        "  Not a choice: 4. Pick 1–3, Enter for the default, ? for help.\n",
        "  Module order: answer `toppings` must have at most 2 items\n",
        "  Module order: answer `toppings` must have at least 1 item\n",
    ] {
        assert!(transcript.contains(line), "{line}{transcript}");
    }
}

#[test]
fn other_is_listed_as_configure_new_and_picking_it_summarises_the_contract() {
    let (transcript, recorded) = fixture_case(
        "order",
        "other",
        &[
            "size=other",
            "toppings=sprinkles",
            "delivery=false",
            "note=none",
        ],
    );
    assert!(
        transcript.contains("  3) other — configure new (seed skeleton + manual steps)\n"),
        "{transcript}"
    );
    assert!(
        transcript.contains(
            "  other: contract order.size; the plan generates an env contract (CUP_URL), a seed skeleton (order/cup.sh), a seed guide (docs/agent-setup/integrations/order.size.md) and 1 manual step (endpoint-answers-cup-url).\n"
        ),
        "{transcript}"
    );
    assert!(recorded.contains("\"size\": \"other\""), "{recorded}");
}

#[test]
fn two_runs_on_one_fixture_give_identical_transcripts_and_recorded_files() {
    for (case, sets) in [
        ("all-defaults", ORDER_DEFAULTS),
        (
            "array",
            &[
                "size=small",
                "toppings=sauce,nuts",
                "delivery=false",
                "note=none",
            ][..],
        ),
    ] {
        assert_eq!(
            fixture_case("order", case, sets),
            fixture_case("order", case, sets),
            "{case}"
        );
    }
}

// ---- The CLI: `--interactive`, `--no-input`, goldens on repo-baseline ----

fn cli(root: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(args.iter().map(|a| {
            if *a == "<repo>" {
                root.as_os_str()
            } else {
                std::ffi::OsStr::new(a)
            }
        }))
        // A temporary repository has no remote: it is declared new and personal.
        .arg("--new-personal")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A process that never reads stdin may close it first; that is not an error here.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

/// One CLI golden on repo-baseline. Stdout of `configure --interactive` must be,
/// byte for byte, the golden transcript (`.out`), the provenance line naming the
/// interactive answers, and the very plan `configure --set <sets>` prints: the
/// plan half is compared with the `--set` run rather than pinned, so a template
/// added to another module does not rewrite these goldens. Then the same input
/// with `--apply`: the recorded file against `.answers.json` and against what
/// `configure --set <sets> --apply` records, lock included.
fn repo_baseline_case(case: &str, sets: &[&str]) {
    let stdin = read_golden("repo-baseline", case, "in");
    let mut set_args = vec!["configure", "<repo>", "repo-baseline"];
    for pair in sets {
        set_args.extend(["--set", pair]);
    }
    let repo = Repo::new();
    let plan = cli(
        &repo.root,
        &["configure", "<repo>", "repo-baseline", "--interactive"],
        &stdin,
    );
    assert!(plan.status.success(), "{}", stderr(&plan));
    assert!(
        repo.recorded("repo-baseline").is_none(),
        "nothing is written without --apply"
    );
    let by_set = Repo::new();
    let set_plan = stdout(&cli(&by_set.root, &set_args, ""));
    let (provenance, set_rest) = set_plan.split_once('\n').unwrap();
    assert!(provenance.starts_with("ANSWERS --set "), "{set_plan}");
    let out = stdout(&plan);
    let at = out.find("ANSWERS ").expect("a provenance line");
    assert_golden("repo-baseline", case, "out", &out[..at]);
    assert_eq!(
        &out[at..],
        format!(
            "ANSWERS interactive approvals, bypass_actors, codeowners, dependency_updates\n{set_rest}"
        )
    );
    let applied = cli(
        &repo.root,
        &[
            "configure",
            "<repo>",
            "repo-baseline",
            "--interactive",
            "--apply",
        ],
        &stdin,
    );
    assert!(applied.status.success(), "{}", stderr(&applied));
    let recorded = repo.recorded("repo-baseline").unwrap();
    assert_golden("repo-baseline", case, "answers.json", &recorded);
    set_args.push("--apply");
    let set = cli(&by_set.root, &set_args, "");
    assert!(set.status.success(), "{}", stderr(&set));
    assert_eq!(recorded, by_set.recorded("repo-baseline").unwrap());
    let lock = |repo: &Repo| fs::read_to_string(repo.root.join(LOCK)).unwrap();
    assert_eq!(lock(&repo), lock(&by_set), "same lock, same answers_digest");
}

#[test]
fn cli_enter_on_every_question_plans_the_defaults_and_applies_as_set_would() {
    repo_baseline_case(
        "all-defaults",
        &[
            "approvals=checks-only",
            "dependency_updates=dependabot",
            "codeowners=false",
            "bypass_actors=",
        ],
    );
}

#[test]
fn cli_enum_by_number_and_by_text() {
    repo_baseline_case(
        "enum-number-and-text",
        &[
            "approvals=checks-only",
            "dependency_updates=renovate",
            "codeowners=true",
            "bypass_actors=",
        ],
    );
}

#[test]
fn cli_eof_cancels_with_exit_2_and_writes_nothing() {
    let repo = Repo::new();
    let output = cli(
        &repo.root,
        &[
            "configure",
            "<repo>",
            "repo-baseline",
            "--interactive",
            "--apply",
        ],
        &read_golden("repo-baseline", "eof", "in"),
    );
    assert_eq!(output.status.code(), Some(2));
    assert_golden("repo-baseline", "eof", "out", &stdout(&output));
    assert_eq!(stderr(&output), "REFUSED: Cancelled; nothing recorded.\n");
    assert_eq!(fs::read_dir(&repo.root).unwrap().count(), 1, "only .git");
}

#[test]
fn cli_a_pipe_without_interactive_never_prompts_nor_reads_stdin() {
    let repo = Repo::new();
    // `q` would cancel if stdin were read.
    let output = cli(&repo.root, &["configure", "<repo>", "repo-baseline"], "q\n");
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(!out.contains("[1/3]"), "{out}");
    assert!(out.starts_with("ANSWERS default"), "{out}");
    let no_input = cli(
        &repo.root,
        &["configure", "<repo>", "repo-baseline", "--no-input"],
        "q\n",
    );
    assert!(no_input.status.success(), "{}", stderr(&no_input));
    assert_eq!(stdout(&no_input), out);
}

#[test]
fn cli_interactive_with_no_input_refuses() {
    let repo = Repo::new();
    let output = cli(
        &repo.root,
        &[
            "configure",
            "<repo>",
            "repo-baseline",
            "--interactive",
            "--no-input",
        ],
        "",
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stderr(&output),
        "REFUSED: --interactive and --no-input cannot be combined\n"
    );
    assert_eq!(stdout(&output), "");
}

#[test]
fn cli_interactive_is_only_available_with_configure_and_no_input_with_install_too() {
    let repo = Repo::new();
    for (operation, flag, message) in [
        (
            "install",
            "--interactive",
            "REFUSED: --interactive is only available with configure\n",
        ),
        (
            "doctor",
            "--interactive",
            "REFUSED: --interactive is only available with configure\n",
        ),
        (
            "doctor",
            "--no-input",
            "REFUSED: --no-input is only available with configure and install\n",
        ),
    ] {
        let output = cli(&repo.root, &[operation, "<repo>", flag], "");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(stderr(&output), message);
    }
}

#[test]
fn cli_accept_commands_refuses_interactive_and_no_input() {
    let repo = Repo::new();
    for flag in ["--interactive", "--no-input"] {
        let output = cli(
            &repo.root,
            &[
                "configure",
                "<repo>",
                "stack-packs",
                "--accept-commands",
                flag,
            ],
            "",
        );
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            stderr(&output),
            "REFUSED: --accept-commands cannot be combined with --interactive or --no-input\n"
        );
        assert_eq!(stdout(&output), "");
    }
}
