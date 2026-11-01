//! `contracts-check.sh` under `bash` (SPEC-qa.md, Contracts (slice 2); T17,
//! #1016): the external-`$ref` refusal before any tool runs, lint, and the
//! comparison with the merge commit's first parent, against stub `vacuum`,
//! `oasdiff`, `asyncapi` and `node` executables on `PATH` that record their
//! arguments and answer with the exit code and output each test sets. The real
//! tools are never downloaded or run.
mod common;

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use tempfile::TempDir;

const CHECK: &str = include_str!("../../../templates/qa/fragments/contracts-check.sh");
const OPENAPI: &str = "openapi: 3.1.0\ninfo:\n  title: Shop\n  version: 1.0.0\npaths: {}\n";
const ASYNCAPI: &str = "asyncapi: 3.0.0\ninfo:\n  title: Events\n  version: 1.0.0\n";

/// A stub that logs `<name> <args>` to `$STUB_LOG`, prints `$STUB_<NAME>_OUT`
/// and exits with `$STUB_<NAME>_EXIT` (0 when unset).
fn stub(name: &str) -> String {
    let var = name.to_uppercase();
    format!(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"{name} $*\" >> \"$STUB_LOG\"\nprintf '%s' \"${{STUB_{var}_OUT:-}}\"\nexit \"${{STUB_{var}_EXIT:-0}}\"\n"
    )
}

struct Fixture {
    dir: TempDir,
    path: String,
}

impl Fixture {
    /// A repository whose base commit holds `base`, a branch commit `head`
    /// merged into it with `--no-ff`, so `HEAD^1` is the base.
    fn merged(base: &[(&str, &str)], head: &[(&str, &str)]) -> Self {
        let f = Self::empty();
        f.git(&["init", "-q", "-b", "main"]);
        f.commit(base, "base");
        f.git(&["checkout", "-q", "-b", "topic"]);
        f.commit(head, "head");
        f.git(&["checkout", "-q", "main"]);
        f.commit(&[("unrelated.txt", "x\n")], "main moved");
        f.git(&["merge", "-q", "--no-ff", "-m", "merge", "topic"]);
        f
    }

    fn empty() -> Self {
        let dir = TempDir::new().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for tool in ["vacuum", "oasdiff", "asyncapi", "node"] {
            common::write_executable(&bin.join(tool), &stub(tool));
        }
        fs::create_dir(dir.path().join("repo")).unwrap();
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
        Self { dir, path }
    }

    fn repo(&self) -> PathBuf {
        self.dir.path().join("repo")
    }

    fn out(&self) -> PathBuf {
        self.dir.path().join("out")
    }

    fn git(&self, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(self.repo())
            .args(["-c", "user.email=ci@example.invalid", "-c", "user.name=ci"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn commit(&self, files: &[(&str, &str)], message: &str) {
        for (path, text) in files {
            let path = self.repo().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
    }

    /// Runs the check at `stage` with `env` added to the defaults.
    fn run(&self, stage: &str, env: &[(&str, &str)]) -> Output {
        self.run_in(".", stage, env)
    }

    /// Runs the check from `dir` under the repository, as an app job does.
    fn run_in(&self, dir: &str, stage: &str, env: &[(&str, &str)]) -> Output {
        let script = self.dir.path().join("contracts-check.sh");
        fs::write(&script, CHECK).unwrap();
        let mut command = Command::new("bash");
        command
            .arg(&script)
            .current_dir(self.repo().join(dir))
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", self.dir.path())
            .env("STUB_LOG", self.dir.path().join("calls.log"))
            .env("QA_STAGE", stage)
            .env("QA_OUT", self.out())
            .env("QA_VACUUM_VERSION", "0.35.0")
            .env("QA_ASYNCAPI_VERSION", "6.2.1");
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.dir.path().join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn lines(out: &Output) -> Vec<String> {
    stdout(out).lines().map(str::to_owned).collect()
}

fn has_line(out: &Output, line: &str) -> bool {
    stdout(out).lines().any(|l| l == line)
}

fn assert_fails_with(out: &Output, line: &str) {
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}\n{}",
        stdout(out),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(has_line(out, line), "missing `{line}` in:\n{}", stdout(out));
}

// ---- external $ref ------------------------------------------------------------------

#[test]
fn an_external_ref_is_refused_before_any_tool_runs() {
    for (file, text, value) in [
        (
            "openapi.yaml",
            "openapi: 3.1.0\npaths:\n  /x:\n    $ref: './paths/x.yaml'\n",
            "./paths/x.yaml",
        ),
        (
            "openapi.json",
            "{\"openapi\": \"3.1.0\", \"paths\": {\"/x\": {\"$ref\": \"#/a\"}, \"/y\": {\"$ref\": \"https://example.com/y.json\"}}}\n",
            "https://example.com/y.json",
        ),
    ] {
        let f = Fixture::merged(&[(file, text)], &[]);
        let out = f.run("lint", &[("QA_OPENAPI", file)]);
        let line = if file.ends_with(".json") { 1 } else { 4 };
        assert_fails_with(
            &out,
            &format!(
                "::error::qa-contracts: {file}:{line} has an external $ref ({value}); bundle the contract into one file (docs/agent-setup/qa.md)"
            ),
        );
        assert_eq!(f.calls(), Vec::<String>::new(), "{file}");
    }
}

#[test]
fn a_local_ref_passes_and_lint_runs_with_its_flags() {
    let text =
        "openapi: 3.1.0\ncomponents:\n  schemas:\n    A:\n      $ref: '#/components/schemas/B'\n";
    let f = Fixture::merged(&[("openapi.yaml", text), (".spectral.yaml", "{}\n")], &[]);
    let out = f.run(
        "lint",
        &[
            ("QA_OPENAPI", "openapi.yaml"),
            ("QA_CONTRACT_RULESET", ".spectral.yaml"),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(
        has_line(&out, "contract-lint: openapi.yaml ok (vacuum 0.35.0)"),
        "{}",
        stdout(&out)
    );
    assert_eq!(
        f.calls(),
        [
            "vacuum lint --details --no-style --no-banner --no-update-check --remote=false --fail-severity error --ruleset .spectral.yaml openapi.yaml"
        ]
    );
    assert!(f.out().join("vacuum-lint/openapi.yaml.txt").is_file());
}

// ---- lint -----------------------------------------------------------------------------

#[test]
fn a_lint_failure_fails_the_job_naming_the_tool() {
    let f = Fixture::merged(&[("openapi.yaml", OPENAPI)], &[]);
    let mut out = f.run(
        "lint",
        &[("QA_OPENAPI", "openapi.yaml"), ("STUB_VACUUM_EXIT", "1")],
    );
    assert_fails_with(
        &out,
        "::error::qa-contracts: openapi.yaml fails lint (vacuum); see the report artifact",
    );
    let f = Fixture::merged(&[("asyncapi.yaml", ASYNCAPI)], &[]);
    out = f.run(
        "lint",
        &[
            ("QA_ASYNCAPI", "asyncapi.yaml"),
            ("STUB_ASYNCAPI_EXIT", "1"),
        ],
    );
    assert_fails_with(
        &out,
        "::error::qa-contracts: asyncapi.yaml fails lint (asyncapi); see the report artifact",
    );
    assert_eq!(
        f.calls(),
        ["asyncapi validate asyncapi.yaml --fail-severity error"]
    );
}

#[test]
fn an_asyncapi_contract_lints_with_its_claim_line() {
    let f = Fixture::merged(&[("asyncapi.yaml", ASYNCAPI)], &[]);
    let out = f.run("lint", &[("QA_ASYNCAPI", "asyncapi.yaml")]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(has_line(
        &out,
        "contract-lint: asyncapi.yaml ok (asyncapi 6.2.1)"
    ));
}

// ---- compatibility --------------------------------------------------------------------

const BREAK_TITLE: &str =
    "2 changes: 2 error, 0 warning, 0 info\nerror [api-path-removed-without-deprecation] ...\n";

#[test]
fn a_breaking_openapi_change_is_red_without_the_label() {
    let f = Fixture::merged(
        &[("openapi.yaml", OPENAPI)],
        &[("openapi.yaml", "openapi: 3.1.0\npaths: {}\n")],
    );
    let out = f.run(
        "compat",
        &[
            ("QA_OPENAPI", "openapi.yaml"),
            ("PR_LABELS", "[\"bug\"]"),
            ("STUB_OASDIFF_EXIT", "1"),
            ("STUB_OASDIFF_OUT", BREAK_TITLE),
        ],
    );
    assert_fails_with(
        &out,
        "::error::qa-contracts: openapi.yaml breaks clients of the base (2 breaking changes); add the human-approved label if the break is intended",
    );
    let base = f.out().join("base/openapi.yaml");
    assert_eq!(
        fs::read_to_string(&base).unwrap(),
        OPENAPI,
        "the base is HEAD^1's file"
    );
    assert_eq!(
        f.calls(),
        [format!(
            "oasdiff breaking --fail-on ERR --allow-external-refs=false --format text {} openapi.yaml",
            base.display()
        )]
    );
}

#[test]
fn a_breaking_change_with_human_approved_passes_with_a_warning() {
    let f = Fixture::merged(
        &[("openapi.yaml", OPENAPI)],
        &[("openapi.yaml", "openapi: 3.1.0\npaths: {}\n")],
    );
    let out = f.run(
        "compat",
        &[
            ("QA_OPENAPI", "openapi.yaml"),
            ("PR_LABELS", "[\"bug\",\"human-approved\"]"),
            ("STUB_OASDIFF_EXIT", "1"),
            ("STUB_OASDIFF_OUT", BREAK_TITLE),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(has_line(
        &out,
        "::warning::qa-contracts: openapi.yaml breaking changes accepted by human-approved"
    ));
    assert!(has_line(
        &out,
        "contract-compatible: openapi.yaml accepted (2 breaking)"
    ));
}

#[test]
fn a_compatible_change_and_a_new_contract_pass() {
    let f = Fixture::merged(&[("openapi.yaml", OPENAPI)], &[("openapi.yaml", OPENAPI)]);
    let out = f.run("compat", &[("QA_OPENAPI", "openapi.yaml")]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(has_line(&out, "contract-compatible: openapi.yaml ok"));
    let f = Fixture::merged(&[], &[("openapi.yaml", OPENAPI)]);
    let out = f.run("compat", &[("QA_OPENAPI", "openapi.yaml")]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert_eq!(
        lines(&out),
        ["contract-compatible: openapi.yaml new in this pull request; nothing to compare"]
    );
    assert_eq!(f.calls(), Vec::<String>::new());
}

#[test]
fn a_document_the_tool_cannot_load_is_red_even_with_the_label() {
    let f = Fixture::merged(&[("openapi.yaml", OPENAPI)], &[("openapi.yaml", OPENAPI)]);
    let out = f.run(
        "compat",
        &[
            ("QA_OPENAPI", "openapi.yaml"),
            ("PR_LABELS", "[\"human-approved\"]"),
            ("STUB_OASDIFF_EXIT", "102"),
        ],
    );
    assert_fails_with(
        &out,
        "::error::qa-contracts: openapi.yaml could not be compared (oasdiff exit 102); see the report artifact",
    );
}

#[test]
fn head_with_one_parent_is_refused() {
    let f = Fixture::empty();
    f.git(&["init", "-q", "-b", "main"]);
    f.commit(&[("openapi.yaml", OPENAPI)], "only");
    let out = f.run("compat", &[("QA_OPENAPI", "openapi.yaml")]);
    assert_fails_with(
        &out,
        "::error::qa-contracts: HEAD is not a merge commit; cannot find the base",
    );
}

#[test]
fn an_asyncapi_break_is_counted_from_the_json_array() {
    let f = Fixture::merged(
        &[("asyncapi.yaml", ASYNCAPI)],
        &[("asyncapi.yaml", ASYNCAPI)],
    );
    let out = f.run(
        "compat",
        &[("QA_ASYNCAPI", "asyncapi.yaml"), ("STUB_NODE_OUT", "3")],
    );
    assert_fails_with(
        &out,
        "::error::qa-contracts: asyncapi.yaml breaks clients of the base (3 breaking changes); add the human-approved label if the break is intended",
    );
    let calls = f.calls();
    let base = f.out().join("base/asyncapi.yaml");
    assert_eq!(
        calls[0],
        format!(
            "asyncapi diff {} asyncapi.yaml --type breaking --format json --no-error",
            base.display()
        )
    );
    assert!(calls[1].starts_with("node -e "), "{calls:?}");
    let f = Fixture::merged(
        &[("asyncapi.yaml", ASYNCAPI)],
        &[("asyncapi.yaml", ASYNCAPI)],
    );
    let out = f.run(
        "compat",
        &[("QA_ASYNCAPI", "asyncapi.yaml"), ("STUB_NODE_OUT", "0")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(has_line(&out, "contract-compatible: asyncapi.yaml ok"));
}

#[test]
fn the_check_is_hardened_shell() {
    assert!(CHECK.starts_with("#!/usr/bin/env bash\n"));
    assert!(CHECK.contains("\nset -euo pipefail\n"));
    for forbidden in [
        "|| true",
        "continue-on-error",
        "--update-snapshots",
        "curl ",
        "wget ",
    ] {
        assert!(!CHECK.contains(forbidden), "{forbidden}");
    }
}

// ---- an app job runs from the app's directory (#1115) -------------------------------

#[test]
fn from_an_app_directory_the_base_is_read_relative_to_it() {
    let f = Fixture::merged(
        &[("apps/shop/openapi.yaml", OPENAPI)],
        &[("apps/shop/openapi.yaml", "openapi: 3.1.0\npaths: {}\n")],
    );
    let out = f.run_in(
        "apps/shop",
        "compat",
        &[
            ("QA_OPENAPI", "openapi.yaml"),
            ("STUB_OASDIFF_EXIT", "1"),
            ("STUB_OASDIFF_OUT", BREAK_TITLE),
        ],
    );
    assert_fails_with(
        &out,
        "::error::qa-contracts: openapi.yaml breaks clients of the base (2 breaking changes); add the human-approved label if the break is intended",
    );
    assert_eq!(
        fs::read_to_string(f.out().join("base/openapi.yaml")).unwrap(),
        OPENAPI,
        "HEAD^1's apps/shop/openapi.yaml"
    );
}

// ---- several contracts and published copies (#1182) -------------------------------

const LIVE_A: &str = "contratos/ventas/openapi.yaml";
const LIVE_B: &str = "contratos/precios/openapi.yaml";
const PUBLISHED_A: &str = "contratos/ventas/publicado/v1.openapi.yaml";

#[test]
fn every_listed_contract_is_linted_with_its_own_report() {
    let f = Fixture::merged(&[], &[(LIVE_A, OPENAPI), (LIVE_B, OPENAPI)]);
    let out = f.run("lint", &[("QA_OPENAPI", &format!("{LIVE_A},{LIVE_B}"))]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    for contract in [LIVE_A, LIVE_B] {
        assert!(
            has_line(
                &out,
                &format!("contract-lint: {contract} ok (vacuum 0.35.0)")
            ),
            "{}",
            stdout(&out)
        );
        assert!(
            f.out()
                .join(format!("vacuum-lint/{contract}.txt"))
                .is_file()
        );
    }
    assert_eq!(f.calls().len(), 2, "{:?}", f.calls());
    // A failing second contract fails the job naming it.
    let out = f.run(
        "lint",
        &[
            ("QA_OPENAPI", &format!("{LIVE_A},{LIVE_B}")),
            ("STUB_VACUUM_EXIT", "1"),
        ],
    );
    assert_fails_with(
        &out,
        &format!("::error::qa-contracts: {LIVE_A} fails lint (vacuum); see the report artifact"),
    );
}

#[test]
fn an_external_ref_in_a_published_copy_is_refused() {
    let f = Fixture::merged(
        &[],
        &[
            (LIVE_A, OPENAPI),
            (PUBLISHED_A, "openapi: 3.1.0\npaths:\n  $ref: other.yaml\n"),
        ],
    );
    let out = f.run(
        "lint",
        &[
            ("QA_OPENAPI", LIVE_A),
            ("QA_PUBLISHED", &format!("{LIVE_A}={PUBLISHED_A}")),
        ],
    );
    assert_fails_with(
        &out,
        &format!(
            "::error::qa-contracts: {PUBLISHED_A}:3 has an external $ref (other.yaml); bundle the contract into one file (docs/agent-setup/qa.md)"
        ),
    );
    assert_eq!(f.calls(), Vec::<String>::new());
}

#[test]
fn a_live_contract_is_compared_with_its_published_copy_and_the_other_with_the_base() {
    let f = Fixture::merged(
        &[(LIVE_A, OPENAPI), (PUBLISHED_A, OPENAPI), (LIVE_B, OPENAPI)],
        &[(LIVE_A, "openapi: 3.1.0\npaths: {}\n")],
    );
    let out = f.run(
        "compat",
        &[
            ("QA_OPENAPI", &format!("{LIVE_A},{LIVE_B}")),
            ("QA_PUBLISHED", &format!("{LIVE_A}={PUBLISHED_A}")),
            ("PR_LABELS", "[]"),
            ("STUB_OASDIFF_EXIT", "1"),
            ("STUB_OASDIFF_OUT", BREAK_TITLE),
        ],
    );
    assert_fails_with(
        &out,
        &format!(
            "::error::qa-contracts: {LIVE_A} breaks clients of {PUBLISHED_A} (2 breaking changes); add the human-approved label if the break is intended"
        ),
    );
    assert_eq!(
        f.calls(),
        [format!(
            "oasdiff breaking --fail-on ERR --allow-external-refs=false --format text {PUBLISHED_A} {LIVE_A}"
        )]
    );
    // Compatible: both are compared, B against HEAD^1's copy.
    let out = f.run(
        "compat",
        &[
            ("QA_OPENAPI", &format!("{LIVE_A},{LIVE_B}")),
            ("QA_PUBLISHED", &format!("{LIVE_A}={PUBLISHED_A}")),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    for contract in [LIVE_A, LIVE_B] {
        assert!(has_line(
            &out,
            &format!("contract-compatible: {contract} ok")
        ));
    }
    let base_b = f.out().join(format!("base/{LIVE_B}"));
    assert!(
        f.calls().contains(&format!(
            "oasdiff breaking --fail-on ERR --allow-external-refs=false --format text {} {LIVE_B}",
            base_b.display()
        )),
        "{:?}",
        f.calls()
    );
}

#[test]
fn a_changed_published_copy_is_red_unless_human_approved() {
    let v2 = "openapi: 3.1.0\ninfo:\n  title: Shop\n  version: 2.0.0\npaths: {}\n";
    let f = Fixture::merged(
        &[(LIVE_A, OPENAPI), (PUBLISHED_A, OPENAPI)],
        &[(PUBLISHED_A, v2)],
    );
    let env = |labels: &'static str| {
        vec![
            ("QA_OPENAPI", LIVE_A.to_owned()),
            ("QA_PUBLISHED", format!("{LIVE_A}={PUBLISHED_A}")),
            ("PR_LABELS", labels.to_owned()),
        ]
    };
    let run = |labels: &'static str| {
        let env = env(labels);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        f.run("compat", &env)
    };
    let out = run("[]");
    assert_fails_with(
        &out,
        &format!(
            "::error::qa-contracts: {PUBLISHED_A} is a published copy and changes in this pull request; add the human-approved label if the new version is intended"
        ),
    );
    assert_eq!(f.calls(), Vec::<String>::new());
    let out = run("[\"human-approved\"]");
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(has_line(
        &out,
        &format!(
            "::warning::qa-contracts: {PUBLISHED_A} published copy changed under human-approved"
        )
    ));
    assert!(has_line(&out, &format!("contract-compatible: {LIVE_A} ok")));
}
