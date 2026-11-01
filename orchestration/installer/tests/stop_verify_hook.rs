//! The Stop→verify hook (#735; SPEC-agent-guardrails.md, "The Stop hook contract"),
//! run as rendered under `sh` inside temporary git repositories, against fake
//! `verify` commands that record their calls outside the repository so the record
//! itself never changes the tree digest.
use brakes::modules::agent_guardrails::{STOP_VERIFY_PATH, render, render_stop_hook};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use tempfile::TempDir;

const TIMEOUT: u64 = 600;

/// A repository with one commit, the rendered hook at its installed path, and a
/// fake `verify` living next to the repository (never inside it).
struct Repo {
    temp: TempDir,
    root: PathBuf,
    hook: PathBuf,
}

impl Repo {
    fn new(verify: Option<&str>, timeout: u64) -> Self {
        Self::build(tempfile::tempdir().unwrap(), verify, timeout)
    }
    /// A fake `verify`: `body` runs with `$CALLS` naming the file that records calls.
    fn with_fake(body: &str, timeout: u64) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("verify.sh");
        let calls = temp.path().join("calls");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nCALLS='{}'\necho run >> \"$CALLS\"\n{body}\n",
                calls.display()
            ),
        )
        .unwrap();
        let verify = format!("sh '{}'", script.display());
        Self::build(temp, Some(&verify), timeout)
    }
    fn build(temp: TempDir, verify: Option<&str>, timeout: u64) -> Self {
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.email", "t@example.invalid"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("README.md"), "# project\n").unwrap();
        git(&root, &["add", "README.md"]);
        git(&root, &["commit", "-qm", "one"]);
        let hook = root.join(STOP_VERIFY_PATH);
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(&hook, render_stop_hook(verify, timeout)).unwrap();
        Self { temp, root, hook }
    }
    fn calls(&self) -> usize {
        fs::read_to_string(self.temp.path().join("calls")).map_or(0, |s| s.lines().count())
    }
    fn payload(&self, stop_hook_active: bool) -> String {
        format!(
            "{{\"session_id\":\"t\",\"transcript_path\":\"/nonexistent\",\"cwd\":\"{}\",\"hook_event_name\":\"Stop\",\"stop_hook_active\":{stop_hook_active}}}",
            self.root.display()
        )
    }
    /// Runs the hook as Claude Code does: `sh <hook>` with the payload on stdin,
    /// from a directory that is not the repository, so `cwd` must come from the payload.
    fn run(&self) -> Output {
        self.run_with(&self.payload(false))
    }
    fn run_with(&self, stdin: &str) -> Output {
        run_hook(&self.hook, self.temp.path(), stdin)
    }
    fn state(&self) -> Option<String> {
        fs::read_to_string(self.root.join(".git/brakes/stop-verify.json")).ok()
    }
    fn dirty(&self, name: &str, text: &str) {
        fs::write(self.root.join(name), text).unwrap();
    }
    fn commit_all(&self, message: &str) {
        git(&self.root, &["add", "-A"]);
        git(&self.root, &["commit", "-qm", message]);
    }
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

fn run_hook(hook: &Path, cwd: &Path, stdin: &str) -> Output {
    let mut child = Command::new("sh")
        .arg(hook)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::{ErrorKind, Write};
    // A hook may exit without reading its payload (the no-verify branch does), so
    // the pipe can close under the write (#836); only that error is expected.
    match child.stdin.take().unwrap().write_all(stdin.as_bytes()) {
        Err(error) if error.kind() != ErrorKind::BrokenPipe => panic!("write stdin: {error}"),
        _ => {}
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("exit code")
}

// --- Rendering -----------------------------------------------------------------

#[test]
fn render_replaces_every_placeholder_and_nothing_else() {
    let out = render("a {{x}} b {{y}} {{x}} {{z}}", &[("x", "1"), ("y", "two")]);
    assert_eq!(out, "a 1 b two 1 {{z}}");
}

#[test]
fn rendered_hook_is_posix_sh_with_the_command_baked_in_verbatim() {
    let command = "cargo test --locked && printf '%s' \"it's $HOME\"";
    let hook = render_stop_hook(Some(command), 45);
    assert!(hook.starts_with("#!/bin/sh\n"));
    assert!(hook.contains(&format!("\n{command}\n")), "{hook}");
    assert!(hook.contains("timeout='45'"), "{hook}");
    assert!(!hook.contains("{{"), "unrendered placeholder:\n{hook}");
    assert_eq!(
        hook,
        render_stop_hook(Some(command), 45),
        "two renders differ"
    );
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("stop_verify.sh");
    fs::write(&path, &hook).unwrap();
    let check = Command::new("sh").arg("-n").arg(&path).output().unwrap();
    assert!(check.status.success(), "sh -n: {}", text(&check.stderr));
}

#[test]
fn rendering_without_verify_leaves_the_command_empty() {
    let hook = render_stop_hook(None, TIMEOUT);
    assert!(!hook.contains("{{"));
    assert_eq!(hook, render_stop_hook(Some(""), TIMEOUT));
}

// --- The contract table ----------------------------------------------------------

#[test]
fn no_verify_declared_exits_zero_with_the_system_message_and_runs_nothing() {
    let repo = Repo::new(None, TIMEOUT);
    repo.dirty("new.txt", "x\n");
    let out = repo.run();
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "{\"systemMessage\":\"Stop hook: no verify command declared in .agent-setup/project.json; nothing was run.\"}\n"
    );
    assert!(text(&out.stderr).is_empty());
    assert!(repo.state().is_none(), "no state without a verify");
}

#[test]
fn green_verify_exits_zero_records_the_digest_and_is_not_rerun_on_the_same_tree() {
    let repo = Repo::with_fake(
        "pwd >> \"$CALLS.pwd\"; cat > \"$CALLS.stdin\"; exit 0",
        TIMEOUT,
    );
    repo.dirty("new.txt", "x\n");
    let out = repo.run();
    assert_eq!(code(&out), 0, "stderr: {}", text(&out.stderr));
    assert!(
        text(&out.stdout).starts_with("{\"systemMessage\":\"verify green ("),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(repo.calls(), 1);
    let state = repo.state().expect("state file written");
    assert!(state.contains("\"verified\":\""), "{state}");
    assert!(state.contains("\"head\":\""), "{state}");
    assert!(state.contains("\"at\":\""), "{state}");
    // `verify` ran in the repository root with stdin closed.
    let pwd = fs::read_to_string(repo.temp.path().join("calls.pwd")).unwrap();
    assert_eq!(
        Path::new(pwd.trim()).canonicalize().unwrap(),
        repo.root.canonicalize().unwrap()
    );
    assert_eq!(
        fs::read_to_string(repo.temp.path().join("calls.stdin")).unwrap(),
        ""
    );

    let again = repo.run();
    assert_eq!(code(&again), 0);
    assert!(text(&again.stdout).is_empty(), "{}", text(&again.stdout));
    assert!(text(&again.stderr).is_empty(), "{}", text(&again.stderr));
    assert_eq!(repo.calls(), 1, "an identical tree is never verified twice");
}

#[test]
fn red_verify_blocks_with_the_reason_and_the_last_sixty_lines() {
    let repo = Repo::with_fake(
        "i=1; while [ $i -le 200 ]; do echo \"line $i\"; i=$((i+1)); done; echo 'to stderr' >&2; exit 3",
        TIMEOUT,
    );
    repo.dirty("new.txt", "x\n");
    let out = repo.run();
    assert_eq!(code(&out), 2, "stdout: {}", text(&out.stdout));
    assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));
    let stderr = text(&out.stderr);
    let mut lines = stderr.lines();
    let reason = lines.next().unwrap();
    assert!(reason.starts_with("verify failed (exit 3, "), "{reason}");
    assert!(
        reason.ends_with(&format!(
            "s): sh '{}'",
            repo.temp.path().join("verify.sh").display()
        )),
        "{reason}"
    );
    let tail: Vec<&str> = lines.collect();
    assert_eq!(tail.len(), 60, "{stderr}");
    assert_eq!(tail[0], "line 142");
    assert_eq!(tail[58], "line 200");
    assert_eq!(
        tail[59], "to stderr",
        "stderr and stdout are captured together"
    );
    assert!(!stderr.contains("line 141\n"));
    let state = repo.state().expect("state file written");
    assert!(state.contains("\"blocked\":\""), "{state}");
    assert!(!state.contains("verified"), "{state}");
    assert_eq!(repo.calls(), 1);
}

#[test]
fn an_identical_tree_after_a_block_is_never_blocked_twice_and_a_change_reruns() {
    let repo = Repo::with_fake("exit 1", TIMEOUT);
    repo.dirty("new.txt", "x\n");
    assert_eq!(code(&repo.run()), 2);
    assert_eq!(repo.calls(), 1);

    let again = repo.run_with(&repo.payload(true));
    assert_eq!(code(&again), 0, "{}", text(&again.stderr));
    assert_eq!(
        text(&again.stdout),
        "{\"systemMessage\":\"Stop hook: verify failed on this exact tree before and nothing changed; stopping so the failure can be reported, not fixed by blocking again.\"}\n"
    );
    assert!(text(&again.stderr).is_empty());
    assert_eq!(repo.calls(), 1, "nothing changed: verify is not rerun");

    // `stop_hook_active: true` with a changed tree runs verify again: that is the point.
    repo.dirty("new.txt", "y\n");
    let changed = repo.run_with(&repo.payload(true));
    assert_eq!(code(&changed), 2, "{}", text(&changed.stdout));
    assert_eq!(repo.calls(), 2);
    let state = repo.state().unwrap();
    assert!(state.contains("blocked"), "{state}");
}

#[test]
fn a_change_in_an_untracked_file_counts_as_a_change_and_an_ignored_one_does_not() {
    let repo = Repo::with_fake("exit 0", TIMEOUT);
    repo.dirty("notes.txt", "a\n");
    assert_eq!(code(&repo.run()), 0);
    assert_eq!(repo.calls(), 1);
    repo.dirty("notes.txt", "b\n");
    assert_eq!(code(&repo.run()), 0);
    assert_eq!(repo.calls(), 2, "untracked content changed");
    fs::write(repo.root.join(".gitignore"), "scratch/\n").unwrap();
    assert_eq!(code(&repo.run()), 0);
    assert_eq!(repo.calls(), 3, ".gitignore itself is a change");
    fs::create_dir(repo.root.join("scratch")).unwrap();
    fs::write(repo.root.join("scratch/out.log"), "noise\n").unwrap();
    assert_eq!(code(&repo.run()), 0);
    assert_eq!(repo.calls(), 3, "ignored files never trigger verify");
}

#[test]
fn clean_tree_at_a_verified_head_takes_the_fast_path_without_running_verify() {
    let repo = Repo::with_fake("exit 0", TIMEOUT);
    repo.dirty("new.txt", "x\n");
    assert_eq!(code(&repo.run()), 0);
    assert_eq!(repo.calls(), 1);
    // Committing the verified content changes HEAD but not the tree.
    repo.commit_all("two");
    let out = repo.run();
    assert_eq!(code(&out), 0);
    assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));
    assert_eq!(repo.calls(), 1, "same tree, committed: no rerun");
    // A clean tree at a HEAD whose content was never verified runs verify.
    repo.dirty("new.txt", "z\n");
    repo.commit_all("three");
    assert_eq!(code(&repo.run()), 0);
    assert_eq!(repo.calls(), 2);
    let state = repo.state().unwrap();
    assert!(state.contains("\"verified\":\""), "{state}");
    // And once verified, the clean checkout is green again without a call.
    assert_eq!(code(&repo.run()), 0);
    assert_eq!(repo.calls(), 2);
}

#[test]
fn timeout_blocks_within_the_bound_and_leaves_no_child_behind() {
    let repo = Repo::with_fake("sleep 5 & echo $! > \"$CALLS.sleep\"; wait", 1);
    repo.dirty("new.txt", "x\n");
    let started = Instant::now();
    let out = repo.run();
    let elapsed = started.elapsed();
    assert_eq!(code(&out), 2, "stdout: {}", text(&out.stdout));
    assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
    let stderr = text(&out.stderr);
    assert!(
        stderr.starts_with("verify failed (timeout after 1s"),
        "{stderr}"
    );
    assert!(stderr.contains("verify.sh'"), "{stderr}");
    let state = repo.state().unwrap();
    assert!(state.contains("\"blocked\":\""), "{state}");
    let pid = fs::read_to_string(repo.temp.path().join("calls.sleep")).unwrap();
    let pid = pid.trim();
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let alive = Command::new("kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        if !alive {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "sleep {pid} survived the timeout"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

// --- Edges -----------------------------------------------------------------------

/// The no-verify branch exits before reading its payload (#836). A payload far
/// larger than any pipe buffer makes the helper's write meet the closed pipe every
/// time, instead of only when the hook wins the race as in CI.
#[test]
fn a_hook_that_exits_before_reading_its_payload_still_reports_its_result() {
    let repo = Repo::new(None, TIMEOUT);
    let payload = format!("{}{}", repo.payload(false), " ".repeat(1 << 20));
    let out = repo.run_with(&payload);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "{\"systemMessage\":\"Stop hook: no verify command declared in .agent-setup/project.json; nothing was run.\"}\n"
    );
}

#[test]
fn outside_a_git_checkout_exits_zero_with_one_stderr_line() {
    let temp = tempfile::tempdir().unwrap();
    let calls = temp.path().join("calls");
    let hook = temp.path().join("plain").join(STOP_VERIFY_PATH);
    fs::create_dir_all(hook.parent().unwrap()).unwrap();
    fs::write(
        &hook,
        render_stop_hook(Some(&format!("echo run >> '{}'", calls.display())), TIMEOUT),
    )
    .unwrap();
    let payload = format!("{{\"cwd\":\"{}\"}}", temp.path().join("plain").display());
    let out = run_hook(&hook, temp.path(), &payload);
    assert_eq!(code(&out), 0);
    assert!(text(&out.stdout).is_empty());
    let stderr = text(&out.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("not inside a git checkout"), "{stderr}");
    assert!(!calls.exists(), "verify never ran");
}

#[test]
fn an_unparsable_payload_falls_back_to_the_hook_directory() {
    let repo = Repo::with_fake("exit 0", TIMEOUT);
    repo.dirty("new.txt", "x\n");
    let out = repo.run_with("this is not json");
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(repo.calls(), 1);
    let empty = repo.run_with("");
    assert_eq!(code(&empty), 0, "{}", text(&empty.stderr));
    assert_eq!(repo.calls(), 1, "same tree: not rerun");
}

#[test]
fn a_payload_cwd_that_does_not_exist_falls_back_to_the_hook_directory() {
    let repo = Repo::with_fake("exit 0", TIMEOUT);
    repo.dirty("new.txt", "x\n");
    let out = repo.run_with("{\"cwd\":\"/nonexistent/path\",\"stop_hook_active\":false}");
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(repo.calls(), 1);
}

#[test]
fn the_state_lives_under_the_gitdir_and_is_never_versioned() {
    let repo = Repo::with_fake("exit 0", TIMEOUT);
    repo.dirty("new.txt", "x\n");
    assert_eq!(code(&repo.run()), 0);
    assert!(repo.root.join(".git/brakes/stop-verify.json").is_file());
    let status = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(&repo.root)
        .output()
        .unwrap();
    let status = text(&status.stdout);
    assert!(!status.contains("brakes"), "{status}");
    assert!(!status.contains("stop-verify"), "{status}");
}
