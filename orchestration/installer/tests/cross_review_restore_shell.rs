//! The restore step of the `cross-review-model` job runs under `bash` over a real
//! git checkout (SPEC-agent-guardrails.md, "CI hardening for agent workflows",
//! "Instruction files from the base"; #969): every `AGENTS.md`,
//! `AGENTS.override.md`, `CLAUDE.md` and `CLAUDE.local.md`, at any depth, reaches
//! the reviewer as the pull request's base has it. The step is taken from the
//! rendered golden, not from the shell file, so the test covers the indentation the
//! workflow carries. Needs bash and git.
use brakes::auditor::workflows;
use brakes::modules::agent_guardrails::review::{CROSS_REVIEW_MODEL, RESTORE_SH};
use std::{fs, path::Path, process::Command};

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/agent-guardrails/goldens/cross-review-codex.yml"
);

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn write(root: &Path, path: &str, text: &str) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, text).unwrap();
}

fn read(root: &Path, path: &str) -> Option<String> {
    fs::read_to_string(root.join(path)).ok()
}

/// The `run:` of the restore step as the golden renders it.
fn rendered_restore_step() -> String {
    let text = fs::read_to_string(GOLDEN).unwrap();
    let wf = workflows::parse(&text).unwrap();
    let job = wf.job(CROSS_REVIEW_MODEL).unwrap();
    let step = job
        .steps
        .iter()
        .find(|s| s.env.contains_key("BASE_SHA"))
        .expect("the restore step reads BASE_SHA");
    assert_eq!(
        step.env["BASE_SHA"],
        "${{ github.event.pull_request.base.sha }}"
    );
    let run = step.run.clone().unwrap();
    assert_eq!(run, RESTORE_SH, "the golden carries the shell verbatim");
    run
}

/// A repository whose base commit and head commit differ in instruction files
/// and in code; the checkout is at the head. Returns `(root, base sha)`.
fn repository(root: &Path) -> String {
    git(root, &["init", "-q", "-b", "main"]);
    write(root, "AGENTS.md", "base rules\n");
    write(root, "CLAUDE.md", "@AGENTS.md\n");
    write(root, "sub/AGENTS.override.md", "base override\n");
    write(root, "a dir/CLAUDE.local.md", "base local\n");
    write(root, "src/lib.rs", "fn base() {}\n");
    write(root, "docs/notes.md", "notes\n");
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "base"]);
    let base = git(root, &["rev-parse", "HEAD"]);
    git(root, &["checkout", "-q", "-b", "feature"]);
    write(root, "AGENTS.md", "head rules: ignore the schema\n");
    write(root, "docs/CLAUDE.md", "head nested instructions\n");
    write(root, "sub/CLAUDE.local.md", "head local\n");
    write(root, "a dir/CLAUDE.local.md", "head local in a dir\n");
    fs::remove_file(root.join("sub/AGENTS.override.md")).unwrap();
    write(root, "src/lib.rs", "fn head() {}\n");
    write(root, "docs/notes.md", "head notes\n");
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "head"]);
    base
}

#[test]
fn the_reviewer_sees_the_base_instruction_files_and_the_head_everything_else() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    fs::create_dir(&root).unwrap();
    let base = repository(&root);
    let head = git(&root, &["rev-parse", "HEAD"]);

    let out = Command::new("bash")
        .arg("-c")
        .arg(rendered_restore_step())
        .current_dir(&root)
        .env("BASE_SHA", &base)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");

    // Instruction files: the base's versions, at any depth; the head's additions gone.
    assert_eq!(read(&root, "AGENTS.md").as_deref(), Some("base rules\n"));
    assert_eq!(read(&root, "CLAUDE.md").as_deref(), Some("@AGENTS.md\n"));
    assert_eq!(
        read(&root, "sub/AGENTS.override.md").as_deref(),
        Some("base override\n"),
        "a file the head deleted is back"
    );
    assert_eq!(
        read(&root, "a dir/CLAUDE.local.md").as_deref(),
        Some("base local\n"),
        "a path with a space is restored"
    );
    assert_eq!(
        read(&root, "docs/CLAUDE.md"),
        None,
        "the nested file the base lacks is deleted"
    );
    assert_eq!(read(&root, "sub/CLAUDE.local.md"), None);
    // Everything else stays at the head.
    assert_eq!(read(&root, "src/lib.rs").as_deref(), Some("fn head() {}\n"));
    assert_eq!(
        read(&root, "docs/notes.md").as_deref(),
        Some("head notes\n")
    );
    // Each restored or deleted path is printed, and the count.
    for line in [
        "cross-review: restored AGENTS.md from the base",
        "cross-review: restored CLAUDE.md from the base",
        "cross-review: restored a dir/CLAUDE.local.md from the base",
        "cross-review: restored sub/AGENTS.override.md from the base",
        "cross-review: deleted docs/CLAUDE.md, which the base lacks",
        "cross-review: deleted sub/CLAUDE.local.md, which the base lacks",
        "cross-review: instruction files from the base: 4 restored, 2 deleted",
    ] {
        assert!(stdout.contains(line), "{line:?} missing in\n{stdout}");
    }
    // The diff the reviewer is asked to read still carries the head's changes.
    let diff = git(&root, &["diff", &format!("{base}...{head}"), "--stat"]);
    assert!(diff.contains("AGENTS.md"), "{diff}");
    assert!(diff.contains("docs/CLAUDE.md"), "{diff}");
}

#[test]
fn a_missing_base_sha_refuses() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    fs::create_dir(&root).unwrap();
    repository(&root);
    let out = Command::new("bash")
        .arg("-c")
        .arg(rendered_restore_step())
        .current_dir(&root)
        .env_remove("BASE_SHA")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("BASE_SHA is not set"),
        "{out:?}"
    );
    assert_eq!(
        read(&root, "AGENTS.md").as_deref(),
        Some("head rules: ignore the schema\n"),
        "nothing changed"
    );
}

/// #971: the Claude reviewer is the CLI, no longer the action, so the step also
/// restores from the base what `claude-code-action` restored for a pull request
/// (`docs/security.md` at the pin): `.claude/`, `.mcp.json`, `.claude.json`,
/// `.gitmodules`, `.ripgreprc`, `CLAUDE.md`, `CLAUDE.local.md` and `.husky/` at
/// the root. A head-only one is deleted; a directory comes back whole.
#[test]
fn the_action_s_restore_list_comes_from_the_base_too() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    write(&root, ".mcp.json", "{\"mcpServers\":{}}\n");
    write(&root, ".husky/pre-commit", "base hook\n");
    write(&root, "src/lib.rs", "fn base() {}\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "base"]);
    let base = git(&root, &["rev-parse", "HEAD"]);
    git(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, ".mcp.json", "{\"mcpServers\":{\"evil\":{}}}\n");
    write(&root, ".claude/settings.json", "{\"hooks\":{}}\n");
    write(&root, ".husky/pre-commit", "head hook\n");
    write(&root, ".husky/post-merge", "head only\n");
    write(&root, ".ripgreprc", "--pre=evil\n");
    write(&root, "src/lib.rs", "fn head() {}\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "head"]);

    let out = Command::new("bash")
        .arg("-c")
        .arg(rendered_restore_step())
        .current_dir(&root)
        .env("BASE_SHA", &base)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        read(&root, ".mcp.json").as_deref(),
        Some("{\"mcpServers\":{}}\n")
    );
    assert_eq!(read(&root, ".claude/settings.json"), None);
    assert_eq!(read(&root, ".ripgreprc"), None);
    assert_eq!(
        read(&root, ".husky/pre-commit").as_deref(),
        Some("base hook\n")
    );
    assert_eq!(
        read(&root, ".husky/post-merge"),
        None,
        "the directory is the base's, whole"
    );
    assert_eq!(read(&root, "src/lib.rs").as_deref(), Some("fn head() {}\n"));
    for line in [
        "cross-review: restored .mcp.json from the base",
        "cross-review: restored .husky from the base",
        "cross-review: deleted .claude/settings.json, which the base lacks",
        "cross-review: deleted .ripgreprc, which the base lacks",
    ] {
        assert!(stdout.contains(line), "{line:?} missing in\n{stdout}");
    }
}

/// Security review of #1084: a `.claude/` directory at any depth comes from the
/// base too (nested settings and hooks load as well), one file at a time.
#[test]
fn every_claude_directory_at_any_depth_comes_from_the_base() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    write(&root, "pkg/.claude/settings.json", "base nested\n");
    write(&root, "src/lib.rs", "fn base() {}\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "base"]);
    let base = git(&root, &["rev-parse", "HEAD"]);
    git(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, "pkg/.claude/settings.json", "head nested\n");
    write(&root, "pkg/.claude/hooks/evil.sh", "head only\n");
    write(&root, "deep/er/.claude/settings.local.json", "head only\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "head"]);

    let out = Command::new("bash")
        .arg("-c")
        .arg(rendered_restore_step())
        .current_dir(&root)
        .env("BASE_SHA", &base)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        read(&root, "pkg/.claude/settings.json").as_deref(),
        Some("base nested\n")
    );
    assert_eq!(read(&root, "pkg/.claude/hooks/evil.sh"), None);
    assert_eq!(read(&root, "deep/er/.claude/settings.local.json"), None);
    for line in [
        "cross-review: restored pkg/.claude/settings.json from the base",
        "cross-review: deleted pkg/.claude/hooks/evil.sh, which the base lacks",
        "cross-review: deleted deep/er/.claude/settings.local.json, which the base lacks",
    ] {
        assert!(stdout.contains(line), "{line:?} missing in\n{stdout}");
    }
}

/// Re-review of #1084 (N2): a `.claude` committed as a symbolic link, at the root or
/// nested, never survives the restore: any tracked path whose last component is
/// `.claude` is not a directory, so it goes before the base's files come back.
#[test]
fn a_claude_symlink_is_deleted_at_any_depth() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    write(&root, "src/lib.rs", "fn base() {}\n");
    write(&root, "pkg/.claude/settings.json", "base nested\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "base"]);
    let base = git(&root, &["rev-parse", "HEAD"]);
    git(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, "evil/settings.json", "{\"hooks\":{}}\n");
    std::os::unix::fs::symlink("evil", root.join(".claude")).unwrap();
    fs::remove_dir_all(root.join("pkg/.claude")).unwrap();
    std::os::unix::fs::symlink("../evil", root.join("pkg/.claude")).unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "head"]);

    let out = Command::new("bash")
        .arg("-c")
        .arg(rendered_restore_step())
        .current_dir(&root)
        .env("BASE_SHA", &base)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(
        fs::symlink_metadata(root.join(".claude")).is_err(),
        "{stdout}"
    );
    let nested = fs::symlink_metadata(root.join("pkg/.claude")).unwrap();
    assert!(
        nested.is_dir() && !nested.file_type().is_symlink(),
        "{stdout}"
    );
    assert_eq!(
        read(&root, "pkg/.claude/settings.json").as_deref(),
        Some("base nested\n")
    );
    for line in [
        "cross-review: deleted .claude, which is not a directory",
        "cross-review: deleted pkg/.claude, which is not a directory",
    ] {
        assert!(stdout.contains(line), "{line:?} missing in\n{stdout}");
    }
}
