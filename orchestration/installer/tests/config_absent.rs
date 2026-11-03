//! A binary without any configuration (nothing embedded, no --config, no XDG file)
//! refuses every write, and every remote read, with one clear message, and still
//! diagnoses and plans locally (SPEC-product-boundary.md, "Configuration contract";
//! #1051, #1259).

use std::{path::Path, process::Command};

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

/// The binary with an empty XDG configuration directory: the repository's test
/// configuration (`.cargo/config.toml`) is out of reach.
fn unconfigured(args: &[&str], config_home: &Path) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_brakes"))
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn without_configuration_writes_and_remote_reads_refuse_with_one_clear_message() {
    if brakes::config::Config::embedded() {
        return; // A build with BRAKES_EMBEDDED_CONFIG always has a configuration.
    }
    let temp = tempfile::tempdir().unwrap();
    let config_home = temp.path().join("empty-config");
    std::fs::create_dir(&config_home).unwrap();
    for (name, remote) in [
        (
            "with-remote",
            Some("https://github.com/example-owner/app.git"),
        ),
        ("new", None),
    ] {
        let repo = temp.path().join(name);
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        if let Some(url) = remote {
            git(&repo, &["remote", "add", "origin", url]);
        }
        let path = repo.to_str().unwrap();
        for args in [
            vec!["install", path, "--apply"],
            vec!["install", path, "--apply", "--new-personal"],
            vec!["configure", path, "repo-baseline", "--apply"],
            vec!["remove", path, "repo-baseline", "--apply"],
            vec!["doctor", path, "--remote"],
            vec!["apply", path],
        ] {
            let (ok, out) = unconfigured(&args, &config_home);
            assert!(!ok, "{args:?}: {out}");
            assert!(
                out.contains("No configuration: writes refused"),
                "{args:?}: {out}"
            );
        }
        assert!(
            !repo.join("AGENTS.md").exists() && !repo.join(".agent-setup").exists(),
            "{name}: nothing written"
        );
    }
}

/// The README's promise: without a configuration, brakes diagnoses and plans
/// locally and writes nothing (#1259).
#[test]
fn without_configuration_doctor_and_plans_run_and_write_nothing() {
    if brakes::config::Config::embedded() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let config_home = temp.path().join("empty-config");
    std::fs::create_dir(&config_home).unwrap();
    for (name, remote) in [
        (
            "with-remote",
            Some("https://github.com/someone-else/app.git"),
        ),
        ("new", None),
    ] {
        let repo = temp.path().join(name);
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        if let Some(url) = remote {
            git(&repo, &["remote", "add", "origin", url]);
        }
        let path = repo.to_str().unwrap();
        let (_, out) = unconfigured(&["doctor", path], &config_home);
        assert!(!out.contains("REFUSED"), "doctor: {out}");
        // A plan is not refused; its last line says the apply would be, and why (#55).
        for args in [
            vec!["install", path],
            vec!["install", path, "--module", "repo-baseline"],
        ] {
            let (ok, out) = unconfigured(&args, &config_home);
            assert!(ok, "{args:?}: {out}");
            assert_eq!(out.matches("REFUSED").count(), 1, "{args:?}: {out}");
            assert_eq!(
                out.lines().last(),
                Some(format!("APPLY REFUSED: {}", brakes::config::NO_CONFIGURATION).as_str()),
                "{args:?}: {out}"
            );
        }
        let (ok, out) = unconfigured(&["install", path], &config_home);
        assert!(ok && out.contains("Plan only; no writes."), "{out}");
        assert!(
            !repo.join("AGENTS.md").exists() && !repo.join(".agent-setup").exists(),
            "{name}: nothing written"
        );
    }
}

#[test]
fn an_explicit_config_file_is_read_and_its_owner_scope_applies() {
    if brakes::config::Config::embedded() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let config_home = temp.path().join("empty-config");
    std::fs::create_dir(&config_home).unwrap();
    let file = temp.path().join("config.json");
    std::fs::write(
        &file,
        r#"{"schema": 1, "owner": "example-owner", "write_allowlist": ["example-owner/*"]}"#,
    )
    .unwrap();
    let repo = temp.path().join("other");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/someone-else/app.git",
        ],
    );
    let path = repo.to_str().unwrap();
    let (ok, out) = unconfigured(
        &[
            "--config",
            file.to_str().unwrap(),
            "install",
            path,
            "--apply",
        ],
        &config_home,
    );
    assert!(!ok, "{out}");
    assert!(
        out.contains("Non-personal remote owner refused: someone-else"),
        "{out}"
    );
    let (ok, out) = unconfigured(&["install", path, "--config"], &config_home);
    assert!(!ok && out.contains("--config needs a file"), "{out}");
}

/// `--config` reaches the commands `main` dispatches before the project parser
/// (#1311): `mcp` serves with the file's configuration, and a file that cannot
/// load refuses with the configuration's message, not the usage line.
#[test]
fn mcp_and_the_early_commands_accept_an_explicit_config_file() {
    use std::io::Write;
    if brakes::config::Config::embedded() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let config_home = temp.path().join("empty-config");
    std::fs::create_dir(&config_home).unwrap();
    let file = temp.path().join("config.json");
    std::fs::write(
        &file,
        r#"{"schema": 1, "owner": "example-owner", "write_allowlist": ["example-owner/*"]}"#,
    )
    .unwrap();
    let file = file.to_str().unwrap();
    for args in [["mcp", "--config", file], ["--config", file, "mcp"]] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_brakes"))
            .args(args)
            .env("XDG_CONFIG_HOME", &config_home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                br#"{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}
"#,
            )
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains(r#""id":0"#) && stdout.contains("result"),
            "{args:?}: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let missing = temp.path().join("missing.json");
    for command in [&["mcp"][..], &["presets"], &["adopt", "."]] {
        let mut args = command.to_vec();
        args.extend(["--config", missing.to_str().unwrap()]);
        let (ok, out) = unconfigured(&args, &config_home);
        assert!(!ok, "{args:?}: {out}");
        assert!(
            out.contains("Configuration refused") && out.contains("missing.json"),
            "{args:?}: {out}"
        );
    }
}
