//! The agent App's token helper, `templates/agent-identity/installation-token.sh` (#1255):
//! its refusal paths. Every one exits 1 with one `installation-token:` line, prints
//! nothing on standard output and never reaches GitHub: `curl` and `security` are
//! stand-ins on PATH that record that they ran.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn helper() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/agent-identity/installation-token.sh")
}

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for name in ["curl", "security"] {
            let path = bin.join(name);
            fs::write(
                &path,
                format!("#!/bin/sh\necho {name} >> \"$FAKE/called\"\nexit 22\n"),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, env: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap()
        );
        let mut cmd = Command::new("bash");
        cmd.arg(helper())
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.dir.path())
            .env("FAKE", self.dir.path())
            .stdin(Stdio::null());
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.output().unwrap()
    }

    fn called(&self) -> String {
        fs::read_to_string(self.path("called")).unwrap_or_default()
    }
}

/// Exit 1, empty standard output, exactly the one expected message.
fn refused(output: &Output, message: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("installation-token: {message}\n")
    );
}

const CLIENT: (&str, &str) = ("AGENT_APP_CLIENT_ID", "Iv23liFakeClient");
const INSTALLATION: (&str, &str) = ("AGENT_APP_INSTALLATION_ID", "42");

#[test]
fn a_missing_or_malformed_client_id_is_refused() {
    let fx = Fixture::new();
    refused(
        &fx.run(&[INSTALLATION]),
        "AGENT_APP_CLIENT_ID is unset or not a client ID",
    );
    refused(
        &fx.run(&[("AGENT_APP_CLIENT_ID", "a b"), INSTALLATION]),
        "AGENT_APP_CLIENT_ID is unset or not a client ID",
    );
    assert_eq!(fx.called(), "");
}

#[test]
fn the_installation_and_repository_are_checked_before_anything_runs() {
    let fx = Fixture::new();
    refused(
        &fx.run(&[CLIENT, ("AGENT_APP_INSTALLATION_ID", "42; true")]),
        "AGENT_APP_INSTALLATION_ID is not a number",
    );
    for repository in ["widgets", "octo/../x", "octo/..", "octo/w id"] {
        refused(
            &fx.run(&[CLIENT, ("AGENT_APP_REPOSITORY", repository)]),
            "AGENT_APP_REPOSITORY is not owner/repo",
        );
    }
    refused(
        &fx.run(&[CLIENT]),
        "set AGENT_APP_INSTALLATION_ID or AGENT_APP_REPOSITORY",
    );
    assert_eq!(fx.called(), "");
}

#[test]
fn only_an_https_api_is_accepted() {
    let fx = Fixture::new();
    for api in ["http://api.github.com", "https://host/$(id)", "file:///etc"] {
        refused(
            &fx.run(&[CLIENT, INSTALLATION, ("GITHUB_API_URL", api)]),
            "GITHUB_API_URL must be an https URL",
        );
    }
    assert_eq!(fx.called(), "");
}

#[test]
fn a_key_that_is_unreadable_or_not_a_pem_private_key_is_refused() {
    let fx = Fixture::new();
    let missing = fx.path("missing.pem");
    refused(
        &fx.run(&[
            CLIENT,
            INSTALLATION,
            ("AGENT_APP_KEY_PATH", missing.to_str().unwrap()),
        ]),
        "AGENT_APP_KEY_PATH is not a readable file",
    );
    let not_pem = fx.path("key.txt");
    fs::write(&not_pem, "not a key\n").unwrap();
    refused(
        &fx.run(&[
            CLIENT,
            INSTALLATION,
            ("AGENT_APP_KEY_PATH", not_pem.to_str().unwrap()),
        ]),
        "the key is not a PEM private key",
    );
    assert_eq!(fx.called(), "");
}

#[test]
fn a_missing_keychain_entry_fails_without_calling_github() {
    let fx = Fixture::new();
    refused(
        &fx.run(&[CLIENT, INSTALLATION]),
        "no Keychain entry for service agent-app-private-key and account Iv23liFakeClient",
    );
    assert_eq!(fx.called(), "security\n");
}

#[test]
fn a_github_failure_fails_with_a_generic_message_and_no_token() {
    let fx = Fixture::new();
    let key = fx.path("key.pem");
    let genrsa = Command::new("openssl")
        .args(["genrsa", "-out"])
        .arg(&key)
        .arg("2048")
        .output()
        .unwrap();
    assert!(genrsa.status.success(), "{genrsa:?}");
    refused(
        &fx.run(&[
            CLIENT,
            INSTALLATION,
            ("AGENT_APP_KEY_PATH", key.to_str().unwrap()),
        ]),
        "could not mint an installation token for installation 42",
    );
    assert_eq!(fx.called(), "curl\n");
}
