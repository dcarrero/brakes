//! `gh pr checks` for the target repository, with a 45 s deadline.
//!
//! The supervisor ran this through its injected `process_runner` and `clock`;
//! here it is `std::process::Command` with a polling wait and a kill at the
//! deadline, the pattern `remote.rs` uses for `gh api`; light mode's protection
//! probe runs through the same [`run`].
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::review::EnvValue;

const GH_TIMEOUT: Duration = Duration::from_secs(45);

pub(super) fn checks(
    selector: Option<&str>,
    repo: &str,
    dir: Option<&PathBuf>,
    host: &EnvValue,
) -> Result<Vec<Value>, String> {
    let gh = std::env::var_os("AGENTIC_TEST_GH").unwrap_or_else(|| "gh".into());
    let mut command = Command::new(gh);
    command
        .args(["pr", "checks"])
        .args(selector)
        .args(["--repo", repo, "--json", "name,bucket"])
        .env_remove("GH_REPO");
    match host {
        EnvValue::Set(value) => {
            command.env("GH_HOST", value);
        }
        EnvValue::Unset => {
            command.env_remove("GH_HOST");
        }
        EnvValue::Inherited => {}
        EnvValue::Unknown => return Err("unknown GH_HOST".into()),
    }
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let out = run(command, Instant::now() + GH_TIMEOUT, "gh pr checks")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stderr: String = stderr.trim().chars().take(300).collect();
        return Err(if stderr.is_empty() {
            format!("gh pr checks exited {}", out.status)
        } else {
            stderr
        });
    }
    match serde_json::from_str(&stdout) {
        Ok(Value::Array(checks)) => Ok(checks),
        _ => Err("gh pr checks returned no check list".into()),
    }
}

/// Runs `command` to its end or kills it at `deadline` (`<what> timed out`).
/// Both pipes are drained on threads so a verbose `gh` cannot block on a full
/// pipe while this loop waits for it to exit.
pub(super) fn run(mut command: Command, deadline: Instant, what: &str) -> Result<Output, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| format!("gh: {e}"))?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{what} timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok(Output {
        status,
        stdout: stdout.join().map_err(|_| "gh reader failed")?,
        stderr: stderr.join().map_err(|_| "gh reader failed")?,
    })
}

/// Reads a child's pipe to its end on a thread; a missing pipe reads as empty.
fn drain(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_kills_a_command_at_its_deadline() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 5"]);
        let start = Instant::now();
        let error = run(command, start + Duration::from_millis(100), "the probe").unwrap_err();
        assert_eq!(error, "the probe timed out");
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
