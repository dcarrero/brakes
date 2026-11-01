//! Helpers shared by the integration tests (`mod common;`).

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

/// Writes an executable script that something will later run by path, without this
/// test process ever opening it for writing (#1082): a child `sh` writes it and
/// exits before the path is used. Were the test process to write it, a sibling test
/// forking a subprocess at that moment would inherit the writable descriptor until
/// its `exec`, and Linux would refuse to run the script with ETXTBSY ("Text file
/// busy"). Scripts only ever run through an interpreter (`sh <file>`) do not need it.
pub fn write_executable(path: &Path, body: &str) {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    assert!(
        child.wait().unwrap().success(),
        "writing {}",
        path.display()
    );
}
