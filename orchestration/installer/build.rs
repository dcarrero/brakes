use std::{path::Path, process::Command};

fn main() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_owned())
    };
    let revision = git(&["rev-parse", "HEAD"]).unwrap_or_default();
    // `cargo install --git` builds from Cargo's checkout, where Cargo itself leaves an
    // untracked `.cargo-ok` marker: not a change to the source (#1290).
    let dirty = git(&["status", "--porcelain", "--", ".", ":(exclude).cargo-ok"])
        .is_none_or(|s| !s.is_empty());
    println!("cargo:rustc-env=BRAKES_COMMIT={revision}");
    println!("cargo:rustc-env=BRAKES_DIRTY={dirty}");
    // Re-evaluate provenance on each build, including after a commit without code changes.
    println!("cargo:rerun-if-changed=build-provenance");
    embed_config(&source);
}

/// The configuration embedded in this binary (`src/config.rs`, lookup step 1): the file
/// `BRAKES_EMBEDDED_CONFIG` names, only when the build sets it (a relative path resolves
/// against the source checkout); nothing otherwise, whatever the checkout holds. The
/// owner installs his binary with
/// `BRAKES_EMBEDDED_CONFIG=neutrality/owner-config.json cargo install --locked --path orchestration/installer`.
/// The file is validated at run time, where an invalid one is refused, never ignored.
fn embed_config(source: &Path) {
    println!("cargo:rerun-if-env-changed=BRAKES_EMBEDDED_CONFIG");
    let path = std::env::var_os("BRAKES_EMBEDDED_CONFIG")
        .filter(|v| !v.is_empty())
        .map(|v| {
            let path = std::path::PathBuf::from(v);
            if path.is_absolute() {
                path
            } else {
                source.join(path)
            }
        });
    let text = match &path {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", path.display());
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("BRAKES_EMBEDDED_CONFIG {}: {e}", path.display()))
        }
        None => String::new(),
    };
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out.join("embedded-config.json"), text).expect("write embedded config");
}
