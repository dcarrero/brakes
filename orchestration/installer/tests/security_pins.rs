//! The scanner pin table and the checksum install fragment (#786).
//! No network: the fragment is exercised under `bash` against `file://` fixtures.
use brakes::modules::security::pins::{
    ACTIONLINT_HOOK, Arch, Format, GITLEAKS_HOOK_REV, INSTALL_TOOL, ImagePin, PINS, SEMGREP, TRIVY,
    TRIVY_COMPROMISED, ToolPin, check_trivy_pin, pin, verify_all,
};
use brakes::modules::stack_packs::PinTable;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[test]
fn every_pin_has_both_architectures_with_well_formed_checksums() {
    assert!(!PINS.is_empty());
    for pin in PINS {
        for arch in [Arch::Amd64, Arch::Arm64] {
            let (url, sha256) = pin.artifact(arch);
            assert!(is_hex(sha256, 64), "{} {arch:?}: {sha256}", pin.name);
            assert!(
                url.starts_with("https://github.com/"),
                "{} {arch:?}: {url}",
                pin.name
            );
            assert!(url.contains(pin.version), "{} {arch:?}: {url}", pin.name);
            assert!(
                arch.asset_tokens().iter().any(|t| url.contains(t)),
                "{} {arch:?}: {url} does not name the architecture",
                pin.name
            );
        }
        assert_ne!(
            pin.amd64.1, pin.arm64.1,
            "{}: both architectures share one checksum",
            pin.name
        );
        assert!(!pin.version.starts_with('v'), "{}: bare version", pin.name);
        assert!(
            pin.released.len() == 10 && pin.released.as_bytes()[4] == b'-',
            "{}: release date {}",
            pin.name,
            pin.released
        );
        assert!(pin.checksums.starts_with("https://github.com/"));
        assert!(!pin.bin.is_empty());
    }
    verify_all().expect("pin table verifies");
}

#[test]
fn the_free_gate_scanners_are_pinned_and_looked_up_by_name() {
    let gitleaks = pin("gitleaks").expect("gitleaks pinned");
    assert_eq!(gitleaks.format, Format::TarGz);
    assert_eq!(gitleaks.bin, "gitleaks");
    let osv = pin("osv-scanner").expect("osv-scanner pinned");
    assert_eq!(osv.format, Format::Binary);
    assert_eq!(osv.bin, "osv-scanner");
    assert!(pin("GitLeaks").is_none(), "lookup is exact");
}

// ---- T10 (#798): Trivy by checksum, Semgrep by image digest ------------------------

#[test]
fn trivy_is_pinned_by_checksum_outside_the_compromise_window() {
    let trivy = pin("trivy").expect("trivy pinned");
    assert_eq!(trivy, &TRIVY);
    assert_eq!(trivy.format, Format::TarGz);
    assert_eq!(trivy.bin, "trivy");
    assert!(
        !TRIVY_COMPROMISED.contains(&trivy.version),
        "{} is compromised",
        trivy.version
    );
    let parts: Vec<u64> = trivy
        .version
        .split('.')
        .map(|p| p.parse().unwrap())
        .collect();
    assert!(
        parts > vec![0, 69, 6],
        "{} is not after the window",
        trivy.version
    );
    // The release assets are named `Linux-64bit` and `Linux-ARM64`.
    assert!(
        trivy.amd64.0.ends_with("_Linux-64bit.tar.gz"),
        "{}",
        trivy.amd64.0
    );
    assert!(
        trivy.arm64.0.ends_with("_Linux-ARM64.tar.gz"),
        "{}",
        trivy.arm64.0
    );
    assert!(
        trivy
            .checksums
            .starts_with("https://github.com/aquasecurity/trivy/releases/download/v")
    );
    check_trivy_pin(trivy).expect("outside the window");
    assert!(Arch::Amd64.asset_tokens().contains(&"64bit"));
    assert!(Arch::Arm64.asset_tokens().contains(&"ARM64"));
}

#[test]
fn semgrep_is_pinned_by_image_digest_with_its_source() {
    assert_eq!(SEMGREP.name, "semgrep");
    assert_eq!(
        SEMGREP.image,
        format!("docker.io/semgrep/semgrep:{}", SEMGREP.version)
    );
    let hex = SEMGREP
        .digest
        .strip_prefix("sha256:")
        .expect("sha256 digest");
    assert!(is_hex(hex, 64), "{}", SEMGREP.digest);
    assert_eq!(
        SEMGREP.pinned(),
        format!("{}@{}", SEMGREP.image, SEMGREP.digest)
    );
    assert!(SEMGREP.source.starts_with("https://"), "{}", SEMGREP.source);
    assert!(SEMGREP.released.len() == 10);
    SEMGREP.verify().expect("the Semgrep pin verifies");
    assert!(
        pin("semgrep").is_none(),
        "semgrep is an image, not a binary"
    );
    let bad = ImagePin {
        digest: "sha256:short",
        ..SEMGREP
    };
    let err = bad.verify().expect_err("short digest");
    assert!(err.to_string().contains("semgrep"), "{err}");
    let bad = ImagePin {
        image: "docker.io/semgrep/semgrep:latest",
        ..SEMGREP
    };
    let err = bad.verify().expect_err("image without the version");
    assert!(err.to_string().contains(SEMGREP.version), "{err}");
}

#[test]
fn gitleaks_hook_rev_is_the_full_commit_of_the_pinned_release() {
    assert!(is_hex(GITLEAKS_HOOK_REV, 40), "{GITLEAKS_HOOK_REV}");
    let gitleaks = pin("gitleaks").expect("gitleaks pinned");
    assert!(
        gitleaks
            .amd64
            .0
            .contains(&format!("/v{}/", gitleaks.version))
    );
}

fn trivy(version: &'static str) -> ToolPin {
    ToolPin {
        name: "trivy",
        version,
        released: "2026-03-19",
        bin: "trivy",
        format: Format::TarGz,
        checksums: "https://github.com/aquasecurity/trivy/releases",
        amd64: ("https://github.com/aquasecurity/trivy/releases/x", "0"),
        arm64: ("https://github.com/aquasecurity/trivy/releases/y", "1"),
    }
}

#[test]
fn trivy_versions_of_the_march_2026_compromise_window_are_refused() {
    for version in ["0.69.4", "0.69.5", "0.69.6", "v0.69.5"] {
        let bare = version.trim_start_matches('v');
        let err = check_trivy_pin(&trivy(version)).expect_err(version);
        assert_eq!(
            err.to_string(),
            format!(
                "security: Trivy {bare} is within the March 2026 compromise window (CVE-2026-33634); pin 0.69.7 or later"
            )
        );
    }
    for version in ["0.69.3", "0.69.7", "0.70.0"] {
        check_trivy_pin(&trivy(version)).expect(version);
    }
    check_trivy_pin(pin("gitleaks").expect("pinned")).expect("only Trivy is checked");
}

#[test]
fn verify_all_rejects_a_malformed_pin() {
    let mut bad = trivy("0.70.0");
    bad.amd64.1 = "not-hex";
    let err = ToolPin::verify(&bad).expect_err("malformed checksum");
    assert!(err.to_string().contains("trivy"), "{err}");
    assert!(err.to_string().contains("amd64"), "{err}");
    let mut bad = trivy("0.70.0");
    bad.amd64.1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bad.arm64.1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    bad.arm64.0 = "https://github.com/aquasecurity/trivy/releases/download/v0.69.9/x";
    let err = ToolPin::verify(&bad).expect_err("url without the version");
    assert!(err.to_string().contains("0.70.0"), "{err}");
}

/// Every `TOOL_*` name the fragment reads.
fn fragment_reads() -> Vec<String> {
    let mut read: Vec<String> = INSTALL_TOOL
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.starts_with("TOOL_"))
        .map(str::to_owned)
        .collect();
    read.sort();
    read.dedup();
    read
}

#[test]
fn the_fragment_env_names_every_variable_the_fragment_reads() {
    let gitleaks = pin("gitleaks").expect("pinned");
    let env = gitleaks.env();
    let produced: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
    let read = fragment_reads();
    for name in &read {
        assert!(
            produced.contains(&name.as_str()) || name == "TOOL_BIN_DIR" || name == "TOOL_BIN_PATH",
            "fragment reads {name} which env() does not produce"
        );
    }
    for name in &produced {
        assert!(
            read.iter().any(|r| r == name),
            "env() produces {name} unused by the fragment"
        );
    }
    assert_eq!(env[0], ("TOOL_NAME", "gitleaks".to_owned()));
}

#[test]
fn the_shared_tables_hurl_pin_names_exactly_what_the_fragment_reads() {
    let env = PinTable::embedded()
        .expect("table")
        .tool_binary("hurl")
        .expect("hurl is a binary pin");
    let mut produced: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
    produced.sort_unstable();
    let read = fragment_reads();
    let expected: Vec<&str> = read
        .iter()
        .map(String::as_str)
        .filter(|n| *n != "TOOL_BIN_DIR")
        .collect();
    assert_eq!(produced, expected);
    assert_eq!(env[0], ("TOOL_NAME", "hurl".to_owned()));
}

#[test]
fn the_fragment_installs_hurl_from_the_shared_tables_env_shape() {
    let fx = Fixture::new();
    let src = fx.path().join("src");
    hurl_layout(&src, "x86_64-unknown-linux-gnu");
    let (archive, sum) = tarball(&fx, &src, "hurl-8.1.0-x86_64-unknown-linux-gnu.tar.gz");
    let url = format!("file://{}", archive.display());
    let mut vars: Vec<(&'static str, String)> = PinTable::embedded()
        .expect("table")
        .tool_binary("hurl")
        .expect("hurl")
        .into_iter()
        .map(|(k, v)| match k {
            "TOOL_URL_AMD64" | "TOOL_URL_ARM64" => (k, url.clone()),
            "TOOL_SHA256_AMD64" | "TOOL_SHA256_ARM64" => (k, sum.clone()),
            _ => (k, v),
        })
        .collect();
    vars.push(("TOOL_BIN_DIR", fx.bin_dir.display().to_string()));

    let out = fx.run(&vars);

    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        fs::read_to_string(fx.bin_dir.join("hurl")).expect("installed"),
        FAKE_TOOL
    );
    assert!(
        text(&out).ends_with(&format!("tool: hurl 8.1.0 sha256={sum}\n")),
        "{}",
        text(&out)
    );

    let wrong: Vec<(&'static str, String)> = vars
        .iter()
        .map(|(k, v)| match *k {
            "TOOL_SHA256_AMD64" | "TOOL_SHA256_ARM64" => (*k, "0".repeat(64)),
            _ => (*k, v.clone()),
        })
        .collect();
    fs::remove_dir_all(&fx.bin_dir).expect("clean");
    let out = fx.run(&wrong);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("checksum mismatch"), "{}", text(&out));
    assert!(nothing_installed(&fx));
}

// ---- the install fragment under bash -------------------------------------

struct Fixture {
    dir: tempfile::TempDir,
    bin_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("install-tool.sh"), INSTALL_TOOL).expect("fragment");
        let bin_dir = dir.path().join("bin");
        Self { dir, bin_dir }
    }
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn run(&self, vars: &[(&str, String)]) -> Output {
        Command::new("bash")
            .arg(self.path().join("install-tool.sh"))
            .current_dir(self.path())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.path())
            .envs(vars.iter().map(|(k, v)| (*k, v.as_str())))
            .output()
            .expect("bash runs")
    }
    fn vars(
        &self,
        name: &str,
        file: &Path,
        sha256: &str,
        format: &str,
    ) -> Vec<(&'static str, String)> {
        let url = format!("file://{}", file.display());
        vec![
            ("TOOL_NAME", name.to_owned()),
            ("TOOL_VERSION", "1.2.3".to_owned()),
            ("TOOL_BIN", name.to_owned()),
            ("TOOL_FORMAT", format.to_owned()),
            ("TOOL_URL_AMD64", url.clone()),
            ("TOOL_SHA256_AMD64", sha256.to_owned()),
            ("TOOL_URL_ARM64", url),
            ("TOOL_SHA256_ARM64", sha256.to_owned()),
            ("TOOL_BIN_DIR", self.bin_dir.display().to_string()),
        ]
    }
}

fn sha256_of(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).expect("fixture")))
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const FAKE_TOOL: &str = "#!/usr/bin/env bash\necho fake-tool 1.2.3\n";

#[test]
fn the_fragment_parses_and_is_strict() {
    let fx = Fixture::new();
    let status = Command::new("bash")
        .args(["-n", "install-tool.sh"])
        .current_dir(fx.path())
        .status()
        .expect("bash -n");
    assert!(status.success());
    assert!(INSTALL_TOOL.starts_with("#!/usr/bin/env bash\n"));
    assert!(INSTALL_TOOL.contains("set -euo pipefail"));
    assert!(!INSTALL_TOOL.contains("|| true"));
    assert!(!INSTALL_TOOL.contains("grep -v"));
    assert!(INSTALL_TOOL.contains("--retry 3"));
}

#[test]
fn a_raw_binary_with_a_matching_checksum_is_installed() {
    let fx = Fixture::new();
    let file = fx.path().join("fake-tool_linux");
    fs::write(&file, FAKE_TOOL).expect("fixture");
    let sum = sha256_of(&file);
    let out = fx.run(&fx.vars("fake-tool", &file, &sum, "bin"));
    assert!(out.status.success(), "{}", text(&out));
    let installed = fx.bin_dir.join("fake-tool");
    assert_eq!(
        fs::read_to_string(&installed).expect("installed"),
        FAKE_TOOL
    );
    let run = Command::new(&installed).output().expect("executable");
    assert_eq!(String::from_utf8_lossy(&run.stdout), "fake-tool 1.2.3\n");
    let claim = text(&out);
    assert!(
        claim
            .lines()
            .last()
            .is_some_and(|l| l == format!("tool: fake-tool 1.2.3 sha256={sum}")),
        "{claim}"
    );
}

#[test]
fn a_tarball_with_a_matching_checksum_is_extracted_into_the_bin_dir() {
    let fx = Fixture::new();
    let src = fx.path().join("src");
    fs::create_dir(&src).expect("src");
    fs::write(src.join("fake-tool"), FAKE_TOOL).expect("fixture");
    fs::write(src.join("LICENSE"), "MIT\n").expect("fixture");
    let archive = fx.path().join("fake-tool_1.2.3_linux.tar.gz");
    let tar = Command::new("tar")
        .args([
            "-czf",
            archive.to_str().expect("utf8"),
            "-C",
            src.to_str().expect("utf8"),
            ".",
        ])
        .status()
        .expect("tar");
    assert!(tar.success());
    let sum = sha256_of(&archive);
    let out = fx.run(&fx.vars("fake-tool", &archive, &sum, "tgz"));
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        fs::read_to_string(fx.bin_dir.join("fake-tool")).expect("installed"),
        FAKE_TOOL
    );
    assert!(
        !fx.bin_dir.join("LICENSE").exists(),
        "only the binary is installed"
    );
}

#[test]
fn a_mismatching_checksum_is_refused_and_nothing_is_installed() {
    let fx = Fixture::new();
    let file = fx.path().join("fake-tool_linux");
    fs::write(&file, FAKE_TOOL).expect("fixture");
    let wrong = "0".repeat(64);
    for format in ["bin", "tgz"] {
        let out = fx.run(&fx.vars("fake-tool", &file, &wrong, format));
        assert!(!out.status.success(), "{format}: {}", text(&out));
        let log = text(&out);
        assert!(
            log.lines()
                .any(|l| l.starts_with("::error::security: fake-tool 1.2.3 ")
                    && l.contains("checksum mismatch")),
            "{format}: {log}"
        );
        assert!(
            log.contains(&sha256_of(&file)),
            "the observed digest is named: {log}"
        );
        assert!(!fx.bin_dir.exists() || fs::read_dir(&fx.bin_dir).expect("bin").next().is_none());
        assert!(
            !fx.path().join("fake-tool").exists(),
            "{format}: extracted into the workspace"
        );
    }
}

#[test]
fn a_missing_download_or_parameter_is_refused() {
    let fx = Fixture::new();
    let missing = fx.path().join("absent");
    let out = fx.run(&fx.vars("fake-tool", &missing, &"0".repeat(64), "bin"));
    assert!(!out.status.success());
    assert!(
        text(&out).contains("::error::security: fake-tool 1.2.3"),
        "{}",
        text(&out)
    );
    let mut vars = fx.vars("fake-tool", &missing, &"0".repeat(64), "bin");
    vars.retain(|(k, _)| *k != "TOOL_SHA256_ARM64" && *k != "TOOL_SHA256_AMD64");
    let out = fx.run(&vars);
    assert!(
        !out.status.success(),
        "unset parameter must fail under set -u"
    );
    let file = fx.path().join("fake-tool_linux");
    fs::write(&file, FAKE_TOOL).expect("fixture");
    let out = fx.run(&fx.vars("fake-tool", &file, &sha256_of(&file), "zip"));
    assert!(!out.status.success());
    assert!(
        text(&out).contains("::error::security: fake-tool 1.2.3 unknown format zip"),
        "{}",
        text(&out)
    );
    assert!(!fx.bin_dir.join("fake-tool").exists());
}

#[test]
fn actionlint_ci_binary_and_hook_are_the_same_release() {
    let actionlint = pin("actionlint").expect("actionlint pinned");
    assert_eq!(actionlint.format, Format::TarGz);
    assert_eq!(actionlint.bin, "actionlint");
    assert_eq!(actionlint.version, ACTIONLINT_HOOK.version);
}

// ---- TOOL_BIN_PATH: a binary below the archive root (Hurl, #997) ---------

/// A tarball of `src` (its contents at the archive root), and its digest.
fn tarball(fx: &Fixture, src: &Path, name: &str) -> (PathBuf, String) {
    let archive = fx.path().join(name);
    let tar = Command::new("tar")
        .args([
            "-czf",
            archive.to_str().expect("utf8"),
            "-C",
            src.to_str().expect("utf8"),
            ".",
        ])
        .status()
        .expect("tar");
    assert!(tar.success());
    let sum = sha256_of(&archive);
    (archive, sum)
}

/// Lays out `dir` as Hurl 8.1.0's Linux archive: `hurl-8.1.0-<triple>/{bin,man,completions}`.
fn hurl_layout(dir: &Path, triple: &str) {
    let top = dir.join(format!("hurl-8.1.0-{triple}"));
    fs::create_dir_all(top.join("bin")).expect("bin");
    fs::create_dir_all(top.join("man/man1")).expect("man");
    fs::create_dir_all(top.join("completions")).expect("completions");
    fs::write(top.join("bin/hurl"), FAKE_TOOL).expect("hurl");
    fs::write(
        top.join("bin/hurlfmt"),
        "#!/usr/bin/env bash\necho hurlfmt\n",
    )
    .expect("hurlfmt");
    fs::write(top.join("man/man1/hurl.1.gz"), "man").expect("man page");
    fs::write(top.join("completions/hurl.bash"), "complete").expect("completion");
}

fn with_bin_path(
    mut vars: Vec<(&'static str, String)>,
    bin_path: &str,
) -> Vec<(&'static str, String)> {
    vars.push(("TOOL_BIN_PATH", bin_path.to_owned()));
    vars
}

fn nothing_installed(fx: &Fixture) -> bool {
    !fx.bin_dir.exists() || fs::read_dir(&fx.bin_dir).expect("bin").next().is_none()
}

#[test]
fn a_tarball_laid_out_like_hurls_installs_the_one_binary_bin_path_names() {
    let fx = Fixture::new();
    let src = fx.path().join("src");
    hurl_layout(&src, "x86_64-unknown-linux-gnu");
    let (archive, sum) = tarball(&fx, &src, "hurl-8.1.0-x86_64-unknown-linux-gnu.tar.gz");

    let out = fx.run(&with_bin_path(
        fx.vars("hurl", &archive, &sum, "tgz"),
        "hurl-*/bin/hurl",
    ));

    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        fs::read_to_string(fx.bin_dir.join("hurl")).expect("installed"),
        FAKE_TOOL
    );
    let installed: Vec<_> = fs::read_dir(&fx.bin_dir)
        .expect("bin")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(installed, ["hurl"], "only the named binary is installed");
    assert!(
        text(&out)
            .lines()
            .last()
            .is_some_and(|l| l == format!("tool: hurl 1.2.3 sha256={sum}")),
        "{}",
        text(&out)
    );
}

#[test]
fn bin_path_must_resolve_to_exactly_one_file() {
    let fx = Fixture::new();
    let src = fx.path().join("src");
    hurl_layout(&src, "x86_64-unknown-linux-gnu");
    hurl_layout(&src, "aarch64-unknown-linux-gnu");
    let (archive, sum) = tarball(&fx, &src, "two.tar.gz");

    for (pattern, count) in [("hurl-*/bin/hurl", 2), ("hurl-*/bin/curl", 0)] {
        let out = fx.run(&with_bin_path(
            fx.vars("hurl", &archive, &sum, "tgz"),
            pattern,
        ));
        assert_eq!(out.status.code(), Some(1), "{pattern}: {}", text(&out));
        assert!(
            text(&out).contains(&format!(
                "::error::security: hurl 1.2.3 (amd64) TOOL_BIN_PATH {pattern} matches {count} files in the archive; exactly one is required"
            )) || text(&out).contains(&format!(
                "::error::security: hurl 1.2.3 (arm64) TOOL_BIN_PATH {pattern} matches {count} files in the archive; exactly one is required"
            )),
            "{pattern}: {}",
            text(&out)
        );
        assert!(nothing_installed(&fx), "{pattern}");
    }
}

#[test]
fn bin_path_refuses_an_escape_before_downloading() {
    let fx = Fixture::new();
    let missing = fx.path().join("never-downloaded.tar.gz");
    for pattern in ["/usr/bin/hurl", "hurl-8.1.0/../../hurl", ".."] {
        let out = fx.run(&with_bin_path(
            fx.vars("hurl", &missing, &"0".repeat(64), "tgz"),
            pattern,
        ));
        assert_eq!(out.status.code(), Some(1), "{pattern}: {}", text(&out));
        assert_eq!(
            text(&out),
            format!(
                "::error::security: hurl 1.2.3 TOOL_BIN_PATH {pattern} must be relative to the archive root without ..\n"
            ),
            "{pattern}"
        );
        assert!(nothing_installed(&fx), "{pattern}");
    }
}

#[test]
fn bin_path_needs_a_tarball() {
    let fx = Fixture::new();
    let file = fx.path().join("hurl_linux");
    fs::write(&file, FAKE_TOOL).expect("fixture");
    let out = fx.run(&with_bin_path(
        fx.vars("hurl", &file, &sha256_of(&file), "bin"),
        "hurl",
    ));
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert_eq!(
        text(&out),
        "::error::security: hurl 1.2.3 TOOL_BIN_PATH needs format tgz, got bin\n"
    );
    assert!(nothing_installed(&fx));
}

#[test]
fn bin_path_refuses_a_symlink_or_a_directory() {
    let fx = Fixture::new();
    let outside = fx.path().join("outside-hurl");
    fs::write(&outside, FAKE_TOOL).expect("outside");
    let src = fx.path().join("src");
    fs::create_dir_all(src.join("hurl-8.1.0-x/bin/hurl-dir")).expect("dir");
    std::os::unix::fs::symlink(&outside, src.join("hurl-8.1.0-x/bin/hurl")).expect("symlink");
    std::os::unix::fs::symlink(fx.path(), src.join("hurl-link")).expect("dir symlink");
    let (archive, sum) = tarball(&fx, &src, "links.tar.gz");

    for pattern in [
        "hurl-*/bin/hurl",
        "hurl-*/bin/hurl-dir",
        "hurl-link/outside-hurl",
    ] {
        let out = fx.run(&with_bin_path(
            fx.vars("hurl", &archive, &sum, "tgz"),
            pattern,
        ));
        assert_eq!(out.status.code(), Some(1), "{pattern}: {}", text(&out));
        assert!(
            text(&out)
                .lines()
                .any(|l| l.starts_with("::error::security: hurl 1.2.3 (")
                    && l.ends_with(&format!(
                        "TOOL_BIN_PATH {pattern} is not a regular file inside the archive"
                    ))),
            "{pattern}: {}",
            text(&out)
        );
        assert!(nothing_installed(&fx), "{pattern}");
    }
}

#[test]
fn a_mismatching_checksum_with_bin_path_extracts_nothing() {
    let fx = Fixture::new();
    let src = fx.path().join("src");
    hurl_layout(&src, "x86_64-unknown-linux-gnu");
    let (archive, _) = tarball(&fx, &src, "hurl.tar.gz");

    let out = fx.run(&with_bin_path(
        fx.vars("hurl", &archive, &"0".repeat(64), "tgz"),
        "hurl-*/bin/hurl",
    ));

    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("checksum mismatch"), "{}", text(&out));
    assert!(nothing_installed(&fx));
}
