//! The scanner pin table: every tool the security jobs run is downloaded by
//! URL and verified by SHA-256 from here, never from a marketplace action
//! (`aquasecurity/trivy-action` and `setup-trivy` were re-pointed in March
//! 2026, CVE-2026-33634). Versions and checksums come from the upstream
//! release checksum files, recorded in `checksums`; they change through PRs.
//! Semgrep CE ships no release binary, so it is pinned by container image
//! digest instead (T10, #798): the manifest-list digest Docker Hub reports for
//! the version tag, which covers both architectures.
use crate::{Result, refuse};

/// The bash fragment the CI jobs run to install one pin (`templates/security/fragments/install-tool.sh`).
pub const INSTALL_TOOL: &str =
    include_str!("../../../../../templates/security/fragments/install-tool.sh");

/// The commit the gitleaks tag `v<GITLEAKS.version>` points to; the pre-commit
/// hook seed uses it as `rev` so the hook and CI run the same release.
pub const GITLEAKS_HOOK_REV: &str = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e";

/// A pre-commit hook repository pinned to the full commit SHA of a release tag,
/// with the version as the `# frozen:` comment `pre-commit autoupdate --freeze` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HookPin {
    pub repo: &'static str,
    /// Bare version, without a leading `v`.
    pub version: &'static str,
    /// The commit the tag `v<version>` points to.
    pub rev: &'static str,
}

/// `detect-private-key`, `check-added-large-files`, `check-merge-conflict`.
pub const PRE_COMMIT_HOOKS: HookPin = HookPin {
    repo: "https://github.com/pre-commit/pre-commit-hooks",
    version: "6.0.0",
    rev: "3e8a8703264a2f4a69428a0aa4dcb512790b2c8c",
};

/// The `actionlint` hook, seeded when `.github/workflows/` exists.
pub const ACTIONLINT_HOOK: HookPin = HookPin {
    repo: "https://github.com/rhysd/actionlint",
    version: "1.7.12",
    rev: "914e7df21a07ef503a81201c76d2b11c789d3fca",
};

/// The runner architectures one job must support: GitHub-hosted amd64 and self-hosted arm64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    Amd64,
    Arm64,
}

impl Arch {
    /// The architecture as the fragment and messages name it.
    pub fn token(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
        }
    }

    /// The names upstream release assets use for this architecture (gitleaks
    /// says `x64`, Trivy `Linux-64bit` and `Linux-ARM64`).
    pub fn asset_tokens(self) -> &'static [&'static str] {
        match self {
            Arch::Amd64 => &["amd64", "x64", "x86_64", "64bit"],
            Arch::Arm64 => &["arm64", "aarch64", "ARM64"],
        }
    }
}

/// How the downloaded asset holds the binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// A gzipped tarball containing `bin` at its root.
    TarGz,
    /// The executable itself.
    Binary,
}

impl Format {
    /// The value `install-tool.sh` reads as `TOOL_FORMAT`.
    pub fn token(self) -> &'static str {
        match self {
            Format::TarGz => "tgz",
            Format::Binary => "bin",
        }
    }
}

/// One pinned scanner. Both architectures are required: self-hosted arm64 and
/// GitHub amd64 run the same job. Each architecture is `(url, sha256)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolPin {
    pub name: &'static str,
    /// Bare version, without a leading `v`.
    pub version: &'static str,
    /// Upstream release date, `YYYY-MM-DD`.
    pub released: &'static str,
    /// The executable's name once installed.
    pub bin: &'static str,
    pub format: Format,
    /// The upstream checksum file the digests were copied from.
    pub checksums: &'static str,
    pub amd64: (&'static str, &'static str),
    pub arm64: (&'static str, &'static str),
}

pub const GITLEAKS: ToolPin = ToolPin {
    name: "gitleaks",
    version: "8.30.1",
    released: "2026-03-21",
    bin: "gitleaks",
    format: Format::TarGz,
    checksums: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt",
    amd64: (
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
    arm64: (
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
        "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    ),
};

pub const OSV_SCANNER: ToolPin = ToolPin {
    name: "osv-scanner",
    version: "2.7.0",
    released: "2026-10-12",
    bin: "osv-scanner",
    format: Format::Binary,
    checksums: "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_SHA256SUMS",
    amd64: (
        "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64",
        "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b",
    ),
    arm64: (
        "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_arm64",
        "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7",
    ),
};

/// Trivy, for `container-scan` (`trivy fs`, `trivy config`, `trivy image`).
/// Pinned after the March 2026 window (`TRIVY_COMPROMISED`); `check_trivy_pin`
/// refuses a pin inside it.
pub const TRIVY: ToolPin = ToolPin {
    name: "trivy",
    version: "0.76.1",
    released: "2026-10-21",
    bin: "trivy",
    format: Format::TarGz,
    checksums: "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_checksums.txt",
    amd64: (
        "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz",
        "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
    ),
    arm64: (
        "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-ARM64.tar.gz",
        "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
    ),
};

/// A scanner pinned as a container image by manifest digest: one digest for
/// both architectures, run with `docker run <pinned>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImagePin {
    pub name: &'static str,
    /// Bare version, without a leading `v`.
    pub version: &'static str,
    /// Upstream release date, `YYYY-MM-DD`.
    pub released: &'static str,
    /// `registry/repository:tag`, the tag naming `version`.
    pub image: &'static str,
    /// `sha256:<64 hex>`, the manifest-list digest.
    pub digest: &'static str,
    /// Where the digest was read (the registry's tag record).
    pub source: &'static str,
}

impl ImagePin {
    /// The reference `docker run` pulls: `<image>@<digest>`.
    pub fn pinned(&self) -> String {
        format!("{}@{}", self.image, self.digest)
    }

    /// The image names the version and the digest is `sha256:` plus 64 lowercase hex.
    pub fn verify(&self) -> Result<()> {
        let hex = self.digest.strip_prefix("sha256:").unwrap_or("");
        if !lowercase_hex(hex, 64) {
            return refuse(format!(
                "security: image pin {} {} has no sha256: plus 64-hex lowercase digest",
                self.name, self.version
            ));
        }
        if self.version.is_empty() || !self.image.ends_with(&format!(":{}", self.version)) {
            return refuse(format!(
                "security: image pin {} {} is not tagged with that version: {}",
                self.name, self.version, self.image
            ));
        }
        Ok(())
    }
}

/// Semgrep CE, for `sast` when `sast == semgrep`: run from its image by digest
/// (`docker run --rm -v "$PWD:/src" <pinned> semgrep scan …`).
pub const SEMGREP: ImagePin = ImagePin {
    name: "semgrep",
    version: "1.182.0",
    released: "2026-10-20",
    image: "docker.io/semgrep/semgrep:1.182.0",
    digest: "sha256:4a34048c04fef049f71665047f074cffb00cc3d89482f965a5cd151d589237af",
    source: "https://hub.docker.com/v2/repositories/semgrep/semgrep/tags/1.182.0",
};

/// The workflow linter `ci-baseline`'s `workflow-lint` job installs; the same
/// release as `ACTIONLINT_HOOK`.
pub const ACTIONLINT: ToolPin = ToolPin {
    name: "actionlint",
    version: "1.7.12",
    released: "2026-03-30",
    bin: "actionlint",
    format: Format::TarGz,
    checksums: "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_checksums.txt",
    amd64: (
        "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
        "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
    ),
    arm64: (
        "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_arm64.tar.gz",
        "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6",
    ),
};

/// The upstream repository of each scanner a workflow may pin, by the name the
/// install fragment's `TOOL_NAME` (or the Semgrep image) gives it;
/// `security.scanner-stale` reads their latest releases (#801).
pub const UPSTREAMS: [(&str, &str); 5] = [
    ("actionlint", "rhysd/actionlint"),
    ("gitleaks", "gitleaks/gitleaks"),
    ("osv-scanner", "google/osv-scanner"),
    ("semgrep", "semgrep/semgrep"),
    ("trivy", "aquasecurity/trivy"),
];

/// Every pin the module may install, in the order the jobs name them.
pub const PINS: &[ToolPin] = &[GITLEAKS, OSV_SCANNER, TRIVY, ACTIONLINT];

/// Trivy versions whose binaries or images were published by the attacker
/// (GHSA-69fq-xp46-6x23: the v0.69.4 release on 2026-03-19, the v0.69.5 and
/// v0.69.6 Docker Hub images on 2026-03-22).
pub const TRIVY_COMPROMISED: [&str; 3] = ["0.69.4", "0.69.5", "0.69.6"];

/// The pin named `name`, exactly.
pub fn pin(name: &str) -> Option<&'static ToolPin> {
    PINS.iter().find(|p| p.name == name)
}

/// Refuses a Trivy pin inside the March 2026 compromise window; any other tool passes.
pub fn check_trivy_pin(pin: &ToolPin) -> Result<()> {
    let version = pin.version.trim_start_matches('v');
    if pin.name == "trivy" && TRIVY_COMPROMISED.contains(&version) {
        return refuse(format!(
            "security: Trivy {version} is within the March 2026 compromise window (CVE-2026-33634); pin 0.69.7 or later"
        ));
    }
    Ok(())
}

/// Every pin is well formed and no pin is a compromised Trivy.
pub fn verify_all() -> Result<()> {
    PINS.iter().try_for_each(ToolPin::verify)?;
    SEMGREP.verify()
}

fn lowercase_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ToolPin {
    /// The `(url, sha256)` the runner of `arch` downloads.
    pub fn artifact(&self, arch: Arch) -> (&'static str, &'static str) {
        match arch {
            Arch::Amd64 => self.amd64,
            Arch::Arm64 => self.arm64,
        }
    }

    /// Both architectures carry an https GitHub URL naming the version and a
    /// 64-hex lowercase digest; the Trivy window is refused.
    pub fn verify(&self) -> Result<()> {
        check_trivy_pin(self)?;
        if self.version.starts_with('v') || self.version.is_empty() {
            return refuse(format!(
                "security: pin {} needs a bare version, got {:?}",
                self.name, self.version
            ));
        }
        for arch in [Arch::Amd64, Arch::Arm64] {
            let (url, sha256) = self.artifact(arch);
            if !lowercase_hex(sha256, 64) {
                return refuse(format!(
                    "security: pin {} {} has no 64-hex lowercase sha256 for {}",
                    self.name,
                    self.version,
                    arch.token()
                ));
            }
            let named = arch.asset_tokens().iter().any(|t| url.contains(t));
            if !url.starts_with("https://github.com/") || !url.contains(self.version) || !named {
                return refuse(format!(
                    "security: pin {} {} URL for {} is not a GitHub release asset of that version and architecture: {url}",
                    self.name,
                    self.version,
                    arch.token()
                ));
            }
        }
        Ok(())
    }

    /// The environment `install-tool.sh` reads, in a stable order.
    pub fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("TOOL_NAME", self.name.to_owned()),
            ("TOOL_VERSION", self.version.to_owned()),
            ("TOOL_BIN", self.bin.to_owned()),
            ("TOOL_FORMAT", self.format.token().to_owned()),
            ("TOOL_URL_AMD64", self.amd64.0.to_owned()),
            ("TOOL_SHA256_AMD64", self.amd64.1.to_owned()),
            ("TOOL_URL_ARM64", self.arm64.0.to_owned()),
            ("TOOL_SHA256_ARM64", self.arm64.1.to_owned()),
        ]
    }
}
