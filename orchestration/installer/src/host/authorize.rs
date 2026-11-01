//! The two gates of the host adapter (decision 2026-10-28, "Host adapter"):
//! reads anywhere the token reads except identities the configured denylist names;
//! writes only to the configured write allowlist, one repository per call, behind an explicit flag:
//! `--remote` of `apply`, or `--publish-issue` of `doctor --fleet` (#736).
//! Both decide on the identity alone, before any transport call.
use super::RepoId;
use crate::{Result, refuse, scope};

/// Proof that `write` admitted one repository. Its fields are private and this
/// module has the only constructor, so a `Host` write cannot be called without
/// passing the gate:
///
/// ```compile_fail
/// use brakes::host::{HostKind, RepoId, authorize::WriteToken};
/// let token = WriteToken {
///     repo: RepoId::parse("example-owner/x").unwrap(),
///     _private: (),
/// };
/// ```
#[derive(Clone)]
pub struct WriteToken {
    repo: RepoId,
    _private: (),
}
impl WriteToken {
    /// The one repository this token writes to.
    pub fn repo(&self) -> &RepoId {
        &self.repo
    }
}
impl std::fmt::Debug for WriteToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WriteToken({})", self.repo)
    }
}

/// The read gate: every repository the token can read, except an identity naming a
/// word of the configured denylist, which the installer never reads even when the
/// owner runs it.
pub fn read(repo: &RepoId) -> Result<()> {
    read_identity(&repo.identity())
}

/// The read gate for an owner (user or organization) name.
pub fn read_owner(name: &str) -> Result<()> {
    read_identity(name)
}

fn read_identity(identity: &str) -> Result<()> {
    read_identity_in(crate::config::current()?, identity)
}

fn read_identity_in(config: &crate::config::Config, identity: &str) -> Result<()> {
    if let Some(word) = config.refused_word(identity) {
        return refuse(format!(
            "Remote read refused: {identity} is a {word} identity and the installer never reads one (decision 2026-10-28)"
        ));
    }
    Ok(())
}

/// The write gate and the only constructor of `WriteToken`: the explicit flag
/// first, then the read gate, then the configured write allowlist. A new
/// organization needs a decision entry plus a PR to the owner's configuration.
pub fn write(repo: &RepoId, allow_writes: bool) -> Result<WriteToken> {
    if !allow_writes {
        return refuse(format!(
            "Remote write to {repo} needs the explicit --remote flag of apply"
        ));
    }
    read(repo)?;
    if !scope::write_allowed(&repo.identity()) {
        return refuse(format!(
            "Remote write refused: {repo} is not in the authorized write allowlist; a new organization needs an owner decision in docs/decisions.md"
        ));
    }
    Ok(WriteToken {
        repo: repo.clone(),
        _private: (),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn the_empty_configuration_reads_anything() {
        for identity in [
            "example-owner/app",
            "example-corp",
            "anyone/example-corp-notes",
        ] {
            assert!(
                read_identity_in(&Config::empty(), identity).is_ok(),
                "{identity}"
            );
        }
    }

    #[test]
    fn a_configured_denylist_refuses_the_read_naming_its_word() {
        let config = Config::for_test("example-owner", &[], &["example-corp"]);
        assert_eq!(
            read_identity_in(&config, "Example-Corp-Labs/app")
                .unwrap_err()
                .to_string(),
            "Remote read refused: Example-Corp-Labs/app is a Example-corp identity and the installer never reads one (decision 2026-10-28)"
        );
    }
}
