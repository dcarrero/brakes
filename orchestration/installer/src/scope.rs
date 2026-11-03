use crate::{LOCK, Result, config::Config, read, refuse};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

pub fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        return refuse(String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub fn destination(root: &Path, name: &str) -> Result<PathBuf> {
    let current = location(root, name)?;
    if current.exists() && !current.is_file() {
        return refuse(format!("Expected a file: {}", current.display()));
    }
    Ok(current)
}

/// Like `destination`, for a repository-relative path that may be a directory.
pub fn directory(root: &Path, name: &str) -> Result<PathBuf> {
    let current = location(root, name)?;
    if current.exists() && !current.is_dir() {
        return refuse(format!("Expected a directory: {}", current.display()));
    }
    Ok(current)
}

/// A repository-relative path, validated (inside the repository, no symlinks) but not
/// required to exist or to be of any type.
pub(crate) fn location(root: &Path, name: &str) -> Result<PathBuf> {
    let relative = Path::new(name);
    if relative.is_absolute() || relative.components().any(|p| p == Component::ParentDir) {
        return refuse(format!("Path outside repository: {name}"));
    }
    let mut current = root.to_owned();
    for part in relative.components() {
        current.push(part);
        if fs::symlink_metadata(&current).is_ok_and(|m| m.file_type().is_symlink()) {
            return refuse(format!("Symlink refused: {}", current.display()));
        }
    }
    Ok(current)
}

/// The read scope: the Git root of a checkout whose path and remotes name no word
/// of the configured denylist. It needs no configuration (SPEC-product-boundary.md,
/// "Configuration contract": every read is allowed except what the denylist refuses),
/// so `doctor` and every plan run without one (#1259); the write scope
/// (`personal_scope`) is checked before anything is written.
pub fn read_scope(root: &Path) -> Result<PathBuf> {
    if std::fs::symlink_metadata(root)?.file_type().is_symlink() {
        return refuse("Symlink target refused");
    }
    let root = root.canonicalize()?;
    if let Some(word) = crate::config::denied_word(&root.to_string_lossy())? {
        return refuse(format!(
            "{word}/corporate workspace refused, regardless of remote owner"
        ));
    }
    if Path::new(&git(&root, &["rev-parse", "--show-toplevel"])?).canonicalize()? != root {
        return refuse("Target must be the Git repository root");
    }
    for url in remote_urls(&root)? {
        crate::config::refuse_denied_repository(&url)?;
    }
    Ok(root)
}

/// Validate every fetch and push URL before reading or changing managed files.
pub fn personal_scope(root: &Path, new_personal: bool) -> Result<PathBuf> {
    personal_scope_in(crate::config::current()?, root, new_personal)
}

/// `personal_scope` under an explicit configuration.
pub fn personal_scope_in(config: &Config, root: &Path, new_personal: bool) -> Result<PathBuf> {
    if config.owner().is_empty() && config.write_allowlist.is_empty() {
        return refuse(crate::config::NO_CONFIGURATION);
    }
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return refuse("Symlink target refused");
    }
    let root = root.canonicalize()?;
    if let Some(word) = root
        .components()
        .find_map(|p| config.refused_word(&p.as_os_str().to_string_lossy()))
    {
        return refuse(format!(
            "{word}/corporate workspace refused, regardless of remote owner"
        ));
    }
    if Path::new(&git(&root, &["rev-parse", "--show-toplevel"])?).canonicalize()? != root {
        return refuse("Target must be the Git repository root");
    }
    for ancestor in root.ancestors().skip(1) {
        if ancestor.join(".git").exists() {
            return refuse(format!("Nested repository refused: {}", ancestor.display()));
        }
    }
    let urls = remote_urls(&root)?;
    for url in &urls {
        remote_identity_in(config, url)?;
    }
    if urls.is_empty() && !new_personal {
        let lock = read(&root, LOCK)?;
        let declared = lock
            .as_deref()
            .map(serde_json::from_str::<serde_json::Value>)
            .transpose()?;
        if declared
            .as_ref()
            .and_then(|v| v.get("personal_owner"))
            .and_then(|v| v.as_str())
            .is_none_or(|owner| owner.is_empty() || owner != config.owner())
        {
            return refuse("No remote: declare a new personal repository with --new-personal");
        }
    }
    Ok(root)
}

pub fn remote_urls(root: &Path) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    for remote in git(root, &["remote"])?.lines() {
        urls.extend(
            git(root, &["remote", "get-url", "--all", remote])?
                .lines()
                .map(str::to_owned),
        );
        urls.extend(
            git(root, &["remote", "get-url", "--push", "--all", remote])?
                .lines()
                .map(str::to_owned),
        );
    }
    Ok(urls)
}

/// Whether a lowercased `owner/name` identity is in the write allowlist in effect;
/// the comparison ignores case and never matches a wildcard against a nested path.
/// A configuration that cannot load allows nothing.
pub fn write_allowed(identity: &str) -> bool {
    crate::config::current().is_ok_and(|c| c.write_allowed(identity))
}

/// The `Owner/Name[.git]` path of a GitHub remote, as written, once the URL form,
/// the host and the protocol are validated; the identity rules stay with the callers.
pub(crate) fn github_path(remote: &str) -> Result<String> {
    let path = if let Some(path) = remote.strip_prefix("git@github.com:") {
        path.to_owned()
    } else {
        // A path, a `file:` URL or any other text that is not a URL (#55): named,
        // with the fix. A URL that fails to parse otherwise may carry a
        // credential, so its text is never printed.
        let not_github = |named: &str| {
            refuse(format!(
                "Remote is not a GitHub URL: {named}; the write scope names the repository by its GitHub remote (git remote set-url <remote> https://github.com/<owner>/<name>.git)"
            ))
        };
        let url = match url::Url::parse(remote) {
            Ok(url) => url,
            Err(url::ParseError::RelativeUrlWithoutBase) => return not_github(remote),
            Err(error) => return not_github(&format!("it does not parse ({error})")),
        };
        if url.scheme() == "file" {
            return not_github(url.path());
        }
        if url.host_str() != Some("github.com") {
            return refuse("Remote is not an allowed personal GitHub repository");
        }
        if !["https", "ssh"].contains(&url.scheme()) {
            return refuse("Remote protocol is not supported");
        }
        url.path().trim_matches('/').to_owned()
    };
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() != 2 || parts.iter().any(|s| s.is_empty()) {
        return refuse("Remote is not an allowed personal GitHub repository");
    }
    Ok(path)
}

pub fn remote_identity(remote: &str) -> Result<String> {
    remote_identity_in(crate::config::current()?, remote)
}

/// `remote_identity` under an explicit configuration.
pub fn remote_identity_in(config: &Config, remote: &str) -> Result<String> {
    if let Some(word) = config.refused_word(remote) {
        return refuse(format!(
            "{word} repository refused, regardless of remote owner"
        ));
    }
    let path = github_path(remote)?;
    let identity = path.strip_suffix(".git").unwrap_or(&path).to_lowercase();
    if config.write_allowlist.is_empty() {
        return refuse(crate::config::NO_CONFIGURATION);
    }
    if !config.write_allowed(&identity) {
        let owner = path.split('/').next().unwrap_or_default();
        return refuse(format!("Non-personal remote owner refused: {owner}"));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_configuration_refuses_every_write_and_denies_nothing() {
        let empty = Config::empty();
        for remote in [
            "https://github.com/example-owner/app.git",
            "git@github.com:example-org/app.git",
        ] {
            let error = remote_identity_in(&empty, remote).unwrap_err().to_string();
            assert_eq!(error, crate::config::NO_CONFIGURATION, "{remote}");
        }
    }

    #[test]
    fn a_remote_that_is_not_a_url_is_refused_naming_it_and_the_fix() {
        // #55: a clone of a local path has a path for its origin; `url` answered
        // "relative URL without a base", which named neither the remote nor the fix.
        let config = Config::for_test("example-owner", &["example-owner/*"], &[]);
        let hint = "the write scope names the repository by its GitHub remote (git remote set-url <remote> https://github.com/<owner>/<name>.git)";
        for (remote, named) in [
            ("/srv/clones/app", "/srv/clones/app"),
            ("../app", "../app"),
            ("file-less-path", "file-less-path"),
            ("file:///srv/clones/app", "/srv/clones/app"),
        ] {
            let error = remote_identity_in(&config, remote).unwrap_err().to_string();
            assert_eq!(
                error,
                format!("Remote is not a GitHub URL: {named}; {hint}"),
                "{remote}"
            );
        }
        // A URL that fails to parse for another reason may carry a credential:
        // it is refused without its text.
        for remote in [
            "https://x-access-token:secret-token@github.com:99999/o/r.git",
            "https://user:secret-token@git hub.com/o/r",
        ] {
            let error = remote_identity_in(&config, remote).unwrap_err().to_string();
            assert!(!error.contains("secret-token"), "{error}");
            assert!(
                error.starts_with("Remote is not a GitHub URL: it does not parse ("),
                "{error}"
            );
            assert!(error.ends_with(hint), "{error}");
        }
    }

    #[test]
    fn a_configured_denylist_refuses_before_the_allowlist_with_its_word() {
        let config = Config::for_test("example-owner", &["example-owner/*"], &["example-corp"]);
        assert_eq!(
            remote_identity_in(
                &config,
                "https://github.com/example-owner/example-corp-notes"
            )
            .unwrap_err()
            .to_string(),
            "Example-corp repository refused, regardless of remote owner"
        );
        assert_eq!(
            remote_identity_in(&config, "https://github.com/Example-Owner/App.git").unwrap(),
            "example-owner/app"
        );
    }

    #[test]
    fn the_workspace_path_is_refused_by_the_configured_denylist() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("example-corp-workspace");
        fs::create_dir(&workspace).unwrap();
        let config = Config::for_test("example-owner", &["example-owner/*"], &["example-corp"]);
        assert_eq!(
            personal_scope_in(&config, &workspace, true)
                .unwrap_err()
                .to_string(),
            "Example-corp/corporate workspace refused, regardless of remote owner"
        );
        let error = personal_scope_in(&Config::empty(), &workspace, true)
            .unwrap_err()
            .to_string();
        assert_eq!(error, crate::config::NO_CONFIGURATION);
    }
}
