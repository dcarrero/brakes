//! Hurl files never name a host (`SPEC-qa.md`, Objective): every request
//! starts with `{{base_url}}` or another variable, so one file serves the
//! pull-request test, `delivery`'s post-deploy smoke and `observability`'s
//! uptime probe. `literal_host` is the one reading of a request line, shared by
//! the seed check here and the auditor's `qa.hurl-no-literal-host` (T10).
use crate::{Result, refuse};

/// The URL of a request line (an upper-case method, then the URL) when it
/// names a host with `http://` or `https://`; `None` for a line that is not a
/// request (a `#` comment, `HTTP 200`, a section such as `[Asserts]`, an
/// assert) or whose URL starts with a variable.
pub fn literal_host(line: &str) -> Option<&str> {
    let line = line.trim_start();
    let (method, rest) = line.split_once([' ', '\t'])?;
    if method.is_empty() || method == "HTTP" || !method.chars().all(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let url = rest.split_whitespace().next()?;
    let lower = url.to_ascii_lowercase();
    (lower.starts_with("http://") || lower.starts_with("https://")).then_some(url)
}

/// The finding of the first request line of `text` that names a host, as
/// `<file>:<line> names a host; …` (the auditor's text).
pub fn host_finding(file: &str, text: &str) -> Option<String> {
    text.lines()
        .enumerate()
        .find(|(_, line)| literal_host(line).is_some())
        .map(|(index, _)| {
            format!(
                "{file}:{} names a host; use {{{{base_url}}}} so the file serves test, smoke and uptime",
                index + 1
            )
        })
}

/// Refuses a `.hurl` seed whose request line names a host.
pub fn check_seed(file: &str, text: &str) -> Result<()> {
    match host_finding(file, text) {
        Some(finding) => refuse(format!("qa: {finding}")),
        None => Ok(()),
    }
}
