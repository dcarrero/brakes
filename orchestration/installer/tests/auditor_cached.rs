//! The audit's read cache delegates every method of `Host` (#920): a method
//! left to its trait default would answer `Unsupported` through the cache,
//! which happened once with `latest_deployments`. The trait keeps its
//! `Unsupported` defaults (additive methods, SPEC-auditor.md), so the check
//! compares the methods the trait declares with those `Cached` implements.
use std::fs;

/// The methods declared directly inside the item that `opener` starts, a
/// line of the file; the item ends at the first unindented `}`.
fn methods(file: &str, opener: &str) -> Vec<String> {
    let path = format!("{}/src/{file}", env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(&path).unwrap();
    let (_, body) = source
        .split_once(&format!("\n{opener}\n"))
        .unwrap_or_else(|| panic!("{path} has no line `{opener}`"));
    let mut names: Vec<String> = body
        .lines()
        .take_while(|line| *line != "}")
        .filter_map(|line| line.strip_prefix("    fn "))
        .map(|rest| rest.split(['(', '<']).next().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn cached_implements_every_host_method() {
    let host = methods("host/mod.rs", "pub trait Host {");
    let cached = methods("auditor/cached.rs", "impl Host for Cached<'_> {");
    // The parser still finds the trait: reads, writes and `kind`.
    assert!(
        host.len() >= 40,
        "only {} Host methods found: {host:?}",
        host.len()
    );
    let missing: Vec<&String> = host.iter().filter(|m| !cached.contains(m)).collect();
    assert!(
        missing.is_empty(),
        "auditor::cached::Cached does not implement Host::{missing:?}: through the cache they answer Unsupported; delegate each with `self.read` (reads) or `self.wrote` (writes)"
    );
}

/// The Azure DevOps stub (#685) answers one fixed message from every method;
/// a method left to its trait default would answer the generic sentence.
#[test]
fn azure_devops_implements_every_host_method() {
    let host = methods("host/mod.rs", "pub trait Host {");
    let azure = methods("host/azure_devops.rs", "impl Host for AzureDevOps {");
    let missing: Vec<&String> = host.iter().filter(|m| !azure.contains(m)).collect();
    assert!(
        missing.is_empty(),
        "host::azure_devops::AzureDevOps does not implement Host::{missing:?}: through the trait default they answer another message; answer each with `unsupported()`"
    );
}
