//! The test configuration in effect (`tests/fixtures/config/brakes/config.json`, read
//! through the `XDG_CONFIG_HOME` that `.cargo/config.toml` sets), for the tests whose
//! subject is a configured value: a denylisted word, the configured owner, a runner
//! label. They read the value here instead of naming it (product-boundary T6f, #1193),
//! so the test sources carry no personal value and follow the configuration when it
//! changes. Not every file uses every item.
#![allow(dead_code)]

use brakes::config::{Config, NamedRunner};

/// The configuration the tests and the binaries they spawn read.
pub fn config() -> Config {
    Config::load(None).expect("the test configuration").0
}

/// A word the test configuration denies (lowercase, as the configuration stores it).
pub fn denied() -> String {
    config()
        .identity_denylist
        .first()
        .expect("the test configuration denies at least one word")
        .clone()
}

/// `word` with its first letter upper-cased, as the refusal messages name it.
pub fn capitalised(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// The owner the test configuration names.
pub fn owner() -> String {
    config().owner().to_owned()
}

/// The Linux runner the test configuration names (answer value and label).
pub fn linux_runner() -> NamedRunner {
    config()
        .runners
        .linux
        .expect("the test configuration names a Linux runner")
}

/// The macOS runner the test configuration names (answer value and label).
pub fn macos_runner() -> NamedRunner {
    config()
        .runners
        .macos
        .expect("the test configuration names a macOS runner")
}

/// The reusable verify workflow's callee the test configuration names (`owner/name`).
pub fn reusable_callee() -> String {
    config()
        .reusable_callee
        .expect("the test configuration names a reusable callee")
}
