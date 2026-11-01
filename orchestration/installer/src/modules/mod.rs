//! The registry of compiled-in modules, in install order.
use crate::engine::Module;

pub mod agent_guardrails;
pub mod ci_baseline;
pub mod merge_guard;
pub mod qa;
pub mod repo_baseline;
pub mod security;
#[cfg(feature = "setup-core")]
#[rustfmt::skip] // the file is not in this repository; rustfmt would fail to resolve it
pub mod setup_core;
pub mod stack_packs;

pub use agent_guardrails::AgentGuardrails;
pub use ci_baseline::CiBaseline;
pub use merge_guard::MergeGuard;
pub use qa::Qa;
pub use repo_baseline::RepoBaseline;
pub use security::Security;
#[cfg(feature = "setup-core")]
pub use setup_core::{SETUP_CORE_VERSION, SetupCore};

/// `setup-core`'s version where it is compiled in (feature `setup-core`), else
/// `0.0.0`, the version the engine reads a lock with when the module is absent.
pub fn core_version() -> &'static str {
    #[cfg(feature = "setup-core")]
    return SETUP_CORE_VERSION;
    #[cfg(not(feature = "setup-core"))]
    return "0.0.0";
}
pub use stack_packs::StackPacks;

/// A module is active only when `setup-core`, recorded in the lock or requested
/// with `install --module`; `merge-guard` also wherever `setup-core` would still
/// render the hook it took over (no lock yet, or the hook recorded under
/// `setup-core`), and follows it in the capability map's build order, after
/// `stack-packs` and before `repo-baseline` (#696). `repo-baseline` precedes
/// `ci-baseline`, which names its aggregate job after the check the ruleset requires; `agent-guardrails`
/// follows its first requirement and contributes no CI job; `security` contributes
/// `security-gate` and `deps-scan` (#891); `qa` contributes `qa-api` and `qa-web`
/// (#1000); `ci_baseline` is last: it renders after
/// every module whose `ci_jobs` it collects.
pub fn all() -> Vec<&'static dyn Module> {
    vec![
        #[cfg(feature = "setup-core")]
        &SetupCore,
        &StackPacks,
        &MergeGuard,
        &RepoBaseline,
        &AgentGuardrails,
        &Security,
        &Qa,
        &CiBaseline,
    ]
}

/// The compiled module with this id, if any.
pub fn find(id: &str) -> Option<&'static dyn Module> {
    all().into_iter().find(|m| m.id() == id)
}
