//! The rules of each block, as `Rule` constants that `rules::REGISTRY` lists.
pub mod baseline;
pub mod ci_health;
pub mod dora;
pub mod governance;
pub mod modules;
pub mod operations;
pub mod posture;
pub mod qa;
pub mod security_remote;

use super::{Cx, rules::Outcome};

/// The `evaluate` of a rule that waits for a module: `auditor::evaluate`
/// reports it as `waits for module <id>` without calling this, and a direct
/// call still reads nothing and never fails.
fn waiting(_: &Cx<'_>) -> Outcome {
    Outcome::unavailable("waits for the module that defines its convention")
}
