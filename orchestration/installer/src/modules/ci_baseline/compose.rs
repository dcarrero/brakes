//! Composition (SPEC-ci-baseline.md, "Composition: how other modules add jobs"):
//! the jobs the other active modules contribute through `Module::ci_jobs`, read
//! from `Context::contributed_jobs`, checked once. The renderer inserts each body
//! verbatim before `required`, adds its id to `required`'s `needs` and hands the
//! docs-skippable ids to the scope job; `required.sh` is unchanged.
use super::CI_BASELINE;
use crate::{
    Result,
    engine::{CiTier, Context},
    refuse,
};
use std::collections::BTreeMap;

/// The job ids the renderer may emit itself; a contributor never takes one.
pub const BUILT_IN_JOBS: &[&str] = &[
    "scope",
    "checks",
    "lint",
    "shard",
    "heldout",
    "heldout-properties",
    "workflow-lint",
    "macos",
    super::AGGREGATE_CHECK,
    super::CONTRIBUTED_AGGREGATE_CHECK,
];

/// A contributed job, checked, with the module that contributes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contributed {
    pub module: String,
    pub id: String,
    /// The job's mapping as it sits under `<id>:`, at column zero.
    pub yaml: String,
    pub docs_skippable: bool,
    /// The stack-packs app the job verifies (#1097), checked against the record.
    pub app: Option<String>,
}

fn kebab(id: &str) -> bool {
    !id.is_empty()
        && id.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// The other active modules' jobs in module order; a non-kebab id, or an id equal
/// to a built-in or to an earlier contributor's, refuses naming both modules.
pub fn contributed(cx: &Context<'_>) -> Result<Vec<Contributed>> {
    let mut owners: BTreeMap<&str, &str> =
        BUILT_IN_JOBS.iter().map(|id| (*id, CI_BASELINE)).collect();
    let mut jobs = Vec::new();
    let mut apps: Option<Vec<String>> = None;
    for (module, job) in cx.contributed_jobs() {
        let id = job.id.as_str();
        if !kebab(id) {
            return refuse(format!(
                "Module {module} contributes CI job {id}, which is not kebab-case"
            ));
        }
        if let Some(owner) = owners.insert(id, module) {
            return refuse(format!(
                "Module {module} contributes CI job {id}, which collides with module {owner}"
            ));
        }
        if let Some(app) = &job.app {
            if apps.is_none() {
                apps = Some(
                    crate::modules::stack_packs::required_packs(cx)?
                        .into_iter()
                        .map(|(app, _)| app.id)
                        .collect(),
                );
            }
            if !apps.iter().flatten().any(|known| known == app) {
                return refuse(format!(
                    "Module {module} contributes CI job {id} for app {app}, which is not a stack-packs app"
                ));
            }
        }
        jobs.push(Contributed {
            module: module.to_owned(),
            id: id.to_owned(),
            yaml: job.yaml.clone(),
            docs_skippable: job.skippable_under.contains(&CiTier::Docs),
            app: job.app.clone(),
        });
    }
    Ok(jobs)
}
