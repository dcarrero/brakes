//! The "configure new" contract (SPEC-questions.md, Decision 3; decision
//! 2026-10-28 point 9): an enum question that lists `other` and declares
//! `x-configure-new` gets, when answered `other`, the module's
//! `IntegrationContract`. This turns it into ordinary plan items: the skeleton
//! and the guide as `seed` (so a file being filled is never overwritten), the
//! env contract appended to the guide, and manual steps whose probes are only
//! the two generic remote ones, `endpoint-answers {env}` and
//! `secret-exists {name, environment}`. The answers file records `"other"` and
//! nothing more; the contract never asks for a secret value or a provider name.
use super::hints::{Hints, OTHER};
use crate::engine::manual::Owner;
use crate::engine::{
    Answers, Context, IntegrationContract, Lock, ManualStep, Module, Ownership, Probe, Rendered,
};
use crate::profile::Profile;
use crate::{Result, Source, refuse};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

/// The marker every skeleton and guide line left for the project carries.
pub const MARKER: &str = "TODO(configure-new):";
/// The generic remote probe: the endpoint named by an env variable answers.
pub const ENDPOINT_ANSWERS: &str = "endpoint-answers";
/// The generic remote probe: a named secret exists in a named environment.
pub const SECRET_EXISTS: &str = "secret-exists";

/// Where the guide of contract `id` lives.
pub fn guide_path(id: &str) -> String {
    format!("docs/agent-setup/integrations/{id}.md")
}

fn slug(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// The step whose probe asks whether the endpoint named by `env` answers.
pub fn endpoint_answers(env: &str) -> ManualStep {
    ManualStep {
        id: format!("{ENDPOINT_ANSWERS}-{}", slug(env)),
        title: format!("The endpoint named by {env} answers"),
        owner: Owner::Owner,
        instructions: format!(
            "Finish the skeleton, set {env} where the delivery reads it and deliver once; the probe only reads."
        ),
        probe: Probe::Remote {
            id: ENDPOINT_ANSWERS.to_owned(),
            args: BTreeMap::from([("env".to_owned(), json!(env))]),
        },
        after: None,
    }
}

/// The step whose probe asks whether secret `name` exists in `environment`;
/// its value is never asked for, read or stored.
pub fn secret_exists(name: &str, environment: &str) -> ManualStep {
    ManualStep {
        id: format!("{SECRET_EXISTS}-{}", slug(name)),
        title: format!("Secret {name} exists in environment {environment}"),
        owner: Owner::Owner,
        instructions: format!(
            "Create the secret {name} in the {environment} environment yourself; the installer never asks for its value."
        ),
        probe: Probe::Remote {
            id: SECRET_EXISTS.to_owned(),
            args: BTreeMap::from([
                ("name".to_owned(), json!(name)),
                ("environment".to_owned(), json!(environment)),
            ]),
        },
        after: None,
    }
}

/// True when `value` is, or lists, the reserved `other`.
pub(crate) fn picks_other(value: &Value) -> bool {
    let other = |item: &Value| item.as_str() == Some(OTHER);
    match value {
        Value::Array(items) => items.iter().any(other),
        single => other(single),
    }
}

/// The contracts of `module` for the questions `cx.answers` answers `other`,
/// each checked against the question's `x-configure-new`. A declared question
/// answered `other` without a contract refuses.
fn contracts(module: &dyn Module, cx: &Context<'_>) -> Result<Vec<IntegrationContract>> {
    let id = module.id();
    let mut found = Vec::new();
    for question in &module.questions().questions {
        let Some(declared) = Hints::of(question).configure_new else {
            continue;
        };
        if !cx.answers.get(&question.id).is_some_and(picks_other) {
            continue;
        }
        let q = &question.id;
        let Some(contract) = module.configure_new(q, cx) else {
            return refuse(format!(
                "Module {id}: question `{q}` is answered `other` but `configure_new` returns no contract"
            ));
        };
        if contract.id != declared.contract {
            return refuse(format!(
                "Module {id}: question `{q}` declares contract `{}` but `configure_new` returns `{}`",
                declared.contract, contract.id
            ));
        }
        found.push(contract);
    }
    Ok(found)
}

/// The seeds the contracts of `module` add to its plan: the skeleton files and
/// the guide with the env contract appended, each a seed carrying `MARKER`.
pub fn rendered(module: &dyn Module, cx: &Context<'_>) -> Result<Vec<Rendered>> {
    let mut items = Vec::new();
    for contract in contracts(module, cx)? {
        let refusal = |what: String| {
            refuse(format!(
                "Module {}: contract `{}` {what}",
                module.id(),
                contract.id
            ))
        };
        let expected = guide_path(contract.id);
        if contract.guide.path != expected {
            return refusal(format!(
                "guide must be {expected}, not {}",
                contract.guide.path
            ));
        }
        let IntegrationContract {
            env, seed, guide, ..
        } = contract;
        let guide = Rendered {
            content: guide.content.map(|text| {
                let rows: String = env
                    .iter()
                    .map(|var| {
                        format!(
                            "| `{}` | {} | {} | `{}` |\n",
                            var.name,
                            if var.required { "yes" } else { "no" },
                            var.purpose,
                            var.example
                        )
                    })
                    .collect();
                format!(
                    "{}\n\n## Environment contract\n\n| Variable | Required | Purpose | Example |\n|---|---|---|---|\n{rows}",
                    text.trim_end()
                )
            }),
            ..guide
        };
        for item in seed.into_iter().chain([guide]) {
            if item.class != Ownership::Seed {
                return refusal(format!(
                    "renders {} as {}; a contract renders seeds only",
                    item.path, item.class
                ));
            }
            if !item
                .content
                .as_deref()
                .is_some_and(|text| text.contains(MARKER))
            {
                return refusal(format!("file {} carries no `{MARKER}` marker", item.path));
            }
            items.push(item);
        }
    }
    Ok(items)
}

/// The manual steps the contracts of `module` add: only the generic remote
/// probes, and `endpoint-answers` only on a variable of the env contract.
pub fn steps(module: &dyn Module, cx: &Context<'_>) -> Result<Vec<ManualStep>> {
    let mut steps = Vec::new();
    for contract in contracts(module, cx)? {
        for step in contract.steps {
            let refusal = |what: String| {
                refuse(format!(
                    "Module {}: contract `{}` step `{}` {what}",
                    module.id(),
                    contract.id,
                    step.id
                ))
            };
            match &step.probe {
                Probe::Remote { id, args } if id == ENDPOINT_ANSWERS => {
                    let env = args.get("env").and_then(Value::as_str).unwrap_or_default();
                    if !contract.env.iter().any(|var| var.name == env) {
                        return refusal(format!(
                            "probes `{env}`, which is not in its env contract"
                        ));
                    }
                }
                Probe::Remote { id, .. } if id == SECRET_EXISTS => {}
                _ => {
                    return refusal(format!(
                        "uses a probe other than the generic remote `{ENDPOINT_ANSWERS}` and `{SECRET_EXISTS}`"
                    ));
                }
            }
            steps.push(step);
        }
    }
    Ok(steps)
}

/// The CI gate: every question of `module` that declares `x-configure-new`
/// gets a contract from `configure_new`; refuses naming module and question.
pub fn check_declared(module: &dyn Module, cx: &Context<'_>) -> Result<()> {
    for question in &module.questions().questions {
        if Hints::of(question).configure_new.is_some()
            && module.configure_new(&question.id, cx).is_none()
        {
            return refuse(format!(
                "Module {}: question `{}` declares `x-configure-new` but `configure_new` returns None",
                module.id(),
                question.id
            ));
        }
    }
    Ok(())
}

/// The installed lock, or an empty one on a repository without a lock: what
/// `preview` reads as `Context::previous`. A schema-1 lock is migrated with every
/// path known: the preview only shows a summary, and the plan that follows reads
/// the lock with the real rules.
pub(crate) fn installed_or_empty(root: &Path, source: &Source) -> Result<Lock> {
    let empty = || Lock {
        schema: crate::engine::lock::SCHEMA,
        version: source.version.clone(),
        source_commit: None,
        source_dirty: source.dirty,
        personal_owner: crate::config::current_owner(),
        modules: BTreeMap::new(),
        files: BTreeMap::new(),
    };
    Ok(crate::engine::installed_lock(root, "0.0.0", &|_| true)?.unwrap_or_else(empty))
}

/// The TUI's summary of `module`'s contract for `question` over `answers` (the
/// answers given so far); `None` when the module returns no contract, which the
/// plan then refuses.
pub(crate) fn preview(
    root: &Path,
    source: &Source,
    profile: &Profile,
    previous: &Lock,
    module: &dyn Module,
    question: &str,
    answers: &Answers,
) -> Option<String> {
    let resolved = BTreeMap::from([(module.id().to_owned(), answers.clone())]);
    let cx = Context::new(root, profile, source, previous, answers, module, &resolved);
    module.configure_new(question, &cx).as_ref().map(summary)
}

/// The line the TUI prints once `other` is picked: what this contract generates.
pub fn summary(contract: &IntegrationContract) -> String {
    let names = |items: Vec<&str>| items.join(", ");
    format!(
        "{OTHER}: contract {}; the plan generates an env contract ({}), a seed skeleton ({}), a seed guide ({}) and {} manual step{} ({}).",
        contract.id,
        names(contract.env.iter().map(|v| v.name.as_str()).collect()),
        names(contract.seed.iter().map(|s| s.path.as_str()).collect()),
        contract.guide.path,
        contract.steps.len(),
        if contract.steps.len() == 1 { "" } else { "s" },
        names(contract.steps.iter().map(|s| s.id.as_str()).collect()),
    )
}
