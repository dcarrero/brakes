//! merge-guard as a module (SPEC-merge-guard.md, Project Structure and
//! Registration; #696): it renders the hook wrapper `.claude/hooks/merge_guard.sh`
//! as `managed` content, taken over from `setup-core`, which distributed it until
//! 1.1.0 (`Module::takes_over`: a repository whose lock records the hook under
//! `setup-core` sees only a lock change). Registering the hook in the
//! project-owned `.claude/settings.json` (#442; #848, point 5) is a manual step
//! whose `json-pointer` probe `doctor` evaluates; the guard itself is
//! `brakes guard pre-bash` (`crate::guard`). Since #748 the step stands
//! only where `agent-guardrails` is not active: there, its `managed-entries`
//! object for `.claude/settings.json` carries [`hook_entry`] and the installer
//! registers the wrapper itself (decision "Installer owns the entries it adds to
//! `.claude/settings.json`: ownership class `managed-entries`", 2026-10-29).
use crate::{
    Result,
    engine::{
        Context, Module, Rendered, Takeover,
        lock::{Ownership, SETUP_CORE},
        manual::{ManualStep, Owner, Probe},
    },
    modules::agent_guardrails::AGENT_GUARDRAILS,
    refuse,
};
use serde_json::{Value, json};

pub const MERGE_GUARD: &str = "merge-guard";
/// The Claude Code ask rule through which the person approves `human-approved`
/// (#1146); the guard opens that route only while it reads this rule.
pub use crate::guard::approval::APPROVAL_ASK_RULE;
pub const MERGE_GUARD_VERSION: &str = "1.0.0";

/// Where the wrapper lives in a target repository.
pub const HOOK_PATH: &str = ".claude/hooks/merge_guard.sh";
/// Repository files distributed as they are versioned here, by destination.
/// The hook wrapper finds the `brakes` merge guard (the frozen
/// `agentic-run` one second), or denies only merges without either;
/// registering it in `.claude/settings.json` stays with the project.
pub const HOOKS: &[(&str, &str)] = &[(
    HOOK_PATH,
    include_str!("../../../../.claude/hooks/merge_guard.sh"),
)];
/// The project's settings file, where the host reads hooks.
const SETTINGS: &str = ".claude/settings.json";

/// The `hooks.PreToolUse` entry that runs the wrapper on every Bash call: what
/// `agent-guardrails` registers as a managed entry (#748) and what the
/// `hook-registered` step asks the project for otherwise.
pub fn hook_entry() -> Value {
    json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": format!("sh \"$CLAUDE_PROJECT_DIR/{HOOK_PATH}\""),
            "timeout": 60,
            "onFailure": "block"
        }]
    })
}

/// The registration probe: some string under `hooks.PreToolUse` names the wrapper.
pub fn registration_probe() -> Probe {
    Probe::JsonPointerContains {
        path: SETTINGS.to_owned(),
        under: "/hooks/PreToolUse".to_owned(),
        contains: "merge_guard.sh".to_owned(),
    }
}

/// The spec's `hook-registered` step: the project registers the wrapper.
pub fn registration_step() -> ManualStep {
    ManualStep {
        id: "hook-registered".to_owned(),
        title: "Register the merge guard hook".to_owned(),
        owner: Owner::Project,
        instructions: format!(
            "Add to {SETTINGS} hooks.PreToolUse (matcher Bash): {{\"type\":\"command\",\"command\":\"sh \\\"$CLAUDE_PROJECT_DIR/{HOOK_PATH}\\\"\",\"timeout\":60,\"onFailure\":\"block\"}}"
        ),
        probe: registration_probe(),
        after: None,
    }
}

pub struct MergeGuard;

impl Module for MergeGuard {
    fn id(&self) -> &'static str {
        MERGE_GUARD
    }
    fn version(&self) -> &'static str {
        MERGE_GUARD_VERSION
    }
    /// The hook it took over was `setup-core`'s; without that feature nothing is
    /// required (product-boundary T7a).
    fn requires(&self) -> &'static [&'static str] {
        #[cfg(feature = "setup-core")]
        return &[SETUP_CORE];
        #[cfg(not(feature = "setup-core"))]
        return &[];
    }
    fn takes_over(&self) -> Option<Takeover> {
        Some(Takeover {
            from: SETUP_CORE,
            paths: &[HOOK_PATH],
        })
    }
    /// The registration step, unless `agent-guardrails` registers the entry in
    /// this plan (#748).
    fn manual_steps(&self, cx: &Context<'_>) -> Vec<ManualStep> {
        if cx.answers_if_active(AGENT_GUARDRAILS).is_some() {
            return Vec::new();
        }
        vec![registration_step()]
    }
    /// The wrapper as the source carries it (embedded, or a `--source` checkout).
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>> {
        HOOKS
            .iter()
            .map(|(path, _)| match cx.source.documents.get(*path) {
                Some(content) => Ok(Rendered {
                    path: (*path).to_owned(),
                    class: Ownership::Managed,
                    content: Some(content.clone()),
                    scaffold: None,
                }),
                None => refuse(format!("Module {MERGE_GUARD}: the source has no {path}")),
            })
            .collect()
    }
}
