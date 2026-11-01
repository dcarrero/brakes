//! A compiled-in capability. Rendering is pure: same inputs, same output.
use crate::{
    Result, Source,
    engine::answers::{Answers, Schema},
    engine::lock::Lock,
    engine::lock::Ownership,
    engine::manual::ManualStep,
    host::desired::RemoteWrite,
    profile::Profile,
    refuse,
};
use std::collections::BTreeMap;
use std::path::Path;

/// What a module sees when it renders: never the network, never a command.
pub struct Context<'a> {
    pub root: &'a Path,
    pub profile: &'a Profile,
    pub source: &'a Source,
    /// The lock as installed before this plan (migrated to schema 2 if needed).
    pub previous: &'a Lock,
    /// The module's recorded answers, validated, with defaults filled and
    /// gated-out questions dropped; empty for a module without questions.
    pub answers: &'a Answers,
    /// The module rendering, whose `requires` bounds `answers_of`.
    pub module: &'a dyn Module,
    /// The answers of every active module in this plan, resolved like `answers`
    /// (pending ones included), by module id. Read through `answers_of` and
    /// `answers_if_active`.
    pub resolved: &'a BTreeMap<String, Answers>,
    /// `owner/name` of the checkout's `origin`, derived once per plan. Crate-private,
    /// so code outside the crate builds a context with `new` and later fields do not
    /// break it. Read through `repository`.
    pub(crate) repository: Option<&'a str>,
    /// The CI jobs every active module contributes, with its module id, in module
    /// order; collected once per plan before any module renders. Crate-private;
    /// read through `contributed_jobs`.
    pub(crate) ci_jobs: &'a [(&'static str, CiJob)],
    /// The maturity profile (P1–P3) the module is installed for: recorded with its
    /// answers, `answers::DEFAULT_TIER` otherwise. Read through `tier`.
    pub(crate) tier: &'a str,
}

impl<'a> Context<'a> {
    /// A context with no repository identity and no contributed jobs;
    /// `with_repository` and `with_contributed_jobs` set them.
    pub fn new(
        root: &'a Path,
        profile: &'a Profile,
        source: &'a Source,
        previous: &'a Lock,
        answers: &'a Answers,
        module: &'a dyn Module,
        resolved: &'a BTreeMap<String, Answers>,
    ) -> Self {
        Self {
            root,
            profile,
            source,
            previous,
            answers,
            module,
            resolved,
            repository: None,
            ci_jobs: &[],
            tier: crate::engine::answers::DEFAULT_TIER,
        }
    }

    pub fn with_repository(self, repository: Option<&'a str>) -> Self {
        Self { repository, ..self }
    }

    pub fn with_contributed_jobs(self, ci_jobs: &'a [(&'static str, CiJob)]) -> Self {
        Self { ci_jobs, ..self }
    }

    /// The CI jobs the other active modules contribute (`Module::ci_jobs`), each
    /// with its module id, in module order; the reading module's own are left
    /// out. Empty outside a plan. `ci-baseline` inserts them in its workflow.
    pub fn contributed_jobs(&self) -> impl Iterator<Item = (&'static str, &'a CiJob)> {
        let reader = self.module.id();
        self.ci_jobs
            .iter()
            .filter(move |(module, _)| *module != reader)
            .map(|(module, job)| (*module, job))
    }

    pub fn with_tier(self, tier: &'a str) -> Self {
        Self { tier, ..self }
    }

    /// The maturity profile the module renders for (`install --profile`, recorded
    /// with its answers); the engine resolved per-profile defaults with it.
    pub fn tier(&self) -> &'a str {
        self.tier
    }

    /// `owner/name` of the checkout's `origin` remote, as written there; `None`
    /// without one, or when it names a repository the scope guard refuses or
    /// several repositories. A module renders a placeholder then.
    pub fn repository(&self) -> Option<&'a str> {
        self.repository
    }

    /// The resolved answers of `id` when it is active in this plan, without
    /// requiring it (a soft read); `None` otherwise. `answers_of` is the read of
    /// a required module.
    pub fn answers_if_active(&self, id: &str) -> Option<&'a Answers> {
        self.resolved.get(id)
    }

    /// The resolved answers of `id`, a module this one `requires`; any other id
    /// refuses, so a cross-module read is always a declared dependency.
    pub fn answers_of(&self, id: &str) -> Result<&'a Answers> {
        let reader = self.module.id();
        if !self.module.requires().contains(&id) {
            return refuse(format!(
                "Module {reader} reads the answers of module {id}, which it does not require; add {id} to its requires"
            ));
        }
        match self.resolved.get(id) {
            Some(answers) => Ok(answers),
            None => refuse(format!(
                "Module {reader} reads the answers of module {id}, which is not active in this plan"
            )),
        }
    }
}

/// One path a module wants in the repository.
pub struct Rendered {
    pub path: String,
    pub class: Ownership,
    /// Required for `managed`, `managed-block` and `seed` (the initial file);
    /// `never-touch` and `remote` carry `None`, and the plan refuses otherwise.
    pub content: Option<String>,
    /// `managed-block` only: the whole file written when the path is absent, a
    /// skeleton that contains `content` exactly once. A present file keeps its
    /// text and gains the block; the lock pins the block, never the skeleton.
    pub scaffold: Option<String>,
}

/// A tier the `ci-baseline` scope job decides for a run: `full` verifies
/// everything; `docs` is a pull request that changed only inert paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiTier {
    Full,
    Docs,
}

impl CiTier {
    /// The spelling the scope job prints and the aggregate job reads.
    pub const fn as_str(self) -> &'static str {
        match self {
            CiTier::Full => "full",
            CiTier::Docs => "docs",
        }
    }
}

/// A job another module contributes to `ci-baseline`'s generated workflow
/// (SPEC-ci-baseline.md, Composition). `ci-baseline` inserts it, adds `id` to
/// the `needs` of `required` and hands the scope job the tiers it may skip under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiJob {
    /// Job id and display name, kebab-case, unique across modules.
    pub id: String,
    /// The job body, rendered by the contributor with pins from the shared table.
    pub yaml: String,
    /// Tiers under which the scope job may list the job as skippable.
    pub skippable_under: Vec<CiTier>,
    /// The stack-packs app the job verifies (#1097): the scope job may also
    /// list it when that app saw no change, as ci-baseline's own app jobs. The
    /// job's own `if:` then reads the skippable list; `None` for a job of the
    /// whole repository.
    pub app: Option<String>,
}

/// Paths a module took over from another one: an ownership transfer (#696).
/// The paths keep their content; only their owner in the lock changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Takeover {
    /// The module that rendered `paths` before.
    pub from: &'static str,
    pub paths: &'static [&'static str],
}

/// One environment variable an integration needs: its name, what it is for and
/// an example value that is never a secret. Part of an [`IntegrationContract`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvVar {
    pub name: String,
    pub purpose: String,
    pub example: String,
    pub required: bool,
}

/// What a module returns for an enum question answered `other` (the "configure
/// new" contract, SPEC-questions.md, decision 2026-10-28 point 9). Data, not a
/// provider template: the module renders the seed skeleton with
/// `TODO(configure-new):` markers, and the engine plans it like any seed
/// (`questions::configure_new`).
pub struct IntegrationContract {
    /// The contract the question's `x-configure-new` names (`delivery.target`).
    pub id: &'static str,
    pub env: Vec<EnvVar>,
    /// Class `seed`; every file carries `TODO(configure-new):` markers.
    pub seed: Vec<Rendered>,
    /// Probes: only the generic remote `endpoint-answers` and `secret-exists`.
    pub steps: Vec<ManualStep>,
    /// Seed `docs/agent-setup/integrations/<id>.md`: how an agent finishes it in
    /// one PR; the engine appends the env contract to it.
    pub guide: Rendered,
}

pub trait Module {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn requires(&self) -> &'static [&'static str] {
        &[]
    }
    /// The questions whose answers `render` reads; empty by default.
    fn questions(&self) -> Schema {
        Schema::default()
    }
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>>;
    /// Work the owner or the platform does by hand, each with a read-only probe;
    /// none by default. Declared with the same inputs as `render`.
    fn manual_steps(&self, _cx: &Context<'_>) -> Vec<ManualStep> {
        Vec::new()
    }
    /// Brings the answers recorded by version `from` of this module up to this
    /// version, before they are validated and rendered. The engine calls it once,
    /// when the installed lock records an older version, and records the new
    /// version in the lock and the answers file. Nothing to do by default.
    fn migrate(&self, _from: &str, _answers: &mut Answers) -> Result<()> {
        Ok(())
    }
    /// The paths this module took over from another module, if any. A lock that
    /// records one of them under `from` is not a conflict: `install` selects this
    /// module (as it does on a repository with no lock, where `from` would have
    /// rendered them) and the plan records the path under it, a lock-only change
    /// when the content is unchanged. None by default.
    fn takes_over(&self) -> Option<Takeover> {
        None
    }
    /// Jobs this module adds to `ci-baseline`'s workflow, declared with the same
    /// inputs as `render`. None by default.
    fn ci_jobs(&self, _cx: &Context<'_>) -> Vec<CiJob> {
        Vec::new()
    }
    /// Lines the plan prints after itself as `NOTE [<module>] <text>`, declared
    /// with the same inputs as `render`. Informative: a note never changes the
    /// plan, readiness or the exit code. None by default.
    fn notes(&self, _cx: &Context<'_>) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    /// The desired state of each of this module's remote items, declared with
    /// the same inputs as `render`; what `apply` classifies and `apply --remote`
    /// writes (#902, SPEC-engine.md, Desired state of a remote item). None by default.
    fn remote_writes(&self, _cx: &Context<'_>) -> Result<Vec<RemoteWrite>> {
        Ok(Vec::new())
    }
    /// The "configure new" contract of `question`, an enum answered `other`;
    /// declared with the same inputs as `render`. A module whose schema declares
    /// `x-configure-new` on `question` must return `Some`. None by default.
    fn configure_new(&self, _question: &str, _cx: &Context<'_>) -> Option<IntegrationContract> {
        None
    }
    /// Rewrites, in `answers`, values that stand for a required module's answer
    /// (SPEC-engine.md, Settled answers; #1229). The engine calls it once every
    /// active module's answers are resolved and before any module renders, on the
    /// resolved answers and on the recorded or pending answers file, which the plan
    /// writes when settling changes it. Must be idempotent. Nothing by default.
    fn settle(&self, _cx: &Context<'_>, _answers: &mut Answers) -> Result<()> {
        Ok(())
    }
}
