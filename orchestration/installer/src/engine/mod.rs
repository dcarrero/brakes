//! The module engine (SPEC-engine.md): modules render paths under an ownership
//! class; the engine compares them with the installed lock, refuses local
//! changes to managed content, deletes what a module no longer renders when it
//! is unchanged, and writes the schema-2 lock last.
pub mod answers;
pub mod entries;
pub mod lock;
pub mod manual;
pub mod module;

use crate::host::desired::RemoteWrite;
use crate::questions::configure_new;
pub use answers::{Answers, Schema};
pub use lock::{Lock, Ownership};
pub use manual::{ManualStep, NoRunner, Probe, ProbeResult, RemoteRunner, StepReport, StepState};
pub use module::{CiJob, CiTier, Context, EnvVar, IntegrationContract, Module, Rendered, Takeover};

use crate::{
    LOCK, PROFILE, Plan, Source, block_content, destination, digest, profile, read, refuse, scope,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A path the plan reports without writing or deleting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// A seed whose path already exists: nothing is written.
    Skip,
    /// A retired seed, never-touch or remote entry: the lock forgets it, the path stays.
    Keep,
}

impl std::fmt::Display for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Note::Skip => "SKIP",
            Note::Keep => "KEEP",
        })
    }
}

/// A line a module adds after the plan (`Module::notes`); it changes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanNote {
    pub module: String,
    pub text: String,
}

impl std::fmt::Display for PlanNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NOTE [{}] {}", self.module, self.text)
    }
}

/// The plan plus, for every reported path, its class and module (for the plan lines).
#[derive(Debug)]
pub struct Planned {
    pub changes: Plan,
    pub tags: BTreeMap<String, (Ownership, String)>,
    /// Paths printed with `SKIP` or `KEEP`; `apply` never touches them.
    pub notes: BTreeMap<String, Note>,
    /// Engine-owned answers files in the plan, by path -> module id
    /// (printed as `[answers:<module>]`).
    pub answers: BTreeMap<String, String>,
    /// The manual steps of the active modules, evaluated, sorted by module and id.
    /// Informative: `apply` never performs a step.
    pub steps: Vec<StepReport>,
    /// The notes of the active modules, in module order. Informative.
    pub plan_notes: Vec<PlanNote>,
    /// What each `SKIP` seed would have written, by path: `adopt` compares it
    /// with what exists to tell an open proposal from a seed already in place.
    pub skipped_seeds: BTreeMap<String, String>,
}

/// `owner/name` of the checkout's `origin`, as its fetch URLs write it (without
/// `.git`), once each passes the scope guard's parse. `None` without an origin,
/// when a URL is refused or when the URLs name different repositories. One `git`
/// call that reads the local configuration, never the network.
pub fn repository(root: &Path) -> Option<String> {
    let urls = scope::git(root, &["remote", "get-url", "--all", "origin"]).ok()?;
    let mut found: Option<String> = None;
    for url in urls.lines() {
        let identity = scope::remote_identity(url).ok()?;
        if found
            .as_ref()
            .is_some_and(|f| !f.eq_ignore_ascii_case(&identity))
        {
            return None;
        }
        if found.is_none() {
            let path = scope::github_path(url).ok()?;
            found = Some(path.strip_suffix(".git").unwrap_or(&path).to_owned());
        }
    }
    found
}

/// Reads and, if needed, migrates the installed lock. `None` when no lock exists.
pub fn installed_lock(
    root: &Path,
    core_version: &str,
    known: &dyn Fn(&str) -> bool,
) -> Result<Option<Lock>, Box<dyn std::error::Error>> {
    read(root, LOCK)?
        .map(|raw| Lock::parse(&raw, core_version, known))
        .transpose()
}

/// The modules one `install` reconciles, in registry order: `setup-core` always,
/// every module the installed lock records, and the ids requested with
/// `--module`. An id no compiled module answers to is refused by name; a
/// recorded id this build does not know is left to the plan, which carries its
/// lock entries over untouched.
pub fn select<'a>(
    registry: &[&'a dyn Module],
    previous: Option<&Lock>,
    requested: &[&str],
) -> crate::Result<Vec<&'a dyn Module>> {
    for id in requested {
        if !registry.iter().any(|m| m.id() == *id) {
            return refuse(format!("Unknown module id: {id}"));
        }
    }
    let selected = |m: &dyn Module| {
        m.id() == lock::SETUP_CORE
            || requested.contains(&m.id())
            || previous.is_some_and(|lock| lock.modules.contains_key(m.id()))
    };
    // A module that took over paths of a selected module joins it where that
    // module would still render them: no lock yet, or a lock recording one of
    // them under it. After `remove`, neither holds and it stays out.
    let takes_over = |m: &dyn Module| {
        m.takes_over().is_some_and(|t| {
            registry.iter().any(|f| f.id() == t.from && selected(*f))
                && previous.is_none_or(|lock| {
                    t.paths.iter().any(|path| {
                        lock.files
                            .get(*path)
                            .is_some_and(|entry| entry.module == t.from)
                    })
                })
        })
    };
    Ok(registry
        .iter()
        .copied()
        .filter(|m| selected(*m) || takes_over(*m))
        .collect())
}

/// Whether `module` took `path` over from module `from` (`Module::takes_over`).
fn took_over(module: &dyn Module, from: &str, path: &str) -> bool {
    module
        .takes_over()
        .is_some_and(|t| t.from == from && t.paths.contains(&path))
}

pub fn plan(
    root: &Path,
    source: &Source,
    profile: &profile::Profile,
    modules: &[&dyn Module],
    known: &dyn Fn(&str) -> bool,
) -> crate::Result<Planned> {
    plan_with(root, source, profile, modules, known, &BTreeMap::new())
}

/// A module's answers as recorded (or as `configure` or `install --profile` is
/// about to record them), unvalidated, with the file text they came from and
/// the recorded profile (`None` when the file names none, or there is no file).
struct Recorded {
    schema: Schema,
    raw: Answers,
    text: Option<String>,
    profile: Option<String>,
}

impl Recorded {
    /// The maturity profile per-profile defaults resolve with.
    fn tier(&self) -> String {
        self.profile
            .clone()
            .unwrap_or_else(|| answers::DEFAULT_TIER.to_owned())
    }
}

/// Reads a module's recorded answers: the schema is checked, the file parsed.
fn recorded_answers(
    root: &Path,
    module: &dyn Module,
    pending: Option<&String>,
) -> crate::Result<Recorded> {
    let schema = module.questions();
    schema.check(module.id())?;
    let text = match pending {
        Some(text) => Some(text.clone()),
        None => read(root, &answers::path(module.id()))?,
    };
    let file = text
        .as_deref()
        .map(|raw| answers::AnswersFile::parse(module.id(), raw))
        .transpose()?;
    let (raw, profile) = file.map_or_else(Default::default, |f| (f.answers, f.profile));
    Ok(Recorded {
        schema,
        raw,
        text,
        profile,
    })
}

/// A module's answers as `doctor` sees them: recorded, validated, no migration;
/// with the profile they were resolved for.
fn load_answers(root: &Path, module: &dyn Module) -> crate::Result<(Answers, String)> {
    let recorded = recorded_answers(root, module, None)?;
    let tier = recorded.tier();
    Ok((
        recorded
            .schema
            .validate(module.id(), &recorded.raw, &tier)?,
        tier,
    ))
}

/// How the installed version of a module compares with the compiled one.
/// Dotted numbers compare numerically; anything else is older unless identical.
fn version_order(installed: &str, compiled: &str) -> std::cmp::Ordering {
    let parse = |v: &str| {
        v.split('.')
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .ok()
    };
    match (parse(installed), parse(compiled)) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ if installed == compiled => std::cmp::Ordering::Equal,
        _ => std::cmp::Ordering::Less,
    }
}

/// What a module's answers file becomes in this plan, if it changes.
struct AnswersUpdate {
    path: String,
    text: String,
}

/// A module's answers for this plan: recorded, migrated when the installed lock
/// records an older version, then validated with the recorded profile. Returns
/// the answers `render` sees, the file text whose digest the lock records, after
/// a migration the file the plan writes (when one was recorded or the migration
/// left answers), and the profile.
fn plan_answers(
    root: &Path,
    module: &dyn Module,
    pending: Option<&String>,
    previous: &Lock,
) -> crate::Result<(Answers, Option<String>, Option<AnswersUpdate>, String)> {
    let id = module.id();
    let recorded = recorded_answers(root, module, pending)?;
    let tier = recorded.tier();
    let Recorded {
        schema,
        mut raw,
        mut text,
        profile,
    } = recorded;
    let mut update = None;
    let mut migrated = false;
    if let Some(installed) = previous.modules.get(id) {
        match version_order(&installed.version, module.version()) {
            std::cmp::Ordering::Equal => {}
            std::cmp::Ordering::Greater => {
                return refuse(format!(
                    "Module {id} is installed at version {}, newer than this installer's {}; update the installer",
                    installed.version,
                    module.version()
                ));
            }
            std::cmp::Ordering::Less => {
                module.migrate(&installed.version, &mut raw)?;
                migrated = text.is_some() || !raw.is_empty();
            }
        }
    }
    let validated = schema.validate(id, &raw, &tier)?;
    if migrated {
        let file = answers::AnswersFile {
            module: id.to_owned(),
            version: module.version().to_owned(),
            profile,
            answers: validated.clone(),
        };
        let text_after = file.to_json_string()?;
        update = Some(AnswersUpdate {
            path: answers::path(id),
            text: text_after.clone(),
        });
        text = Some(text_after);
    }
    Ok((validated, text, update, tier))
}

/// `plan` with, per module id, the answers file text that replaces the recorded one.
fn plan_with(
    root: &Path,
    source: &Source,
    profile: &profile::Profile,
    modules: &[&dyn Module],
    known: &dyn Fn(&str) -> bool,
    pending_answers: &BTreeMap<&str, String>,
) -> crate::Result<Planned> {
    let core_version = modules
        .iter()
        .find(|m| m.id() == lock::SETUP_CORE)
        .map_or("0.0.0", |m| m.version());
    let old_raw = read(root, LOCK)?;
    let previous = match &old_raw {
        Some(raw) => Lock::parse(raw, core_version, known)?,
        None => Lock {
            schema: lock::SCHEMA,
            version: source.version.clone(),
            source_commit: None,
            source_dirty: source.dirty,
            personal_owner: crate::config::current_owner(),
            modules: BTreeMap::new(),
            files: BTreeMap::new(),
        },
    };
    let active: BTreeSet<&str> = modules.iter().map(|m| m.id()).collect();
    // A requirement is met by a module active in this plan: recorded, requested
    // or `setup-core`. Nothing is added on the module's behalf.
    for module in modules {
        if let Some(missing) = module
            .requires()
            .iter()
            .find(|required| !active.contains(**required))
        {
            return refuse(format!(
                "Module {} requires module {missing}, which is not installed; add it with --module {missing}",
                module.id()
            ));
        }
    }
    let mut changes: Plan = BTreeMap::new();
    let mut tags = BTreeMap::new();
    let mut notes = BTreeMap::new();
    let mut skipped_seeds = BTreeMap::new();
    let mut next = Lock {
        schema: lock::SCHEMA,
        version: source.version.clone(),
        source_commit: source.revision.clone(),
        source_dirty: source.dirty,
        personal_owner: crate::config::current_owner(),
        modules: BTreeMap::new(),
        files: BTreeMap::new(),
    };
    // Entries of modules this invocation does not know are carried over untouched.
    for (id, entry) in &previous.modules {
        if !active.contains(id.as_str()) {
            next.modules.insert(id.clone(), entry.clone());
        }
    }
    for (path, entry) in &previous.files {
        if !active.contains(entry.module.as_str()) {
            next.files.insert(path.clone(), entry.clone());
        }
    }
    // Render everything first: a never-touch declaration protects its path from every
    // module, whichever order they come in. Each module renders with its own
    // validated answers; the digest of its answers file is recorded below.
    let mut items: Vec<(&dyn Module, Rendered)> = Vec::new();
    let mut answers_digests: BTreeMap<&str, Option<String>> = BTreeMap::new();
    let mut answers_files = BTreeMap::new();
    let mut steps = Vec::new();
    let mut plan_notes = Vec::new();
    let identity = repository(root);
    // Every module's answers are resolved before any module renders, so a module
    // reading a required module's answers sees the ones this plan records.
    let mut resolved: BTreeMap<String, Answers> = BTreeMap::new();
    let mut tiers: BTreeMap<&str, String> = BTreeMap::new();
    let mut answers_texts: BTreeMap<&str, Option<String>> = BTreeMap::new();
    for module in modules {
        let (answers, answers_text, update, tier) =
            plan_answers(root, *module, pending_answers.get(module.id()), &previous)?;
        if let Some(AnswersUpdate { path, text }) = update {
            if read(root, &path)?.as_deref() != Some(&text) {
                changes.insert(path.clone(), Some(text));
            }
            answers_files.insert(path, module.id().to_owned());
        }
        resolved.insert(module.id().to_owned(), answers);
        tiers.insert(module.id(), tier);
        answers_texts.insert(module.id(), answers_text);
    }
    // Settled answers (#1229): every module's answers are resolved, so a value
    // standing for a required module's answer is rewritten before any renders.
    let mut settled = Vec::new();
    for module in modules {
        let id = module.id();
        let cx = Context::new(
            root,
            profile,
            source,
            &previous,
            &resolved[id],
            *module,
            &resolved,
        )
        .with_repository(identity.as_deref())
        .with_tier(&tiers[id]);
        let mut answers = resolved[id].clone();
        module.settle(&cx, &mut answers)?;
        let schema = module.questions();
        let answers = schema.validate(id, &answers, &tiers[id])?;
        let mut text = answers_texts[id].clone();
        if let Some(recorded) = text.as_deref() {
            let mut file = answers::AnswersFile::parse(id, recorded)?;
            let before = file.answers.clone();
            module.settle(&cx, &mut file.answers)?;
            if file.answers != before {
                schema.validate(id, &file.answers, &tiers[id])?;
                let after = file.to_json_string()?;
                let path = answers::path(id);
                if read(root, &path)?.as_deref() != Some(&after) {
                    changes.insert(path.clone(), Some(after.clone()));
                }
                answers_files.insert(path, id.to_owned());
                text = Some(after);
            }
        }
        settled.push((id, answers, text));
    }
    for (id, answers, text) in settled {
        resolved.insert(id.to_owned(), answers);
        answers_digests.insert(id, text.as_deref().map(digest));
    }
    let context = |i: usize| {
        let module = modules[i];
        Context::new(
            root,
            profile,
            source,
            &previous,
            &resolved[module.id()],
            module,
            &resolved,
        )
        .with_repository(identity.as_deref())
        .with_tier(&tiers[module.id()])
    };
    // Every module's CI jobs are collected before any module renders, so
    // ci-baseline sees them all whatever the order (`Context::contributed_jobs`).
    let ci_jobs: Vec<(&'static str, CiJob)> = modules
        .iter()
        .enumerate()
        .flat_map(|(i, module)| {
            let id = module.id();
            module
                .ci_jobs(&context(i))
                .into_iter()
                .map(move |job| (id, job))
        })
        .collect();
    for (i, module) in modules.iter().enumerate() {
        let cx = context(i).with_contributed_jobs(&ci_jobs);
        items.extend(module.render(&cx)?.into_iter().map(|item| (*module, item)));
        items.extend(
            configure_new::rendered(*module, &cx)?
                .into_iter()
                .map(|item| (*module, item)),
        );
        steps.extend(module_steps(*module, &cx, &NoRunner)?);
        plan_notes.extend(module.notes(&cx)?.into_iter().map(|text| PlanNote {
            module: module.id().to_owned(),
            text,
        }));
    }
    steps.sort_by(|a, b| (&a.module, &a.id).cmp(&(&b.module, &b.id)));
    let never_touch: BTreeSet<&str> = items
        .iter()
        .filter(|(_, item)| item.class == Ownership::NeverTouch)
        .map(|(_, item)| item.path.as_str())
        .collect();
    let mut rendered_paths: BTreeSet<String> = BTreeSet::new();
    for (module, item) in &items {
        if item.content.is_some() && never_touch.contains(item.path.as_str()) {
            return refuse(format!(
                "Module {}: path declared never-touch is rendered: {}",
                module.id(),
                item.path
            ));
        }
        if !rendered_paths.insert(item.path.clone()) {
            return refuse(format!("Path rendered by two modules: {}", item.path));
        }
        tags.insert(item.path.clone(), (item.class, module.id().to_owned()));
        let prior = previous.files.get(&item.path);
        if let Some(prior) =
            prior.filter(|p| p.module != module.id() && !took_over(*module, &p.module, &item.path))
        {
            return refuse(format!(
                "Managed destination owned by module {}: {}",
                prior.module, item.path
            ));
        }
        if let Some(scaffold) = &item.scaffold {
            if item.class != Ownership::ManagedBlock {
                return refuse(format!(
                    "Module {}: ownership class {} takes no scaffold: {}",
                    module.id(),
                    item.class,
                    item.path
                ));
            }
            let contains_block = matches!(block_content(scaffold), Ok(Some(found)) if Some(found) == item.content.as_deref());
            if !contains_block {
                return refuse(format!(
                    "Module {}: the scaffold must contain its managed block once: {}",
                    module.id(),
                    item.path
                ));
            }
        }
        let content = match (item.class, &item.content) {
            (Ownership::NeverTouch | Ownership::Remote, None) => {
                // Declared, recorded without digest, never written.
                next.insert_file(&item.path, module.id(), item.class, None);
                continue;
            }
            (Ownership::Remote, Some(_)) => {
                return refuse(format!(
                    "Module {}: ownership class {} carries no content: {}",
                    module.id(),
                    item.class,
                    item.path
                ));
            }
            (_, None) => {
                return refuse(format!(
                    "Module {}: ownership class {} requires content: {}",
                    module.id(),
                    item.class,
                    item.path
                ));
            }
            (_, Some(content)) => content,
        };
        let current = read(root, &item.path)?;
        if item.class == Ownership::ManagedEntries {
            // The module owns the fragment's entries inside the project's file (#747):
            // missing ones are appended, present ones left alone, edited ones refused,
            // and the ones an earlier fragment added but this one dropped taken out.
            let fragment = entries::fragment(module.id(), &item.path, content)?;
            let recorded = prior.and_then(|p| p.entries.as_ref());
            if let Some(text) = entries::reconcile(
                module.id(),
                &item.path,
                current.as_deref(),
                &fragment,
                recorded,
            )? {
                changes.insert(item.path.clone(), Some(text));
            }
            next.insert_entries(&item.path, module.id(), &digest(content), fragment);
            continue;
        }
        if item.class == Ownership::Seed {
            // A seed is written once; whatever lives at the path afterwards is the project's.
            if current.is_some() {
                notes.insert(item.path.clone(), Note::Skip);
                skipped_seeds.insert(item.path.clone(), content.clone());
            } else {
                changes.insert(item.path.clone(), Some(content.clone()));
            }
            next.insert_file(&item.path, module.id(), item.class, None);
            continue;
        }
        let is_block = item.class == Ownership::ManagedBlock;
        let installed = if is_block {
            block_content(current.as_deref().unwrap_or(""))?
        } else {
            current.as_deref()
        };
        match prior {
            Some(prior) => {
                if installed.is_none_or(|s| prior.digest.as_deref() != Some(&digest(s))) {
                    return refuse(format!(
                        "Locally changed or missing managed content: {}",
                        item.path
                    ));
                }
            }
            None => {
                if installed.is_some() {
                    return refuse(format!("Unowned managed destination: {}", item.path));
                }
            }
        }
        let result = if is_block {
            match (installed, &item.scaffold) {
                (Some(installed), _) => current
                    .as_deref()
                    .unwrap_or("")
                    .replacen(installed, content, 1),
                // An absent file takes the module's skeleton around the block.
                (None, Some(scaffold)) if current.is_none() => scaffold.clone(),
                (None, _) => format!(
                    "{}{}{content}\n",
                    current.as_deref().unwrap_or("").trim_end(),
                    if current.as_ref().is_some_and(|s| !s.is_empty()) {
                        "\n\n"
                    } else {
                        ""
                    }
                ),
            }
        } else {
            content.clone()
        };
        if current.as_deref() != Some(&result) {
            changes.insert(item.path.clone(), Some(result));
        }
        next.insert_file(&item.path, module.id(), item.class, Some(&digest(content)));
    }
    for module in modules {
        next.record(
            module.id(),
            module.version(),
            answers_digests.get(module.id()).and_then(Option::as_deref),
        );
    }
    // A path an active module recorded before and no longer renders is retired.
    // Managed content is deleted when unchanged, refused when edited, forgotten when
    // absent. A seed or never-touch path is kept and reported when present; a remote
    // setting is always reported, since the engine never sees it. The lock forgets all.
    for (path, prior) in &previous.files {
        if !active.contains(prior.module.as_str()) || rendered_paths.contains(path) {
            continue;
        }
        let kept = match prior.class {
            Ownership::Managed | Ownership::ManagedBlock => match read(root, path)? {
                Some(text) if prior.digest.as_deref() != Some(&digest(&text)) => {
                    return refuse(format!(
                        "Locally changed retired managed content: {path}; restore it or move it out of docs/agent-setup/"
                    ));
                }
                Some(_) => {
                    changes.insert(path.clone(), None);
                    false
                }
                None => continue,
            },
            Ownership::Seed | Ownership::NeverTouch => {
                if read(root, path)?.is_none() {
                    continue;
                }
                true
            }
            Ownership::Remote => true,
            // The recorded entries leave the project's file; the rest stays.
            Ownership::ManagedEntries => {
                let Some(recorded) = &prior.entries else {
                    continue;
                };
                let change = entries::retire(
                    &prior.module,
                    path,
                    read(root, path)?.as_deref(),
                    recorded,
                    |pointer, name| {
                        format!(
                            "Locally changed retired managed entry: {path} at {pointer} ({name})"
                        )
                    },
                )?;
                let Some(change) = change else {
                    continue;
                };
                changes.insert(path.clone(), change);
                false
            }
        };
        if kept {
            notes.insert(path.clone(), Note::Keep);
        }
        tags.insert(path.clone(), (prior.class, prior.module.clone()));
    }
    if profile.raw.is_none() {
        changes.insert(PROFILE.to_owned(), Some(profile::default_json().to_owned()));
    }
    // Provenance moves with the recorded content (#1322): a clean-source record
    // (a commit, `source_dirty` false) whose files, modules and answers this plan
    // leaves as they are is kept, so a run from another commit plans `No changes.`.
    // The commit it names produced exactly the recorded digests. A dirty or
    // commit-less record never equals `kept`, so a clean run replaces it.
    if previous.source_commit.is_some() {
        let kept = Lock {
            source_commit: previous.source_commit.clone(),
            source_dirty: false,
            ..next.clone()
        };
        if kept == previous {
            next = kept;
        }
    }
    let serialized = next.to_json_string()?;
    if old_raw.as_deref() != Some(&serialized) {
        changes.insert(LOCK.to_owned(), Some(serialized));
    }
    for name in changes.keys() {
        destination(root, name)?;
    }
    Ok(Planned {
        changes,
        tags,
        notes,
        answers: answers_files,
        steps,
        plan_notes,
        skipped_seeds,
    })
}

/// One module's manual steps, checked at load and evaluated against the repository.
fn module_steps(
    module: &dyn Module,
    cx: &Context<'_>,
    runner: &dyn RemoteRunner,
) -> crate::Result<Vec<StepReport>> {
    let mut declared = module.manual_steps(cx);
    declared.extend(configure_new::steps(module, cx)?);
    manual::check(module.id(), &declared)?;
    Ok(manual::evaluate(cx.root, module.id(), &declared, runner))
}

/// The manual steps of `modules` evaluated against the repository as installed
/// (`previous` is the installed lock), sorted by module and id. What `doctor` lists;
/// `runner` answers the remote probes, `NoRunner` when no host adapter is present.
pub fn steps(
    root: &Path,
    source: &Source,
    profile: &profile::Profile,
    modules: &[&dyn Module],
    previous: &Lock,
    runner: &dyn RemoteRunner,
) -> crate::Result<Vec<StepReport>> {
    let mut steps = per_installed(root, source, profile, modules, previous, |module, cx| {
        module_steps(module, cx, runner)
    })?;
    steps.sort_by(|a, b| (&a.module, &a.id).cmp(&(&b.module, &b.id)));
    Ok(steps)
}

/// The desired state each of `modules` declares for its remote items (#902),
/// with the module id, in module order; the contexts are those of [`steps`].
pub fn remote_writes(
    root: &Path,
    source: &Source,
    profile: &profile::Profile,
    modules: &[&dyn Module],
    previous: &Lock,
) -> crate::Result<Vec<(String, RemoteWrite)>> {
    per_installed(root, source, profile, modules, previous, |module, cx| {
        Ok(module
            .remote_writes(cx)?
            .into_iter()
            .map(|write| (module.id().to_owned(), write))
            .collect())
    })
}

/// `each` over `modules` as installed (`previous` is the installed lock), each
/// with its resolved answers, tier, the repository identity and the contributed
/// jobs, as `doctor` evaluates them.
fn per_installed<T>(
    root: &Path,
    source: &Source,
    profile: &profile::Profile,
    modules: &[&dyn Module],
    previous: &Lock,
    mut each: impl FnMut(&dyn Module, &Context<'_>) -> crate::Result<Vec<T>>,
) -> crate::Result<Vec<T>> {
    let mut resolved = BTreeMap::new();
    let mut tiers = BTreeMap::new();
    for module in modules {
        let (answers, tier) = load_answers(root, *module)?;
        resolved.insert(module.id().to_owned(), answers);
        tiers.insert(module.id(), tier);
    }
    let identity = repository(root);
    let context = |i: usize| {
        let module = modules[i];
        Context::new(
            root,
            profile,
            source,
            previous,
            &resolved[module.id()],
            module,
            &resolved,
        )
        .with_repository(identity.as_deref())
        .with_tier(&tiers[module.id()])
    };
    // The contributed jobs, as the plan collects them: ci-baseline's steps
    // under `workflow: existing` depend on them (#895).
    let ci_jobs: Vec<(&'static str, CiJob)> = modules
        .iter()
        .enumerate()
        .flat_map(|(i, module)| {
            let id = module.id();
            module
                .ci_jobs(&context(i))
                .into_iter()
                .map(move |job| (id, job))
        })
        .collect();
    let mut found = Vec::new();
    for (i, module) in modules.iter().enumerate() {
        let cx = context(i).with_contributed_jobs(&ci_jobs);
        found.extend(each(*module, &cx)?);
    }
    Ok(found)
}

/// The plan of `install [--module <id>]... [--profile <P>]`: `setup-core`, every
/// module the installed lock records and the `requested` ids. With `tier`, each
/// requested module is installed for that maturity profile: when it differs from
/// the recorded one (none recorded means `DEFAULT_TIER`), the module's answers
/// file records it, its answers kept, and joins the plan. `answered` holds, per
/// module id, the patch `install --preset`/`--answers` resolved: an installed
/// module with one records it as `configure` would (merged over the recorded
/// answers, validated, the compiled version); a patch for a module this install
/// does not reconcile is ignored.
#[allow(clippy::too_many_arguments)]
pub fn install(
    root: &Path,
    source: &Source,
    profile: &profile::Profile,
    registry: &[&dyn Module],
    known: &dyn Fn(&str) -> bool,
    requested: &[&str],
    tier: Option<&str>,
    answered: &BTreeMap<String, Answers>,
) -> crate::Result<Planned> {
    if let Some(tier) = tier {
        answers::check_tier(tier)?;
    }
    let core_version = registry
        .iter()
        .find(|m| m.id() == lock::SETUP_CORE)
        .map_or("0.0.0", |m| m.version());
    let installed = installed_lock(root, core_version, known)?;
    let active = select(registry, installed.as_ref(), requested)?;
    let mut pending = BTreeMap::new();
    for module in &active {
        let id = module.id();
        let patch = answered.get(id);
        let tier = tier.filter(|_| requested.contains(&id));
        if patch.is_none() && tier.is_none() {
            continue;
        }
        let path = answers::path(id);
        destination(root, &path)?;
        let raw = read(root, &path)?;
        let current = raw
            .as_deref()
            .map(|raw| answers::AnswersFile::parse(id, raw))
            .transpose()?;
        let recorded_tier = current.as_ref().map_or(answers::DEFAULT_TIER, |f| f.tier());
        if patch.is_none() && tier == Some(recorded_tier) {
            continue;
        }
        let (version, recorded_profile, mut merged) = current.map_or_else(
            || (module.version().to_owned(), None, Answers::new()),
            |f| (f.version, f.profile, f.answers),
        );
        let profile = tier.map(str::to_owned).or(recorded_profile);
        let file = match patch {
            Some(patch) => {
                let schema = module.questions();
                schema.check(id)?;
                merged.extend(patch.iter().map(|(k, v)| (k.clone(), v.clone())));
                let tier = profile.as_deref().unwrap_or(answers::DEFAULT_TIER);
                answers::AnswersFile {
                    module: id.to_owned(),
                    version: module.version().to_owned(),
                    answers: schema.validate(id, &merged, tier)?,
                    profile,
                }
            }
            None => answers::AnswersFile {
                module: id.to_owned(),
                version,
                answers: merged,
                profile,
            },
        };
        let text = file.to_json_string()?;
        if raw.as_deref() != Some(&text) {
            pending.insert(id, text);
        }
    }
    let mut planned = plan_with(root, source, profile, &active, known, &pending)?;
    // After a version bump the plan already carries the migrated file.
    for (id, text) in pending {
        let path = answers::path(id);
        if !planned.answers.contains_key(&path) {
            planned.changes.insert(path.clone(), Some(text));
            planned.answers.insert(path, id.to_owned());
        }
    }
    Ok(planned)
}

/// Records answers for one module: the patch is merged over the recorded
/// answers, validated against the module's schema, and the resulting file joins
/// the plan (written with the rest, never before the plan is shown). Every
/// driver that answers questions ends here. `modules` is the registry: the plan
/// covers `setup-core`, the modules the installed lock records and `module_id`.
pub fn configure(
    root: &Path,
    source: &Source,
    profile: &profile::Profile,
    modules: &[&dyn Module],
    known: &dyn Fn(&str) -> bool,
    module_id: &str,
    patch: &Answers,
) -> crate::Result<Planned> {
    let Some(module) = modules.iter().find(|m| m.id() == module_id) else {
        return refuse(format!("Unknown module id: {module_id}"));
    };
    let schema = module.questions();
    schema.check(module_id)?;
    let path = answers::path(module_id);
    destination(root, &path)?;
    let current = read(root, &path)?;
    let recorded = current
        .as_deref()
        .map(|raw| answers::AnswersFile::parse(module_id, raw))
        .transpose()?;
    // The recorded profile stays: `configure` answers questions, `install
    // --profile` chooses the profile.
    let (mut merged, recorded_profile) =
        recorded.map_or_else(Default::default, |file| (file.answers, file.profile));
    merged.extend(patch.iter().map(|(k, v)| (k.clone(), v.clone())));
    let tier = recorded_profile.as_deref().unwrap_or(answers::DEFAULT_TIER);
    let file = answers::AnswersFile {
        module: module_id.to_owned(),
        version: module.version().to_owned(),
        answers: schema.validate(module_id, &merged, tier)?,
        profile: recorded_profile,
    };
    let text = file.to_json_string()?;
    let pending = BTreeMap::from([(module_id, text.clone())]);
    let core_version = modules
        .iter()
        .find(|m| m.id() == lock::SETUP_CORE)
        .map_or("0.0.0", |m| m.version());
    let installed = installed_lock(root, core_version, known)?;
    let active = select(modules, installed.as_ref(), &[module_id])?;
    let mut planned = plan_with(root, source, profile, &active, known, &pending)?;
    // After a version bump the plan already carries the migrated file.
    if !planned.answers.contains_key(&path) && current.as_deref() != Some(&text) {
        planned.changes.insert(path.clone(), Some(text));
    }
    planned.answers.insert(path, module_id.to_owned());
    Ok(planned)
}

/// Uninstalls one module (SPEC-engine.md, assumption 6): the same rule as a
/// retired path, applied to every path the lock records for the module. Managed
/// content is deleted when unchanged (a managed block leaves its file, the rest
/// stays), refused when edited, forgotten when absent; a seed or never-touch path
/// is kept and reported when present; a remote setting is always reported. The
/// module's lock entries and its answers file go. Driven by the lock alone, so a
/// module no longer compiled in can still be removed. Nothing is written here.
pub fn remove(
    root: &Path,
    modules: &[&dyn Module],
    known: &dyn Fn(&str) -> bool,
    module_id: &str,
) -> crate::Result<Planned> {
    if module_id == lock::SETUP_CORE {
        return refuse(format!(
            "Cannot remove {}: it is the installer's own content",
            lock::SETUP_CORE
        ));
    }
    let core_version = modules
        .iter()
        .find(|m| m.id() == lock::SETUP_CORE)
        .map_or("0.0.0", |m| m.version());
    let old_raw = read(root, LOCK)?;
    let previous = old_raw
        .as_deref()
        .map(|raw| Lock::parse(raw, core_version, known))
        .transpose()?;
    let compiled = modules.iter().any(|m| m.id() == module_id);
    let recorded = previous
        .as_ref()
        .is_some_and(|lock| lock.modules.contains_key(module_id));
    if !compiled && !recorded {
        return refuse(format!("Unknown module id: {module_id}"));
    }
    let Some(previous) = previous.filter(|_| recorded) else {
        return refuse(format!(
            "Module {module_id} is not installed; nothing to remove"
        ));
    };
    let mut changes: Plan = BTreeMap::new();
    let mut tags = BTreeMap::new();
    let mut notes = BTreeMap::new();
    let mut next = previous.clone();
    next.modules.remove(module_id);
    for (path, prior) in &previous.files {
        if prior.module != module_id {
            continue;
        }
        next.files.remove(path);
        tags.insert(path.clone(), (prior.class, prior.module.clone()));
        let kept = match prior.class {
            Ownership::Managed | Ownership::ManagedBlock => {
                let Some(current) = read(root, path)? else {
                    continue;
                };
                let installed = if prior.class == Ownership::ManagedBlock {
                    block_content(&current)?
                } else {
                    Some(current.as_str())
                };
                let Some(installed) =
                    installed.filter(|s| prior.digest.as_deref() == Some(&digest(s)))
                else {
                    return refuse(format!(
                        "Locally changed managed content of module {module_id}: {path}; restore it before removing the module"
                    ));
                };
                let remaining = if prior.class == Ownership::ManagedBlock {
                    without_block(&current, installed)
                } else {
                    None
                };
                changes.insert(path.clone(), remaining);
                false
            }
            Ownership::Seed | Ownership::NeverTouch => {
                if read(root, path)?.is_none() {
                    continue;
                }
                true
            }
            Ownership::Remote => true,
            // Only the module's entries leave the file; `{}` left behind is deleted.
            Ownership::ManagedEntries => {
                let Some(recorded) = &prior.entries else {
                    continue;
                };
                let change = entries::retire(
                    module_id,
                    path,
                    read(root, path)?.as_deref(),
                    recorded,
                    |pointer, name| {
                        format!(
                            "Locally changed managed entry of module {module_id}: {path} at {pointer} ({name}); restore it before removing the module"
                        )
                    },
                )?;
                let Some(change) = change else {
                    continue;
                };
                changes.insert(path.clone(), change);
                false
            }
        };
        if kept {
            notes.insert(path.clone(), Note::Keep);
        }
    }
    let mut answers_files = BTreeMap::new();
    let answers_path = answers::path(module_id);
    if read(root, &answers_path)?.is_some() {
        changes.insert(answers_path.clone(), None);
        answers_files.insert(answers_path, module_id.to_owned());
    }
    let serialized = next.to_json_string()?;
    if old_raw.as_deref() != Some(&serialized) {
        changes.insert(LOCK.to_owned(), Some(serialized));
    }
    for name in changes.keys() {
        destination(root, name)?;
    }
    Ok(Planned {
        changes,
        tags,
        notes,
        answers: answers_files,
        steps: Vec::new(),
        plan_notes: Vec::new(),
        skipped_seeds: BTreeMap::new(),
    })
}

/// The file with its managed block taken out, undoing how the block was added:
/// the separating blank line goes with it. `None` when nothing but whitespace
/// remains, so the file the engine created for the block alone is deleted.
fn without_block(current: &str, installed: &str) -> Option<String> {
    let with_separator = format!("\n\n{installed}\n");
    let remaining = if current.contains(&with_separator) {
        current.replacen(&with_separator, "\n", 1)
    } else {
        current.replacen(installed, "", 1)
    };
    if remaining.trim().is_empty() {
        None
    } else {
        Some(remaining)
    }
}
