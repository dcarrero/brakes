//! `brakes ci init` (#24, part of #19): the guided setup of a repository without
//! CI. It asks only what it cannot detect: which detected apps to record, the
//! commands their profiles leave `null` (a pack's proposal is offered, never
//! invented) and the runner. Then it plans stack-packs, ci-baseline and
//! security in one engine plan, with the profile it is about to write, so the
//! seed workflow is complete on its first and only write: it is a seed, and a
//! later install never rewrites it.
//!
//! Nothing here writes: `run` returns the plan and the lines to print; the
//! caller applies it through `crate::apply`, as every command does.
use crate::{
    LOCK, PROFILE, Result, Source,
    engine::{self, Answers, Planned, answers},
    modules::{
        self,
        ci_baseline::{CI_BASELINE, Runner},
        security::SECURITY,
        stack_packs::{
            STACK_PACKS,
            detect::{self, CommandLine, Proposal},
        },
    },
    profile, questions, read, refuse,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
    path::Path,
};

/// The modules the guided setup plans together.
pub const MODULES: [&str; 3] = [STACK_PACKS, CI_BASELINE, SECURITY];
const WORKFLOWS: &str = ".github/workflows";
/// The commands a seed can run, in the order detection lists them.
const RUNNABLE: [&str; 4] = ["build", "test", "lint", "verify"];

/// Where the answers come from: the terminal (or a test's pipe), or nowhere.
pub enum Asker<'a> {
    NoInput,
    Prompt(&'a mut dyn BufRead, &'a mut dyn Write),
}

impl Asker<'_> {
    /// The trimmed line answered to `prompt`, or `None` without input.
    fn ask(&mut self, prompt: &str) -> Result<Option<String>> {
        match self {
            Asker::NoInput => Ok(None),
            Asker::Prompt(input, output) => {
                write!(output, "{prompt}")?;
                output.flush()?;
                let mut line = String::new();
                input.read_line(&mut line)?;
                Ok(Some(line.trim().to_owned()))
            }
        }
    }
}

/// What `ci init` prints and plans.
pub struct CiInit {
    /// One line per step, printed before the plan.
    pub steps: Vec<String>,
    /// The profiles the setup declares, by path, written before the plan applies.
    pub profiles: BTreeMap<String, String>,
    /// The answers the setup records, per module (`--answers` files win).
    pub patches: BTreeMap<String, Answers>,
    /// What to commit and how to see it green, printed after the plan.
    pub next: Vec<String>,
}

/// Refuses a repository that already runs a CI `brakes` did not seed: its CI is
/// audited, never doubled. A workflow the lock records is `brakes`'.
fn refuse_existing_ci(root: &Path) -> Result<()> {
    let recorded: Vec<String> = read(root, LOCK)?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|lock| lock.get("files").and_then(Value::as_object).cloned())
        .map(|paths| paths.keys().cloned().collect())
        .unwrap_or_default();
    let mut foreign = Vec::new();
    let mut ours = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root.join(WORKFLOWS)) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
                continue;
            }
            let path = format!("{WORKFLOWS}/{name}");
            if recorded.contains(&path) {
                ours.push(path);
            } else {
                foreign.push(path);
            }
        }
    }
    foreign.sort();
    if !foreign.is_empty() {
        return refuse(format!(
            "ci init: this repository already has a CI ({}); brakes audits it instead of seeding another: answer ci-baseline `workflow: existing` and run `brakes doctor . --propose`",
            foreign.join(", ")
        ));
    }
    ours.sort();
    if !ours.is_empty() {
        return refuse(format!(
            "ci init: brakes already set up this repository's CI ({}); run `brakes doctor .`",
            ours.join(", ")
        ));
    }
    Ok(())
}

/// The profile path of an app at `path`.
fn profile_path(path: &str) -> String {
    match path {
        "." => PROFILE.to_owned(),
        dir => format!("{dir}/{PROFILE}"),
    }
}

/// The apps to set up: those stack-packs records, and each detected one the
/// user keeps (all of them without input).
fn apps(root: &Path, recorded: &Answers, asker: &mut Asker<'_>) -> Result<Vec<Proposal>> {
    let detection = detect::propose(root, recorded)?;
    if detection.proposals.is_empty() {
        return refuse(
            "ci init: no stack detected and none recorded; record the apps with `brakes configure . stack-packs` or an answers file (--answers), then run it again",
        );
    }
    let mut kept: Vec<Proposal> = Vec::new();
    for proposal in detection.proposals {
        if !proposal.recorded {
            if let Some(other) = kept.iter().find(|k| k.path == proposal.path)
                && matches!(asker, Asker::NoInput)
            {
                return refuse(format!(
                    "ci init: several stacks at `{}` ({}, {}); record one with `brakes configure . stack-packs`",
                    proposal.path, other.stack, proposal.stack
                ));
            }
            let prompt = format!(
                "Record app {} ({} at {})? [Y/n] ",
                proposal.id, proposal.stack, proposal.path
            );
            if asker
                .ask(&prompt)?
                .is_some_and(|a| a.to_ascii_lowercase().starts_with('n'))
            {
                continue;
            }
        }
        kept.push(proposal);
    }
    if kept.is_empty() {
        return refuse(
            "ci init: no app to set up; record one with `brakes configure . stack-packs`",
        );
    }
    Ok(kept)
}

/// The commands of one app after the setup: what its profile declares, plus
/// each `null` field filled with the answer or, without one, the proposal.
/// Returns the profile text when it changes and the step lines.
fn commands(
    root: &Path,
    app: &Proposal,
    asker: &mut Asker<'_>,
) -> Result<(Option<String>, Vec<String>)> {
    let path = profile_path(&app.path);
    let before = read(root, &path)?;
    let text = before
        .clone()
        .unwrap_or_else(|| profile::default_json().to_owned());
    let value: Value = serde_json::from_str(&text)?;
    let fillable = |name: &str| value["commands"].get(name).is_some_and(Value::is_null);
    let proposed: BTreeMap<&str, &str> = app
        .commands
        .iter()
        .filter_map(|(name, line)| match line {
            CommandLine::Proposed(command) => Some((*name, command.as_str())),
            CommandLine::Declared(_) => None,
        })
        .collect();
    let mut fills: Vec<(&str, String, &str)> = Vec::new();
    for name in RUNNABLE.into_iter().filter(|n| fillable(n)) {
        let offered = proposed.get(name).copied();
        let prompt = match offered {
            Some(command) => format!("commands.{name} of {} [{command}]: ", app.id),
            None => format!(
                "commands.{name} of {} (empty leaves it undeclared): ",
                app.id
            ),
        };
        let chosen = match (asker.ask(&prompt)?, offered) {
            (Some(answer), _) if answer == "-" => None,
            (Some(answer), offered) if answer.is_empty() => {
                offered.map(|c| (c.to_owned(), "proposed"))
            }
            (Some(answer), _) => Some((answer, "answered")),
            (None, offered) => offered.map(|c| (c.to_owned(), "proposed")),
        };
        if let Some((command, how)) = chosen {
            fills.push((name, command, how));
        }
    }
    let declared = RUNNABLE.iter().any(|name| {
        value["commands"][*name].is_string() || fills.iter().any(|(n, _, _)| n == name)
    });
    if !declared {
        return refuse(format!(
            "ci init: no command to run for app {}; declare commands.test (or verify, lint, build) in {path}",
            app.id
        ));
    }
    let mut steps = Vec::new();
    for name in RUNNABLE {
        if let Some((_, command, how)) = fills.iter().find(|(n, _, _)| *n == name) {
            let why = match *how {
                "proposed" => format!("proposed for {}", app.stack),
                _ => "answered".to_owned(),
            };
            steps.push(format!(
                "STEP 2/4 commands of {}: {name} = `{command}` ({why}; your CI runs it, brakes never does)",
                app.id
            ));
        } else if let Some(command) = value["commands"][name].as_str() {
            steps.push(format!(
                "STEP 2/4 commands of {}: {name} = `{command}` (declared in {path})",
                app.id
            ));
        }
    }
    if fills.is_empty() {
        return Ok((None, steps));
    }
    let pairs: Vec<(&str, &str)> = fills
        .iter()
        .map(|(name, command, _)| (*name, command.as_str()))
        .collect();
    Ok((
        Some(profile::fill_null_commands(&text, &path, &pairs)?),
        steps,
    ))
}

/// The stack-packs answers that record `apps` not yet recorded; no container,
/// since the guided setup builds CI, not images.
fn record(apps: &[Proposal]) -> Answers {
    let mut patch = Answers::new();
    for app in apps.iter().filter(|a| !a.recorded) {
        let key = |field: &str| format!("apps.{}.{field}", app.id);
        patch.insert(key("path"), Value::from(app.path.clone()));
        patch.insert(key("stack"), Value::from(app.stack.as_str()));
        patch.insert(key("container"), Value::from(false));
    }
    patch
}

/// The runner step: the default unless the user picks another one.
fn runner(asker: &mut Asker<'_>) -> Result<(Option<Value>, String)> {
    let available = Runner::available();
    let default = Runner::default_choice();
    let mut chosen = default;
    if available.len() > 1 {
        let names: Vec<&str> = available.iter().map(|r| r.as_str()).collect();
        let prompt = format!(
            "Runner [{}] (one of {}): ",
            default.as_str(),
            names.join(", ")
        );
        if let Some(answer) = asker.ask(&prompt)?.filter(|a| !a.is_empty()) {
            chosen = *available
                .iter()
                .find(|r| r.as_str() == answer)
                .ok_or_else(|| {
                    format!(
                        "ci init: runner `{answer}` is not one of {}",
                        names.join(", ")
                    )
                })?;
        }
    }
    let line = format!(
        "STEP 3/4 runner: {} (ci-baseline `runner`; the label comes from your configuration, never from free text)",
        chosen.as_str()
    );
    Ok((
        (chosen != default).then(|| Value::from(chosen.as_str())),
        line,
    ))
}

/// The guided setup of `root`: the steps, the profiles it declares and the
/// answers it records, asked once. `files` are `--answers` files
/// (multi-module shape); they win over what the setup derives. `plan` turns
/// the result into the engine's plan.
pub fn run(root: &Path, files: &[std::path::PathBuf], asker: &mut Asker<'_>) -> Result<CiInit> {
    refuse_existing_ci(root)?;
    let mut sections: Vec<BTreeMap<String, Answers>> = Vec::new();
    for file in files {
        sections.push(questions::answers_file::sections(file)?);
    }
    // The apps an answers file records count as recorded: detection keeps them.
    let mut recorded = answers::recorded(root, STACK_PACKS)?
        .map(|file| file.answers)
        .unwrap_or_default();
    for section in &sections {
        if let Some(apps) = section.get(STACK_PACKS) {
            recorded.extend(apps.clone());
        }
    }
    let apps = apps(root, &recorded, asker)?;
    let mut steps: Vec<String> = apps
        .iter()
        .map(|app| {
            let how = if app.recorded {
                "recorded by stack-packs".to_owned()
            } else {
                format!("detected from {}", app.evidence.join(", "))
            };
            format!(
                "STEP 1/4 apps: {} ({} at {}), {how}",
                app.id, app.stack, app.path
            )
        })
        .collect();
    let mut profiles = BTreeMap::new();
    for app in &apps {
        let (text, lines) = commands(root, app, asker)?;
        if let Some(text) = text {
            profiles.insert(profile_path(&app.path), text);
        }
        steps.extend(lines);
    }
    let (runner, line) = runner(asker)?;
    steps.push(line);
    steps.push(format!(
        "STEP 4/4 workflows: {WORKFLOWS}/ci.yml is a seed, yours from now on; brakes owns only the judges (agentic-security.yml, agentic-coverage.yml)"
    ));
    let mut patches: BTreeMap<String, Answers> = BTreeMap::new();
    let recorded_apps = record(&apps);
    if !recorded_apps.is_empty() {
        patches.insert(STACK_PACKS.to_owned(), recorded_apps);
    }
    if let Some(runner) = runner {
        patches
            .entry(CI_BASELINE.to_owned())
            .or_default()
            .insert("runner".to_owned(), runner);
    }
    for section in sections {
        for (module, answers) in section {
            patches.entry(module).or_default().extend(answers);
        }
    }
    let next = vec![
        "NEXT git add -A && git commit -m \"ci: the project's CI, seeded by brakes\" (every file the plan wrote, seeds included)".to_owned(),
        "NEXT open a pull request; `gh pr checks` shows `required` (your CI) and `agentic-required` (the judges) green".to_owned(),
        "NEXT `brakes apply . --remote` makes both required on the default branch".to_owned(),
    ];
    Ok(CiInit {
        steps,
        profiles,
        patches,
        next,
    })
}

/// The engine's plan of stack-packs, ci-baseline and security for `setup`.
/// `written` says the caller already wrote `setup.profiles`; otherwise the root
/// profile the setup is about to write is the one planned with, so the plan
/// shows the seed the apply will write.
pub fn plan(root: &Path, source: &Source, setup: &CiInit, written: bool) -> Result<Planned> {
    let profile = match setup.profiles.get(PROFILE).filter(|_| !written) {
        Some(text) => profile::profile_from(root, Some(text.clone()))?,
        None => profile::profile_for(root)?,
    };
    engine::install(
        root,
        source,
        &profile,
        &modules::all(),
        &crate::known_path,
        &MODULES,
        None,
        &setup.patches,
    )
}
