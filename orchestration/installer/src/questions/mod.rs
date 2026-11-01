//! Answer drivers over the engine's question schema (SPEC-questions.md). Each
//! driver contributes a layer of answers; `resolve` merges the layers in the order
//! recorded < default < preset < file (in the order given) < set < interactive
//! into one patch, and `engine::configure` is the only place that validates and records it. The
//! provenance of a run is printed and never written to the repository.
pub mod answers_file;
pub mod configure_new;
pub mod hints;
pub mod tui;

use crate::{
    Result, Source,
    engine::{self, Answers, Module, Planned, Schema, answers},
    profile::Profile,
    refuse,
};
use std::{
    collections::BTreeMap,
    fmt,
    io::{BufRead, Write},
    path::{Path, PathBuf},
};

/// Where an answer came from, lowest precedence first. `Recorded` and `Default`
/// are the engine's own layers (the recorded file and the schema); the drivers
/// contribute the rest; `Preset` is the section `--preset` names and
/// `Interactive` what the TUI asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerSource {
    Recorded,
    Default,
    Preset(String),
    File(PathBuf),
    Set,
    Interactive,
}

impl AnswerSource {
    fn rank(&self) -> u8 {
        match self {
            AnswerSource::Recorded => 0,
            AnswerSource::Default => 1,
            AnswerSource::Preset(_) => 2,
            AnswerSource::File(_) => 3,
            AnswerSource::Set => 4,
            AnswerSource::Interactive => 5,
        }
    }

    /// True for the layers the engine already holds: they inform provenance and
    /// never travel in the patch.
    fn is_engine_layer(&self) -> bool {
        self.rank() <= AnswerSource::Default.rank()
    }
}

impl fmt::Display for AnswerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnswerSource::Recorded => f.write_str("recorded"),
            AnswerSource::Default => f.write_str("default"),
            AnswerSource::Preset(name) => write!(f, "preset {name}"),
            AnswerSource::File(path) => write!(f, "file {}", path.display()),
            AnswerSource::Set => f.write_str("--set"),
            AnswerSource::Interactive => f.write_str("interactive"),
        }
    }
}

/// The answers one source contributes.
#[derive(Clone, Debug, PartialEq)]
pub struct Layer {
    pub source: AnswerSource,
    pub answers: Answers,
}

/// The merged layers: the patch `engine::configure` takes, and the source that
/// decided each key (recorded keys included, so provenance can name them).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Resolution {
    pub patch: Answers,
    pub origins: BTreeMap<String, AnswerSource>,
    /// The distinct sources in merge order, for the provenance line.
    sources: Vec<AnswerSource>,
}

/// Merges `layers` by precedence; layers of equal precedence apply in the order
/// given, so a later `--answers` file overrides an earlier one.
pub fn resolve(mut layers: Vec<Layer>) -> Resolution {
    layers.sort_by_key(|layer| layer.source.rank());
    let mut resolution = Resolution::default();
    for layer in layers {
        for (key, value) in layer.answers {
            if !layer.source.is_engine_layer() {
                resolution.patch.insert(key.clone(), value);
            }
            resolution.origins.insert(key, layer.source.clone());
        }
        if !resolution.sources.contains(&layer.source) {
            resolution.sources.push(layer.source);
        }
    }
    resolution
}

impl Resolution {
    /// One line naming the source of every key in `answers` (what the engine
    /// recorded, or is about to), in merge order: `ANSWERS recorded name + default
    /// enabled + file a.json count + --set reason`. A key no layer answered came
    /// from the schema default. Printed before the plan, never written to a file.
    pub fn provenance(&self, answers: &Answers) -> String {
        let mut sources = self.sources.clone();
        let default_at = sources
            .iter()
            .position(|source| source.rank() > AnswerSource::Default.rank())
            .unwrap_or(sources.len());
        if !sources.contains(&AnswerSource::Default) {
            sources.insert(default_at, AnswerSource::Default);
        }
        let segments: Vec<String> = sources
            .iter()
            .filter_map(|source| {
                let keys: Vec<&str> = answers
                    .keys()
                    .filter(|key| {
                        self.origins.get(*key).unwrap_or(&AnswerSource::Default) == source
                    })
                    .map(String::as_str)
                    .collect();
                (!keys.is_empty()).then(|| format!("{source} {}", keys.join(", ")))
            })
            .collect();
        if segments.is_empty() {
            "ANSWERS none".to_owned()
        } else {
            format!("ANSWERS {}", segments.join(" + "))
        }
    }
}

/// What the `configure` subcommand received: `--answers` files in the order
/// given, `--set key=value` pairs and `--preset <name>`, looked up in the
/// embedded catalogue or, with `--source`, in `catalogue`'s `templates/presets/`.
/// `interactive` is the patch `interview` returned, when the run asked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inputs {
    pub files: Vec<PathBuf>,
    pub sets: Vec<String>,
    pub preset: Option<String>,
    pub catalogue: Option<PathBuf>,
    pub interactive: Option<Answers>,
}

/// What a driver run yields: the engine's plan, the provenance line to print
/// before it and the notes that follow it (`PRESET <name>: no answers for <id>`).
#[derive(Debug)]
pub struct Configured {
    pub planned: Planned,
    pub provenance: String,
    pub notes: Vec<String>,
}

/// The layers `inputs` name for `module_id`, the recorded file they start from
/// and the notes to print after the plan. Nothing is validated here.
fn layers(
    root: &Path,
    schema: &Schema,
    module_id: &str,
    inputs: &Inputs,
) -> Result<(Vec<Layer>, Option<answers::AnswersFile>, Vec<String>)> {
    let recorded = answers::recorded(root, module_id)?;
    let mut layers = vec![Layer {
        source: AnswerSource::Recorded,
        answers: recorded
            .as_ref()
            .map(|file| file.answers.clone())
            .unwrap_or_default(),
    }];
    let mut notes = Vec::new();
    if let Some(name) = &inputs.preset {
        let mut preset = answers_file::preset(name, inputs.catalogue.as_deref())?;
        match preset.modules.remove(module_id) {
            Some(section) => layers.push(Layer {
                source: AnswerSource::Preset(name.clone()),
                answers: section,
            }),
            None => notes.push(preset.absence(module_id)),
        }
    }
    for file in &inputs.files {
        layers.push(Layer {
            source: AnswerSource::File(file.clone()),
            answers: answers_file::load(file, module_id)?,
        });
    }
    let sets = inputs
        .sets
        .iter()
        .map(|pair| answers::parse_set(schema, pair))
        .collect::<Result<Answers>>()?;
    layers.push(Layer {
        source: AnswerSource::Set,
        answers: sets,
    });
    if let Some(asked) = &inputs.interactive {
        layers.push(Layer {
            source: AnswerSource::Interactive,
            answers: asked.clone(),
        });
    }
    Ok((layers, recorded, notes))
}

/// The recorded answers with the patch over them: what the questions start from.
fn merged(recorded: Option<&answers::AnswersFile>, patch: &Answers) -> Answers {
    let mut merged = recorded
        .map(|file| file.answers.clone())
        .unwrap_or_default();
    merged.extend(patch.iter().map(|(k, v)| (k.clone(), v.clone())));
    merged
}

/// The maturity profile defaults resolve with: the recorded one, P1 otherwise.
fn tier(recorded: Option<&answers::AnswersFile>) -> &str {
    recorded.map_or(answers::DEFAULT_TIER, answers::AnswersFile::tier)
}

/// The required questions, in schema order and with `when` read as the engine
/// reads it, that neither `merged` nor a default answers. A question left open
/// gates nothing after it.
fn missing<'a>(schema: &'a Schema, merged: &Answers, tier: &str) -> Vec<&'a str> {
    let mut resolved = Answers::new();
    let mut open = Vec::new();
    for question in schema.questions.iter().filter(|q| !q.is_pattern()) {
        if !schema.when_holds(question, &resolved) {
            continue;
        }
        match merged
            .get(&question.id)
            .cloned()
            .or_else(|| question.default_for(tier))
        {
            Some(value) => {
                resolved.insert(question.id.clone(), value);
            }
            None if question.required => open.push(question.id.as_str()),
            None => {}
        }
    }
    open
}

/// The first of the `missing` questions.
fn first_missing<'a>(schema: &'a Schema, merged: &Answers, tier: &str) -> Option<&'a str> {
    missing(schema, merged, tier).first().copied()
}

/// The questions of `module_id` in `root` that `patch` over the recorded answers
/// still leaves open (the MCP server elicits them, SPEC-questions.md), and the
/// maturity profile the defaults resolved with.
pub fn open_questions(
    root: &Path,
    schema: &Schema,
    module_id: &str,
    patch: &Answers,
) -> Result<(Vec<String>, String)> {
    let recorded = answers::recorded(root, module_id)?;
    let tier = tier(recorded.as_ref());
    let open = missing(schema, &merged(recorded.as_ref(), patch), tier)
        .into_iter()
        .map(str::to_owned)
        .collect();
    Ok((open, tier.to_owned()))
}

/// The refusal of a non-interactive run that leaves `question` of `module` open.
fn unanswered<T>(module: &str, question: &str) -> Result<T> {
    refuse(format!(
        "Module {module}: question {question} has no answer; pass --set {question}=<value>, --answers <file> or --preset <name>"
    ))
}

/// The answers-file driver: collects the layers `inputs` name, resolves them into
/// one patch and ends in `engine::configure`, which validates and records.
/// Nothing is written and nothing is validated here. A required question no
/// layer answers refuses with its id: a run that did not ask never prompts.
pub fn configure(
    root: &Path,
    source: &Source,
    profile: &Profile,
    modules: &[&dyn Module],
    known: &dyn Fn(&str) -> bool,
    module_id: &str,
    inputs: &Inputs,
) -> Result<Configured> {
    // An unknown module is the engine's refusal; an empty schema parses `--set`
    // values as strings until then.
    let schema = modules
        .iter()
        .find(|m| m.id() == module_id)
        .map_or_else(Schema::default, |m| m.questions());
    let (layers, recorded, notes) = layers(root, &schema, module_id, inputs)?;
    let resolution = resolve(layers);
    let tier = tier(recorded.as_ref());
    if let Some(id) = first_missing(&schema, &merged(recorded.as_ref(), &resolution.patch), tier) {
        return unanswered(module_id, id);
    }
    let planned = engine::configure(
        root,
        source,
        profile,
        modules,
        known,
        module_id,
        &resolution.patch,
    )?;
    let recorded = recorded.map(|file| file.answers).unwrap_or_default();
    // What the engine will record: the file in the plan, or the recorded one when
    // nothing changed.
    let final_answers = match planned.changes.get(&answers::path(module_id)) {
        Some(Some(text)) => answers::AnswersFile::parse(module_id, text)?.answers,
        _ => recorded,
    };
    Ok(Configured {
        provenance: resolution.provenance(&final_answers),
        notes,
        planned,
    })
}

/// What `install --preset`/`--answers` yields: the engine's plan, one provenance
/// line per configured module (`<id>: ANSWERS …`) and the preset notes.
#[derive(Debug)]
pub struct Installed {
    pub planned: Planned,
    pub provenance: Vec<String>,
    pub notes: Vec<String>,
}

/// `install` with `--preset` and `--answers` (SPEC-questions.md, Commands): sugar
/// over `configure`. Every module this install reconciles that has a section in
/// the preset or in a multi-module answers file is configured with it first
/// (recorded < default < preset < files in the order given), then the whole
/// install is planned in one pass through `engine::install`, so the result is
/// what `configure --apply` followed by `install --apply` leaves. Without a
/// preset or files it is the plain install. Nothing is written here.
#[allow(clippy::too_many_arguments)]
pub fn install(
    root: &Path,
    source: &Source,
    profile: &Profile,
    modules: &[&dyn Module],
    known: &dyn Fn(&str) -> bool,
    requested: &[&str],
    profile_tier: Option<&str>,
    inputs: &Inputs,
) -> Result<Installed> {
    let preset = inputs
        .preset
        .as_deref()
        .map(|name| answers_file::preset(name, inputs.catalogue.as_deref()))
        .transpose()?;
    let files = inputs
        .files
        .iter()
        .map(|file| Ok((file, answers_file::sections(file)?)))
        .collect::<Result<Vec<_>>>()?;
    let core_version = modules
        .iter()
        .find(|m| m.id() == engine::lock::SETUP_CORE)
        .map_or("0.0.0", |m| m.version());
    let lock = engine::installed_lock(root, core_version, known)?;
    let mut patches = BTreeMap::new();
    let mut configured = Vec::new();
    let mut notes = Vec::new();
    for module in engine::select(modules, lock.as_ref(), requested)? {
        let id = module.id();
        let recorded = answers::recorded(root, id)?;
        let mut layers = Vec::new();
        if let Some(preset) = &preset {
            match preset.modules.get(id) {
                Some(section) => layers.push(Layer {
                    source: AnswerSource::Preset(preset.name.clone()),
                    answers: section.clone(),
                }),
                None => notes.push(preset.absence(id)),
            }
        }
        for (file, sections) in &files {
            if let Some(section) = sections.get(id) {
                layers.push(Layer {
                    source: AnswerSource::File((*file).clone()),
                    answers: section.clone(),
                });
            }
        }
        if layers.is_empty() {
            continue;
        }
        layers.push(Layer {
            source: AnswerSource::Recorded,
            answers: recorded
                .as_ref()
                .map(|file| file.answers.clone())
                .unwrap_or_default(),
        });
        let resolution = resolve(layers);
        let at = profile_tier
            .filter(|_| requested.contains(&id))
            .unwrap_or_else(|| tier(recorded.as_ref()));
        let merged = merged(recorded.as_ref(), &resolution.patch);
        if let Some(qid) = first_missing(&module.questions(), &merged, at) {
            return unanswered(id, qid);
        }
        patches.insert(id.to_owned(), resolution.patch.clone());
        configured.push((id, resolution, recorded));
    }
    let planned = engine::install(
        root,
        source,
        profile,
        modules,
        known,
        requested,
        profile_tier,
        &patches,
    )?;
    let provenance = configured
        .into_iter()
        .map(|(id, resolution, recorded)| {
            // What the engine will record: the file in the plan, or the recorded
            // one when nothing changed.
            let answers = match planned.changes.get(&answers::path(id)) {
                Some(Some(text)) => answers::AnswersFile::parse(id, text)?.answers,
                _ => recorded.map(|file| file.answers).unwrap_or_default(),
            };
            Ok(format!("{id}: {}", resolution.provenance(&answers)))
        })
        .collect::<Result<_>>()?;
    Ok(Installed {
        planned,
        provenance,
        notes,
    })
}

/// The TUI driver: asks every live question of `module_id` over `input` and
/// `output`, starting from what the layers of `inputs` merge to, and returns the
/// patch for `Inputs::interactive`; `other` on a question that declares
/// `x-configure-new` prints the summary of the module's real contract. Writes nothing to the repository; `configure`
/// then plans it like any other layer.
pub fn interview(
    root: &Path,
    source: &Source,
    modules: &[&dyn Module],
    module_id: &str,
    inputs: &Inputs,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Answers> {
    let Some(module) = modules.iter().find(|m| m.id() == module_id) else {
        return refuse(format!("Unknown module id: {module_id}"));
    };
    let schema = module.questions();
    schema.check(module_id)?;
    let (layers, recorded, _) = layers(root, &schema, module_id, inputs)?;
    let resolution = resolve(layers);
    let header = tui::Header {
        module: module_id,
        version: module.version(),
        tier: tier(recorded.as_ref()),
        recorded: recorded.as_ref().map_or(0, |file| file.answers.len()),
        preset: inputs.preset.as_deref(),
    };
    let profile = crate::profile_for(root)?;
    let previous = configure_new::installed_or_empty(root, source)?;
    let contract = |question: &str, answers: &Answers| {
        configure_new::preview(
            root, source, &profile, &previous, *module, question, answers,
        )
    };
    tui::ask(
        &header,
        &schema,
        &merged(recorded.as_ref(), &resolution.patch),
        &contract,
        input,
        output,
    )
}

const PRESETS_USAGE: &str = "Usage: brakes presets [<module-id>] [--source <checkout>]";

/// `brakes presets [<module-id>] [--source <checkout>]`: without a module,
/// one `<name>: <description>` line per preset; with one, the section each preset
/// holds for it or `PRESET <name>: no answers for <module>[: <reason>]`. Read-only and outside
/// any repository, like `guard`.
pub fn presets_cli(args: &[std::ffi::OsString]) -> std::process::ExitCode {
    match presets_lines(args) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("REFUSED: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

fn presets_lines(args: &[std::ffi::OsString]) -> Result<Vec<String>> {
    let mut module = None;
    let mut checkout = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--source") if checkout.is_none() => {
                checkout = Some(PathBuf::from(args.next().ok_or(PRESETS_USAGE)?))
            }
            Some(id) if !id.starts_with('-') && module.is_none() => module = Some(id),
            _ => return crate::refuse(PRESETS_USAGE),
        }
    }
    answers_file::catalogue(checkout.as_deref())?
        .into_iter()
        .map(|preset| {
            let Some(module) = module else {
                return Ok(format!("{}: {}", preset.name, preset.description));
            };
            Ok(match preset.modules.get(module) {
                Some(section) => format!(
                    "PRESET {}: {}",
                    preset.name,
                    serde_json::to_string(section)?
                ),
                None => preset.absence(module),
            })
        })
        .collect()
}
