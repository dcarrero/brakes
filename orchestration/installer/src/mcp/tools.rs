//! The tools of `brakes mcp` (SPEC-questions.md, MCP server). Four read
//! tools — `list_modules`, `get_questions`, `propose_answers`, `plan` — and
//! `apply`, which writes a plan only with the token `plan` returned for it and
//! the human's confirmation in the client's own form (decision 2026-10-28,
//! point 9); a client without form elicitation is refused `apply`. `plan` asks
//! the client for the questions still open (`elicit`). Only `apply` writes, and
//! only local files through the engine's plan, as `configure --apply` does:
//! never `apply --remote`, never a project command, never the network. A `repo`
//! argument passes `personal_scope(path, false)`: one repository per call, never
//! `--new-personal`.
use super::{Client, Server, elicit};
use crate::{
    Result,
    engine::{
        self, Answers, Ownership,
        answers::{self, Kind, Question, When},
    },
    modules::{self, core_version},
    personal_scope, questions, refuse,
};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, path::Path, path::PathBuf};

/// The tool names, in the order `tools/list` returns them.
pub const NAMES: [&str; 5] = [
    "list_modules",
    "get_questions",
    "propose_answers",
    "plan",
    "apply",
];

/// The `tools/list` entries: input schemas are JSON Schema 2020-12 objects that
/// accept only the named arguments.
pub fn list() -> Value {
    let repo = json!({"type": "string",
        "description": "Absolute path of the repository root; one repository per call, inside the owner's scope."});
    let module = json!({"type": "string", "description": "A module id from list_modules."});
    let answers = json!({"type": "object",
        "description": "A patch of answers by question id, merged over the recorded ones and validated by the engine."});
    let schema = |properties: Value, required: &[&str]| {
        json!({"type": "object", "properties": properties, "required": required,
               "additionalProperties": false})
    };
    let read_only = json!({"readOnlyHint": true, "openWorldHint": false});
    json!([
        {"name": "list_modules",
         "description": "The compiled modules with version and requirements; with `repo`, whether each is installed there.",
         "inputSchema": schema(json!({"repo": repo}), &[]),
         "annotations": read_only},
        {"name": "get_questions",
         "description": "A module's question schema (types, enums, validators, `when`, x-* hints) with defaults resolved for the repository's profile (P1 without `repo`). No question is ever a secret.",
         "inputSchema": schema(json!({"module": module, "repo": repo}), &["module"]),
         "annotations": read_only},
        {"name": "propose_answers",
         "description": "Deterministic proposals for a module's questions: recorded answers, then what the repository's files show, then the schema default; each with its source and evidence. Never reads .env files, environment variables or ignored paths; never runs a command.",
         "inputSchema": schema(json!({"module": module, "repo": repo}), &["module", "repo"]),
         "annotations": read_only},
        {"name": "plan",
         "description": "The plan `configure` would print for these answers, its manual steps, the merged answers and the confirmation token apply needs. Writes nothing.",
         "inputSchema": schema(json!({"module": module, "repo": repo, "answers": answers}), &["module", "repo"]),
         "annotations": read_only},
        {"name": "apply",
         "description": "Writes the plan `plan` showed in this session for the same module, repository and answers: needs its confirmation token, then asks the human to confirm in the client's own form. Local files only, never remote. A client without elicitation is refused: run `brakes configure --apply` yourself.",
         "inputSchema": schema(json!({"module": module, "repo": repo, "answers": answers,
             "confirmation_token": {"type": "string", "description": "The token plan returned."}}),
             &["answers", "confirmation_token", "module", "repo"]),
         "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false}},
    ])
}

/// Runs tool `name` (one of `NAMES`) for `server`, asking `client` when the
/// tool needs the human; `Err` is the refusal, without its prefix, or
/// `elicit::Stopped` when the human declined or cancelled.
pub fn call(
    name: &str,
    arguments: &Map<String, Value>,
    server: &Server,
    client: &mut dyn Client,
) -> Result<Value> {
    let args = Arguments {
        tool: name,
        map: arguments,
    };
    match name {
        "list_modules" => {
            args.only(&["repo"])?;
            list_modules(server, args.repo()?.as_deref())
        }
        "get_questions" => {
            args.only(&["module", "repo"])?;
            get_questions(server, args.module()?, args.repo()?.as_deref())
        }
        "propose_answers" => {
            args.only(&["module", "repo"])?;
            let module = args.module()?;
            propose_answers(server, module, &args.required_repo()?)
        }
        "plan" => {
            args.only(&["module", "repo", "answers"])?;
            let module = args.module()?;
            plan(
                server,
                client,
                module,
                &args.required_repo()?,
                &args.answers()?,
            )
        }
        _ => {
            args.only(&["module", "repo", "answers", "confirmation_token"])?;
            let module = args.module()?;
            let root = args.required_repo()?;
            let token = args.token()?;
            apply(server, client, module, &root, &args.answers()?, token)
        }
    }
}

struct Arguments<'a> {
    tool: &'a str,
    map: &'a Map<String, Value>,
}

impl Arguments<'_> {
    fn only(&self, keys: &[&str]) -> Result<()> {
        match self.map.keys().find(|k| !keys.contains(&k.as_str())) {
            Some(key) => refuse(format!("{} takes no argument `{key}`", self.tool)),
            None => Ok(()),
        }
    }
    fn module(&self) -> Result<&str> {
        match self.map.get("module").and_then(Value::as_str) {
            Some(module) => Ok(module),
            None => refuse(format!("{} needs `module`", self.tool)),
        }
    }
    /// The repository root, through the CLI's scope guard; a second repository
    /// (an array, or any value that is not one path) is refused.
    fn repo(&self) -> Result<Option<PathBuf>> {
        match self.map.get("repo") {
            None => Ok(None),
            Some(Value::String(path)) => Ok(Some(personal_scope(Path::new(path), false)?)),
            Some(_) => refuse("one repository per call: `repo` is one path"),
        }
    }
    fn required_repo(&self) -> Result<PathBuf> {
        match self.repo()? {
            Some(root) => Ok(root),
            None => refuse(format!("{} needs `repo`", self.tool)),
        }
    }
    fn token(&self) -> Result<&str> {
        match self.map.get("confirmation_token").and_then(Value::as_str) {
            Some(token) => Ok(token),
            None => refuse(format!("{} needs `confirmation_token`", self.tool)),
        }
    }
    fn answers(&self) -> Result<Answers> {
        match self.map.get("answers") {
            None => Ok(Answers::new()),
            Some(Value::Object(map)) => Ok(map.clone().into_iter().collect()),
            Some(_) => refuse("`answers` must be an object of answers by question id"),
        }
    }
}

fn module(server: &Server, id: &str) -> Result<&'static dyn engine::Module> {
    match server.modules.iter().find(|m| m.id() == id) {
        Some(module) => Ok(*module),
        None => refuse(format!("Unknown module id: {id}")),
    }
}

fn installed_lock(root: &Path) -> Result<Option<engine::Lock>> {
    engine::installed_lock(root, core_version(), &crate::known_path)
}

fn list_modules(server: &Server, root: Option<&Path>) -> Result<Value> {
    let lock = root.map(installed_lock).transpose()?.flatten();
    let modules = server
        .modules
        .iter()
        .map(|m| {
            let mut entry = json!({"id": m.id(), "version": m.version(), "requires": m.requires()});
            if root.is_some() {
                let installed = lock
                    .as_ref()
                    .is_some_and(|l| l.modules.contains_key(m.id()));
                entry["installed"] = json!(installed);
            }
            entry
        })
        .collect::<Vec<_>>();
    Ok(json!({"modules": modules}))
}

/// The maturity profile `id`'s defaults resolve with in `root`: the recorded
/// one, P1 otherwise (and without a repository).
fn tier(root: Option<&Path>, id: &str) -> Result<String> {
    Ok(match root {
        Some(root) => answers::recorded(root, id)?
            .map_or(answers::DEFAULT_TIER.to_owned(), |file| {
                file.tier().to_owned()
            }),
        None => answers::DEFAULT_TIER.to_owned(),
    })
}

fn get_questions(server: &Server, id: &str, root: Option<&Path>) -> Result<Value> {
    let module = module(server, id)?;
    let schema = module.questions();
    schema.check(id)?;
    let tier = tier(root, id)?;
    let questions: Vec<Value> = schema
        .questions
        .iter()
        .map(|q| question(q, &tier))
        .collect();
    Ok(json!({"module": id, "version": module.version(), "profile": tier, "questions": questions}))
}

/// One question in the module specs' JSON form, its default resolved for `tier`.
fn question(q: &Question, tier: &str) -> Value {
    let mut out = Map::new();
    out.insert("id".into(), json!(q.id));
    match &q.kind {
        Kind::String => out.insert("type".into(), json!("string")),
        Kind::Boolean => out.insert("type".into(), json!("boolean")),
        Kind::Integer => out.insert("type".into(), json!("integer")),
        Kind::Enum(options) => {
            out.insert("type".into(), json!("string"));
            out.insert("enum".into(), json!(options))
        }
        Kind::ArrayOfEnum(options) => {
            out.insert("type".into(), json!("array"));
            out.insert("items".into(), json!({"type": "string", "enum": options}))
        }
        Kind::ArrayOfString => {
            out.insert("type".into(), json!("array"));
            out.insert("items".into(), json!({"type": "string"}))
        }
    };
    out.insert("description".into(), json!(q.description));
    out.insert("required".into(), json!(q.required));
    if let Some(default) = q.default_for(tier) {
        out.insert("default".into(), default);
    }
    if let Some(when) = &q.when {
        out.insert("when".into(), json!(when_text(when)));
    }
    let bounds = [
        ("minLength", q.min_length.map(|n| json!(n))),
        ("maxLength", q.max_length.map(|n| json!(n))),
        ("minimum", q.minimum.map(|n| json!(n))),
        ("maximum", q.maximum.map(|n| json!(n))),
        ("minItems", q.min_items.map(|n| json!(n))),
        ("maxItems", q.max_items.map(|n| json!(n))),
    ];
    out.extend(
        bounds
            .into_iter()
            .filter_map(|(k, v)| Some((k.to_owned(), v?))),
    );
    out.extend(q.extensions.iter().map(|(k, v)| (k.clone(), v.clone())));
    Value::Object(out)
}

/// A `when` as the module specs write it.
fn when_text(when: &When) -> String {
    match when {
        When::Truthy(id) => id.clone(),
        When::Falsy(id) => format!("!{id}"),
        When::Eq(id, literal) => format!("{id} == {literal}"),
        When::Ne(id, literal) => format!("{id} != {literal}"),
    }
}

/// `{proposals: {qid: {value, source, evidence}}}`: recorded, then detected,
/// then the default, for every question whose `when` holds over the proposals
/// before it; a pattern question's instances come from the recorded answers and
/// detection only. Deterministic: same files, same answer.
fn propose_answers(server: &Server, id: &str, root: &Path) -> Result<Value> {
    let schema = module(server, id)?.questions();
    schema.check(id)?;
    let recorded = answers::recorded(root, id)?;
    let tier = recorded
        .as_ref()
        .map_or(answers::DEFAULT_TIER, answers::AnswersFile::tier);
    let recorded_answers = recorded
        .as_ref()
        .map(|f| f.answers.clone())
        .unwrap_or_default();
    let recorded_at = answers::path(id);
    let detected = detect(id, root, &recorded_answers)?;
    let mut proposals = BTreeMap::new();
    let mut resolved = Answers::new();
    for q in &schema.questions {
        if q.is_pattern() {
            let instances = recorded_answers
                .keys()
                .chain(detected.keys())
                .filter(|key| q.answers(key));
            for key in instances {
                let proposal = match recorded_answers.get(key) {
                    Some(value) => proposal(value, "recorded", &recorded_at),
                    None => {
                        let (value, evidence) = &detected[key];
                        proposal(value, "detected", evidence)
                    }
                };
                proposals.insert(key.clone(), proposal);
            }
            continue;
        }
        if !schema.when_holds(q, &resolved) {
            continue;
        }
        let found = if let Some(value) = recorded_answers.get(&q.id) {
            Some((value.clone(), proposal(value, "recorded", &recorded_at)))
        } else if let Some((value, evidence)) = detected.get(&q.id) {
            Some((value.clone(), proposal(value, "detected", evidence)))
        } else {
            q.default_for(tier).map(|value| {
                let evidence = format!("schema default for {tier}");
                (value.clone(), proposal(&value, "default", &evidence))
            })
        };
        if let Some((value, proposal)) = found {
            resolved.insert(q.id.clone(), value);
            proposals.insert(q.id.clone(), proposal);
        }
    }
    Ok(json!({"proposals": proposals}))
}

fn proposal(value: &Value, source: &str, evidence: &str) -> Value {
    json!({"value": value, "source": source, "evidence": evidence})
}

/// Answers the files of `root` show for module `id`, each with its evidence:
/// lockfiles and manifests for `stack-packs` (its own detection), a workflow the
/// lock does not record for `ci-baseline`'s `workflow: existing`. A path git
/// ignores is never evidence; `.env*` and the environment are never read.
fn detect(id: &str, root: &Path, recorded: &Answers) -> Result<BTreeMap<String, (Value, String)>> {
    let mut found = BTreeMap::new();
    if id == modules::stack_packs::STACK_PACKS {
        let detection = modules::stack_packs::detect::propose(root, recorded)?;
        for p in detection.proposals {
            if p.recorded || ignored(root, &p.path) {
                continue;
            }
            let evidence = p.evidence.join(", ");
            found.insert(
                format!("apps.{}.path", p.id),
                (json!(p.path), evidence.clone()),
            );
            found.insert(
                format!("apps.{}.stack", p.id),
                (json!(p.stack.to_string()), evidence),
            );
        }
    }
    if id == modules::ci_baseline::CI_BASELINE {
        let lock = installed_lock(root)?;
        let managed = |path: &str| lock.as_ref().is_some_and(|l| l.files.contains_key(path));
        let workflows: Vec<String> = workflow_files(root)?
            .into_iter()
            .filter(|path| !managed(path) && !ignored(root, path))
            .collect();
        if !workflows.is_empty() {
            found.insert(
                "workflow".to_owned(),
                (json!("existing"), workflows.join(", ")),
            );
        }
    }
    Ok(found)
}

/// `.github/workflows/*.yml` and `*.yaml`, sorted; none without the directory.
fn workflow_files(root: &Path) -> Result<Vec<String>> {
    const DIR: &str = ".github/workflows";
    let dir = crate::directory(root, DIR)?;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type()?.is_file() && (name.ends_with(".yml") || name.ends_with(".yaml")) {
            files.push(format!("{DIR}/{name}"));
        }
    }
    files.sort();
    Ok(files)
}

/// True when `path` is an `.env*` file or git ignores it; a `git` failure counts
/// as ignored, so doubt never turns into evidence. `git check-ignore` reads the
/// local ignore rules only.
fn ignored(root: &Path, path: &str) -> bool {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned());
    if name.is_some_and(|n| n.starts_with(".env")) {
        return true;
    }
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["check-ignore", "-q", "--", path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_or(true, |status| status.code() != Some(1))
}

/// What `configure <repo> <module>` with this patch plans (the questions driver,
/// the patch as its highest layer), the merged answers and the token that binds
/// them to this plan in this process. Asks nothing: an open question refuses.
struct Shown {
    planned: engine::Planned,
    merged: Answers,
    token: String,
}

fn shown(server: &Server, id: &str, root: &Path, patch: &Answers) -> Result<Shown> {
    module(server, id)?;
    let inputs = questions::Inputs {
        interactive: Some(patch.clone()),
        ..questions::Inputs::default()
    };
    let profile = crate::profile_for(root)?;
    let configured = questions::configure(
        root,
        &server.source,
        &profile,
        &server.modules,
        &crate::known_path,
        id,
        &inputs,
    )?;
    let planned = configured.planned;
    let merged = match planned.changes.get(&answers::path(id)) {
        Some(Some(text)) => answers::AnswersFile::parse(id, text)?.answers,
        _ => answers::recorded(root, id)?
            .map(|f| f.answers)
            .unwrap_or_default(),
    };
    let lines = crate::plan_lines(&planned, false);
    let plan_digest = crate::digest(&serde_json::to_string(&json!({
        "changes": planned.changes, "lines": lines,
    }))?);
    let token = super::confirmation_token(
        &server.nonce,
        &root.to_string_lossy(),
        id,
        &serde_json::to_string(&merged)?,
        &plan_digest,
    );
    Ok(Shown {
        planned,
        merged,
        token,
    })
}

/// `plan`: the questions the patch leaves open asked in the client first
/// (`elicit::complete`), then the plan, its steps, the merged answers and the
/// confirmation token. Writes nothing.
fn plan(
    server: &Server,
    client: &mut dyn Client,
    id: &str,
    root: &Path,
    patch: &Answers,
) -> Result<Value> {
    let schema = module(server, id)?.questions();
    schema.check(id)?;
    let (_, tier) = questions::open_questions(root, &schema, id, patch)?;
    let open = |patch: &Answers| Ok(questions::open_questions(root, &schema, id, patch)?.0);
    let patch = elicit::complete(client, &server.peer, id, &schema, &tier, patch, &open)?;
    let shown = shown(server, id, root, &patch)?;
    Ok(json!({
        "lines": crate::plan_lines(&shown.planned, false),
        "steps": shown.planned.steps,
        "answers": shown.merged,
        "confirmation_token": shown.token,
    }))
}

/// The refusal of `apply` to a client that cannot show the confirmation.
pub const NO_ELICITATION: &str =
    "apply needs a client with elicitation; run `brakes configure --apply` yourself";

/// `apply`: refused without form elicitation; otherwise the plan is computed
/// again and refused unless `token` is the one `plan` returned for it, then the
/// human confirms its summary in the client and the engine's local changes are
/// written, exactly as `configure --apply` writes them.
fn apply(
    server: &Server,
    client: &mut dyn Client,
    id: &str,
    root: &Path,
    patch: &Answers,
    token: &str,
) -> Result<Value> {
    if !server.peer.elicitation {
        return refuse(NO_ELICITATION);
    }
    let shown = shown(server, id, root, patch)?;
    if shown.token != token {
        return refuse(
            "the confirmation token does not match the plan for these answers in this repository; call plan again and review it",
        );
    }
    let planned = &shown.planned;
    let seeds = planned
        .changes
        .keys()
        .filter(|path| matches!(planned.tags.get(*path), Some((Ownership::Seed, _))))
        .count();
    let message = format!(
        "brakes: apply this plan for {id} to {}? {} writes, {seeds} seeds, {} steps, token {token}.\n\n{}",
        root.display(),
        planned.changes.len() - seeds,
        planned.steps.len(),
        crate::plan_lines(planned, false).join("\n"),
    );
    elicit::confirm(client, &server.peer, &message)?;
    crate::apply(root, &planned.changes)?;
    Ok(json!({
        "lines": crate::plan_lines(planned, true),
        "steps": planned.steps,
    }))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn every_listed_tool_has_a_name_in_names_and_an_object_schema() {
        let listed = list();
        let names: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, NAMES);
        for tool in listed.as_array().unwrap() {
            assert_eq!(tool["inputSchema"]["type"], "object");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
    }

    #[test]
    fn when_is_written_back_as_the_specs_write_it() {
        for text in ["tiers", "!macos", "workflow == existing", "a != b"] {
            assert_eq!(when_text(&text.parse().unwrap()), text);
        }
    }
}
