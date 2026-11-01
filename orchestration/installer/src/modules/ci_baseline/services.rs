//! Services a declared command needs (SPEC-ci-baseline.md, #1170): the
//! `ci.services` and `ci.env` an app's profile declares, read at render time
//! and rendered as the `services:` and `env:` of every generated job that runs
//! that app's commands, in this module and in `security`. Declared, never
//! invented: an image is pinned by digest, a value is a literal, and nothing
//! is read from the network.
use crate::{Result, engine::Context, modules::stack_packs::App, refuse};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// One service container.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Service {
    pub image: String,
    pub env: BTreeMap<String, String>,
    pub ports: Vec<String>,
    pub health_cmd: Option<String>,
}

/// What a job gets: its service containers and its environment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Services {
    pub services: BTreeMap<String, Service>,
    pub env: BTreeMap<String, String>,
}

impl Services {
    pub fn is_empty(&self) -> bool {
        self.services.is_empty() && self.env.is_empty()
    }
}

/// The profile file that declares the commands of the app at `path` (Decision 8).
pub fn profile_path(path: &str) -> String {
    if path == "." {
        ".agent-setup/project.json".to_owned()
    } else {
        format!("{}/.agent-setup/project.json", path.trim_end_matches('/'))
    }
}

/// The declaration of the root profile, the one `checks` runs.
pub fn of_root(cx: &Context<'_>) -> Result<Services> {
    declared(&cx.profile.value, ".agent-setup/project.json")
}

/// The declaration of an app's profile; an absent or unreadable profile
/// declares nothing here (the job's own refusal names it).
pub fn of_app(cx: &Context<'_>, app: &App) -> Result<Services> {
    of_dir(cx, &app.path)
}

/// The declaration of the profile of the app at `dir`.
pub fn of_dir(cx: &Context<'_>, dir: &str) -> Result<Services> {
    if dir == "." {
        return of_root(cx);
    }
    let path = profile_path(dir);
    let Some(text) = crate::read(cx.root, &path)? else {
        return Ok(Services::default());
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(profile) => declared(&profile, &path),
        Err(_) => Ok(Services::default()),
    }
}

/// The union for a job that runs several apps; a name declared differently
/// by two of them refuses.
pub fn of_apps<'a>(cx: &Context<'_>, apps: impl IntoIterator<Item = &'a App>) -> Result<Services> {
    let mut all = Services::default();
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for app in apps {
        let one = of_app(cx, app)?;
        for (name, service) in one.services {
            let key = format!("ci.services.{name}");
            merge(&mut all.services, &mut owner, key, name, service, &app.id)?;
        }
        for (name, value) in one.env {
            let key = format!("ci.env.{name}");
            merge(&mut all.env, &mut owner, key, name, value, &app.id)?;
        }
    }
    Ok(all)
}

fn merge<T: PartialEq>(
    into: &mut BTreeMap<String, T>,
    owner: &mut BTreeMap<String, String>,
    key: String,
    name: String,
    value: T,
    app: &str,
) -> Result<()> {
    match into.get(&name) {
        Some(existing) if *existing != value => refuse(format!(
            "ci-baseline: apps {} and {app} declare {key} differently; a job that runs both needs one value",
            owner[&key]
        )),
        Some(_) => Ok(()),
        None => {
            owner.insert(key, app.to_owned());
            into.insert(name, value);
            Ok(())
        }
    }
}

fn is_service_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_variable(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_port(port: &str) -> bool {
    let digits = |p: &str| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit());
    match port.split_once(':') {
        Some((host, container)) => digits(host) && digits(container),
        None => digits(port),
    }
}

fn is_pinned(image: &str) -> bool {
    image.split_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty()
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn bad(key: &str, path: &str) -> Result<Services> {
    refuse(format!(
        "ci-baseline: {key} in {path} is not a valid declaration; see SPEC-ci-baseline.md, \"Services a declared command needs\""
    ))
}

/// A literal value, or the refusal naming its key.
fn literal(value: &Value, key: &str, path: &str) -> Result<Option<String>> {
    let Some(text) = value.as_str() else {
        return Ok(None);
    };
    if text.contains("${{") {
        return refuse(format!(
            "ci-baseline: {key} in {path} holds an expression; ci.services and ci.env take literal values, never a secret"
        ));
    }
    Ok(Some(text.to_owned()))
}

/// A string map of literals under `key`, or `None` when it is not one.
fn literals(value: &Value, key: &str, path: &str) -> Result<Option<BTreeMap<String, String>>> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let mut out = BTreeMap::new();
    for (name, v) in object {
        let entry = format!("{key}.{name}");
        if !is_variable(name) {
            return Ok(None);
        }
        let Some(text) = literal(v, &entry, path)? else {
            return Ok(None);
        };
        out.insert(name.clone(), text);
    }
    Ok(Some(out))
}

/// `ci.services` and `ci.env` of one profile, validated.
pub fn declared(profile: &Value, path: &str) -> Result<Services> {
    let ci = &profile["ci"];
    let mut out = Services::default();
    match &ci["services"] {
        Value::Null => {}
        Value::Object(services) => {
            for (name, spec) in services {
                let key = format!("ci.services.{name}");
                if !is_service_name(name) || !spec.is_object() {
                    return bad(&key, path);
                }
                let Some(image) = literal(&spec["image"], &format!("{key}.image"), path)? else {
                    return bad(&format!("{key}.image"), path);
                };
                if !is_pinned(&image) {
                    return refuse(format!(
                        "ci-baseline: service {name} in {path} is not pinned by digest: {image}; declare {image}@sha256:<digest>"
                    ));
                }
                let env = match &spec["env"] {
                    Value::Null => BTreeMap::new(),
                    v => match literals(v, &format!("{key}.env"), path)? {
                        Some(env) => env,
                        None => return bad(&format!("{key}.env"), path),
                    },
                };
                let ports = match &spec["ports"] {
                    Value::Null => Vec::new(),
                    Value::Array(ports) => {
                        let ports: Vec<String> = ports
                            .iter()
                            .filter_map(Value::as_str)
                            .filter(|p| is_port(p))
                            .map(str::to_owned)
                            .collect();
                        if ports.len() != spec["ports"].as_array().map_or(0, Vec::len) {
                            return bad(&format!("{key}.ports"), path);
                        }
                        ports
                    }
                    _ => return bad(&format!("{key}.ports"), path),
                };
                let health_cmd = match &spec["health_cmd"] {
                    Value::Null => None,
                    v => match literal(v, &format!("{key}.health_cmd"), path)? {
                        Some(cmd) if !cmd.is_empty() && !cmd.contains(['"', '\n', '\r']) => {
                            Some(cmd)
                        }
                        _ => return bad(&format!("{key}.health_cmd"), path),
                    },
                };
                out.services.insert(
                    name.clone(),
                    Service {
                        image,
                        env,
                        ports,
                        health_cmd,
                    },
                );
            }
        }
        _ => return bad("ci.services", path),
    }
    match &ci["env"] {
        Value::Null => {}
        v => match literals(v, "ci.env", path)? {
            Some(env) => out.env = env,
            None => return bad("ci.env", path),
        },
    }
    Ok(out)
}

/// A YAML double-quoted scalar: JSON's string escapes are YAML's, control
/// characters included, so no value can end the line it is written on.
fn quoted(text: &str) -> String {
    Value::String(text.to_owned()).to_string()
}

/// The job keys, at indent 0: `services:` then `env:`, each only when declared.
pub fn yaml(services: &Services) -> String {
    let mut out = String::new();
    if !services.services.is_empty() {
        out.push_str("services:\n");
        for (name, service) in &services.services {
            let _ = writeln!(out, "  {name}:");
            let _ = writeln!(out, "    image: {}", quoted(&service.image));
            if !service.env.is_empty() {
                out.push_str("    env:\n");
                for (k, v) in &service.env {
                    let _ = writeln!(out, "      {k}: {}", quoted(v));
                }
            }
            if !service.ports.is_empty() {
                out.push_str("    ports:\n");
                for port in &service.ports {
                    let _ = writeln!(out, "      - {}", quoted(port));
                }
            }
            if let Some(cmd) = &service.health_cmd {
                let options = format!(
                    "--health-cmd \"{cmd}\" --health-interval 5s --health-timeout 5s --health-retries 20"
                );
                let _ = writeln!(out, "    options: {}", quoted(&options));
            }
        }
    }
    if !services.env.is_empty() {
        out.push_str("env:\n");
        for (k, v) in &services.env {
            let _ = writeln!(out, "  {k}: {}", quoted(v));
        }
    }
    out
}

/// A contributed job's YAML (indent 0) with the keys inserted after its
/// `timeout-minutes:` line; unchanged when nothing is declared.
pub fn into_job(job_yaml: &str, services: &Services) -> String {
    if services.is_empty() {
        return job_yaml.to_owned();
    }
    let block = yaml(services);
    let mut out = String::with_capacity(job_yaml.len() + block.len());
    let mut done = false;
    for line in job_yaml.split_inclusive('\n') {
        out.push_str(line);
        if !done && line.starts_with("timeout-minutes:") {
            out.push_str(&block);
            done = true;
        }
    }
    out
}

/// The jobs of the workflows the installer does not own that start services,
/// as plan notes, when no profile of the plan declares any (#1170): evidence
/// the person turns into a declaration; nothing is copied.
pub fn evidence_notes(
    cx: &Context<'_>,
    foreign: &[String],
    app_dirs: &[String],
) -> Result<Vec<String>> {
    for dir in app_dirs {
        if !of_dir(cx, dir)?.services.is_empty() {
            return Ok(Vec::new());
        }
    }
    if !of_root(cx)?.services.is_empty() {
        return Ok(Vec::new());
    }
    let profile = match app_dirs {
        [one] => profile_path(one),
        _ => "the profile of the app whose command needs them".to_owned(),
    };
    let mut notes = Vec::new();
    for path in foreign {
        let Some(text) = crate::read(cx.root, path)? else {
            continue;
        };
        let Ok(docs) = yaml_rust2::YamlLoader::load_from_str(&text) else {
            continue;
        };
        let Some(jobs) = docs.first().and_then(|d| d["jobs"].as_hash()) else {
            continue;
        };
        for (id, job) in jobs {
            let Some(services) = job["services"].as_hash() else {
                continue;
            };
            let names: Vec<&str> = services.keys().filter_map(|k| k.as_str()).collect();
            if let (Some(id), false) = (id.as_str(), names.is_empty()) {
                notes.push(format!(
                    "{path} job {id} starts services ({}); declare what the generated jobs need under ci.services in {profile}",
                    names.join(", ")
                ));
            }
        }
    }
    Ok(notes)
}
