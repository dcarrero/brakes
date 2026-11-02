use brakes::{
    Result, Source, apply, auditor, diagnose_at, diagnose_with, doctor_audit_json,
    engine::Planned,
    guard,
    host::{CallBudget, RepoId, github::GitHub, probes::HostRunner},
    modules, personal_scope, questions, read_scope, refuse, remote,
};
use std::{io::IsTerminal, path::PathBuf, process::ExitCode};

const USAGE: &str = "Usage: brakes <install|doctor> <project> [--apply] [--new-personal] [--source <checkout>] [--module <id>]... [--profile P1|P2|P3] [--preset <name>] [--answers <file.json>]... [--no-input] [--remote] [--json] [--propose] [--now <YYYY-MM-DD>] [--report <file.md>]\n       brakes doctor --fleet <org-or-user> [--json] [--report <file.md>] [--include-archived] [--now <YYYY-MM-DD>] [--publish-issue <owner/repo>]\n       brakes adopt <project> [--apply] [--json]\n       brakes configure <project> <module-id> [--set key=value]... [--answers <file.json>]... [--preset <name>] [--interactive | --no-input] [--apply]\n       brakes configure <project> stack-packs --accept-commands [<app-id>] [--apply]\n       brakes ci init <project> [--answers <file.json>]... [--no-input] [--apply]\n       brakes presets [<module-id>] [--source <checkout>]\n       brakes mcp\n       brakes remove <project> <module-id> [--apply]\n       brakes apply <project> [--remote]\n       brakes guard pre-bash\n       brakes host features <owner/repo> [--json]\n       brakes host repos <owner> [--json] [--call-budget <n>]\n       brakes host org <org> [--json]\n       brakes host probe <owner/repo> <probe-id> [--arg key=value]... [--json]\n       Any command: --config <file.json> (the configuration; one embedded at build time wins)";
/// `--config <file.json>` anywhere: the explicit lookup step, installed before any
/// command reads the configuration (src/config.rs), and removed from `args`. Every
/// command takes it, those `main` dispatches early included (#1311).
fn install_config(args: &mut Vec<std::ffi::OsString>) -> Result<()> {
    if let Some(at) = args.iter().position(|a| a == "--config") {
        let Some(path) = args.get(at + 1).cloned() else {
            return refuse("--config needs a file");
        };
        args.drain(at..=at + 1);
        brakes::config::install_from(std::path::Path::new(&path))?;
    }
    Ok(())
}

fn run(raw: Vec<std::ffi::OsString>) -> Result<u8> {
    let mut args = raw.into_iter();
    let mut operation = None;
    let mut project = None;
    let mut module_id: Option<String> = None;
    let mut requested: Vec<String> = Vec::new();
    let mut source = None;
    let mut inputs = questions::Inputs::default();
    let mut apply_changes = false;
    let mut new_personal = false;
    let mut check_remote = false;
    let mut json = false;
    let mut propose = false;
    let mut now = None;
    let mut report = None;
    let mut tier: Option<String> = None;
    // `--accept-commands [<app-id>]`: `Some(None)` names the root app.
    let mut accept: Option<Option<String>> = None;
    let mut interactive = false;
    let mut no_input = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => {
                println!("{USAGE}");
                return Ok(0);
            }
            Some("--version") => {
                println!("brakes {}", include_str!("../../../VERSION").trim());
                return Ok(0);
            }
            Some("--apply") => apply_changes = true,
            Some("--interactive") => interactive = true,
            Some("--no-input") => no_input = true,
            Some("--new-personal") => new_personal = true,
            Some("--remote") => check_remote = true,
            Some("--json") => json = true,
            Some("--propose") => propose = true,
            Some("--accept-commands") => accept = Some(None),
            Some("--now") => {
                let date = args.next().and_then(|s| s.into_string().ok());
                now = Some(
                    date.as_deref()
                        .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
                        .ok_or("--now needs a YYYY-MM-DD date")?,
                )
            }
            Some("--report") => {
                report = Some(PathBuf::from(args.next().ok_or("--report needs a file")?))
            }
            // The fleet report's only write needs `--fleet` (#736).
            Some("--publish-issue") => {
                return Err("--publish-issue is only available with doctor --fleet".into());
            }
            Some("--source") => {
                source = Some(PathBuf::from(
                    args.next().ok_or("--source needs a checkout")?,
                ))
            }
            Some("--module") => requested.push(
                args.next()
                    .and_then(|s| s.into_string().ok())
                    .ok_or("--module needs a module id")?,
            ),
            Some("--profile") => {
                tier = Some(
                    args.next()
                        .and_then(|s| s.into_string().ok())
                        .ok_or("--profile needs P1, P2 or P3")?,
                )
            }
            Some("--set") => inputs.sets.push(
                args.next()
                    .and_then(|s| s.into_string().ok())
                    .ok_or("--set needs key=value")?,
            ),
            Some("--preset") => {
                inputs.preset = Some(
                    args.next()
                        .and_then(|s| s.into_string().ok())
                        .ok_or("--preset needs a preset name")?,
                )
            }
            Some("--answers") => inputs
                .files
                .push(PathBuf::from(args.next().ok_or("--answers needs a file")?)),
            Some(s) if s.starts_with('-') => return refuse(USAGE),
            Some("install" | "doctor" | "configure" | "remove" | "apply")
                if operation.is_none() =>
            {
                operation = Some(arg)
            }
            _ if operation.is_none() => return refuse(USAGE),
            _ if project.is_none() => project = Some(PathBuf::from(arg)),
            Some(id)
                if operation
                    .as_ref()
                    .is_some_and(|o| o == "configure" || o == "remove")
                    && module_id.is_none() =>
            {
                module_id = Some(id.to_owned())
            }
            Some(id) if accept == Some(None) && module_id.is_some() => {
                accept = Some(Some(id.to_owned()))
            }
            _ => return refuse(USAGE),
        }
    }
    let operation = operation.ok_or(USAGE)?;
    if check_remote && operation != "doctor" && operation != "apply" {
        return refuse("--remote is only available with doctor and apply");
    }
    if json && operation != "doctor" {
        return refuse("--json is only available with doctor");
    }
    if propose && operation != "doctor" {
        return refuse("--propose is only available with doctor");
    }
    if (now.is_some() || report.is_some()) && operation != "doctor" {
        return refuse("--now and --report are only available with doctor");
    }
    if !inputs.sets.is_empty() && operation != "configure" {
        return refuse("--set is only available with configure");
    }
    if (inputs.preset.is_some() || !inputs.files.is_empty())
        && operation != "configure"
        && operation != "install"
    {
        return refuse("--preset and --answers are only available with configure and install");
    }
    if interactive && operation != "configure" {
        return refuse("--interactive is only available with configure");
    }
    // `install` never prompts; `--no-input` states it (SPEC-questions.md, Commands).
    if no_input && operation != "configure" && operation != "install" {
        return refuse("--no-input is only available with configure and install");
    }
    if interactive && no_input {
        return refuse("--interactive and --no-input cannot be combined");
    }
    if !requested.is_empty() && operation != "install" {
        return refuse("--module is only available with install");
    }
    // The profile is recorded with the answers of the requested modules.
    if tier.is_some() && (operation != "install" || requested.is_empty()) {
        return refuse("--profile is only available with install --module");
    }
    if accept.is_some()
        && (operation != "configure"
            || module_id.as_deref() != Some(modules::stack_packs::STACK_PACKS)
            || inputs != questions::Inputs::default())
    {
        return refuse(
            "--accept-commands is only available with configure <project> stack-packs, without --set, --answers or --preset",
        );
    }
    // `--accept-commands` asks nothing: it prints a diff and writes on `--apply`.
    if accept.is_some() && (interactive || no_input) {
        return refuse("--accept-commands cannot be combined with --interactive or --no-input");
    }
    if operation == "apply" && (apply_changes || new_personal || source.is_some()) {
        return refuse("apply takes only <project>; it reads the remote items and writes nothing");
    }
    let project = project.ok_or(USAGE)?;
    // A local read (doctor, and the plan of install, configure and remove) needs only
    // the read scope, so it runs without a configuration (#1259). Whatever writes, or
    // reads the remote with the user's credentials, passes the write scope first.
    let root = if apply_changes || operation == "apply" || check_remote {
        personal_scope(&project, new_personal)?
    } else {
        read_scope(&project)?
    };
    if operation == "apply" {
        // The read-only REMOTE diff (#901): the origin repository's state through
        // host-adapter's probes, behind the read gate; no WriteToken is minted.
        let repo = RepoId::parse(&remote::repository(&root)?)?;
        // `--remote` (#903): the token is minted before any `gh` process, so the
        // allowlist and denylist refusals stand unchanged.
        let token = check_remote
            .then(|| brakes::host::authorize::write(&repo, true))
            .transpose()?;
        let gh = remote::Gh::default();
        let host = GitHub::new(&gh, CallBudget::default());
        if let Some(token) = token {
            let applied = brakes::apply_remote::apply_remote(
                &root,
                &Source::embedded(),
                &modules::all(),
                &HostRunner::new(&host, repo),
                &brakes::apply_remote::HostWriter::new(&host, token),
            )?;
            for line in &applied.lines {
                println!("{line}");
            }
            println!("{}", applied.closing);
            return Ok(if applied.verified { 0 } else { 1 });
        }
        let diff = brakes::apply_remote::remote_plan(
            &root,
            &Source::embedded(),
            &modules::all(),
            &HostRunner::new(&host, repo),
        )?;
        for line in &diff {
            println!("{}", line.line());
        }
        println!("{}", brakes::apply_remote::closing(&diff));
        return Ok(0);
    }
    if operation == "doctor" {
        let now = now.unwrap_or_else(brakes::today);
        let mut mode_line = None;
        // The protection read once, for the mode line and the rule object.
        let mut probed = None;
        let gh = remote::Gh::default();
        let repository = check_remote.then(|| remote::repository(&root));
        // With `--remote`, manual steps' remote probes run through the host
        // adapter for the origin repository (#683); otherwise they are unavailable.
        let probes_host = GitHub::new(&gh, CallBudget::default());
        let mut diagnosis = match repository
            .as_ref()
            .and_then(|r| r.as_deref().ok())
            .map(RepoId::parse)
        {
            Some(Ok(repo)) => diagnose_with(
                &root,
                now,
                &Source::embedded(),
                &modules::all(),
                &HostRunner::new(&probes_host, repo),
            )?,
            _ => diagnose_at(&root, now)?,
        };
        let mut remote_ok = false;
        let remote_report = if let Some(repository) = repository {
            let ci = brakes::profile_for(&root)?.value["ci"].clone();
            match repository {
                Ok(repository) => {
                    remote_ok = true;
                    let protection = guard::doctor::probe(&gh, &repository);
                    mode_line = Some(guard::doctor::line(&repository, &protection));
                    probed = Some((
                        repository.clone(),
                        protection,
                        chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now())
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ));
                    // #1109: with ci-baseline installed, what it renders, never the retired keys.
                    match remote::policy_for(&root, &ci)? {
                        Some(rendered) => remote::inspect_policy(
                            &gh,
                            &repository,
                            &remote::Policy::CiBaseline(rendered),
                        ),
                        None => remote::inspect_report(&gh, &repository, &ci),
                    }
                }
                Err(_) => remote::Report {
                    findings: vec![
                        "Remote diagnosis needs an unambiguous GitHub origin repository."
                            .to_owned(),
                    ],
                    note: None,
                },
            }
        } else {
            remote::Report {
                findings: Vec::new(),
                note: None,
            }
        };
        let suppress_incomplete = remote_report
            .note
            .as_ref()
            .is_some_and(|n| n.contains("en curso"));
        diagnosis
            .findings
            .extend(remote_report.findings.iter().cloned());
        let not_ready = !diagnosis.ready();
        // The lines as printed: today's prefixes, incomplete ones hidden while a
        // remote diagnosis is in progress. `--json` emits them instead of printing.
        let printed: Vec<String> = diagnosis
            .printed_findings()
            .into_iter()
            .filter(|line| !(suppress_incomplete && line.contains("incomplete")))
            .collect();
        // The project's CI, audited with the patches it would take (#23); read only.
        let proposals = brakes::auditor::ci_audit::proposals(&root);
        // The audit: `GitHub` over the same `gh` with `--remote`, offline without
        // it. Computed before printing, so a refusal leaves no partial output.
        let identity = auditor::checkout_identity(&root);
        // The baseline block re-labels today's findings and steps (#730).
        let today = auditor::Today {
            findings: &diagnosis.findings,
            steps: &diagnosis.steps,
            remote: check_remote,
        };
        let audited = if remote_ok {
            let host = GitHub::new(&gh, CallBudget::new(auditor::CALL_BUDGET));
            auditor::audit_checkout(&root, &host, host.budget(), &identity, now, true, &today)?
        } else {
            let budget = CallBudget::new(auditor::CALL_BUDGET);
            auditor::audit_checkout(
                &root,
                &auditor::offline_host(),
                &budget,
                &identity,
                now,
                false,
                &today,
            )?
        };
        if let Some(path) = &report {
            std::fs::write(path, audited.markdown())?;
        }
        let code = u8::try_from(audited.exit_code(!not_ready))?;
        if json {
            let mut extra = audited.json();
            // The project's CI audit with its patches (#23): only with `--propose`.
            if propose {
                extra.insert("proposals".to_owned(), ci_proposals_json(&proposals));
            }
            // Declared exclusions (#1171): present only when there is one.
            if !diagnosis.excluded.is_empty() {
                extra.insert("excluded".to_owned(), serde_json::json!(diagnosis.excluded));
            }
            // The merge-guard rule object where the module is installed (#696).
            if diagnosis
                .modules
                .iter()
                .any(|(id, _)| id == modules::merge_guard::MERGE_GUARD)
            {
                let repository = probed
                    .as_ref()
                    .map(|(r, _, _)| r.clone())
                    .or_else(|| brakes::engine::repository(&root));
                let remote = probed.as_ref().map(|(_, p, at)| (p, at.as_str()));
                extra.insert(
                    "merge_guard".to_owned(),
                    guard::doctor::rule(&root, repository.as_deref(), remote)?,
                );
            }
            print!(
                "{}",
                doctor_audit_json(
                    !not_ready,
                    &printed,
                    &diagnosis.steps,
                    &diagnosis.modules,
                    Some(&extra)
                )?
            );
            return Ok(code);
        }
        for line in &printed {
            println!("{line}");
        }
        // Manual steps are the owner's work: listed with their state, never a finding.
        for step in &diagnosis.steps {
            println!("{}", step.doctor_line());
        }
        // A declared exclusion is information, never a finding (#1171).
        for line in &diagnosis.excluded {
            println!("{line}");
        }
        // The merge-guard mode is information, never a finding: it cannot fail readiness.
        if let Some(line) = &mode_line {
            println!("{line}");
        }
        if let Some(note) = &remote_report.note {
            println!("{note}");
        }
        // The CI audit is proposals, never a finding: it cannot fail readiness (#23).
        print!(
            "{}",
            ci_proposals_text(&proposals, propose, &project.display().to_string())
        );
        if !not_ready {
            println!("Configuration ready. Runtime/agent behavior has not been verified.");
        }
        for line in audited.lines() {
            println!("{line}");
        }
        return Ok(code);
    }
    // Writes only `null` `commands.*` of the app's profile, diff first (decision
    // 2026-10-28, point 8); the engine plan is not involved.
    if let Some(app) = &accept {
        let accepted = modules::stack_packs::detect::accept_commands(&root, app.as_deref())?;
        print!("{}", accepted.diff());
        let changed = accepted.changed();
        if changed {
            println!(
                "{} {}",
                if apply_changes { "WRITE" } else { "PLAN" },
                accepted.path
            );
        }
        if changed && apply_changes {
            apply(&root, &[(accepted.path, Some(accepted.after))].into())?;
        }
        println!("{}", outcome(changed, apply_changes));
        return Ok(0);
    }
    inputs.catalogue = source.clone();
    let source = source
        .as_deref()
        .map(Source::checkout)
        .transpose()?
        .unwrap_or_else(Source::embedded);
    // `configure <repo> stack-packs` with no answers given prints what detection
    // proposes after the plan; it never reaches a file (SPEC-stack-packs.md).
    // Computed first, so a detection refusal stops before anything is applied.
    let proposals = (operation == "configure"
        && module_id.as_deref() == Some(modules::stack_packs::STACK_PACKS)
        && inputs.sets.is_empty()
        && inputs.files.is_empty()
        && inputs.preset.is_none())
    .then(|| modules::stack_packs::detect::proposal_block(&root))
    .transpose()?;
    let planned = if operation == "configure" {
        // The questions driver merges recorded < default < preset < file < --set <
        // interactive and ends in the engine; its provenance line precedes the
        // plan and reaches no file. A run asks only on a terminal (or with
        // `--interactive`, the test hook) and never with `--no-input`; otherwise
        // stdin is never read.
        let module_id = module_id.ok_or(USAGE)?;
        let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        if interactive || (terminal && !no_input) {
            let asked = brakes::interview(
                &root,
                &source,
                &module_id,
                &inputs,
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
            )?;
            inputs.interactive = Some(asked);
        }
        let configured = brakes::configure(&root, &source, &module_id, &inputs)?;
        println!("{}", configured.provenance);
        for note in &configured.notes {
            println!("{note}");
        }
        configured.planned
    } else if operation == "remove" {
        // The plan is shown first, as for every command; `--apply` writes it.
        brakes::remove(&root, &module_id.ok_or(USAGE)?)?
    } else {
        // `--preset` and `--answers` configure each installed module with a
        // section first; their provenance lines and notes precede the plan.
        let requested: Vec<&str> = requested.iter().map(String::as_str).collect();
        let installed = brakes::install(&root, &source, &requested, tier.as_deref(), &inputs)?;
        for line in installed.provenance.iter().chain(&installed.notes) {
            println!("{line}");
        }
        installed.planned
    };
    print_plan(&planned, apply_changes);
    if apply_changes {
        apply(&root, &planned.changes)?;
    }
    println!("{}", outcome(!planned.changes.is_empty(), apply_changes));
    if let Some(block) = &proposals {
        print!("{block}");
    }
    Ok(0)
}

/// `brakes ci init <project> [--answers <file.json>]... [--no-input] [--apply]`:
/// the steps, the plan of the profiles and modules it sets up, and what comes
/// next. It asks on a terminal (or with `--interactive`, the test hook) and never
/// with `--no-input`. Every write passes the write scope and `apply`.
fn ci_cli(args: &[std::ffi::OsString]) -> Result<u8> {
    const CI_USAGE: &str =
        "Usage: brakes ci init <project> [--answers <file.json>]... [--no-input] [--apply]";
    let mut args = args.iter();
    if args.next().and_then(|a| a.to_str()) != Some("init") {
        return refuse(CI_USAGE);
    }
    let (mut project, mut files) = (None, Vec::new());
    let (mut apply_changes, mut no_input, mut interactive) = (false, false, false);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--apply") => apply_changes = true,
            Some("--no-input") => no_input = true,
            Some("--interactive") => interactive = true,
            Some("--answers") => {
                files.push(PathBuf::from(args.next().ok_or("--answers needs a file")?))
            }
            Some(s) if s.starts_with('-') => return refuse(CI_USAGE),
            _ if project.is_none() => project = Some(PathBuf::from(arg)),
            _ => return refuse(CI_USAGE),
        }
    }
    if interactive && no_input {
        return refuse("--interactive and --no-input cannot be combined");
    }
    let project = project.ok_or(CI_USAGE)?;
    let root = if apply_changes {
        personal_scope(&project, false)?
    } else {
        read_scope(&project)?
    };
    let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let (mut input, mut output) = (std::io::stdin().lock(), std::io::stdout());
    let mut asker = if interactive || (terminal && !no_input) {
        brakes::ci_init::Asker::Prompt(&mut input, &mut output)
    } else {
        brakes::ci_init::Asker::NoInput
    };
    let source = Source::embedded();
    let setup = brakes::ci_init::run(&root, &files, &mut asker)?;
    // Planned before anything is written, so a refusal leaves the tree as it was.
    let planned = brakes::ci_init::plan(&root, &source, &setup, false)?;
    if interactive {
        println!();
    }
    for line in &setup.steps {
        println!("{line}");
    }
    if apply_changes {
        // The profiles first, so the plan below reads the commands it seeds
        // from disk, as every later install does.
        let profiles: brakes::Plan = setup
            .profiles
            .iter()
            .map(|(path, text)| (path.clone(), Some(text.clone())))
            .collect();
        for path in profiles.keys() {
            println!("WRITE {path}");
        }
        apply(&root, &profiles)?;
        let planned = brakes::ci_init::plan(&root, &source, &setup, true)?;
        print_plan(&planned, true);
        apply(&root, &planned.changes)?;
        println!("{}", outcome(true, true));
        for line in &setup.next {
            println!("{line}");
        }
        return Ok(0);
    }
    for path in setup.profiles.keys() {
        println!("PLAN {path}");
    }
    print_plan(&planned, false);
    println!(
        "{}",
        outcome(
            !planned.changes.is_empty() || !setup.profiles.is_empty(),
            false
        )
    );
    for line in &setup.next {
        println!("{line}");
    }
    Ok(0)
}

/// The closing line of a plan.
/// The CI audit as `doctor` prints it (#23): every finding with its diff under
/// `--propose`, else one line with the count; nothing when there is none.
fn ci_proposals_text(
    proposals: &[brakes::auditor::ci_audit::Proposal],
    propose: bool,
    project: &str,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if proposals.is_empty() {
        return out;
    }
    if !propose {
        let (noun, pronoun) = if proposals.len() == 1 {
            ("finding", "it")
        } else {
            ("findings", "them")
        };
        let _ = writeln!(
            out,
            "PROPOSE {} {noun} on the project's CI: brakes doctor {project} --propose prints {pronoun} with the patches; nothing is applied",
            proposals.len()
        );
        return out;
    }
    for p in proposals {
        let _ = writeln!(out, "PROPOSE {} {}: {}", p.rule, p.file, p.text);
        match &p.patch {
            Some(patch) => out.push_str(&patch.diff),
            None => out.push_str("  (no patch: change it by hand)\n"),
        }
    }
    out.push_str(
        "Nothing was written. Apply a patch on a branch and merge it through a pull request labelled human-approved: .github/workflows/ is a protected path.\n",
    );
    out
}

fn ci_proposals_json(proposals: &[brakes::auditor::ci_audit::Proposal]) -> serde_json::Value {
    serde_json::Value::Array(
        proposals
            .iter()
            .map(|p| {
                serde_json::json!({
                    "rule": p.rule,
                    "file": p.file,
                    "text": p.text,
                    "diff": p.patch.as_ref().map(|patch| patch.diff.clone()),
                })
            })
            .collect(),
    )
}

fn outcome(changed: bool, apply_changes: bool) -> &'static str {
    if !changed {
        "No changes."
    } else if apply_changes {
        "Applied; fill/review project profile and run doctor."
    } else {
        "Plan only; no writes. Review before using --apply."
    }
}

/// The plan lines (`brakes::plan_lines`), printed.
fn print_plan(planned: &Planned, apply_changes: bool) {
    for line in brakes::plan_lines(planned, apply_changes) {
        println!("{line}");
    }
}
fn main() -> ExitCode {
    // The merge-guard hook runs in any directory, read-only, and answers with
    // JSON: dispatched before the project-scope parsing of `run`.
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if let Err(error) = install_config(&mut args) {
        eprintln!("REFUSED: {error}");
        return ExitCode::from(2);
    }
    if args.first().is_some_and(|a| a == "guard") {
        return brakes::guard::cli(&args[1..]);
    }
    if args.first().is_some_and(|a| a == "host") {
        return brakes::host::cli::cli(&args[1..]);
    }
    // `doctor --fleet` takes no checkout: read-only over an owner (#734).
    if args.first().is_some_and(|a| a == "doctor") && args.iter().any(|a| a == "--fleet") {
        return auditor::fleet::cli(&args[1..]);
    }
    // `adopt` plans for an unmanaged repository and writes nothing (#738).
    if args.first().is_some_and(|a| a == "adopt") {
        return auditor::adopt::cli(&args[1..]);
    }
    // The guided setup of a repository without CI (#24).
    if args.first().is_some_and(|a| a == "ci") {
        return match ci_cli(&args[1..]) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("REFUSED: {error}");
                ExitCode::from(2)
            }
        };
    }
    if args.first().is_some_and(|a| a == "presets") {
        return questions::presets_cli(&args[1..]);
    }
    // The MCP server on stdio: a fourth entry point that takes no argument; each
    // tool call names its repository and passes the same scope guard (#727).
    if args.first().is_some_and(|a| a == "mcp") {
        return brakes::mcp::cli(&args[1..]);
    }
    match run(args) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("REFUSED: {error}");
            ExitCode::from(2)
        }
    }
}
