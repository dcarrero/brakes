//! The `human-approved` label (owner, 2026-10-29, #941): the one label a
//! person sets and an agent may not. `ci-baseline`'s aggregate refuses a
//! protected-path change without it, so every `gh` route that sets, removes or
//! redefines it is denied in both modes, without calling `gh`; a label write
//! the guard cannot read is denied with its own cannot-tell reason, and
//! creating the label stays allowed (`SPEC-merge-guard.md`).
use std::io::Read;
use std::path::Path;

use super::review::{Dir, WRITE_METHODS, api_method, expands, positionals};
use super::{LABEL_CHANGE, LABEL_UNKNOWN};

/// The label a person sets and an agent may not (owner, 2026-10-29).
const HUMAN_APPROVED: &str = "human-approved";
/// The most the guard reads of a file a `gh api` call names; a larger one is unreadable.
const MAX_READ: u64 = 1 << 20;
/// GraphQL mutations that change labels by id, which the guard cannot read.
const LABEL_MUTATIONS: [&str; 3] = ["labelable", "updatelabel", "deletelabel"];
/// `gh api` options that take a value other than a field or the input.
const API_VALUE_FLAGS: [&str; 12] = [
    "-X",
    "--method",
    "-H",
    "--header",
    "-q",
    "--jq",
    "-t",
    "--template",
    "--hostname",
    "--cache",
    "-p",
    "--preview",
];

/// What a `gh` command does to `human-approved`, as far as the guard can
/// read it; the worse of two verdicts wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Label {
    Untouched,
    Unknown,
    Named,
}

impl Label {
    fn reason(self) -> Option<String> {
        match self {
            Label::Untouched => None,
            Label::Unknown => Some(LABEL_UNKNOWN.into()),
            Label::Named => Some(LABEL_CHANGE.into()),
        }
    }

    /// A label value: named, unreadable, or another label.
    fn of(value: &str) -> Self {
        if mentions_label(value) {
            Label::Named
        } else if expands(value) {
            Label::Unknown
        } else {
            Label::Untouched
        }
    }

    /// A run by an unknown wrapper may add the label itself (`xargs`).
    fn floor(wrapped: bool) -> Self {
        if wrapped {
            Label::Unknown
        } else {
            Label::Untouched
        }
    }
}

/// GitHub matches label names without regard to case.
fn mentions_label(text: &str) -> bool {
    text.to_ascii_lowercase().contains(HUMAN_APPROVED)
}

/// Whether a `gh` command sets, removes or redefines `human-approved`, in
/// every mode and without calling `gh` (#941). Creating the label is allowed.
pub(super) fn review_labels(args: &[String], dir: &Dir, wrapped: bool) -> Option<String> {
    labels(args, dir, wrapped).reason()
}

fn labels(args: &[String], dir: &Dir, wrapped: bool) -> Label {
    match positionals(args).as_slice() {
        ["pr" | "issue", "edit", ..] => {
            label_values(args, &["--add-label", "--remove-label"], wrapped)
        }
        ["pr", "create", ..] => label_values(args, &["-l", "--label"], wrapped),
        // Any word: the label edited or deleted, or a new `--name` for another.
        ["label", "edit" | "delete", ..] => args
            .iter()
            .map(|a| Label::of(a))
            .fold(Label::floor(wrapped), Label::max),
        ["alias", "set", ..] if args.iter().any(|a| mentions_label(a)) => Label::Named,
        ["api", ..] => api_labels(args, dir, wrapped),
        _ => Label::Untouched,
    }
}

/// The values of the label options `flags` (long, and one short `-l`), in
/// `--flag value`, `--flag=value` and `-lvalue` forms, comma lists included.
fn label_values(args: &[String], flags: &[&str], wrapped: bool) -> Label {
    let short = flags
        .iter()
        .find_map(|f| f.strip_prefix('-').filter(|c| c.len() == 1))
        .and_then(|c| c.chars().next());
    let mut verdict = Label::floor(wrapped);
    let mut words = args.iter().map(String::as_str);
    while let Some(arg) = words.next() {
        let value = if flags.contains(&arg) {
            words.next()
        } else if let Some(value) = flags
            .iter()
            .find_map(|f| arg.strip_prefix(f)?.strip_prefix('='))
        {
            Some(value)
        } else if let Some(rest) = short.and_then(|c| short_value(arg, c)) {
            if rest.is_empty() {
                words.next()
            } else {
                Some(rest)
            }
        } else {
            continue;
        };
        verdict = verdict.max(value.map_or(Label::Unknown, Label::of));
    }
    verdict
}

/// What follows the short option `c` in a cluster of short options
/// (`-dl`, `-lbug`, `-l=bug`); `None` when `arg` is not such a cluster.
fn short_value(arg: &str, c: char) -> Option<&str> {
    let cluster = arg.strip_prefix('-').filter(|a| !a.starts_with('-'))?;
    let (before, rest) = cluster.split_once(c)?;
    before
        .chars()
        .all(|b| b.is_ascii_alphabetic())
        .then(|| rest.strip_prefix('=').unwrap_or(rest))
}

/// The parts of a `gh api` call the label rule reads.
#[derive(Default)]
struct ApiCall<'a> {
    endpoint: Option<&'a str>,
    /// `-f`/`--raw-field` values, `key=value`, taken as written.
    raw: Vec<&'a str>,
    /// `-F`/`--field` values, where `key=@path` reads a file.
    typed: Vec<&'a str>,
    input: Option<&'a str>,
}

impl<'a> ApiCall<'a> {
    fn parse(args: &'a [String]) -> Self {
        let mut call = ApiCall::default();
        let mut seen_api = false;
        let mut words = args.iter().map(String::as_str);
        while let Some(arg) = words.next() {
            let (flag, attached) = if arg.starts_with("--") {
                arg.split_once('=')
                    .map_or((arg, None), |(f, v)| (f, Some(v)))
            } else if arg.starts_with('-') && arg.len() > 2 {
                arg.split_at_checked(2)
                    .map_or((arg, None), |(f, v)| (f, Some(v)))
            } else if arg.starts_with('-') {
                (arg, None)
            } else {
                if seen_api {
                    call.endpoint.get_or_insert(arg);
                }
                seen_api = true;
                continue;
            };
            let takes = matches!(flag, "-f" | "--raw-field" | "-F" | "--field" | "--input")
                || API_VALUE_FLAGS.contains(&flag);
            if !takes {
                continue;
            }
            let Some(value) = attached.or_else(|| words.next()) else {
                continue;
            };
            match flag {
                "-f" | "--raw-field" => call.raw.push(value),
                "-F" | "--field" => call.typed.push(value),
                "--input" => call.input = Some(value),
                _ => {}
            }
        }
        call
    }
}

/// Which `gh api` endpoints the label rule reviews.
#[derive(PartialEq)]
enum LabelEndpoint {
    /// `…/issues/<n>/labels…`, `…/issues/<n>` (it takes `labels`), `…/labels/<name>`.
    Labels,
    Graphql,
    /// Not a label endpoint, as far as its literal text tells.
    Other,
    /// No endpoint, or one that expands into what the guard cannot read.
    Opaque,
}

fn label_endpoint(endpoint: Option<&str>) -> LabelEndpoint {
    let Some(endpoint) = endpoint else {
        return LabelEndpoint::Opaque;
    };
    let path = endpoint.split('?').next().unwrap_or("");
    let segments: Vec<_> = path.trim_matches('/').split('/').collect();
    if segments.last() == Some(&"graphql") {
        return LabelEndpoint::Graphql;
    }
    let issue_labels = segments
        .iter()
        .position(|s| *s == "issues")
        .is_some_and(|at| segments.len() == at + 2 || segments.get(at + 2) == Some(&"labels"));
    // `…/labels/<name>`; `POST …/labels` creates a label and stays allowed.
    let definition = segments
        .iter()
        .position(|s| *s == "labels")
        .is_some_and(|at| segments.len() > at + 1);
    if issue_labels || definition {
        LabelEndpoint::Labels
    } else if expands(endpoint) {
        LabelEndpoint::Opaque
    } else {
        LabelEndpoint::Other
    }
}

/// A file named in a `gh api` call, read from the directory the command runs
/// in; `None` when the guard cannot read it (`-`, an expansion, a missing
/// file, a relative path in an unknown directory).
fn read_named(path: &str, dir: &Dir) -> Option<String> {
    if path == "-" || expands(path) {
        return None;
    }
    let path = Path::new(path);
    let path = match dir {
        _ if path.is_absolute() => path.to_path_buf(),
        Dir::Known(base) => base.join(path),
        Dir::Unknown => return None,
    };
    // Bounded, so a device or a huge file cannot stall the hook.
    let mut text = String::new();
    let file = std::fs::File::open(path).ok()?;
    file.take(MAX_READ + 1).read_to_string(&mut text).ok()?;
    (text.len() as u64 <= MAX_READ).then_some(text)
}

/// A `gh api` write that sets, removes or redefines the label (#941).
fn api_labels(args: &[String], dir: &Dir, wrapped: bool) -> Label {
    if !WRITE_METHODS.contains(&api_method(args).as_str()) {
        return Label::Untouched;
    }
    let call = ApiCall::parse(args);
    let kind = label_endpoint(call.endpoint);
    if kind == LabelEndpoint::Other {
        return Label::Untouched;
    }
    // Every text of the request, `None` where the guard cannot read it.
    let mut texts: Vec<(Option<&str>, Option<String>)> = Vec::new();
    for field in &call.raw {
        let value = (!expands(field)).then(|| (*field).to_owned());
        texts.push((field.split_once('=').map(|(k, _)| k), value));
    }
    for field in &call.typed {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        let text = match value.strip_prefix('@') {
            Some(path) => read_named(path, dir),
            None => (!expands(field)).then(|| (*field).to_owned()),
        };
        texts.push((Some(key), text));
    }
    let input = call.input.map(|path| read_named(path, dir));
    let named = call.endpoint.is_some_and(mentions_label)
        || texts
            .iter()
            .any(|(_, t)| t.as_deref().is_some_and(mentions_label))
        || input.iter().flatten().any(|t| mentions_label(t));
    if named {
        return if kind == LabelEndpoint::Opaque {
            Label::Unknown
        } else {
            Label::Named
        };
    }
    let unreadable = texts.iter().any(|(_, t)| t.is_none()) || matches!(input, Some(None));
    match kind {
        LabelEndpoint::Labels if unreadable || wrapped => Label::Unknown,
        LabelEndpoint::Graphql => {
            let query = texts.iter().find(|(key, _)| *key == Some("query"));
            let readable = match query {
                Some((_, text)) => text.is_some(),
                None => matches!(input, Some(Some(_))),
            };
            let mutates = texts
                .iter()
                .filter_map(|(_, t)| t.as_deref())
                .chain(input.iter().flatten().map(String::as_str))
                .any(|t| {
                    let t = t.to_ascii_lowercase();
                    LABEL_MUTATIONS.iter().any(|m| t.contains(m))
                });
            if !readable || mutates {
                Label::Unknown
            } else {
                Label::Untouched
            }
        }
        _ => Label::Untouched,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_endpoints_and_short_clusters_are_matched_as_segments() {
        use LabelEndpoint::*;
        let kind = |e: &str| label_endpoint(Some(e));
        assert!(kind("repos/o/r/issues/3/labels") == Labels);
        assert!(kind("/repos/o/r/issues/3/labels/bug?x=1") == Labels);
        assert!(kind("repos/o/r/issues/3") == Labels);
        assert!(kind("repos/o/r/labels/bug") == Labels);
        assert!(kind("repos/o/r/labels") == Other);
        assert!(kind("repos/o/r/issues/3/comments") == Other);
        assert!(kind("repos/o/r/issues") == Other);
        assert!(kind("repos/o/r/labels-archive") == Other);
        assert!(kind("graphql") == Graphql);
        assert!(kind("$URL") == Opaque);
        assert!(label_endpoint(None) == Opaque);
        assert_eq!(short_value("-dl", 'l'), Some(""));
        assert_eq!(short_value("-lbug", 'l'), Some("bug"));
        assert_eq!(short_value("-l=bug", 'l'), Some("bug"));
        assert_eq!(short_value("--label", 'l'), None);
        assert_eq!(short_value("-Ro/label", 'l'), None);
    }
}
