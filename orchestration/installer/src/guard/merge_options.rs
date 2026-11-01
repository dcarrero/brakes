//! Parse merge options once so their values never become repository overrides.

use super::MERGE_VALUE_FLAGS;

const SWITCHES: [&str; 13] = [
    "--admin",
    "--auto",
    "--disable-auto",
    "--delete-branch",
    "-d",
    "--merge",
    "-m",
    "--rebase",
    "-r",
    "--squash",
    "-s",
    "--help",
    "-h",
];

pub(super) struct MergeOptions<'a> {
    pub repo: Option<&'a str>,
    pub selector: Option<&'a str>,
    pub admin: bool,
}

impl<'a> MergeOptions<'a> {
    pub fn parse(args: &'a [String]) -> Result<Self, &'static str> {
        let mut parsed = Self {
            repo: None,
            selector: None,
            admin: false,
        };
        let mut words = Vec::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if arg == "--" {
                words.extend(args.map(String::as_str));
                break;
            }
            if !arg.starts_with('-') {
                words.push(arg.as_str());
                continue;
            }
            let (flag, attached) = if arg.starts_with("--") {
                match arg.split_once('=') {
                    Some((flag, value)) => (flag, Some(value)),
                    None => (arg.as_str(), None),
                }
            } else if let Some(flag) = MERGE_VALUE_FLAGS
                .iter()
                .find(|flag| flag.len() == 2 && arg.starts_with(**flag))
            {
                let rest = &arg[2..];
                (
                    *flag,
                    (!rest.is_empty()).then(|| rest.strip_prefix('=').unwrap_or(rest)),
                )
            } else {
                (arg.as_str(), None)
            };
            if MERGE_VALUE_FLAGS.contains(&flag) {
                let value = attached
                    .or_else(|| args.next().map(String::as_str))
                    .ok_or("the value of a merge option")?;
                if matches!(flag, "-R" | "--repo") {
                    // gh uses the last occurrence of a string option.
                    parsed.repo = Some(value);
                }
            } else if SWITCHES.contains(&flag) {
                if flag == "--admin" {
                    parsed.admin = true;
                }
            } else {
                // Future options may consume even a token starting with -R.
                // Never guess their arity or reinterpret their value as a flag.
                return Err("the repository selected by an unknown merge option");
            }
        }
        match words.as_slice() {
            ["pr", "merge"] => {}
            ["pr", "merge", selector] => parsed.selector = Some(selector),
            _ => return Err("which pull request the merge arguments select"),
        }
        Ok(parsed)
    }
}
