//! How a security shell fragment enters a rendered workflow (#1088; decision
//! "Security shells are embedded without comment-only lines"): every line as
//! written, except the lines whose first non-blank character is `#` outside a
//! quoted string and a heredoc body. `#!` lines and `# shellcheck` directives
//! stay (#1362). The fragments under
//! `templates/security/fragments/` keep their comments; tests run them.
//!
//! The scan follows just enough of the shell grammar to know, at the start of
//! each line, whether it is inside single quotes, double quotes, `$'…'` or a
//! heredoc: escapes, a `#` that starts a word (the rest of that line is a
//! comment, so an apostrophe in it opens no quote), and `<<`/`<<-` delimiters
//! (`<<<` is a here-string).

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
    Ansi,
}

/// A heredoc waiting for its delimiter line; `tabs` for `<<-`.
struct Heredoc {
    delimiter: String,
    tabs: bool,
}

/// The prefix of a shellcheck directive line, kept with the code it governs.
const SHELLCHECK_DIRECTIVE: &str = "# shellcheck ";

/// `shell` without its comment-only lines, shellcheck directives excepted;
/// every other line unchanged.
pub fn without_comment_lines(shell: &str) -> String {
    let mut out = String::with_capacity(shell.len());
    let mut quote = Quote::None;
    let mut heredocs: Vec<Heredoc> = Vec::new();
    let mut in_body = false;
    for line in shell.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        if in_body {
            out.push_str(line);
            let first = &heredocs[0];
            let candidate = if first.tabs {
                text.trim_start_matches('\t')
            } else {
                text
            };
            if candidate == first.delimiter {
                heredocs.remove(0);
                in_body = !heredocs.is_empty();
            }
            continue;
        }
        let trimmed = text.trim_start();
        // A shellcheck directive is read by the workflow lint (#1362): it stays.
        if quote == Quote::None
            && trimmed.starts_with('#')
            && !trimmed.starts_with("#!")
            && !trimmed.starts_with(SHELLCHECK_DIRECTIVE)
        {
            continue;
        }
        out.push_str(line);
        quote = scan(text, quote, &mut heredocs);
        in_body = quote == Quote::None && !heredocs.is_empty();
    }
    out
}

/// The quote state after `line`, starting in `quote`; heredocs it opens are pushed.
fn scan(line: &str, mut quote: Quote, heredocs: &mut Vec<Heredoc>) -> Quote {
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Quote::Single => {
                if c == '\'' {
                    quote = Quote::None;
                }
            }
            Quote::Ansi | Quote::Double => {
                if c == '\\' {
                    i += 1;
                } else if (quote == Quote::Ansi && c == '\'')
                    || (quote == Quote::Double && c == '"')
                {
                    quote = Quote::None;
                }
            }
            Quote::None => match c {
                '\\' => i += 1,
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '$' if chars.get(i + 1) == Some(&'\'') => {
                    quote = Quote::Ansi;
                    i += 1;
                }
                '#' if i == 0
                    || chars[i - 1].is_whitespace()
                    || ";|&()<>".contains(chars[i - 1]) =>
                {
                    return quote;
                }
                '<' if chars.get(i + 1) == Some(&'<') => {
                    if chars.get(i + 2) == Some(&'<') {
                        i += 3;
                        continue;
                    }
                    i = heredoc(&chars, i + 2, heredocs);
                    continue;
                }
                _ => {}
            },
        }
        i += 1;
    }
    quote
}

/// Reads the delimiter of a heredoc whose `<<` ends before `i`; returns where
/// the scan resumes.
fn heredoc(chars: &[char], mut i: usize, heredocs: &mut Vec<Heredoc>) -> usize {
    let tabs = chars.get(i) == Some(&'-');
    if tabs {
        i += 1;
    }
    while chars.get(i).is_some_and(|c| *c == ' ' || *c == '\t') {
        i += 1;
    }
    let mut delimiter = String::new();
    match chars.get(i) {
        Some(&q @ ('\'' | '"')) => {
            i += 1;
            while let Some(&c) = chars.get(i) {
                i += 1;
                if c == q {
                    break;
                }
                delimiter.push(c);
            }
        }
        _ => {
            while let Some(&c) = chars.get(i) {
                if c.is_whitespace() || ";|&()<>".contains(c) {
                    break;
                }
                if c != '\\' {
                    delimiter.push(c);
                }
                i += 1;
            }
        }
    }
    if !delimiter.is_empty() {
        heredocs.push(Heredoc { delimiter, tabs });
    }
    i
}
