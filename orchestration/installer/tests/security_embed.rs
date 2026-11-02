//! #1088: security shells are embedded in rendered workflows without
//! comment-only lines (decision "Security shells are embedded without
//! comment-only lines"). A line is dropped only when its first non-blank
//! character is `#` outside a quoted string and a heredoc body; `#!` lines and
//! every line that holds code are kept as written.
use brakes::modules::security::embed::without_comment_lines as strip;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[test]
fn comment_only_lines_go_and_code_shebang_and_blank_lines_stay() {
    let shell = "#!/usr/bin/env bash\n# header\n  # indented\nset -euo pipefail\n\necho hi # trailing comment stays with its code\n\t# tabbed\nexit 0\n";
    assert_eq!(
        strip(shell),
        "#!/usr/bin/env bash\nset -euo pipefail\n\necho hi # trailing comment stays with its code\nexit 0\n"
    );
}

/// #1362: a shellcheck directive is a comment-only line that changes what the
/// workflow lint reports (actionlint runs shellcheck on every `run:`), so it stays.
#[test]
fn shellcheck_directives_stay() {
    let shell = "# gone\n# shellcheck disable=SC2016 # a jq program\njq '$x'\n    # shellcheck disable=SC2254\n    case a in $p) ;; esac\n";
    assert_eq!(
        strip(shell),
        "# shellcheck disable=SC2016 # a jq program\njq '$x'\n    # shellcheck disable=SC2254\n    case a in $p) ;; esac\n"
    );
}

#[test]
fn an_apostrophe_in_a_comment_opens_no_quote() {
    let shell = "# the pull request's base\nx='a'\n# gone\necho \"$x\" # it's kept with its code\n# gone too\n";
    assert_eq!(
        strip(shell),
        "x='a'\necho \"$x\" # it's kept with its code\n"
    );
}

#[test]
fn lines_inside_a_multi_line_quoted_program_are_kept() {
    let shell = "jq -n '\n  # a jq comment is part of the program\n  def f: .;\n'\n# gone\nawk \"\n# inside double quotes\n{ print }\n\"\n";
    assert_eq!(
        strip(shell),
        "jq -n '\n  # a jq comment is part of the program\n  def f: .;\n'\nawk \"\n# inside double quotes\n{ print }\n\"\n"
    );
}

#[test]
fn heredoc_bodies_are_kept_whatever_their_delimiter() {
    let shell = "cat > f <<'EOF'\n# body\nEOF\n# gone\ncat <<EOF\n# body $x\nEOF\ncat <<-\"END\"\n\t# body\n\tEND\n# gone\n";
    assert_eq!(
        strip(shell),
        "cat > f <<'EOF'\n# body\nEOF\ncat <<EOF\n# body $x\nEOF\ncat <<-\"END\"\n\t# body\n\tEND\n"
    );
}

#[test]
fn ansi_c_quotes_escapes_counts_and_here_strings_are_read_as_code() {
    let shell = "IFS=$'\\t' read -r a b <<< \"$row\"\n# gone\nprintf '%s' $'it\\'s'\n# gone\nn=${#list} m=$# echo \\'\n# gone\ncase $x in *#*) ;; esac\n# gone\n";
    assert_eq!(
        strip(shell),
        "IFS=$'\\t' read -r a b <<< \"$row\"\nprintf '%s' $'it\\'s'\nn=${#list} m=$# echo \\'\ncase $x in *#*) ;; esac\n"
    );
}

#[test]
fn a_text_without_comments_is_unchanged() {
    let shell = "set -euo pipefail\necho ok\n";
    assert_eq!(strip(shell), shell);
}

// ---- every security fragment ----------------------------------------------------------

fn fragments() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/security/fragments");
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sh"))
        .collect();
    out.sort();
    out
}

/// What the stripper may remove from a fragment: only lines whose first
/// non-blank character is `#` (and never `#!`), the rest in order.
#[test]
fn every_fragment_loses_only_comment_lines_and_still_parses() {
    let tmp = tempfile::TempDir::new().unwrap();
    assert!(fragments().len() >= 7, "{:?}", fragments());
    for path in fragments() {
        let text = fs::read_to_string(&path).unwrap();
        let stripped = strip(&text);
        let mut kept = stripped.lines();
        let mut next = kept.next();
        for line in text.lines() {
            if Some(line) == next {
                next = kept.next();
            } else {
                let t = line.trim_start();
                assert!(
                    t.starts_with('#') && !t.starts_with("#!"),
                    "{}: dropped {line:?}",
                    path.display()
                );
            }
        }
        assert_eq!(
            next,
            None,
            "{}: the stripped text is not a subsequence",
            path.display()
        );
        assert!(
            stripped.len() < text.len(),
            "{}: nothing stripped",
            path.display()
        );
        let out = tmp.path().join(path.file_name().unwrap());
        fs::write(&out, &stripped).unwrap();
        let syntax = Command::new("bash").arg("-n").arg(&out).output().unwrap();
        assert!(
            syntax.status.success(),
            "{}: {}",
            path.display(),
            String::from_utf8_lossy(&syntax.stderr)
        );
        if let Ok(probe) = Command::new("shellcheck").arg("--version").output() {
            assert!(probe.status.success());
            let lint = Command::new("shellcheck")
                .arg("-s")
                .arg("bash")
                .arg(&out)
                .output()
                .unwrap();
            assert!(
                lint.status.success(),
                "{}: {}",
                path.display(),
                String::from_utf8_lossy(&lint.stdout)
            );
        }
    }
}
