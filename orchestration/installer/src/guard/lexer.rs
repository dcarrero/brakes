//! A small POSIX shell lexer: enough to find simple commands and their words.
//!
//! Copied from the supervisor (`orchestration/src/guard.rs`, frozen); the only
//! changes are the `pub` visibilities the sibling review module needs.

/// One parsed item of a command line: a simple command's words, the commands
/// of a substitution, which runs in a subshell, or the `(` and `)` of a group.
#[derive(Debug)]
pub enum Item {
    Command(Vec<String>),
    Subshell(Vec<Item>),
    Separator(Separator),
    Open,
    Close,
}

#[derive(Debug, Clone, Copy)]
pub enum Separator {
    Sequence,
    Conditional,
    Pipeline,
    Background,
}

struct Heredoc {
    delimiter: String,
    strip_tabs: bool,
    expands: bool,
}

/// A small POSIX shell lexer: enough to find simple commands and their words.
/// It does not expand anything; words keep `$` and backticks of expansions.
struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    items: &'a mut Vec<Item>,
    words: Vec<String>,
    word: String,
    in_word: bool,
    heredocs: Vec<Heredoc>,
}

pub fn parse(text: &str) -> Result<Vec<Item>, String> {
    let mut items = Vec::new();
    let mut lexer = Lexer {
        chars: text.chars().collect(),
        pos: 0,
        items: &mut items,
        words: Vec::new(),
        word: String::new(),
        in_word: false,
        heredocs: Vec::new(),
    };
    lexer.run()?;
    Ok(items)
}

impl Lexer<'_> {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn end_word(&mut self) {
        if self.in_word {
            self.words.push(std::mem::take(&mut self.word));
            self.in_word = false;
        }
    }

    fn end_command(&mut self) {
        self.end_word();
        if !self.words.is_empty() {
            self.items
                .push(Item::Command(std::mem::take(&mut self.words)));
        }
    }

    fn push(&mut self, c: char) {
        self.word.push(c);
        self.in_word = true;
    }

    fn run(&mut self) -> Result<(), String> {
        while let Some(c) = self.peek(0) {
            match c {
                ' ' | '\t' => {
                    self.end_word();
                    self.pos += 1;
                }
                '\n' => {
                    self.end_command();
                    // A newline after &&, || or | continues the same list.
                    if !matches!(self.items.last(), Some(Item::Separator(_))) {
                        self.items.push(Item::Separator(Separator::Sequence));
                    }
                    self.pos += 1;
                    self.read_heredocs()?;
                }
                '#' if !self.in_word => {
                    while self.peek(0).is_some_and(|c| c != '\n') {
                        self.pos += 1;
                    }
                }
                ';' | '&' | '|' => {
                    self.end_command();
                    let separator = match (c, self.peek(1)) {
                        ('&', Some('&')) | ('|', Some('|')) => {
                            self.pos += 1;
                            Separator::Conditional
                        }
                        ('|', _) => Separator::Pipeline,
                        ('&', _) => Separator::Background,
                        _ => Separator::Sequence,
                    };
                    self.items.push(Item::Separator(separator));
                    self.pos += 1;
                }
                '(' | ')' => {
                    self.end_command();
                    self.items
                        .push(if c == '(' { Item::Open } else { Item::Close });
                    self.pos += 1;
                }
                '<' | '>' => self.redirection()?,
                _ => self.word_part()?,
            }
        }
        self.end_command();
        Ok(())
    }

    /// Reads one part of a word: a quoted string, an escape, an expansion or a
    /// plain character.
    fn word_part(&mut self) -> Result<(), String> {
        let c = self.peek(0).expect("caller checked");
        match c {
            '\'' => {
                self.in_word = true;
                self.pos += 1;
                loop {
                    match self.peek(0) {
                        None => return Err("unterminated single quote".into()),
                        Some('\'') => break,
                        Some(c) => self.word.push(c),
                    }
                    self.pos += 1;
                }
                self.pos += 1;
            }
            '"' => {
                self.in_word = true;
                self.pos += 1;
                loop {
                    match self.peek(0) {
                        None => return Err("unterminated double quote".into()),
                        Some('"') => break,
                        Some('\\') => {
                            match self.peek(1) {
                                Some('\n') => {}
                                Some(c @ ('"' | '\\' | '$' | '`')) => self.word.push(c),
                                Some(c) => {
                                    self.word.push('\\');
                                    self.word.push(c);
                                }
                                None => return Err("unterminated double quote".into()),
                            }
                            self.pos += 2;
                            continue;
                        }
                        Some('$') if self.peek(1) == Some('(') => {
                            self.substitution()?;
                            continue;
                        }
                        Some('`') => {
                            self.backquote()?;
                            continue;
                        }
                        Some(c) => self.word.push(c),
                    }
                    self.pos += 1;
                }
                self.pos += 1;
            }
            '\\' => {
                match self.peek(1) {
                    Some('\n') | None => {}
                    Some(c) => self.push(c),
                }
                self.pos = (self.pos + 2).min(self.chars.len());
            }
            '$' if self.peek(1) == Some('(') => self.substitution()?,
            '`' => self.backquote()?,
            c => {
                self.push(c);
                self.pos += 1;
            }
        }
        Ok(())
    }

    /// `$(...)`: its commands run, so they are parsed as a subshell.
    fn substitution(&mut self) -> Result<(), String> {
        let start = self.pos + 2;
        let mut depth = 1;
        let mut at = start;
        let mut quote = None;
        while depth > 0 {
            let c = *self
                .chars
                .get(at)
                .ok_or("unterminated command substitution")?;
            match (quote, c) {
                (_, '\\') if quote != Some('\'') => at += 1,
                (None, '\'' | '"') => quote = Some(c),
                (Some(q), _) if c == q => quote = None,
                (None, '(') => depth += 1,
                (None, ')') => depth -= 1,
                _ => {}
            }
            at += 1;
        }
        let inner: String = self.chars[start..at - 1].iter().collect();
        self.word.push_str("$(…)");
        self.in_word = true;
        self.pos = at;
        self.items.push(Item::Subshell(parse(&inner)?));
        Ok(())
    }

    fn backquote(&mut self) -> Result<(), String> {
        let mut at = self.pos + 1;
        let mut inner = String::new();
        loop {
            match self.chars.get(at) {
                None => return Err("unterminated backquote".into()),
                Some('`') => break,
                Some('\\') => {
                    if let Some(c) = self.chars.get(at + 1) {
                        inner.push(*c);
                    }
                    at += 2;
                }
                Some(c) => {
                    inner.push(*c);
                    at += 1;
                }
            }
        }
        self.word.push_str("`…`");
        self.in_word = true;
        self.pos = at + 1;
        self.items.push(Item::Subshell(parse(&inner)?));
        Ok(())
    }

    /// A redirection and its target are not words of the command. A heredoc
    /// records its delimiter; its body is read after the line ends.
    fn redirection(&mut self) -> Result<(), String> {
        if self.in_word && self.word.chars().all(|c| c.is_ascii_digit()) {
            // The descriptor of `2>&1`.
            self.word.clear();
            self.in_word = false;
        }
        self.end_word();
        let heredoc = self.peek(0) == Some('<') && self.peek(1) == Some('<');
        let here_string = heredoc && self.peek(2) == Some('<');
        let strip_tabs = heredoc && !here_string && self.peek(2) == Some('-');
        self.pos += 1;
        while self
            .peek(0)
            .is_some_and(|c| matches!(c, '<' | '>' | '&' | '|' | '-'))
        {
            self.pos += 1;
        }
        while self.peek(0).is_some_and(|c| c == ' ' || c == '\t') {
            self.pos += 1;
        }
        let start = self.pos;
        while self.peek(0).is_some_and(|c| {
            !matches!(
                c,
                ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
            )
        }) {
            self.word_part()?;
        }
        let target = std::mem::take(&mut self.word);
        self.in_word = false;
        if heredoc && !here_string {
            let raw: String = self.chars[start..self.pos].iter().collect();
            self.heredocs.push(Heredoc {
                delimiter: target,
                strip_tabs,
                expands: !raw.contains(['\'', '"', '\\']),
            });
        }
        Ok(())
    }

    /// Heredoc bodies are data. Only when the delimiter is unquoted does the
    /// shell run their command substitutions, so only those are parsed. A body
    /// left open runs to the end of the text, as in the shell.
    fn read_heredocs(&mut self) -> Result<(), String> {
        for heredoc in std::mem::take(&mut self.heredocs) {
            while self.pos < self.chars.len() {
                let end = self.chars[self.pos..]
                    .iter()
                    .position(|c| *c == '\n')
                    .map_or(self.chars.len(), |n| self.pos + n);
                let line: String = self.chars[self.pos..end].iter().collect();
                self.pos = (end + 1).min(self.chars.len());
                let text = if heredoc.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    &line
                };
                if text == heredoc.delimiter {
                    break;
                }
                if heredoc.expands {
                    self.expansions(&line)?;
                }
            }
        }
        Ok(())
    }

    /// Parses only the command substitutions of a heredoc line.
    fn expansions(&mut self, line: &str) -> Result<(), String> {
        let mut body = Lexer {
            chars: line.chars().collect(),
            pos: 0,
            items: &mut *self.items,
            words: Vec::new(),
            word: String::new(),
            in_word: false,
            heredocs: Vec::new(),
        };
        while let Some(c) = body.peek(0) {
            match c {
                '\\' => body.pos += 2,
                '$' if body.peek(1) == Some('(') => body.substitution()?,
                '`' => body.backquote()?,
                _ => body.pos += 1,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn commands(text: &str) -> Vec<Vec<String>> {
        fn flat(items: Vec<Item>, out: &mut Vec<Vec<String>>) {
            for item in items {
                match item {
                    Item::Command(words) => out.push(words),
                    Item::Subshell(inner) => flat(inner, out),
                    Item::Open | Item::Close | Item::Separator(_) => {}
                }
            }
        }
        let mut out = Vec::new();
        flat(parse(text).unwrap(), &mut out);
        out
    }

    #[test]
    fn lexer_splits_commands_and_drops_data() {
        assert_eq!(
            commands("cd /a && gh pr merge 1 2>&1 | tee log; echo 'x; gh pr merge 2'"),
            [
                vec!["cd", "/a"],
                vec!["gh", "pr", "merge", "1"],
                vec!["tee", "log"],
                vec!["echo", "x; gh pr merge 2"],
            ]
        );
        assert_eq!(
            commands("cat <<'EOF'\ngh pr merge 1\nEOF\nls"),
            [vec!["cat"], vec!["ls"]]
        );
        assert_eq!(
            commands("cat <<EOF\n`a` and $(b c)\nEOF"),
            [vec!["cat"], vec!["a"], vec!["b", "c"]]
        );
    }
}
