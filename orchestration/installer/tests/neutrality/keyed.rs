//! The keyed forbidden list (spec N1): HMAC-SHA-256 on `sha2` (no `hmac` crate), the
//! tokeniser and the matcher. The list's tokens never appear here; only their keyed
//! values do, and a hit is reported by line, never by token.

use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};

/// The longest substring of a run that is keyed and compared; a longer entry is
/// refused when the list is keyed, so the cap never hides one.
pub const MAX_TOKEN: usize = 64;
/// The shortest substring of a run compared on its own (a shorter entry matches a
/// whole run only).
pub const MIN_SUBSTRING: usize = 4;
const CHECK: &[u8] = b"check";

/// How an entry matches: anywhere in a run, or as a whole run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Substring,
    Word,
}

impl Kind {
    fn tag(self) -> &'static [u8] {
        match self {
            Kind::Substring => b"s",
            Kind::Word => b"w",
        }
    }
}

/// The key from the secret's value: surrounding whitespace removed; missing or empty
/// is an error (fail-closed).
pub fn key(value: Option<&str>) -> Result<Vec<u8>, String> {
    match value.map(str::trim) {
        Some(k) if !k.is_empty() => Ok(k.as_bytes().to_vec()),
        _ => {
            Err("NEUTRALITY_HMAC_KEY is missing or empty: the neutrality check fails closed".into())
        }
    }
}

/// HMAC-SHA-256 (RFC 2104) as two prefed hashers, cloned per message.
#[derive(Clone)]
struct Mac {
    inner: Sha256,
    outer: Sha256,
}

impl Mac {
    fn new(key: &[u8]) -> Mac {
        let mut block = [0u8; 64];
        if key.len() > block.len() {
            block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let pad = |byte: u8| -> Vec<u8> { block.iter().map(|b| b ^ byte).collect() };
        Mac {
            inner: Sha256::new().chain_update(pad(0x36)),
            outer: Sha256::new().chain_update(pad(0x5c)),
        }
    }

    fn sign(&self, parts: &[&[u8]]) -> String {
        let mut inner = self.inner.clone();
        for part in parts {
            inner.update(part);
        }
        let digest = self.outer.clone().chain_update(inner.finalize()).finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn value(&self, kind: Kind, token: &str) -> String {
        self.sign(&[kind.tag(), b"\0", token.as_bytes()])
    }
}

/// `HMAC-SHA-256(key, message)` as lowercase hex.
pub fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    Mac::new(key).sign(&[message])
}

/// An entry as it is keyed: its lowercase `[a-z0-9]` runs joined.
fn normalise(entry: &str) -> String {
    entry
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .collect()
}

/// The keyed list's text: the check line, then one value per entry, sorted and
/// deduplicated. An entry that is empty once normalised or longer than
/// [`MAX_TOKEN`] is refused by its position, never by its text.
pub fn render(key: &[u8], entries: &[(Kind, &str)]) -> Result<String, String> {
    let mac = Mac::new(key);
    let mut values = BTreeSet::new();
    for (n, (kind, entry)) in entries.iter().enumerate() {
        let token = normalise(entry);
        if token.is_empty() || token.len() > MAX_TOKEN {
            return Err(format!(
                "entry {}: empty or longer than {MAX_TOKEN} once normalised",
                n + 1
            ));
        }
        values.insert(mac.value(*kind, &token));
    }
    if values.is_empty() {
        return Err("no entry to key".into());
    }
    let mut text = format!(
        "# Keyed forbidden list (N1): HMAC-SHA-256 values only, keyed with NEUTRALITY_HMAC_KEY.\n# Generated; never edited by hand.\ncheck {}\n",
        mac.sign(&[CHECK])
    );
    for value in values {
        text.push_str(&value);
        text.push('\n');
    }
    Ok(text)
}

/// The parsed keyed list.
#[derive(Debug)]
pub struct KeyedList {
    check: String,
    values: HashSet<String>,
}

fn is_value(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parse the keyed list: `#` comments, one `check` line, at least one value.
pub fn parse(text: &str) -> Result<KeyedList, String> {
    let mut check = None;
    let mut values = HashSet::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.strip_prefix("check ") {
            Some(c) if is_value(c) && check.is_none() => check = Some(c.to_owned()),
            None if is_value(line) => {
                values.insert(line.to_owned());
            }
            _ => return Err(format!("keyed list line {}: malformed", n + 1)),
        }
    }
    let check = check.ok_or("keyed list: no check line")?;
    if values.is_empty() {
        return Err("keyed list: no value".into());
    }
    Ok(KeyedList { check, values })
}

/// The runs of a line: its maximal lowercase `[a-z0-9]` runs and the camel-case
/// pieces of each ASCII alphanumeric run, deduplicated.
pub fn runs(line: &str) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = line
        .to_lowercase()
        .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
        .filter(|r| !r.is_empty())
        .map(str::to_owned)
        .collect();
    for word in line.split(|c: char| !c.is_ascii_alphanumeric()) {
        let chars: Vec<char> = word.chars().collect();
        let mut start = 0;
        for i in 1..chars.len() {
            let (prev, cur) = (chars[i - 1], chars[i]);
            let next_lower = chars.get(i + 1).is_some_and(char::is_ascii_lowercase);
            let boundary = cur.is_ascii_uppercase()
                && (prev.is_ascii_lowercase()
                    || prev.is_ascii_digit()
                    || (prev.is_ascii_uppercase() && next_lower));
            if boundary {
                found.insert(chars[start..i].iter().collect::<String>().to_lowercase());
                start = i;
            }
        }
        if start > 0 {
            found.insert(chars[start..].iter().collect::<String>().to_lowercase());
        }
    }
    found
}

/// Matches lines against the keyed list; a key that did not key the list is refused.
pub struct Checker {
    mac: Mac,
    list: KeyedList,
    seen: HashMap<String, bool>,
}

impl Checker {
    pub fn new(key: &[u8], list: KeyedList) -> Result<Checker, String> {
        let mac = Mac::new(key);
        if mac.sign(&[CHECK]) != list.check {
            return Err(
                "NEUTRALITY_HMAC_KEY did not key neutrality/forbidden.hmac: the check fails closed"
                    .into(),
            );
        }
        Ok(Checker {
            mac,
            list,
            seen: HashMap::new(),
        })
    }

    fn run_hits(&mut self, run: &str) -> bool {
        if let Some(&hit) = self.seen.get(run) {
            return hit;
        }
        let listed =
            |kind: Kind, token: &str| self.list.values.contains(&self.mac.value(kind, token));
        // Runs are ASCII, so every byte range is a string.
        let len = run.len();
        let hit = listed(Kind::Word, run)
            || listed(Kind::Substring, run)
            || (0..len).any(|start| {
                (start + MIN_SUBSTRING..=(start + MAX_TOKEN).min(len))
                    .any(|end| listed(Kind::Substring, &run[start..end]))
            });
        self.seen.insert(run.to_owned(), hit);
        hit
    }

    /// The 1-based numbers of the lines of `text` that carry a listed token.
    pub fn lines(&mut self, text: &str) -> Vec<usize> {
        text.lines()
            .enumerate()
            .filter(|(_, line)| runs(line).iter().any(|r| self.run_hits(r)))
            .map(|(n, _)| n + 1)
            .collect()
    }
}

/// The home rule: the 1-based lines of `text` where the home's first word appears
/// (case-insensitive) outside an occurrence of the exact `home`.
pub fn home_lines(text: &str, home: &str) -> Vec<usize> {
    let home = home.to_lowercase();
    let word = home
        .split(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or_default();
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let lower = line.to_lowercase();
            let homes: Vec<usize> = lower.match_indices(&home).map(|(i, _)| i).collect();
            !word.is_empty()
                && lower.match_indices(word).any(|(i, _)| {
                    !homes
                        .iter()
                        .any(|&h| h <= i && i + word.len() <= h + home.len())
                })
        })
        .map(|(n, _)| n + 1)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_follows_rfc_4231() {
        assert_eq!(
            hmac_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hmac_hex(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn a_missing_or_blank_key_is_refused() {
        assert!(key(None).is_err());
        assert!(key(Some(" \n")).is_err());
        assert_eq!(key(Some(" k3y\n")).unwrap(), b"k3y");
    }

    #[test]
    fn runs_are_lowercase_alphanumeric_with_camel_pieces() {
        let found = runs("let OldZorbTech = XMLHttp2Go; café-x");
        for run in [
            "let",
            "oldzorbtech",
            "old",
            "zorb",
            "tech",
            "xmlhttp2go",
            "xml",
            "http2",
            "go",
            "caf",
            "x",
        ] {
            assert!(found.contains(run), "{run} in {found:?}");
        }
    }

    fn checker(entries: &[(Kind, &str)]) -> Checker {
        let list = parse(&render(b"test-key", entries).unwrap()).unwrap();
        Checker::new(b"test-key", list).unwrap()
    }

    #[test]
    fn substring_entries_match_inside_runs_and_across_separators_when_joined() {
        let mut c = checker(&[(Kind::Substring, "Zorb-lax")]);
        assert_eq!(
            c.lines("ok\nthe OLDZORBLAXTECH\nzorb lax\nzorblaxed"),
            [2, 4]
        );
    }

    #[test]
    fn word_entries_match_a_whole_run_or_camel_piece_only() {
        let mut c = checker(&[(Kind::Word, "qux")]);
        assert_eq!(c.lines("quxes\nask Qux.\nmyQuxTool\nquxqux"), [2, 3]);
    }

    #[test]
    fn short_substring_entries_match_a_whole_run_only() {
        let mut c = checker(&[(Kind::Substring, "ab1")]);
        assert_eq!(c.lines("xab1y\nab1\nab-1"), [2]);
    }

    #[test]
    fn rendering_refuses_empty_and_overlong_entries_without_their_text() {
        let long = "z".repeat(MAX_TOKEN + 1);
        let err = render(b"k", &[(Kind::Substring, "ok"), (Kind::Substring, &long)]).unwrap_err();
        assert!(err.contains("entry 2") && !err.contains("zzz"), "{err}");
        assert!(render(b"k", &[(Kind::Word, "-é-")]).is_err());
        assert!(render(b"k", &[]).is_err());
    }

    #[test]
    fn the_list_carries_no_token_and_values_are_sorted() {
        let text = render(b"k", &[(Kind::Substring, "zorblax"), (Kind::Word, "qux")]).unwrap();
        assert!(!text.contains("zorblax") && !text.contains("qux"));
        let values: Vec<&str> = text.lines().filter(|l| is_value(l)).collect();
        assert_eq!(values.len(), 2);
        assert!(values[0] < values[1]);
    }

    #[test]
    fn another_key_is_refused_by_the_check_line() {
        let list = parse(&render(b"one", &[(Kind::Substring, "zorblax")]).unwrap()).unwrap();
        assert!(Checker::new(b"two", list).is_err());
    }

    #[test]
    fn a_list_without_check_or_values_or_with_junk_is_refused() {
        let v = "a".repeat(64);
        assert!(parse(&format!("{v}\n")).is_err());
        assert!(parse(&format!("check {v}\n")).is_err());
        let err = parse(&format!("check {v}\n{v}\nzorblax\n")).unwrap_err();
        assert!(err.contains("line 3") && !err.contains("zorblax"), "{err}");
    }

    #[test]
    fn the_home_rule_allows_only_the_exact_home() {
        let home = "acme-org/brakes";
        let text = "see github.com/Acme-Org/brakes/pulls\nacme-org/other\nthe acme letter\nacme-org/brakes and acmeorg";
        assert_eq!(home_lines(text, home), [2, 3, 4]);
    }
}
