//! Block a Write or Edit that introduces an em dash into any file.
//!
//! Enforces the no-em-dash rule in ~/.claude/CLAUDE.md, which covers code,
//! docs and file content of every kind. Only the text the edit introduces is
//! inspected, so a legacy file full of em dashes does not block an unrelated
//! edit to it.

use crate::payload::Payload;

// Spelled as an escape so this file holds no literal em dash of its own.
const EM_DASH: char = '\u{2014}';

const MAX_LINES: usize = 20;
const MAX_LINE_CHARS: usize = 200;

pub fn check(payload: &Payload) -> Option<String> {
    let hits = em_dash_lines(&payload.new_text);
    if hits.is_empty() {
        return None;
    }
    let file = if payload.file_path.is_empty() {
        "this edit"
    } else {
        &payload.file_path
    };
    Some(format!(
        "Em dash (U+2014) in content written to {file}. ~/.claude/CLAUDE.md forbids em dashes \
         in every file. Rewrite using a colon, comma, parentheses, or a separate sentence, \
         then retry:\n{}",
        hits.join("\n")
    ))
}

/// The lines of `text` holding an em dash, numbered like `grep -n`.
fn em_dash_lines(text: &str) -> Vec<String> {
    if !text.contains(EM_DASH) {
        return Vec::new();
    }
    text.lines()
        .enumerate()
        .filter(|(_, line)| line.contains(EM_DASH))
        .take(MAX_LINES)
        .map(|(index, line)| {
            let line: String = line.chars().take(MAX_LINE_CHARS).collect();
            format!("{}:{line}", index + 1)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(file_path: &str, new_text: &str) -> Payload {
        Payload {
            tool_name: "Write".to_string(),
            file_path: file_path.to_string(),
            new_text: new_text.to_string(),
            ..Payload::default()
        }
    }

    #[test]
    fn denies_em_dash_in_any_file() {
        assert!(check(&payload("src/lib.rs", "// a \u{2014} b")).is_some());
        assert!(check(&payload("README.md", "a \u{2014} b")).is_some());
        assert!(check(&payload("notes.txt", "\u{2014}")).is_some());
    }

    #[test]
    fn allows_clean_edits() {
        assert!(check(&payload("src/lib.rs", "// a - b; c: d")).is_none());
        assert!(check(&payload("src/lib.rs", "en dash \u{2013} is not blocked")).is_none());
    }

    #[test]
    fn quotes_the_offending_lines() {
        let reason = check(&payload("a.md", "fine\nbad \u{2014} line\nfine")).unwrap();
        assert!(reason.contains("written to a.md"));
        assert!(reason.ends_with("2:bad \u{2014} line"));
    }
}
