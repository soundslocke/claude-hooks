//! Block a Write or Edit that introduces an em dash into a source file.
//!
//! Enforces the no-em-dash rule in ~/.claude/CLAUDE.md. Docs and data files
//! are skipped because an em dash may be legitimate there.

use crate::payload::Payload;

const SOURCE_EXTENSIONS: &[&str] = &[
    ".php", ".js", ".jsx", ".ts", ".tsx", ".vue", ".css", ".scss", ".py", ".rb", ".rs", ".go",
    ".java", ".kt", ".swift", ".c", ".h", ".cpp", ".cs", ".sh", ".bash", ".zsh", ".sql",
];

// Spelled as an escape so this file holds no literal em dash of its own.
const EM_DASH: char = '\u{2014}';

const MESSAGE: &str = "Em dash found in this edit. ~/.claude/CLAUDE.md forbids em dashes in every \
project. Rewrite with a period, semicolon, colon, or hyphen and retry.";

pub fn check(payload: &Payload) -> Option<String> {
    introduces_em_dash(&payload.file_path, &payload.new_text).then(|| MESSAGE.to_string())
}

fn introduces_em_dash(file_path: &str, new_text: &str) -> bool {
    let is_source = SOURCE_EXTENSIONS.iter().any(|ext| file_path.ends_with(ext));
    is_source && new_text.contains(EM_DASH)
}

#[cfg(test)]
mod tests {
    use super::introduces_em_dash;

    #[test]
    fn denies_em_dash_in_source() {
        assert!(introduces_em_dash("src/lib.rs", "// a \u{2014} b"));
        assert!(introduces_em_dash("src/app.ts", "\u{2014}"));
        assert!(introduces_em_dash(
            "src/main.rs",
            "let x = 1; // one \u{2014} two"
        ));
    }

    #[test]
    fn allows_docs_and_clean_edits() {
        assert!(!introduces_em_dash("README.md", "a \u{2014} b"));
        assert!(!introduces_em_dash("notes.txt", "\u{2014}"));
        assert!(!introduces_em_dash("src/lib.rs", "// a - b; c: d"));
        assert!(!introduces_em_dash(
            "src/lib.rs",
            "en dash \u{2013} is not blocked"
        ));
    }
}
