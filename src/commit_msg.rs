//! Enforce the commit message format from ~/.claude/CLAUDE.md.
//!
//! Pulls the message out of a `git commit` command (-m, -F <file>, or a
//! `-F -` heredoc) and denies the call when the message breaks the spec.
//! Anything it cannot parse is allowed through: this guards known mistakes,
//! it is not a gate on every possible commit form.

use std::fs;
use std::sync::LazyLock;

use regex::Regex;

use crate::payload::Payload;

const SUBJECT_MAX: usize = 50;
const BODY_WRAP: usize = 72;
const BULLET_MAX_LINES: usize = 2;
const MAX_SEMICOLONS: usize = 1;

/// Openings that are imperative despite ending in -ed or -ing.
const IMPERATIVE_EXCEPTIONS: &[&str] = &[
    "embed", "exceed", "feed", "proceed", "read", "seed", "shed", "speed", "spread", "succeed",
    "bring", "ping", "ring", "sing", "string", "swing",
];
const THIRD_PERSON: &[&str] = &[
    "adds", "allows", "bumps", "changes", "converts", "deletes", "drops", "ensures", "fixes",
    "improves", "makes", "moves", "prevents", "removes", "renames", "replaces", "returns",
    "updates", "uses",
];

/// `git commit` counts only in command position, never quoted inside a script.
static COMMIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[\n;|&(]|\|\||&&)\s*(git\s+(?:-\S+\s+)*commit\b)").unwrap());
static HEREDOC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)"#).unwrap());
static TRAILER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Za-z][A-Za-z-]*:\s|Co-Authored-By:|Signed-off-by:)").unwrap()
});
/// Session links are private to one conversation and rot immediately.
static SESSION_TRAILER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*Claude-Session\s*:").unwrap());
static SESSION_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)claude\.ai/code/session[_/]").unwrap());
static CODE_SPAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`[^`]*`").unwrap());

// Spelled as escapes so this file holds no literal dash of its own.
const DASHES: &[(char, &str)] = &[('\u{2014}', "emdash"), ('\u{2013}', "endash")];

pub fn check(payload: &Payload) -> Option<String> {
    if !payload.command.contains("commit") {
        return None;
    }
    let message = extract_message(&payload.command)?;
    let problems = validate(&message);
    if problems.is_empty() {
        return None;
    }
    Some(format!(
        "Commit message does not match the project format:\n{}",
        problems
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// The commit message, or None when there is nothing to check.
fn extract_message(command: &str) -> Option<String> {
    let invocation = COMMIT.captures(command)?;

    // Anchoring keeps a script that merely mentions a commit from being read
    // as one, and drops any leading `git add ... &&` before the split.
    let command = &command[invocation.get(1)?.start()..];

    // A -F - heredoc is the common shape: take the body between the delimiters.
    if let Some(heredoc) = HEREDOC.captures(command) {
        let quote = &heredoc[1];
        let delimiter = &heredoc[2];
        let end = heredoc.get(0)?.end();
        let closes_quote = quote.is_empty() || command[end..].starts_with(quote);
        if closes_quote {
            let mut body: Vec<&str> = Vec::new();
            for line in command[end..].split('\n').skip(1) {
                if line.trim() == delimiter {
                    return Some(body.join("\n"));
                }
                body.push(line);
            }
            return (!body.is_empty()).then(|| body.join("\n"));
        }
    }

    let tokens = shlex::split(command)?;
    let mut messages: Vec<String> = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if (token == "-m" || token == "--message") && index + 1 < tokens.len() {
            messages.push(tokens[index + 1].clone());
            index += 2;
            continue;
        }
        if let Some(rest) = token.strip_prefix("--message=") {
            messages.push(rest.to_string());
        } else if token.len() > 2 && token.starts_with("-m") {
            messages.push(token[2..].to_string());
        } else if (token == "-F" || token == "--file") && index + 1 < tokens.len() {
            messages.push(fs::read_to_string(&tokens[index + 1]).ok()?);
            index += 2;
            continue;
        }
        index += 1;
    }

    (!messages.is_empty()).then(|| messages.join("\n\n"))
}

fn validate(message: &str) -> Vec<String> {
    let lines: Vec<&str> = message
        .trim_matches('\n')
        .split('\n')
        .filter(|line| !line.starts_with('#'))
        .collect();
    if lines.is_empty() {
        return Vec::new();
    }

    let mut problems = Vec::new();
    check_session_link(&lines, &mut problems);
    check_subject(lines[0].trim(), &mut problems);

    if lines.len() > 1 && !lines[1].trim().is_empty() {
        problems.push("no blank line between subject and body".to_string());
    }

    // Drop the trailer block so Co-Authored-By and friends are exempt.
    let mut body: Vec<&str> = lines.iter().skip(2).copied().collect();
    while body
        .last()
        .is_some_and(|last| last.trim().is_empty() || TRAILER.is_match(last))
    {
        body.pop();
    }

    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in body {
        if !line.trim().is_empty() {
            current.push(line.trim_end());
        } else if !current.is_empty() {
            blocks.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }

    if !blocks.is_empty() {
        check_body(&blocks, &mut problems);
    }

    let prose_lines: Vec<&str> = std::iter::once(lines[0])
        .chain(blocks.iter().flatten().copied())
        .collect();
    check_prose(&prose_lines, &mut problems);

    problems
}

fn check_subject(subject: &str, problems: &mut Vec<String>) {
    let length = subject.chars().count();
    if length > SUBJECT_MAX {
        problems.push(format!(
            "subject is {length} chars, max {SUBJECT_MAX}: {subject:?}"
        ));
    }
    if subject.ends_with('.') {
        problems.push("subject ends with a period".to_string());
    }

    let first_word = subject.split(' ').next().unwrap_or("");
    let first: String = first_word
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if !first.is_empty() && !IMPERATIVE_EXCEPTIONS.contains(&first.as_str()) {
        let not_imperative = first.ends_with("ed")
            || first.ends_with("ing")
            || THIRD_PERSON.contains(&first.as_str());
        if not_imperative {
            problems.push(format!("subject is not imperative mood: {first_word:?}"));
        }
    }
}

fn check_body(blocks: &[Vec<&str>], problems: &mut Vec<String>) {
    if blocks.len() > 1 {
        problems.push(format!(
            "body has {} paragraphs, max 1 (use '-' bullets for multiple concepts)",
            blocks.len()
        ));
    }

    for block in blocks {
        for line in block {
            let length = line.chars().count();
            if length > BODY_WRAP && line.trim().contains(' ') {
                problems.push(format!(
                    "body line is {length} chars, wrap at {BODY_WRAP}: {line:?}"
                ));
            }
        }

        if !block[0].starts_with("- ") {
            continue;
        }

        let mut length = 0;
        let mut bullet = "";
        for line in block.iter().copied().chain(std::iter::once("- ")) {
            if line.starts_with("- ") {
                if length > BULLET_MAX_LINES {
                    problems.push(format!(
                        "bullet spans {length} lines, max {BULLET_MAX_LINES}: {bullet:?}"
                    ));
                }
                length = 1;
                bullet = line;
            } else {
                length += 1;
            }
        }
    }
}

/// Flag typography and phrasing tics. Code spans are exempt.
fn check_prose(lines: &[&str], problems: &mut Vec<String>) {
    for (character, name) in DASHES {
        if lines.iter().any(|line| line.contains(*character)) {
            problems.push(format!("contains an {name}, use plain words instead"));
        }
    }

    let prose = lines
        .iter()
        .map(|line| CODE_SPAN.replace_all(line, ""))
        .collect::<Vec<_>>()
        .join(" ");

    if prose.contains(", not ") {
        problems.push("reads as AI phrasing: the \"X, not Y\" construction".to_string());
    }

    let semicolons = prose.matches(';').count();
    if semicolons > MAX_SEMICOLONS {
        problems.push(format!(
            "{semicolons} semicolons, max {MAX_SEMICOLONS}: prefer plain sentences"
        ));
    }
}

/// Deny any Claude-Session trailer or session URL, trailer block included.
fn check_session_link(lines: &[&str], problems: &mut Vec<String>) {
    if lines
        .iter()
        .any(|line| SESSION_TRAILER.is_match(line) || SESSION_URL.is_match(line))
    {
        problems.push(
            "contains a Claude-Session link: session URLs must never appear in a commit message"
                .to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "Retry the upload when the token has expired

The client cached a token past its lifetime, so the first upload after
an idle period always failed. Refresh it once and retry before giving
up.

Co-Authored-By: Someone <s@example.com>";

    #[test]
    fn extracts_heredoc_message_after_a_chained_add() {
        let command =
            format!("git add a.rs && git commit -q -F - <<'EOF'\n{GOOD}\nEOF\ngit log -1");
        assert_eq!(extract_message(&command).as_deref(), Some(GOOD));
    }

    #[test]
    fn extracts_inline_messages() {
        assert_eq!(
            extract_message("git commit -m 'Fix the thing'").as_deref(),
            Some("Fix the thing")
        );
        assert_eq!(
            extract_message("git commit --message=\"Fix it\" -m 'Body here'").as_deref(),
            Some("Fix it\n\nBody here")
        );
        assert_eq!(extract_message("git commit --amend --no-edit"), None);
        assert_eq!(extract_message("echo 'git commit -m nope'"), None);
        assert_eq!(extract_message("git status"), None);
    }

    #[test]
    fn accepts_a_conforming_message() {
        assert!(validate(GOOD).is_empty());
        assert!(validate("Fix the modal header copy").is_empty());
        assert!(validate("Add retries to the uploader\n\n- Refresh the token once\n- Cap the backoff at ten\n  seconds").is_empty());
    }

    #[test]
    fn flags_subject_problems() {
        let long = "Keep a persistent connection for every background worker";
        assert!(validate(long)[0].contains("chars, max 50"));
        assert!(validate("Fix it.")[0].contains("ends with a period"));
        assert!(validate("Fixed the bug")[0].contains("not imperative"));
        assert!(validate("Fixes the bug")[0].contains("not imperative"));
        assert!(validate("Adding a guard")[0].contains("not imperative"));
        assert!(validate("Embed the widget").is_empty());
        assert!(validate("Bring back the footer").is_empty());
    }

    #[test]
    fn flags_body_problems() {
        assert!(validate("Fix it\nno gap")[0].contains("no blank line"));
        let two_paragraphs = "Fix it\n\nFirst paragraph.\n\nSecond paragraph.";
        assert!(validate(two_paragraphs)[0].contains("2 paragraphs"));
        let wide = format!("Fix it\n\n{} word", "x".repeat(72));
        assert!(validate(&wide)[0].contains("wrap at 72"));
        let long_bullet = "Fix it\n\n- one\n  two\n  three\n- four";
        assert!(validate(long_bullet)[0].contains("bullet spans 3 lines"));
    }

    #[test]
    fn flags_prose_tics_outside_code_spans() {
        assert!(validate("Fix it\n\nA \u{2014} B")
            .iter()
            .any(|p| p.contains("emdash")));
        assert!(validate("Fix it\n\nUse X, not Y")
            .iter()
            .any(|p| p.contains("X, not Y")));
        assert!(validate("Fix it\n\nUse `X, not Y`").is_empty());
        assert!(validate("Fix it\n\nA; B; C")
            .iter()
            .any(|p| p.contains("2 semicolons")));
    }

    #[test]
    fn flags_session_links_even_in_trailers() {
        let with_trailer = format!("{GOOD}\nClaude-Session: abc");
        assert!(validate(&with_trailer)
            .iter()
            .any(|p| p.contains("Claude-Session")));
        let with_url = "Fix it\n\nSee https://claude.ai/code/session_123";
        assert!(validate(with_url)
            .iter()
            .any(|p| p.contains("Claude-Session")));
    }

    #[test]
    fn trailers_do_not_count_as_body() {
        let msg = "Fix it\n\nOne sentence.\n\nCo-Authored-By: Someone <s@example.com>";
        assert!(validate(msg).is_empty());
    }
}
