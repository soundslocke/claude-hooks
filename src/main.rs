//! Claude Code PreToolUse guards. Reads the payload on stdin, runs the guards
//! that apply to the tool, and prints a deny decision when one objects.

mod branch_upstream;
mod commit_msg;
mod emdash;
mod payload;
mod waiter_loop;

use std::io::Read;

use payload::Payload;

type Guard = fn(&Payload) -> Option<String>;

const BASH_GUARDS: &[(&str, Guard)] = &[
    ("commit-msg", commit_msg::check),
    ("branch-upstream", branch_upstream::check),
    ("waiter-loop", waiter_loop::check),
];
const EDIT_GUARDS: &[(&str, Guard)] = &[("emdash", emdash::check)];

fn main() {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return;
    }
    let Some(payload) = Payload::parse(&raw) else {
        return;
    };

    let guards: &[(&str, Guard)] = match payload.tool_name.as_str() {
        "Bash" | "Monitor" => BASH_GUARDS,
        "Write" | "Edit" | "MultiEdit" => EDIT_GUARDS,
        _ => return,
    };
    let only = std::env::args().nth(1);

    let reasons: Vec<String> = guards
        .iter()
        .filter(|(name, _)| only.as_deref().is_none_or(|o| o == *name))
        .filter_map(|(_, guard)| guard(&payload))
        .collect();

    if reasons.is_empty() {
        return;
    }

    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reasons.join("\n\n"),
        }
    });
    println!("{out}");
}
