//! Claude Code hooks. Reads the payload on stdin. On PreToolUse it runs the
//! guards that apply to the tool and prints a deny decision when one objects,
//! or else an ask decision when a confirm guard wants the user's consent.
//! On Stop it reports shells the session has left running.

mod branch_upstream;
mod commit_msg;
mod emdash;
mod payload;
mod query_budget;
mod remote_access;
mod stale_shells;
mod waiter_loop;

use std::io::Read;

use payload::Payload;

type Guard = fn(&Payload) -> Option<String>;

const BASH_GUARDS: &[(&str, Guard)] = &[
    ("commit-msg", commit_msg::check),
    ("branch-upstream", branch_upstream::check),
    ("waiter-loop", waiter_loop::check),
    ("query-budget", query_budget::check),
];
/// Guards that ask the user to confirm instead of denying outright.
const BASH_CONFIRM_GUARDS: &[(&str, Guard)] = &[("remote-access", remote_access::check)];
const EDIT_GUARDS: &[(&str, Guard)] = &[("emdash", emdash::check)];
const MCP_QUERY_GUARDS: &[(&str, Guard)] = &[("query-budget", query_budget::check_mcp_query)];

fn main() {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return;
    }
    let Some(payload) = Payload::parse(&raw) else {
        return;
    };

    if payload.hook_event_name == "Stop" {
        if let Some(report) = stale_shells::report() {
            println!("{report}");
        }
        return;
    }

    let (guards, confirm_guards): (&[(&str, Guard)], &[(&str, Guard)]) =
        match payload.tool_name.as_str() {
            "Bash" | "Monitor" => (BASH_GUARDS, BASH_CONFIRM_GUARDS),
            "Write" | "Edit" | "MultiEdit" => (EDIT_GUARDS, &[]),
            "mcp__laravel-boost__database-query" => (MCP_QUERY_GUARDS, &[]),
            _ => return,
        };
    let only = std::env::args().nth(1);
    let run = |guards: &[(&str, Guard)]| -> Vec<String> {
        guards
            .iter()
            .filter(|(name, _)| only.as_deref().is_none_or(|o| o == *name))
            .filter_map(|(_, guard)| guard(&payload))
            .collect()
    };

    // A deny outranks a confirmation: there is no point asking about a
    // command that would be refused anyway.
    let mut decision = "deny";
    let mut reasons = run(guards);
    if reasons.is_empty() {
        decision = "ask";
        reasons = run(confirm_guards);
    }
    if reasons.is_empty() {
        return;
    }

    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reasons.join("\n\n"),
        }
    });
    println!("{out}");
}
