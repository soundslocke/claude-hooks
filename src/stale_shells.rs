//! Stop hook: name any shell this session has left running for a long time.
//!
//! Exists because "is anything still running?" was answered wrong once, by
//! grepping process names instead of asking which processes belong to this
//! session. A backgrounded shell that outlives its purpose is invisible unless
//! something looks for it, so this looks every time a turn ends.
//!
//! Advisory only: it reports and never blocks. The threshold is deliberately
//! high so a legitimate long job does not nag. Reads /proc directly, so on a
//! system without it the report is silently empty.

use std::fs;

const THRESHOLD_MINUTES: u64 = 30;

/// Long-lived children that belong to the harness rather than to a task.
const IGNORED: &[&str] = &["boost:mcp", "laravel-lsp", "mcp-server", "context7"];

/// USER_HZ, the unit of start times in /proc/<pid>/stat. The kernel fixes it
/// at 100 for userspace on every mainstream architecture.
const TICKS_PER_SECOND: f64 = 100.0;

const MAX_COMMAND_CHARS: usize = 160;

pub fn report() -> Option<String> {
    let session = find_session(std::os::unix::process::parent_id())?;
    let uptime = read_uptime()?;

    let mut stale: Vec<(u32, u64, String)> = Vec::new();
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        let Some(stat) = read_stat(pid) else {
            continue;
        };
        let elapsed = (uptime - stat.start_ticks as f64 / TICKS_PER_SECOND).max(0.0) as u64;
        if stat.ppid != session || elapsed <= THRESHOLD_MINUTES * 60 {
            continue;
        }
        let command = read_command(pid);
        if IGNORED.iter().any(|ignored| command.contains(ignored)) {
            continue;
        }
        stale.push((pid, elapsed, command));
    }
    if stale.is_empty() {
        return None;
    }
    stale.sort_unstable_by_key(|(pid, _, _)| *pid);

    let lines: Vec<String> = stale
        .iter()
        .map(|(pid, elapsed, command)| {
            let command: String = command.chars().take(MAX_COMMAND_CHARS).collect();
            format!("  pid {pid}, running {} minutes: {command}", elapsed / 60)
        })
        .collect();
    Some(format!(
        "Shells this session started over {THRESHOLD_MINUTES} minutes ago and has not stopped:\n\
         {}\nCheck whether each is still doing work. If not, kill it.",
        lines.join("\n")
    ))
}

/// The nearest ancestor named `claude`, which is the session that ran this hook.
fn find_session(mut pid: u32) -> Option<u32> {
    while pid > 1 {
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        if comm.trim_end() == "claude" {
            return Some(pid);
        }
        pid = read_stat(pid)?.ppid;
    }
    None
}

fn read_uptime() -> Option<f64> {
    fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// The full command line, arguments joined by spaces like `ps -o args`.
fn read_command(pid: u32) -> String {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    String::from_utf8_lossy(&raw)
        .split('\0')
        .filter(|arg| !arg.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

struct Stat {
    ppid: u32,
    start_ticks: u64,
}

fn read_stat(pid: u32) -> Option<Stat> {
    parse_stat(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn parse_stat(raw: &str) -> Option<Stat> {
    // The command name is parenthesized and may itself hold spaces or parens,
    // so count fields from the last closing paren: state is field 3 of stat(5).
    let fields: Vec<&str> = raw.rsplit_once(')')?.1.split_whitespace().collect();
    Some(Stat {
        ppid: fields.get(1)?.parse().ok()?,
        start_ticks: fields.get(19)?.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ppid_and_start_time() {
        let raw = "139497 (cat) R 139495 139497 139495 0 -1 4194304 89 0 0 0 0 0 0 0 20 0 1 0 \
                   32947201 17518592 429";
        let stat = parse_stat(raw).unwrap();
        assert_eq!(stat.ppid, 139495);
        assert_eq!(stat.start_ticks, 32947201);
    }

    #[test]
    fn survives_a_command_name_with_spaces_and_parens() {
        let raw = "42 (tmux: (server)) S 7 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 900 0 0";
        let stat = parse_stat(raw).unwrap();
        assert_eq!(stat.ppid, 7);
        assert_eq!(stat.start_ticks, 900);
    }

    #[test]
    fn rejects_a_truncated_stat() {
        assert!(parse_stat("42 (x) S 7").is_none());
    }
}
