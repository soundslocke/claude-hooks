//! Deny shells that wait on background work.
//!
//! A shell that loops on sleep, waiting for a file or another process,
//! duplicates the completion notification the harness already delivers and
//! outlives whatever it was waiting on. One polled `until [ -s <file> ]`
//! against a file created empty and ran until it was killed by hand.
//!
//! Three shapes are denied:
//!   - A loop construct plus sleep with no `timeout`. A bounded wait passes
//!     and a loop without sleep passes.
//!   - A loop that asks whether a process exists (`pgrep`, `pidof`, `kill -0`,
//!     `ps | grep`). That is a wait on background work whatever its bound, and
//!     `pgrep -f` matches the polling shell's own command line, so the loop
//!     can never end on its own.
//!   - Following a file under /tmp, where detached jobs and the harness's own
//!     task output land. Real service logs live elsewhere.

use std::sync::LazyLock;

use regex::Regex;

use crate::payload::Payload;

// Quotes, backticks and parens count as separators because `bash -c '...'`,
// `$(...)` and subshells all start a fresh command inside them.
static LOOP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)(^|[;&|\s'"`({])(while|until)(\s|$)"#).unwrap());
static LOOP_END: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bdone\b").unwrap());
static SLEEP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)(^|[;&|\s'"`({])sleep(\s|$)"#).unwrap());
static TIMEOUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)(^|[;&|\s'"`({])timeout(\s|$)"#).unwrap());

/// Ways to ask "is this process alive?". `ps` and `jobs` count only when piped
/// into a filter, since bare they are not an existence test.
static PROBES: LazyLock<Vec<(Regex, &str)>> = LazyLock::new(|| {
    [
        (r"\bpgrep\b", "pgrep"),
        (r"\bpidof\b", "pidof"),
        (r"\bkill\s+-0\b", "kill -0"),
        (
            r"\bps\b[^\n;|&]*\|\s*(?:grep|rg|ugrep)\b",
            "ps piped into grep",
        ),
        (
            r"\bjobs\b[^\n;|&]*\|\s*(?:grep|wc)\b",
            "jobs piped into grep",
        ),
    ]
    .into_iter()
    .map(|(pattern, name)| (Regex::new(pattern).unwrap(), name))
    .collect()
});
static SELF_MATCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bpgrep\b[^\n;|&]*\s-[a-zA-Z]*f").unwrap());

const UNBOUNDED_SLEEP: &str = "DENIED: unbounded polling loop.

This command loops on `sleep` with no `timeout`.";

const FOLLOWS_TMP: &str = "DENIED: following a file under /tmp.

That is where detached jobs and the harness's own task output land, so this is
a wait on your own background work dressed up as an event stream.";

const WHY: &str = "Waiter shells are prohibited: the harness already notifies you when background
work finishes, so polling duplicates that notification and then outlives its
producer. A loop waiting on a file that is never written, or is written empty,
never terminates.";

const SELF_MATCH_NOTE: &str =
    "It also uses `pgrep -f`, so the pattern matches this shell's own command line
and the loop can never terminate on its own.";

const MONITOR_NOTE: &str =
    "Monitor is not a way around the Bash guard. It is for reacting to external
event streams, never for waiting on work you started.";

const GUIDANCE: &str = "Do one of these instead:
  - Run the command in the foreground.
  - Background the real command itself, not a shell that watches it.
  - Wait for another agent by letting its completion notification arrive.
  - Waiting on a background task: END YOUR TURN. The harness re-invokes you
    when it finishes. A Monitor that polls for it is the same waiter shell.
  - Waiting on a process started in this same command: `wait $PID`.
  - If you genuinely must poll an external condition, bound it:
        timeout 300 bash -c 'until <condition>; do sleep 15; done'";

pub fn check(payload: &Payload) -> Option<String> {
    // Substring checks first: regex compilation is the only real cost here
    // and almost no command mentions a loop or a follow at all.
    let command = &payload.command;
    let has_loop = command.contains("while") || command.contains("until");
    let has_follow = command.contains("/tmp/");
    if !has_loop && !has_follow {
        return None;
    }

    let stripped = strip_comments(command);
    let headline = find_reason(&stripped)?;

    let mut sections = vec![headline, WHY.to_string()];
    if SELF_MATCH.is_match(&stripped) {
        sections.push(SELF_MATCH_NOTE.to_string());
    }
    if payload.tool_name == "Monitor" {
        sections.push(MONITOR_NOTE.to_string());
    }
    sections.push(GUIDANCE.to_string());
    Some(sections.join("\n\n"))
}

/// Strip comments so prose about loops never trips the guard.
fn strip_comments(command: &str) -> String {
    command
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Why this command is denied, or None when it is allowed.
fn find_reason(command: &str) -> Option<String> {
    if follows_tmp(command) {
        return Some(FOLLOWS_TMP.to_string());
    }
    if !LOOP.is_match(command) {
        return None;
    }
    if let Some(probe) = probe_in_loop(command) {
        return Some(format!(
            "DENIED: loop that polls for a process using {probe}.\n\n\
             A process-existence check in a loop waits on background work, with or\n\
             without a `timeout`."
        ));
    }
    let unbounded = SLEEP.is_match(command) && !TIMEOUT.is_match(command);
    unbounded.then(|| UNBOUNDED_SLEEP.to_string())
}

/// The first process probe inside a loop, from its keyword to its `done`.
/// Scoping to the loop keeps a probe that merely sits next to an unrelated
/// loop from counting.
fn probe_in_loop(command: &str) -> Option<&'static str> {
    LOOP.find_iter(command).find_map(|keyword| {
        let rest = &command[keyword.end()..];
        let body = LOOP_END.find(rest).map_or(rest, |end| &rest[..end.end()]);
        PROBES
            .iter()
            .find(|(pattern, _)| pattern.is_match(body))
            .map(|(_, name)| *name)
    })
}

/// A `tail -f`, `tailf` or `inotifywait` on a path under /tmp.
fn follows_tmp(command: &str) -> bool {
    command.split(['\n', ';', '|', '&']).any(|segment| {
        let words: Vec<&str> = segment.split_whitespace().collect();
        let watches_tmp = words.iter().any(|word| word.starts_with("/tmp/"));
        let follows = match words.first().copied() {
            Some("tail") => words.iter().skip(1).any(|word| is_follow_flag(word)),
            Some("tailf" | "inotifywait") => true,
            _ => false,
        };
        watches_tmp && follows
    })
}

fn is_follow_flag(word: &str) -> bool {
    if let Some(long) = word.strip_prefix("--") {
        return long == "follow" || long.starts_with("follow=");
    }
    word.len() > 1 && word.starts_with('-') && (word.ends_with('f') || word.ends_with('F'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(command: &str) -> bool {
        find_reason(&strip_comments(command)).is_some()
    }

    #[test]
    fn denies_sleep_loop_without_timeout() {
        assert!(denied("until [ -s out.txt ]; do sleep 5; done"));
        assert!(denied("while true; do\n  sleep 1\ndone"));
        assert!(denied("bash -c 'while true; do sleep 1; done'"));
        assert!(denied("x=$(until test -f y; do sleep 1; done)"));
    }

    #[test]
    fn allows_bounded_and_unrelated_loops() {
        assert!(!denied(
            "timeout 300 bash -c 'until test -f x; do sleep 15; done'"
        ));
        assert!(!denied("for f in *.php; do echo $f; done"));
        assert!(!denied("while read -r l; do echo $l; done < in"));
        assert!(!denied("sleep 2 && ls"));
    }

    #[test]
    fn denies_process_probes_in_a_loop_even_when_bounded() {
        assert!(denied("while pgrep -f cargo; do sleep 5; done"));
        assert!(denied(
            "timeout 60 bash -c 'while kill -0 $PID; do sleep 1; done'"
        ));
        assert!(denied("until ! ps aux | grep -q phpunit; do sleep 2; done"));
        assert!(denied("while pidof node >/dev/null; do :; done"));
    }

    #[test]
    fn allows_probes_outside_a_loop() {
        assert!(!denied("pgrep -x claude"));
        assert!(!denied(
            "while [ $p -gt 1 ]; do p=$(ppid $p); done; pgrep -x claude"
        ));
    }

    #[test]
    fn names_the_pgrep_self_match() {
        let payload = Payload {
            tool_name: "Bash".to_string(),
            command: "while pgrep -f 'cargo test'; do sleep 5; done".to_string(),
            ..Payload::default()
        };
        assert!(check(&payload).unwrap().contains("own command line"));
    }

    #[test]
    fn adds_the_monitor_note_for_monitor() {
        let payload = Payload {
            tool_name: "Monitor".to_string(),
            command: "tail -f /tmp/build.log".to_string(),
            ..Payload::default()
        };
        assert!(check(&payload)
            .unwrap()
            .contains("Monitor is not a way around"));
    }

    #[test]
    fn denies_following_files_under_tmp() {
        assert!(denied("tail -f /tmp/claude-1000/task.output"));
        assert!(denied("tail -n0 -F /tmp/x.log | grep --line-buffered done"));
        assert!(denied("tail --follow=name /tmp/x.log"));
        assert!(denied("inotifywait -m /tmp/out"));
    }

    #[test]
    fn allows_other_reads_of_tmp_and_follows_elsewhere() {
        assert!(!denied("tail -n 50 /tmp/x.log"));
        assert!(!denied("cat /tmp/x.log"));
        assert!(!denied("tail -f /var/log/nginx/error.log"));
    }

    #[test]
    fn ignores_comments() {
        assert!(!denied("ls # while we sleep here nothing loops"));
        assert!(!denied("ls # tail -f /tmp/x.log"));
    }
}
