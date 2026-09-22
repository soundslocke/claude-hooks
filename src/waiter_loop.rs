//! Deny unbounded polling loops.
//!
//! A shell that loops on sleep, waiting for a file or another process,
//! duplicates the completion notification the harness already delivers and
//! outlives whatever it was waiting on. One polled `until [ -s <file> ]`
//! against a file created empty and ran until it was killed by hand.
//!
//! The rule: a loop construct plus sleep must carry `timeout`. Nothing else is
//! inspected, so a bounded wait passes and a loop without sleep passes.

use std::sync::LazyLock;

use regex::Regex;

use crate::payload::Payload;

static LOOP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(^|[;&|\s])(while|until)(\s|$)").unwrap());
static SLEEP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(^|[;&|\s])sleep(\s|$)").unwrap());
static TIMEOUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(^|[;&|\s])timeout(\s|$)").unwrap());

const MESSAGE: &str = "DENIED: unbounded polling loop.

This command loops on `sleep` with no `timeout`. Waiter shells are prohibited:
the harness already notifies you when background work finishes, so polling
duplicates that notification and then outlives its producer. A loop waiting on a
file that is never written, or is written empty, never terminates.

Do one of these instead:
  - Run the command in the foreground.
  - Background the real command itself, not a shell that watches it.
  - Wait for another agent by letting its completion notification arrive.
  - Waiting on a background task: END YOUR TURN. The harness re-invokes you
    when it finishes. A Monitor that polls for it is the same waiter shell.
  - If you genuinely must poll an external condition, bound it:
        timeout 300 bash -c 'until <condition>; do sleep 15; done'";

pub fn check(payload: &Payload) -> Option<String> {
    // Substring checks first: regex compilation is the only real cost here
    // and almost no command mentions a loop at all.
    let command = &payload.command;
    if !command.contains("sleep") || !(command.contains("while") || command.contains("until")) {
        return None;
    }
    is_unbounded_poll(&payload.command).then(|| MESSAGE.to_string())
}

fn is_unbounded_poll(command: &str) -> bool {
    // Strip comments so prose about loops never trips the guard.
    let stripped: String = command
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");

    LOOP.is_match(&stripped) && SLEEP.is_match(&stripped) && !TIMEOUT.is_match(&stripped)
}

#[cfg(test)]
mod tests {
    use super::is_unbounded_poll;

    #[test]
    fn denies_sleep_loop_without_timeout() {
        assert!(is_unbounded_poll("until [ -s out.txt ]; do sleep 5; done"));
        assert!(is_unbounded_poll("while true; do\n  sleep 1\ndone"));
    }

    #[test]
    fn allows_bounded_and_unrelated_loops() {
        assert!(!is_unbounded_poll(
            "timeout 300 bash -c 'until test -f x; do sleep 15; done'"
        ));
        assert!(!is_unbounded_poll("for f in *.php; do echo $f; done"));
        assert!(!is_unbounded_poll("while read -r l; do echo $l; done < in"));
        assert!(!is_unbounded_poll("sleep 2 && ls"));
    }

    #[test]
    fn ignores_comments() {
        assert!(!is_unbounded_poll("ls # while we sleep here nothing loops"));
    }
}
