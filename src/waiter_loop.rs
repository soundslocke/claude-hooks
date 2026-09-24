//! Deny shells that wait on background work.
//!
//! A shell that loops on sleep, waiting for a file or another process,
//! duplicates the completion notification the harness already delivers and
//! outlives whatever it was waiting on. One polled `until [ -s <file> ]`
//! against a file created empty and ran until it was killed by hand. Another
//! waited for `Tests:` in a log the reporter wrote as one JSON line: the suite
//! passed in 101 seconds and the loop sat for eight minutes. A `timeout` would
//! not have saved it, since the wait is only as good as the guess about what
//! ends it, so a bound does not make a sleeping `while` loop acceptable.
//!
//! Denied shapes:
//!   - A `while`, `until` or `for ((;;))` loop that sleeps, spins on an empty
//!     body, or asks whether a process exists (`pgrep`, `pidof`, `kill -0`,
//!     `ps | grep`). `pgrep -f` also matches the polling shell's own command
//!     line, so such a loop can never end on its own.
//!   - A counted `for` loop that probes a process between sleeps, or whose
//!     sleeps add up past `MAX_POLL_SECONDS`.
//!   - Following a file under /tmp, where detached jobs and the harness's own
//!     task output land. Real service logs live elsewhere.
//!
//! A `while read` loop is bounded by its input, so it counts as a `for` loop.

use std::sync::LazyLock;

use regex::Regex;

use crate::payload::Payload;

/// Longest a counted `for` loop may spend sleeping while it probes a port or
/// an endpoint. A condition that has not come true in five minutes will not.
const MAX_POLL_SECONDS: f64 = 300.0;

/// Command position: a line start, a separator, an opening quote, paren or
/// brace, or a keyword that begins a command list. Quotes count because
/// `bash -c '...'` and `$(...)` start a fresh script inside them.
const COMMAND_START: &str = r#"(?:^|[;&|({'"`]|\b(?:do|then|else|elif)\s)\s*"#;

static LOOP_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?m){COMMAND_START}(while|until|for|select)\b")).unwrap()
});
// `do` and `done` only ever follow a separator or a line break.
static LOOP_DO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)(?:^|[;&])\s*(do)\b").unwrap());
static LOOP_DONE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[;&])\s*(done)\b").unwrap());
static INFINITE_FOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*\(\(\s*[^;)]*;\s*;").unwrap());
static READ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[\s!])read\s").unwrap());

/// `sleep`, `/bin/sleep`, `usleep`, and `time.sleep(` in an inline script.
static SLEEP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[^\w-])u?sleep\b").unwrap());
static SLEEP_SECONDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^\w-])sleep\s+(\d+(?:\.\d+)?)([smhd]?)(?:\s|;|$)").unwrap()
});

static SEQ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bseq\s+(?:-\S+\s+)*(-?\d+)(?:\s+(-?\d+))?(?:\s+(-?\d+))?").unwrap()
});
static BRACE_RANGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?\}").unwrap());
static C_STYLE_RANGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\(\(\s*\w+\s*=\s*(-?\d+)\s*;\s*\w+\s*(<=?)\s*(-?\d+)\s*;").unwrap()
});
static WORD_LIST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*\w+\s+in\s+([^;\n]*)").unwrap());

/// Ways to ask "is this process alive?". `ps` and `jobs` count only when piped
/// into a filter or pointed at a pid, since bare they are not an existence test.
static PROBES: LazyLock<Vec<(Regex, &str)>> = LazyLock::new(|| {
    [
        (r"\bpgrep\b", "pgrep"),
        (r"\bpidof\b", "pidof"),
        (r"\bp?kill\s+(?:-0|-s\s*0)\b", "kill -0"),
        (
            r"\bps\b[^\n;|&]*\|\s*(?:grep|rg|ugrep|awk)\b",
            "ps piped into grep",
        ),
        (r"\bps\b[^\n;|&]*\s(?:-[a-zA-Z]*p|--pid)\b", "ps -p"),
        (
            r"\bjobs\b[^\n;|&]*\|\s*(?:grep|wc)\b",
            "jobs piped into grep",
        ),
        // Only an existence test counts: reading /proc/$p/stat to walk the
        // process tree is not a wait.
        (
            r#"-[edf]\s+["']?/proc/\$\{?\w+\}?["']?(?:\s|\]|$)"#,
            "/proc/$PID",
        ),
    ]
    .into_iter()
    .map(|(pattern, name)| (Regex::new(pattern).unwrap(), name))
    .collect()
});
static SELF_MATCH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bpgrep\b[^\n;|&]*\s-[a-zA-Z]*f").unwrap());

/// Where detached jobs and the harness's task output land.
const TMP_PREFIXES: &[&str] = &["/tmp/", "$TMPDIR", "${TMPDIR"];

const SLEEP_LOOP: &str = "DENIED: polling loop.

This `while`/`until` loop waits by sleeping. A `timeout` does not make it
acceptable: the wait is only as good as the guess about what ends it, and a
wrong guess burns the whole bound.";

const BUSY_LOOP: &str = "DENIED: busy-wait loop.

This loop has an empty body, so it spins a CPU until its condition changes.";

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
  - If you genuinely must poll an external condition (a port, an endpoint),
    use a short counted loop that breaks on success:
        for i in $(seq 20); do curl -sf localhost:8080 && break; sleep 3; done";

pub fn check(payload: &Payload) -> Option<String> {
    // Substring checks first: regex compilation is the only real cost here
    // and almost no command mentions a loop or a follow at all.
    let command = &payload.command;
    let may_loop = ["while", "until", "for"]
        .iter()
        .any(|keyword| command.contains(keyword));
    let may_follow = command.contains("/tmp/") || command.contains("TMPDIR");
    if !may_loop && !may_follow {
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

/// Strip shell comments so prose about loops never trips the guard. A `#`
/// opens a comment only at the start of a word and outside quotes, so `$#`,
/// `${#pids[@]}` and `'#'` stay code.
fn strip_comments(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut quote: Option<char> = None;
    let mut in_comment = false;
    let mut previous = '\n';
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if in_comment {
            if c == '\n' {
                in_comment = false;
                out.push(c);
                previous = c;
            }
            continue;
        }
        let escapes = c == '\\' && quote != Some('\'');
        match quote {
            Some(open) if c == open => quote = None,
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == '#'
                && (previous.is_whitespace()
                    || matches!(previous, ';' | '&' | '|' | '(' | ')')) =>
            {
                in_comment = true;
                continue;
            }
            _ => {}
        }
        out.push(c);
        previous = c;
        if escapes {
            if let Some(next) = chars.next() {
                out.push(next);
                previous = next;
            }
        }
    }
    out
}

/// Why this command is denied, or None when it is allowed.
fn find_reason(command: &str) -> Option<String> {
    if follows_tmp(command) {
        return Some(FOLLOWS_TMP.to_string());
    }
    loops(command).iter().find_map(judge)
}

#[derive(Debug, PartialEq)]
enum Kind {
    /// `while`, `until` and `for ((;;))`: nothing but the condition ends them.
    Unbounded,
    /// `for`, `select` and `while read`: bounded by their list or input.
    Counted,
}

struct Loop<'a> {
    kind: Kind,
    /// Everything from the keyword to the matching `done`.
    span: &'a str,
    /// The list or condition, before `do`.
    header: &'a str,
    /// The commands between `do` and `done`, when there is a `do` at all. A
    /// `while` in an inline Python script has none.
    body: Option<&'a str>,
}

/// Every loop in the command, each paired with its own `done` so nested loops
/// neither cut an outer body short nor leak into it.
fn loops(command: &str) -> Vec<Loop<'_>> {
    let opens: Vec<(usize, usize, &str)> = LOOP_OPEN
        .captures_iter(command)
        .filter_map(|c| c.get(1))
        .map(|m| (m.start(), m.end(), m.as_str()))
        .collect();
    let dones: Vec<usize> = LOOP_DONE
        .captures_iter(command)
        .filter_map(|c| c.get(1))
        .map(|m| m.start())
        .collect();

    opens
        .iter()
        .enumerate()
        .filter_map(|(index, &(_, keyword_end, keyword))| {
            let nested = opens[index + 1..].iter().map(|open| open.0);
            let end = matching_done(keyword_end, nested, &dones).unwrap_or(command.len());
            let span = &command[keyword_end..end];
            let (header, body) = match LOOP_DO.captures(span).and_then(|c| c.get(1)) {
                Some(m) => (&span[..m.start()], Some(&span[m.end()..])),
                // Without `do` it is only a loop in an inline script, whose
                // header line ends in a colon. Otherwise it is prose, such as
                // a heredoc line that happens to start with "while".
                None if span.lines().next()?.trim_end().ends_with(':') => (span, None),
                None => return None,
            };
            let kind = match keyword {
                "while" | "until" if !READ.is_match(header) => Kind::Unbounded,
                "for" if INFINITE_FOR.is_match(header) => Kind::Unbounded,
                _ => Kind::Counted,
            };
            Some(Loop {
                kind,
                span,
                header,
                body,
            })
        })
        .collect()
}

/// The `done` that closes a loop opened before `from`, counting the loops
/// opened inside it.
fn matching_done(
    from: usize,
    nested: impl Iterator<Item = usize>,
    dones: &[usize],
) -> Option<usize> {
    let mut nested = nested.peekable();
    let mut depth = 1;
    for &done in dones.iter().filter(|&&done| done >= from) {
        while nested.next_if(|&open| open < done).is_some() {
            depth += 1;
        }
        depth -= 1;
        if depth == 0 {
            return Some(done);
        }
    }
    None
}

fn judge(found: &Loop) -> Option<String> {
    match found.kind {
        Kind::Unbounded => {
            if let Some(probe) = find_probe(found.span) {
                return Some(probe_reason(probe));
            }
            if SLEEP.is_match(found.span) {
                return Some(SLEEP_LOOP.to_string());
            }
            found
                .body
                .is_some_and(is_empty_body)
                .then(|| BUSY_LOOP.to_string())
        }
        Kind::Counted => {
            // The list may run a probe once to enumerate processes. Only a
            // probe between sleeps is a wait.
            let body = found.body?;
            if !SLEEP.is_match(body) {
                return None;
            }
            if let Some(probe) = find_probe(body) {
                return Some(probe_reason(probe));
            }
            let total = iterations(found.header)? as f64 * sleep_seconds(body)?;
            (total > MAX_POLL_SECONDS).then(|| {
                format!(
                    "DENIED: long polling loop.\n\n\
                     This loop can sleep for {total:.0} seconds in total, past the \
                     {MAX_POLL_SECONDS:.0} second\nbudget for probing a condition."
                )
            })
        }
    }
}

fn find_probe(text: &str) -> Option<&'static str> {
    PROBES
        .iter()
        .find(|(pattern, _)| pattern.is_match(text))
        .map(|(_, name)| *name)
}

fn probe_reason(probe: &str) -> String {
    format!(
        "DENIED: loop that polls for a process using {probe}.\n\n\
         A process-existence check in a loop waits on background work, which the\n\
         harness already reports when it finishes."
    )
}

/// A body of nothing but `:` and `true`.
fn is_empty_body(body: &str) -> bool {
    body.split(|c: char| c == ';' || c.is_whitespace())
        .all(|word| word.is_empty() || word == ":" || word == "true")
}

/// How many times a counted loop runs, when its header spells that out.
fn iterations(header: &str) -> Option<u64> {
    let number = |m: Option<regex::Match>| m.and_then(|m| m.as_str().parse::<i64>().ok());
    let count = if let Some(c) = SEQ.captures(header) {
        match (number(c.get(1)), number(c.get(2)), number(c.get(3))) {
            (Some(last), None, None) => last,
            (Some(first), Some(last), None) => last - first + 1,
            (Some(first), Some(step), Some(last)) if step != 0 => (last - first) / step + 1,
            _ => return None,
        }
    } else if let Some(c) = BRACE_RANGE.captures(header) {
        let (first, last) = (number(c.get(1))?, number(c.get(2))?);
        let step = number(c.get(3)).unwrap_or(1).abs().max(1);
        (last - first).abs() / step + 1
    } else if let Some(c) = C_STYLE_RANGE.captures(header) {
        let (first, last) = (number(c.get(1))?, number(c.get(3))?);
        last - first + i64::from(&c[2] == "<=")
    } else {
        // A literal word list: anything expanded at runtime is unknowable.
        let list = WORD_LIST.captures(header)?.get(1)?.as_str();
        if list.contains(['$', '{', '*', '?', '[', '`']) {
            return None;
        }
        list.split_whitespace().count() as i64
    };
    u64::try_from(count.max(0)).ok()
}

/// Seconds the first literal `sleep` in a body waits.
fn sleep_seconds(body: &str) -> Option<f64> {
    let c = SLEEP_SECONDS.captures(body)?;
    let value: f64 = c[1].parse().ok()?;
    let unit = match &c[2] {
        "m" => 60.0,
        "h" => 3600.0,
        "d" => 86400.0,
        _ => 1.0,
    };
    Some(value * unit)
}

/// A follow (`tail -f`, `tailf`, `inotifywait`, `less +F`) of a path under
/// /tmp, wherever it sits in a command: behind `timeout` or `sudo`, in a
/// subshell, or with the path quoted.
fn follows_tmp(command: &str) -> bool {
    command
        .split(['\n', ';', '|', '&', '(', ')', '`'])
        .any(|segment| {
            let words: Vec<&str> = segment
                .split_whitespace()
                .map(|word| word.trim_matches(['\'', '"']))
                .collect();
            let watches_tmp = words
                .iter()
                .any(|word| TMP_PREFIXES.iter().any(|prefix| word.starts_with(prefix)));
            watches_tmp
                && words.iter().enumerate().any(|(index, word)| {
                    let rest = &words[index + 1..];
                    match word.rsplit('/').next().unwrap_or(word) {
                        "tail" => rest.iter().any(|word| is_follow_flag(word)),
                        "less" => rest.contains(&"+F"),
                        "tailf" | "inotifywait" => true,
                        _ => false,
                    }
                })
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
    fn denies_sleep_loops_even_when_bounded() {
        assert!(denied("until [ -s out.txt ]; do sleep 5; done"));
        assert!(denied("while true; do\n  sleep 1\ndone"));
        assert!(denied("bash -c 'while true; do sleep 1; done'"));
        assert!(denied("x=$(until test -f y; do sleep 1; done)"));
        assert!(denied(
            "timeout 600 bash -c 'until grep -q Tests: t.log; do sleep 5; done'"
        ));
        assert!(denied("while true; do echo not done yet; sleep 5; done"));
        assert!(denied("while ! test -f x; do /bin/sleep 1; done"));
        assert!(denied("for ((;;)); do sleep 1; done"));
    }

    #[test]
    fn denies_sleep_loops_in_inline_scripts() {
        assert!(denied(
            "python3 - <<'EOF'\nimport time\nwhile True:\n    time.sleep(1)\nEOF"
        ));
    }

    #[test]
    fn ignores_prose_that_starts_a_line_with_while() {
        assert!(!denied(
            "git commit -F - <<'EOF'\nKeep the worker alive\n\nwhile the build sleeps between retries.\nEOF"
        ));
    }

    #[test]
    fn denies_busy_waits() {
        assert!(denied("while ! test -f x; do :; done"));
        assert!(denied("until [ -s out ]; do true; done"));
    }

    #[test]
    fn allows_loops_that_do_work() {
        assert!(!denied("for f in *.php; do echo $f; done"));
        assert!(!denied("while read -r l; do echo $l; done < in"));
        assert!(!denied(
            "while read -r url; do curl $url; sleep 1; done < urls"
        ));
        assert!(!denied("i=0; while [ $i -lt 5 ]; do i=$((i+1)); done"));
        assert!(!denied("sleep 2 && ls"));
        assert!(!denied("echo 'wait until ready'; sleep 1"));
    }

    #[test]
    fn allows_short_counted_polls() {
        assert!(!denied(
            "for i in $(seq 20); do curl -sf localhost:8080 && break; sleep 3; done"
        ));
        assert!(!denied(
            "for i in 1 2 3; do nc -z db 5432 && break; sleep 2; done"
        ));
        assert!(!denied(
            "for i in $(seq $n); do probe && break; sleep 1; done"
        ));
    }

    #[test]
    fn denies_counted_polls_past_the_budget() {
        assert!(denied(
            "for i in $(seq 100); do curl -sf x && break; sleep 5; done"
        ));
        assert!(denied(
            "for i in {1..20}; do check && break; sleep 1m; done"
        ));
        assert!(denied(
            "for ((i=0; i<60; i++)); do check && break; sleep 10; done"
        ));
    }

    #[test]
    fn denies_process_probes_in_a_loop() {
        assert!(denied("while pgrep -f cargo; do sleep 5; done"));
        assert!(denied(
            "timeout 60 bash -c 'while kill -0 $PID; do sleep 1; done'"
        ));
        assert!(denied("until ! ps aux | grep -q phpunit; do sleep 2; done"));
        assert!(denied("while pidof node >/dev/null; do :; done"));
        assert!(denied("while ps -p $PID >/dev/null; do echo .; done"));
        assert!(denied("while [ -d /proc/$pid ]; do echo .; done"));
        assert!(denied("while test -e \"/proc/${PID}\"; do :; done"));
        assert!(denied(
            "for i in $(seq 5); do pgrep -f build || break; sleep 1; done"
        ));
    }

    #[test]
    fn scopes_probes_to_the_loop_that_holds_them() {
        assert!(!denied("pgrep -x claude"));
        assert!(!denied(
            "while [ $p -gt 1 ]; do p=$(ppid $p); done; pgrep -x claude"
        ));
        assert!(!denied("for pid in $(pgrep node); do kill $pid; done"));
        assert!(!denied(
            "while [ $p -gt 1 ]; do cat /proc/$p/comm; p=$(awk '{print $4}' /proc/$p/stat); done"
        ));
        assert!(denied(
            "timeout 60 bash -c 'while true; do for i in 1; do :; done; kill -0 $P || break; sleep 1; done'"
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
        assert!(denied("timeout 600 tail -f /tmp/build.log"));
        assert!(denied("(tail -f /tmp/build.log)"));
        assert!(denied("x=$(sudo tail -f \"/tmp/build.log\")"));
        assert!(denied("tail -f $TMPDIR/build.log"));
        assert!(denied("less +F /tmp/build.log"));
    }

    #[test]
    fn allows_other_reads_of_tmp_and_follows_elsewhere() {
        assert!(!denied("tail -n 50 /tmp/x.log"));
        assert!(!denied("cat /tmp/x.log"));
        assert!(!denied("tail -f /var/log/nginx/error.log"));
        assert!(!denied("tail -f storage/tmp/x.log"));
    }

    #[test]
    fn strips_only_real_comments() {
        assert!(!denied("ls # while we sleep here nothing loops"));
        assert!(!denied("ls # tail -f /tmp/x.log"));
        assert!(denied("while [ ${#pids[@]} -gt 0 ]; do sleep 1; done"));
        assert!(denied("echo '#'; while true; do sleep 1; done"));
        assert!(denied("echo \"a # b\"; while true; do sleep 1; done"));
        assert!(denied("echo \\#; while true; do sleep 1; done"));
    }

    #[test]
    fn pairs_nested_loops_with_their_own_done() {
        let command = "while true; do for i in 1 2; do echo $i; done; sleep 1; done";
        let found = loops(command);
        assert_eq!(found[0].kind, Kind::Unbounded);
        assert!(found[0].span.ends_with("sleep 1; "));
        assert_eq!(found[1].kind, Kind::Counted);
        assert_eq!(found[1].body, Some(" echo $i; "));
    }

    #[test]
    fn counts_iterations() {
        assert_eq!(iterations(" i in $(seq 20); "), Some(20));
        assert_eq!(iterations(" i in $(seq 5 10); "), Some(6));
        assert_eq!(iterations(" i in $(seq 0 5 100); "), Some(21));
        assert_eq!(iterations(" i in {1..10}; "), Some(10));
        assert_eq!(iterations(" ((i=0; i<=9; i++)); "), Some(10));
        assert_eq!(iterations(" i in a b c; "), Some(3));
        assert_eq!(iterations(" f in *.log; "), None);
    }
}
