//! Deny ad-hoc database queries that are not bounded to two minutes.
//!
//! The user's rule: no query may run longer than two minutes without their
//! explicit approval. A subagent's `php artisan tinker <file> | tail` ran its
//! counts, then left the shell waiting on a pipe for half an hour, because
//! tinker given a file drops into its REPL afterwards. Killing a client does
//! not stop MariaDB either: a scan runs on until it next writes to the socket.
//! So every ad-hoc path needs both a client bound and a server bound.
//!
//! Denied shapes:
//!   - `artisan tinker` without `--execute`: a REPL, or a file followed by one.
//!   - `artisan tinker --execute` or the `mysql`/`mariadb` client, unless the
//!     command runs under `timeout` of at most 120 seconds and sets
//!     `max_statement_time` (seconds) or a `MAX_EXECUTION_TIME` hint
//!     (milliseconds) no higher than two minutes.
//!   - A Boost `database-query` that executes a SELECT without a
//!     `MAX_EXECUTION_TIME` hint of at most 120000. SHOW, DESCRIBE and a plain
//!     EXPLAIN do not execute the query and pass.

use std::sync::LazyLock;

use regex::Regex;

use crate::payload::Payload;

pub const MAX_SECONDS: f64 = 120.0;

/// Command position, as in `waiter_loop`, then any `VAR=value` assignments and
/// an optional `timeout` whose duration is captured as `secs` and `unit`.
const PREFIX: &str = r#"(?m)(?:^|[;&|({'"`]|\b(?:do|then|else|elif)\s)\s*(?:\w+=\S*\s+)*(?:timeout\s+(?:-[ks]\s+\S+\s+|--?[\w-]+(?:=\S+)?\s+)*(?P<secs>\d+(?:\.\d+)?)(?P<unit>[smhd]?)\s+)?"#;

static TINKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"{PREFIX}(?:\S*/)?php\S*\s+(?:\S*/)?artisan\s+tinker\b(?P<rest>[^\n;&|]*)"
    ))
    .unwrap()
});
static CLIENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"{PREFIX}(?:\S*/)?(?:mysql|mariadb)(?:\s|$)")).unwrap());
static EXECUTE_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)--execute\b").unwrap());
static STATEMENT_TIME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)max_statement_time\s*=\s*(\d+(?:\.\d+)?)").unwrap());
static EXECUTION_HINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)MAX_EXECUTION_TIME\s*\(\s*(\d+)\s*\)").unwrap());
static LEADING_COMMENTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:\s+|--[^\n]*\n|#[^\n]*\n|/\*[^!+][\s\S]*?\*/)*").unwrap());
static FIRST_WORDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(\w+)(?:\s+(\w+))?").unwrap());

const REPL: &str = "DENIED: `artisan tinker` without `--execute`.

Without `--execute` tinker opens its REPL, and given a file it runs the file and
then waits in the REPL on stdin. Piped into `tail` or `head`, that shell never
exits. Pass the code inline instead:
    timeout 120 php artisan tinker --execute 'DB::statement(\"SET SESSION max_statement_time=120\"); ...'";

const UNBOUNDED: &str = "DENIED: unbounded ad-hoc query.

No query may run longer than two minutes without the user's explicit approval.
Bound both ends:
  - the client: run it under `timeout 120` (or less), so the shell cannot hang;
  - the server: killing the client does not stop MariaDB, so also set
    `SET SESSION max_statement_time=120` first (tinker: a
    `DB::statement(...)` before the queries; mysql: `--init-command=...`),
    or put `/*+ MAX_EXECUTION_TIME(120000) */` right after each SELECT.";

const UNBOUNDED_MCP: &str = "DENIED: database-query without an execution time limit.

No query may run longer than two minutes without the user's explicit approval.
Put the MariaDB hint right after SELECT, for example:
    SELECT /*+ MAX_EXECUTION_TIME(120000) */ COUNT(*) FROM orders WHERE ...
SHOW, DESCRIBE and a plain EXPLAIN need no hint.";

const APPROVAL: &str = "If the query may genuinely need longer, estimate its cost (EXPLAIN, row
counts) and ask the user first. Once they approve, ask them to run it with the
`!` prefix rather than raising the bound here.";

pub fn check(payload: &Payload) -> Option<String> {
    let command = &payload.command;
    // Cheap substring test first; nearly every command skips the regexes.
    let lower = command.to_ascii_lowercase();
    if !lower.contains("tinker") && !lower.contains("mysql") && !lower.contains("mariadb") {
        return None;
    }

    let mut timeouts: Vec<Option<f64>> = Vec::new();
    for found in TINKER.captures_iter(command) {
        if !EXECUTE_FLAG.is_match(&found["rest"]) {
            return Some(format!("{REPL}\n\n{APPROVAL}"));
        }
        timeouts.push(seconds(&found));
    }
    for found in CLIENT.captures_iter(command) {
        timeouts.push(seconds(&found));
    }
    if timeouts.is_empty() {
        return None;
    }

    let client_bounded = timeouts
        .iter()
        .all(|limit| limit.is_some_and(|s| s > 0.0 && s <= MAX_SECONDS));
    if client_bounded && server_bounded(command) {
        return None;
    }
    Some(format!("{UNBOUNDED}\n\n{APPROVAL}"))
}

/// The Boost `database-query` MCP tool, which takes raw SQL.
pub fn check_mcp_query(payload: &Payload) -> Option<String> {
    let sql = LEADING_COMMENTS.replace(&payload.query, "");
    let words = FIRST_WORDS.captures(&sql)?;
    let first = words[1].to_ascii_uppercase();
    let second = words
        .get(2)
        .map(|w| w.as_str().to_ascii_uppercase())
        .unwrap_or_default();
    let executes = match first.as_str() {
        "SHOW" | "DESCRIBE" | "DESC" => false,
        "EXPLAIN" => second == "ANALYZE",
        _ => true,
    };
    if !executes || hint_bounded(&sql) {
        return None;
    }
    Some(format!("{UNBOUNDED_MCP}\n\n{APPROVAL}"))
}

/// The `timeout` duration in seconds, None when the command has no timeout.
fn seconds(found: &regex::Captures) -> Option<f64> {
    let value: f64 = found.name("secs")?.as_str().parse().ok()?;
    let scale = match found.name("unit").map_or("", |u| u.as_str()) {
        "m" => 60.0,
        "h" => 3_600.0,
        "d" => 86_400.0,
        _ => 1.0,
    };
    Some(value * scale)
}

/// Every server-side limit in the command is within budget, and there is one.
fn server_bounded(command: &str) -> bool {
    let statement: Vec<f64> = STATEMENT_TIME
        .captures_iter(command)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    let within = |s: &f64| *s > 0.0 && *s <= MAX_SECONDS;
    if !statement.iter().all(within) {
        return false;
    }
    let hinted = EXECUTION_HINT.is_match(command);
    if hinted && !hint_bounded(command) {
        return false;
    }
    !statement.is_empty() || hinted
}

/// Every `MAX_EXECUTION_TIME` hint is within budget, and there is one.
fn hint_bounded(sql: &str) -> bool {
    let hints: Vec<f64> = EXECUTION_HINT
        .captures_iter(sql)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    !hints.is_empty()
        && hints
            .iter()
            .all(|ms| *ms > 0.0 && *ms <= MAX_SECONDS * 1_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bash(command: &str) -> Option<String> {
        check(&Payload {
            tool_name: "Bash".to_string(),
            command: command.to_string(),
            ..Payload::default()
        })
    }

    fn mcp(query: &str) -> Option<String> {
        check_mcp_query(&Payload {
            tool_name: "mcp__laravel-boost__database-query".to_string(),
            query: query.to_string(),
            ..Payload::default()
        })
    }

    const BOUNDED_TINKER: &str = r#"cd /app/laravel && timeout 120 php artisan tinker --execute 'DB::statement("SET SESSION max_statement_time=120"); echo 1;'"#;

    #[test]
    fn denies_tinker_without_execute() {
        let reason = bash("php artisan tinker /tmp/measure.php 2>&1 | tail -20").unwrap();
        assert!(reason.starts_with("DENIED: `artisan tinker` without"));
        assert!(bash("timeout 60 php artisan tinker").is_some());
    }

    #[test]
    fn allows_bounded_tinker() {
        assert!(bash(BOUNDED_TINKER).is_none());
        assert!(bash(r#"DB_DATABASE=x timeout 2m php artisan tinker --execute 'DB::select("SELECT /*+ MAX_EXECUTION_TIME(60000) */ 1");'"#).is_none());
        assert!(bash(r#"timeout -k 5 90 php artisan tinker --execute 'DB::statement("SET SESSION max_statement_time=90");'"#).is_none());
    }

    #[test]
    fn denies_tinker_missing_either_bound() {
        assert!(bash(
            r#"php artisan tinker --execute 'DB::statement("SET SESSION max_statement_time=120");'"#
        )
        .is_some());
        assert!(
            bash(r#"timeout 120 php artisan tinker --execute 'DB::select("SELECT 1");'"#).is_some()
        );
    }

    #[test]
    fn denies_bounds_over_two_minutes() {
        assert!(bash(&BOUNDED_TINKER.replace("timeout 120", "timeout 600")).is_some());
        assert!(bash(&BOUNDED_TINKER.replace("timeout 120", "timeout 3m")).is_some());
        assert!(
            bash(&BOUNDED_TINKER.replace("max_statement_time=120", "max_statement_time=0"))
                .is_some()
        );
        assert!(
            bash(&BOUNDED_TINKER.replace("max_statement_time=120", "max_statement_time=900"))
                .is_some()
        );
        assert!(bash(r#"timeout 120 php artisan tinker --execute 'DB::select("SELECT /*+ MAX_EXECUTION_TIME(600000) */ 1");'"#).is_some());
    }

    #[test]
    fn covers_the_mysql_client() {
        assert!(bash("mysql -e 'SELECT COUNT(*) FROM orders' app").is_some());
        assert!(bash(
            "timeout 120 mariadb --init-command='SET SESSION max_statement_time=120' -e 'SELECT 1'"
        )
        .is_none());
    }

    #[test]
    fn ignores_everything_else() {
        assert!(bash("php artisan test --compact --parallel").is_none());
        assert!(bash("mysqldump --no-data app > schema.sql").is_none());
        assert!(bash("php artisan config:show database.connections.mysql").is_none());
        assert!(bash("grep -rn tinker docs/").is_none());
    }

    #[test]
    fn requires_a_hint_on_executing_mcp_queries() {
        assert!(mcp("SELECT COUNT(*) FROM orders").is_some());
        assert!(mcp("WITH x AS (SELECT 1) SELECT * FROM x").is_some());
        assert!(mcp("EXPLAIN ANALYZE SELECT * FROM orders").is_some());
        assert!(mcp("SELECT /*+ MAX_EXECUTION_TIME(300000) */ 1").is_some());
        assert!(mcp("SELECT /*+ MAX_EXECUTION_TIME(120000) */ COUNT(*) FROM orders").is_none());
        assert!(mcp("-- note\nSELECT /*+ MAX_EXECUTION_TIME(5000) */ 1").is_none());
    }

    #[test]
    fn lets_metadata_mcp_queries_through() {
        assert!(mcp("SHOW INDEX FROM orders").is_none());
        assert!(mcp("DESCRIBE orders").is_none());
        assert!(mcp("EXPLAIN SELECT * FROM orders WHERE id = 1").is_none());
    }
}
