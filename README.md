# claude-hooks

Claude Code hooks compiled into one static binary. Each hook was a separate
python or bash script under `~/.claude/hooks/`. Spawning an interpreter per
tool call cost 15 to 30 ms, and this runs in under a millisecond.

On PreToolUse the binary reads the payload on stdin, picks the guards for
`tool_name` and prints a `permissionDecision: deny` JSON object when one
objects. Silence means allow. On Stop it prints an advisory list of shells the
session has left running for over 30 minutes, read from `/proc` (Linux only).

| Guard | Tools | Denies |
|---|---|---|
| `commit-msg` | Bash, Monitor | `git commit` messages that break the project format or carry a session link |
| `branch-upstream` | Bash, Monitor | branches created from `origin/<other>` without `--no-track`, and upstream changes to another branch |
| `waiter-loop` | Bash, Monitor | `while`/`until` loops that sleep (`timeout` or not), spin, or probe for a process (`pgrep`, `kill -0`), `for` loops that poll past five minutes, and follows of files under `/tmp` |
| `query-budget` | Bash, Monitor, Boost `database-query` | `artisan tinker` without `--execute`; tinker and `mysql`/`mariadb` runs not bounded to two minutes by both `timeout` and a server-side `max_statement_time` or `MAX_EXECUTION_TIME` hint; `database-query` SELECTs without a `MAX_EXECUTION_TIME` hint of at most 120000 |
| `emdash` | Write, Edit, MultiEdit | an em dash entering any file |

## Install

```
just install
```

That runs the tests, builds the release binary and installs it to
`~/.claude/hooks/claude-hooks`. `just check` reports whether the installed
binary matches the current build.

`~/.claude/settings.json` points the PreToolUse matcher
`Bash|Monitor|Write|Edit|MultiEdit|mcp__laravel-boost__database-query` and the
Stop hook at that path. Pass a guard name as the only argument to run just that
guard, which the tests and benchmarks use.

## Public repo guard

This repository is public. `githooks/` refuses a commit, commit message or push
that carries a term from `~/.config/claude-hooks/private-terms` (one extended
regex per line, matched case-insensitively). The terms stay outside the repo,
since listing them here would publish them, and a machine without the file
refuses every commit until it exists. `just install` (or `just hooks`) points
`core.hooksPath` at `githooks/`.

## Test

```
cargo test
```
