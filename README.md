# claude-hooks

Claude Code PreToolUse guards compiled into one static binary. Each guard was a
separate python or bash script under `~/.claude/hooks/`; spawning an
interpreter per tool call cost 15 to 30 ms, this runs in under a millisecond.

The binary reads the hook payload on stdin, picks the guards for `tool_name`
and prints a `permissionDecision: deny` JSON object when one objects. Silence
means allow.

| Guard | Tools | Denies |
|---|---|---|
| `commit-msg` | Bash, Monitor | `git commit` messages that break the project format or carry a session link |
| `branch-upstream` | Bash, Monitor | branches created from `origin/<other>` without `--no-track`, and upstream changes to another branch |
| `waiter-loop` | Bash, Monitor | `while`/`until` loops on `sleep` with no `timeout` |
| `emdash` | Write, Edit, MultiEdit | an em dash entering a source file |

## Install

```
just install
```

That runs the tests, builds the release binary and installs it to
`~/.claude/hooks/claude-hooks`. `just check` reports whether the installed
binary matches the current build.

`~/.claude/settings.json` points every PreToolUse matcher at that path. Pass a
guard name as the only argument to run just that guard, which the tests and
benchmarks use.

## Test

```
cargo test
```
