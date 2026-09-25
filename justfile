target := "~/.claude/hooks/claude-hooks"

# Test, build, and install the binary Claude Code's PreToolUse hook runs.
install: hooks test build
    install -m 755 target/release/claude-hooks {{target}}

test:
    cargo test

build:
    cargo build --release

# Report whether the installed binary matches the current build.
check:
    @cmp -s target/release/claude-hooks {{target}} && echo "installed binary is current" || echo "installed binary is stale, run: just install"

# Point git at the repo's hooks, which refuse private terms in this public repo.
hooks:
    git config core.hooksPath githooks
