//! Ask before any command that could reach another machine over ssh, rsync,
//! or a similar remote shell, tunnel or file transfer.
//!
//! The user's rule: Claude never connects to a server on its own, not even for
//! a read-only probe. It once ran three `ssh` probes against a live host to
//! look for files the user had not asked it to fetch. This guard answers `ask`
//! rather than `deny`, so every such command waits on a yes/no prompt and a
//! connection the user did ask for still goes through with their consent.
//!
//! Matching is deliberately broad. A program name counts wherever it stands as
//! a whole word once quotes and backslashes are removed, so `sudo ssh`,
//! `/usr/bin/ssh`, `bash -c "ssh ..."`, `X=ssh` and `s''sh` all ask, and so
//! does prose that merely mentions one. A script the command runs, as its
//! program or through a launcher such as `bash`, `nu` or `sudo`, is read and
//! checked the same way, which catches a `fetch.nu` that runs `scp`. A file the
//! command only reads, as `grep` or `wc` would, is data and is not checked. A
//! false positive costs one prompt; a miss costs a connection nobody approved.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::payload::Payload;

const PROGRAMS: &[&str] = &[
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "sshfs",
    "sshpass",
    "ssh-copy-id",
    "autossh",
    "mosh",
    "telnet",
    "rsh",
    "rlogin",
    "rcp",
    "ftp",
    "lftp",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "pssh",
    "parallel-ssh",
    "pdsh",
    "ansible",
    "ansible-playbook",
];

/// Bash opens a raw socket for a redirect to one of these, with no program.
const DEVICES: &[&str] = &["/dev/tcp/", "/dev/udp/"];

/// Commands that run the word after them as a program or script. A version
/// suffix is ignored, so `python3` and `php8.3` count.
const LAUNCHERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "time", "nice", "ionice", "exec", "command", "builtin",
    "timeout", "xargs", "stdbuf", "watch", "source", ".", "sh", "bash", "zsh", "dash", "ksh",
    "fish", "nu", "python", "php", "perl", "ruby", "node", "deno", "bun", "tsx", "ts-node",
];
/// Shell keywords that can stand before a segment's program.
const KEYWORDS: &[&str] = &["if", "then", "elif", "else", "while", "until", "do", "!", "{"];
/// Launcher options that take the next word as their value, as in
/// `sudo -u deploy` or `xargs -n 1`.
const VALUE_OPTIONS: &[&str] = &["-u", "-g", "-n", "-k", "-C", "-I", "-P", "-m"];
const MAX_SCRIPT_BYTES: u64 = 256 * 1024;

/// A whole word as a program name is spelled; `-` and `.` stay inside it so
/// `ssh-keygen` and `~/.ssh` are not mistaken for `ssh`.
static WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9_.+-]+").unwrap());
/// Separators between simple commands, each of which runs one program.
static SEGMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[;&|()`\n]+").unwrap());
/// A count or duration such as `timeout 5s` takes.
static NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9.]+[smhd]?$").unwrap());
pub(crate) static CD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[;&|(])\s*cd\s+([^\s;&|)]+)").unwrap());

const ASK: &str = "CONFIRM: this command may connect to another machine.

Claude must never ssh, rsync, scp or otherwise reach a server on its own, not
even to read a file or list a directory. Approve only if you asked for this
exact connection. Otherwise decline, and Claude should write the command out
for you to run with the `!` prefix.";

pub fn check(payload: &Payload) -> Option<String> {
    let mut found = remote_programs(&payload.command);
    for script in scripts(&payload.command, &payload.cwd) {
        let Ok(bytes) = std::fs::read(&script) else {
            continue;
        };
        for program in remote_programs(&String::from_utf8_lossy(&bytes)) {
            found.push(format!("{program} (in {})", script.display()));
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(format!("{ASK}\n\nMatched: {}", found.join(", ")))
}

/// Each remote program or socket device named in `text`, once, in order.
fn remote_programs(text: &str) -> Vec<String> {
    let plain = unquote(text);
    let mut found: Vec<String> = Vec::new();
    let mut add = |name: &str| {
        if !found.iter().any(|f| f == name) {
            found.push(name.to_string());
        }
    };
    for word in WORD.find_iter(&plain) {
        if PROGRAMS.contains(&word.as_str()) {
            add(word.as_str());
        }
    }
    for device in DEVICES {
        if plain.contains(device) {
            add(device);
        }
    }
    found
}

/// Script files the command runs: a path it executes, or a file a launcher
/// such as `bash` or `nu` runs. Files it only reads are left alone.
fn scripts(command: &str, cwd: &str) -> Vec<PathBuf> {
    let plain = unquote(command);
    let mut bases = vec![PathBuf::from(cwd)];
    for dir in CD.captures_iter(&plain) {
        bases.push(resolve(&dir[1], &bases[0]));
    }

    let mut found: Vec<PathBuf> = Vec::new();
    for segment in SEGMENT.split(&plain) {
        let Some((program, launched)) = program_of(segment) else {
            continue;
        };
        // A bare name runs from PATH unless a launcher reads it as a file.
        if !launched && !program.contains('/') {
            continue;
        }
        for base in &bases {
            let path = resolve(program, base);
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            let runnable = launched || meta.permissions().mode() & 0o111 != 0;
            if meta.is_file() && meta.len() <= MAX_SCRIPT_BYTES && runnable {
                if !found.contains(&path) {
                    found.push(path);
                }
                break;
            }
        }
    }
    found
}

/// The word a simple command runs as its program, past any assignments,
/// keywords, launchers and their options, and whether a launcher ran it.
fn program_of(segment: &str) -> Option<(&str, bool)> {
    let mut launched = false;
    let mut words = segment.split_whitespace();
    while let Some(word) = words.next() {
        let passed = word.contains('=')
            || word.starts_with('-')
            || NUMBER.is_match(word)
            || KEYWORDS.contains(&word);
        if VALUE_OPTIONS.contains(&word) {
            words.next();
        } else if is_launcher(word) {
            launched = true;
        } else if !passed {
            return Some((word, launched));
        }
    }
    None
}

fn is_launcher(word: &str) -> bool {
    let name = word.rsplit('/').next().unwrap_or(word);
    let unversioned = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    LAUNCHERS.contains(&name) || LAUNCHERS.contains(&unversioned)
}

/// Removes the quoting and escapes a shell would, so `s''sh` reads as `ssh`.
fn unquote(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect()
}

pub(crate) fn resolve(path: &str, base: &Path) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    for prefix in ["~/", "$HOME/", "${HOME}/"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return Path::new(&home).join(rest);
        }
    }
    base.join(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bash_in(cwd: &str, command: &str) -> Option<String> {
        check(&Payload {
            tool_name: "Bash".to_string(),
            command: command.to_string(),
            cwd: cwd.to_string(),
            ..Payload::default()
        })
    }

    fn bash(command: &str) -> Option<String> {
        bash_in("", command)
    }

    /// A scratch directory unique to one test, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir = std::env::temp_dir()
                .join(format!("claude-hooks-remote-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn write(&self, name: &str, content: &str, mode: u32) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn asks_for_plain_remote_commands() {
        let reason = bash("ssh -p 2222 deploy@example.com 'ls /srv/app'").unwrap();
        assert!(reason.starts_with("CONFIRM:"));
        assert!(reason.ends_with("Matched: ssh"));
        assert!(bash("scp -P 2222 deploy@example.com:/srv/a.txt ./a.txt").is_some());
        assert!(bash("rsync -av ./dist/ deploy@example.com:/srv/app/").is_some());
        assert!(bash("rsync -a src/ backup/").is_some());
        assert!(bash("sftp deploy@example.com").is_some());
        assert!(bash("ssh-copy-id deploy@example.com").is_some());
        assert!(bash("nc -z example.com 22").is_some());
        assert!(bash("curl -O sftp://example.com/a.txt").is_some());
    }

    #[test]
    fn asks_wherever_the_program_stands() {
        assert!(bash("/usr/bin/ssh example.com").is_some());
        assert!(bash("sudo ssh example.com").is_some());
        assert!(bash("timeout 5 ssh example.com uptime").is_some());
        assert!(bash("cd /srv && env FOO=1 ssh example.com").is_some());
        assert!(bash(r#"bash -c "ssh example.com""#).is_some());
        assert!(bash("echo example.com | xargs -I{} ssh {} uptime").is_some());
        assert!(bash("H=example.com; X=ssh; $X $H").is_some());
        assert!(bash("git -c core.sshCommand=ssh fetch").is_some());
        assert!(bash("echo $(which ssh)").is_some());
        assert!(bash("ls\nssh example.com").is_some());
    }

    #[test]
    fn sees_through_quoting_and_escapes() {
        assert!(bash("s''sh example.com").is_some());
        assert!(bash(r#"s""sh example.com"#).is_some());
        assert!(bash(r"s\sh example.com").is_some());
        assert!(bash(r"r\sync -a a/ example.com:b/").is_some());
    }

    #[test]
    fn asks_for_bash_network_redirects() {
        let reason = bash("exec 3<>/dev/tcp/example.com/22").unwrap();
        assert!(reason.ends_with("Matched: /dev/tcp/"));
    }

    #[test]
    fn reads_scripts_the_command_names() {
        let scratch = Scratch::new("scripts");
        let dir = scratch.0.to_str().unwrap();
        scratch.write(
            "fetch.nu",
            "scp -P 2222 deploy@example.com:/a.txt .\n",
            0o644,
        );
        scratch.write("tool", "#!/bin/sh\nrsync -a a/ example.com:b/\n", 0o755);
        scratch.write("notes", "rsync later\n", 0o644);
        scratch.write("build.sh", "cargo build\n", 0o755);

        let reason = bash_in(dir, "nu fetch.nu").unwrap();
        assert!(reason.contains("scp (in "));
        assert!(bash_in(dir, "./tool --flag").is_some());
        assert!(bash(&format!("cd {dir} && nu ./fetch.nu")).is_some());
        assert!(bash(&format!("{dir}/tool")).is_some());
        assert!(bash_in(dir, "./build.sh").is_none());
        assert!(bash_in(dir, "wc -l ./notes").is_none());
    }

    #[test]
    fn reads_scripts_however_they_are_launched() {
        let scratch = Scratch::new("launched");
        let dir = scratch.0.to_str().unwrap();
        scratch.write("fetch.nu", "scp deploy@example.com:/a.txt .\n", 0o644);
        scratch.write("tool", "#!/bin/sh\nrsync -a a/ example.com:b/\n", 0o755);

        assert!(bash_in(dir, "sudo -u deploy nu fetch.nu").is_some());
        assert!(bash_in(dir, "timeout 5s ./tool").is_some());
        assert!(bash_in(dir, "/usr/bin/env FOO=1 python3 fetch.nu").is_some());
        assert!(bash_in(dir, "source fetch.nu").is_some());
        assert!(bash_in(dir, ". ./fetch.nu").is_some());
        assert!(bash_in(dir, "if ./tool; then echo ok; fi").is_some());
        assert!(bash_in(dir, "ls | xargs -n 1 ./tool").is_some());
        assert!(bash_in(dir, "echo $(./tool)").is_some());
    }

    #[test]
    fn ignores_scripts_the_command_only_reads() {
        let scratch = Scratch::new("read");
        let app = scratch.0.join("app");
        std::fs::create_dir_all(app.join("config")).unwrap();
        // A state list in a regex names `nc`, as North Carolina.
        std::fs::write(app.join("config/states.php"), "'/(ca|nc|ny)/'\n").unwrap();
        scratch.write("fetch.nu", "scp deploy@example.com:/a.txt .\n", 0o755);
        let dir = scratch.0.to_str().unwrap();

        let read = format!(
            "cd {}; ls config/states.php 2>&1; grep -n x config/states.php; wc -l config/states.php",
            app.display()
        );
        assert!(bash(&read).is_none());
        assert!(bash_in(dir, "grep -n deploy fetch.nu").is_none());
        assert!(bash_in(dir, "cat ./fetch.nu | head").is_none());
        assert!(bash_in(dir, "cp fetch.nu fetch.nu.bak").is_none());
    }

    #[test]
    fn ignores_local_ssh_tooling() {
        assert!(bash("ssh-keygen -l -f key.pub").is_none());
        assert!(bash("ssh-add -l").is_none());
        assert!(bash("ls -la ~/.ssh/").is_none());
        assert!(bash("grep -n Host sshd_config").is_none());
    }

    #[test]
    fn ignores_everything_else() {
        assert!(bash("git status && git log --oneline -5").is_none());
        assert!(bash("npm test").is_none());
        assert!(bash("node blast.js -c campaigns/x/settings.json --test").is_none());
        assert!(bash("cargo build --release").is_none());
        assert!(bash("grep -rn sync src/").is_none());
    }
}
