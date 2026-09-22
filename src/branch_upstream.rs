//! Never let a branch track a remote branch of another name.
//!
//! `git checkout -b feature origin/main` (and the switch/branch equivalents)
//! sets branch.feature.merge to origin/main, so the prompt shows
//! `feature:main`, a bare `git push` targets main, and `git status` reports
//! ahead/behind against main. The same mistake arrives via --track,
//! --set-upstream-to and `git push -u` with a mismatched refspec.
//!
//! Remote names and the current branch are read straight from the .git
//! directory so no git process is spawned.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::payload::Payload;

static GIT_SUBCOMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|[\n;|&(]|\|\||&&)\s*(git\s+(?:-\S+\s+)*(checkout|switch|branch|push)\b[^\n;|&]*)",
    )
    .unwrap()
});

pub fn check(payload: &Payload) -> Option<String> {
    // Only the four subcommands can set an upstream; skip the regex otherwise.
    let command = &payload.command;
    if !command.contains("git")
        || !["checkout", "switch", "branch", "push"]
            .iter()
            .any(|s| command.contains(s))
    {
        return None;
    }
    let repo = Repo::discover(Path::new(&payload.cwd));
    let problems = find_problems(&payload.command, &repo);
    if problems.is_empty() {
        return None;
    }
    Some(format!(
        "Branch would track the wrong upstream:\n{}",
        problems
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// What the guard needs to know about the repository the command runs in.
struct Repo {
    remotes: HashSet<String>,
    current_branch: String,
}

impl Repo {
    fn discover(cwd: &Path) -> Repo {
        let fallback = Repo {
            remotes: HashSet::from(["origin".to_string()]),
            current_branch: String::new(),
        };
        let Some(git_dir) = find_git_dir(cwd) else {
            return fallback;
        };

        // A worktree's gitdir holds HEAD; its config lives in the common dir.
        let common_dir = fs::read_to_string(git_dir.join("commondir"))
            .map(|rel| git_dir.join(rel.trim()))
            .unwrap_or_else(|_| git_dir.clone());

        let remotes: HashSet<String> = fs::read_to_string(common_dir.join("config"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("[remote \"")
                    .and_then(|rest| rest.strip_suffix("\"]"))
                    .map(str::to_string)
            })
            .collect();

        let current_branch = fs::read_to_string(git_dir.join("HEAD"))
            .ok()
            .and_then(|head| {
                head.trim()
                    .strip_prefix("ref: refs/heads/")
                    .map(str::to_string)
            })
            .unwrap_or_default();

        Repo {
            remotes: if remotes.is_empty() {
                fallback.remotes
            } else {
                remotes
            },
            current_branch,
        }
    }
}

fn find_git_dir(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.as_os_str().is_empty() {
        std::env::current_dir().ok()?
    } else {
        start.to_path_buf()
    };
    loop {
        let candidate = dir.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if candidate.is_file() {
            let pointer = fs::read_to_string(&candidate).ok()?;
            let target = pointer.trim().strip_prefix("gitdir:")?.trim();
            let path = Path::new(target);
            return Some(if path.is_absolute() {
                path.to_path_buf()
            } else {
                dir.join(path)
            });
        }
        dir = dir.parent()?.to_path_buf();
    }
}

fn split_remote_ref<'a>(
    reference: &'a str,
    remotes: &HashSet<String>,
) -> Option<(&'a str, &'a str)> {
    let reference = reference.strip_prefix("refs/remotes/").unwrap_or(reference);
    let (remote, branch) = reference.split_once('/')?;
    (remotes.contains(remote) && !branch.is_empty()).then_some((remote, branch))
}

fn find_problems(command: &str, repo: &Repo) -> Vec<String> {
    let mut problems = Vec::new();
    for caps in GIT_SUBCOMMAND.captures_iter(command) {
        let Some(words) = shlex::split(&caps[1]) else {
            continue;
        };
        let subcommand = &caps[2];
        let Some(index) = words.iter().position(|w| w == subcommand) else {
            continue;
        };
        let args: Vec<&str> = words[index + 1..].iter().map(String::as_str).collect();

        let problem = match subcommand {
            "push" => check_push(&args, repo),
            "branch" if args.iter().any(|a| is_set_upstream_flag(a)) => {
                check_set_upstream(&args, repo)
            }
            _ => check_create(subcommand, &args, &repo.remotes),
        };
        if let Some(problem) = problem {
            problems.push(problem);
        }
    }
    problems
}

fn is_set_upstream_flag(arg: &str) -> bool {
    arg == "-u" || arg == "--set-upstream-to" || arg.starts_with("--set-upstream-to=")
}

/// checkout -b / switch -c / branch <name> [<start-point>].
fn check_create(subcommand: &str, args: &[&str], remotes: &HashSet<String>) -> Option<String> {
    let create_flags: &[&str] = match subcommand {
        "checkout" => &["-b", "-B"],
        "switch" => &["-c", "-C"],
        _ => &[],
    };

    let mut positional: Vec<&str> = Vec::new();
    let mut new_name: Option<&str> = None;
    let mut no_track = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--no-track" {
            no_track = true;
        } else if create_flags.contains(&arg) {
            i += 1;
            new_name = args.get(i).copied();
        } else if !arg.starts_with('-') {
            positional.push(arg);
        }
        i += 1;
    }

    let (new_name, start_point) = if subcommand == "branch" {
        (positional.first().copied(), positional.get(1).copied())
    } else {
        (new_name, positional.first().copied())
    };
    let (new_name, start_point) = (new_name?, start_point?);
    if no_track {
        return None;
    }

    let (remote, branch) = split_remote_ref(start_point, remotes)?;
    if branch == new_name {
        return None;
    }

    let create_flag = match subcommand {
        "checkout" => "-b ",
        "switch" => "-c ",
        _ => "",
    };
    Some(format!(
        "`{new_name}` would track {remote}/{branch}: git sets the upstream whenever a\n  \
         branch starts from a remote-tracking ref. Use:\n    \
         git {subcommand} {create_flag}{new_name} --no-track {start_point}"
    ))
}

/// branch --set-upstream-to=<ref> / -u <ref> [<branch>].
fn check_set_upstream(args: &[&str], repo: &Repo) -> Option<String> {
    let mut target: Option<&str> = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if let Some(value) = arg.strip_prefix("--set-upstream-to=") {
            target = Some(value);
        } else if arg == "-u" || arg == "--set-upstream-to" {
            i += 1;
            target = args.get(i).copied();
        } else if !arg.starts_with('-') {
            positional.push(arg);
        }
        i += 1;
    }

    let (remote, branch) = split_remote_ref(target?, &repo.remotes)?;
    let local = positional.first().copied().unwrap_or(&repo.current_branch);
    if local.is_empty() || branch == local {
        return None;
    }
    Some(format!(
        "`{local}` would track {remote}/{branch}. A branch's upstream must be its own\n  \
         remote counterpart ({remote}/{local}), or nothing until it is first pushed."
    ))
}

/// push -u/--set-upstream <remote> <refspec> with a mismatched destination.
fn check_push(args: &[&str], repo: &Repo) -> Option<String> {
    if !args.iter().any(|a| *a == "-u" || *a == "--set-upstream") {
        return None;
    }
    let positional: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .collect();
    if positional.len() < 2 || !repo.remotes.contains(positional[0]) {
        return None;
    }
    let remote = positional[0];
    let local = repo.current_branch.as_str();
    if local.is_empty() {
        return None;
    }
    for refspec in &positional[1..] {
        let (src, dst) = match refspec.split_once(':') {
            Some((src, dst)) => (src, Some(dst)),
            None => (*refspec, None),
        };
        let src = if src.is_empty() || src == "HEAD" {
            local
        } else {
            src
        };
        let dst = dst.unwrap_or(src);
        if dst != src {
            return Some(format!(
                "`push -u` would make `{local}` track {remote}/{dst}. Push a branch to\n  \
                 its own name: git push -u {remote} {local}"
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> Repo {
        Repo {
            remotes: HashSet::from(["origin".to_string()]),
            current_branch: "fix-widget".to_string(),
        }
    }

    fn denied(command: &str) -> bool {
        !find_problems(command, &repo()).is_empty()
    }

    #[test]
    fn denies_branches_created_from_another_remote_branch() {
        assert!(denied("git checkout -b fix-x origin/main"));
        assert!(denied(
            "git fetch origin -q && git checkout -b fix-x origin/main 2>&1 | tail -2"
        ));
        assert!(denied("git switch -c fix-x origin/main"));
        assert!(denied("git branch fix-x origin/main"));
        assert!(denied("git checkout --track origin/main -b fix-x"));
        assert!(denied("git checkout -b fix-x refs/remotes/origin/main"));
    }

    #[test]
    fn allows_no_track_local_start_points_and_same_name() {
        assert!(!denied("git checkout -b fix-x --no-track origin/main"));
        assert!(!denied("git switch -c fix-x --no-track origin/main"));
        assert!(!denied("git branch --no-track fix-x origin/main"));
        assert!(!denied("git checkout -b fix-x origin/fix-x"));
        assert!(!denied("git checkout -b fix-x"));
        assert!(!denied("git checkout -b fix-x main"));
        assert!(!denied("git checkout main"));
        assert!(!denied("git status"));
    }

    #[test]
    fn denies_set_upstream_to_another_branch() {
        assert!(denied("git branch --set-upstream-to=origin/main"));
        assert!(denied("git branch -u origin/main fix-x"));
        assert!(!denied("git branch -u origin/fix-widget"));
        assert!(!denied("git branch --unset-upstream"));
    }

    #[test]
    fn denies_push_u_with_mismatched_destination() {
        assert!(denied("git push -u origin HEAD:main"));
        assert!(denied("git push --set-upstream origin fix-widget:main"));
        assert!(!denied("git push -u origin fix-widget"));
        assert!(!denied("git push -u origin HEAD"));
        assert!(!denied("git push -u origin main"));
        assert!(!denied("git push origin fix-widget"));
    }

    #[test]
    fn ignores_git_inside_quoted_strings() {
        assert!(!denied("echo \"git checkout -b foo origin/main\""));
    }

    #[test]
    fn suggests_the_no_track_form() {
        let problems = find_problems("git checkout -b fix-x origin/main", &repo());
        assert!(problems[0].contains("git checkout -b fix-x --no-track origin/main"));
    }

    #[test]
    fn unknown_remote_is_not_a_remote_ref() {
        let repo = Repo {
            remotes: HashSet::from(["upstream".to_string()]),
            current_branch: String::new(),
        };
        assert!(find_problems("git checkout -b x origin/main", &repo).is_empty());
        assert!(!find_problems("git checkout -b x upstream/main", &repo).is_empty());
    }
}
