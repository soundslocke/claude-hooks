//! Deny PHP test and migration runs while vendor/ lags composer.lock.
//!
//! A pull or merge that changes composer.lock leaves vendor/ on the old
//! versions, and tests or migrations that need the new ones fail in ways that
//! hide the cause. Comparing the lock with vendor/composer/installed.json names
//! it before the run starts.
//!
//! The project is the nearest ancestor holding composer.lock of the cwd, a `cd`
//! target or an `artisan` path. Unreadable files pass silently.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::payload::Payload;
use crate::remote_access::{resolve, CD};

/// Drifted packages listed in the reason before the rest are summarized.
const SHOWN: usize = 5;

static RUNNER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?P<artisan>[^\s;&|()'`]*artisan)\s+(?:test|migrate\S*|dusk)\b|(?:^|[\s;&|(/])(?:pest|phpunit|paratest)(?:\s|$)",
    )
    .unwrap()
});

const DENY: &str = "DENIED: vendor/ is out of sync with composer.lock.";

const ADVICE: &str = "Run `composer install` in that directory first. It installs exactly what the
lock pins and changes no dependency. A merge, pull or checkout that changes
composer.lock leaves vendor/ behind, and code or migrations that expect the new
versions then fail. A test suite that rebuilds its database per test retries the
failing migration every time, so the run looks hung rather than failing fast.";

pub fn check(payload: &Payload) -> Option<String> {
    let command = &payload.command;
    // Cheap substring test first; nearly every command skips the regexes.
    if !["artisan", "pest", "phpunit", "paratest"]
        .iter()
        .any(|word| command.contains(word))
    {
        return None;
    }
    let runners: Vec<regex::Captures> = RUNNER.captures_iter(command).collect();
    if runners.is_empty() {
        return None;
    }

    let cwd = PathBuf::from(&payload.cwd);
    let mut bases = vec![cwd.clone()];
    for dir in CD.captures_iter(command) {
        bases.push(resolve(&dir[1], &cwd));
    }
    for runner in &runners {
        if let Some(artisan) = runner.name("artisan") {
            if let Some(dir) = Path::new(artisan.as_str()).parent() {
                for base in bases.clone() {
                    bases.push(resolve(&dir.to_string_lossy(), &base));
                }
            }
        }
    }

    let mut projects: Vec<PathBuf> = Vec::new();
    for base in bases.iter().rev() {
        if let Some(project) = base
            .ancestors()
            .find(|dir| dir.join("composer.lock").is_file())
        {
            if !projects.iter().any(|p| p == project) {
                projects.push(project.to_path_buf());
            }
        }
    }
    projects.iter().find_map(|project| {
        let lines = drift(project)?;
        let shown: Vec<String> = lines.iter().take(SHOWN).map(|l| format!("  {l}")).collect();
        let more = match lines.len().saturating_sub(SHOWN) {
            0 => String::new(),
            n => format!("\n  and {n} more"),
        };
        Some(format!(
            "{DENY}\n\nIn {}:\n{}{more}\n\n{ADVICE}",
            project.display(),
            shown.join("\n")
        ))
    })
}

/// How vendor/ differs from the lock, one line per package, or None when they
/// match or either file cannot be read.
fn drift(project: &Path) -> Option<Vec<String>> {
    let lock: Value =
        serde_json::from_slice(&std::fs::read(project.join("composer.lock")).ok()?).ok()?;
    let Ok(bytes) = std::fs::read(project.join("vendor/composer/installed.json")) else {
        return Some(vec!["vendor/ is not installed".to_string()]);
    };
    let installed: Value = serde_json::from_slice(&bytes).ok()?;
    let with_dev = installed
        .get("dev")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let mut have: HashMap<&str, &Value> = HashMap::new();
    for package in installed.get("packages")?.as_array()? {
        have.insert(package.get("name")?.as_str()?, package);
    }

    let mut lines: Vec<String> = Vec::new();
    let mut locked: Vec<&str> = Vec::new();
    let sections: &[&str] = if with_dev {
        &["packages", "packages-dev"]
    } else {
        &["packages"]
    };
    for section in sections {
        let Some(packages) = lock.get(*section).and_then(Value::as_array) else {
            continue;
        };
        for want in packages {
            let Some(name) = want.get("name").and_then(Value::as_str) else {
                continue;
            };
            locked.push(name);
            let wanted = version(want);
            match have.get(name) {
                None => lines.push(format!("{name}: locked {wanted}, not installed")),
                Some(got) if version(got) != wanted => {
                    lines.push(format!(
                        "{name}: locked {wanted}, installed {}",
                        version(got)
                    ));
                }
                Some(got) if reference(got) != reference(want) => {
                    lines.push(format!(
                        "{name}: locked {wanted} at a different commit than installed"
                    ));
                }
                Some(_) => {}
            }
        }
    }
    let mut extra: Vec<&str> = have
        .keys()
        .copied()
        .filter(|n| !locked.contains(n))
        .collect();
    extra.sort_unstable();
    for name in extra {
        lines.push(format!(
            "{name}: installed {}, no longer locked",
            version(have[name])
        ));
    }

    (!lines.is_empty()).then_some(lines)
}

fn version(package: &Value) -> &str {
    package
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("?")
}

/// The commit or dist hash a package was installed from, which tells two
/// installs of one dev branch apart.
fn reference(package: &Value) -> Option<&str> {
    ["source", "dist"]
        .iter()
        .find_map(|key| package.get(*key)?.get("reference")?.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bash_in(cwd: &Path, command: &str) -> Option<String> {
        check(&Payload {
            tool_name: "Bash".to_string(),
            command: command.to_string(),
            cwd: cwd.to_string_lossy().to_string(),
            ..Payload::default()
        })
    }

    /// A scratch project unique to one test, removed when dropped.
    struct Project(PathBuf);

    impl Project {
        fn new(name: &str) -> Project {
            let dir = std::env::temp_dir()
                .join(format!("claude-hooks-vendor-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("app/vendor/composer")).unwrap();
            Project(dir)
        }

        fn app(&self) -> PathBuf {
            self.0.join("app")
        }

        fn lock(&self, packages: &str, dev: &str) {
            let json = format!(r#"{{"packages": [{packages}], "packages-dev": [{dev}]}}"#);
            std::fs::write(self.app().join("composer.lock"), json).unwrap();
        }

        fn installed(&self, packages: &str, dev: bool) {
            let json = format!(r#"{{"packages": [{packages}], "dev": {dev}}}"#);
            std::fs::write(self.app().join("vendor/composer/installed.json"), json).unwrap();
        }
    }

    impl Drop for Project {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn package(name: &str, version: &str, reference: &str) -> String {
        format!(
            r#"{{"name": "{name}", "version": "{version}", "source": {{"reference": "{reference}"}}}}"#
        )
    }

    #[test]
    fn passes_when_vendor_matches_the_lock() {
        let project = Project::new("match");
        let widgets = package("acme/widgets", "v2.0.0", "aaa");
        let faker = package("acme/faker", "v1.0.0", "bbb");
        project.lock(&widgets, &faker);
        project.installed(&format!("{widgets}, {faker}"), true);
        assert!(bash_in(&project.app(), "php artisan test --parallel").is_none());
    }

    #[test]
    fn denies_a_test_run_on_a_stale_package() {
        let project = Project::new("stale");
        project.lock(&package("acme/widgets", "v2.0.0", "aaa"), "");
        project.installed(&package("acme/widgets", "v1.4.0", "zzz"), true);
        let reason = bash_in(&project.app(), "php artisan test --compact").unwrap();
        assert!(reason.starts_with(DENY));
        assert!(reason.contains("acme/widgets: locked v2.0.0, installed v1.4.0"));
        assert!(reason.contains("composer install"));
    }

    #[test]
    fn covers_migrations_and_the_other_runners() {
        let project = Project::new("runners");
        project.lock(&package("acme/widgets", "v2.0.0", "aaa"), "");
        project.installed(&package("acme/widgets", "v1.4.0", "zzz"), true);
        for command in [
            "php artisan migrate",
            "php artisan migrate:status",
            "vendor/bin/pest tests/Feature",
            "./vendor/bin/phpunit",
            "vendor/bin/paratest -p8",
        ] {
            assert!(bash_in(&project.app(), command).is_some(), "{command}");
        }
        for command in [
            "php artisan route:list",
            "git diff composer.lock",
            "cat test.php",
        ] {
            assert!(bash_in(&project.app(), command).is_none(), "{command}");
        }
    }

    #[test]
    fn finds_the_project_from_cd_artisan_paths_and_subdirectories() {
        let project = Project::new("locate");
        project.lock(&package("acme/widgets", "v2.0.0", "aaa"), "");
        project.installed(&package("acme/widgets", "v1.4.0", "zzz"), true);
        let app = project.app().to_string_lossy().to_string();
        assert!(bash_in(&project.0, &format!("cd {app} && php artisan test")).is_some());
        assert!(bash_in(&project.0, "cd app && php artisan test").is_some());
        assert!(bash_in(&project.0, "php app/artisan test").is_some());
        std::fs::create_dir_all(project.app().join("tests")).unwrap();
        assert!(bash_in(&project.app().join("tests"), "php ../artisan test").is_some());
        assert!(bash_in(&project.0, "php artisan test").is_none());
    }

    #[test]
    fn reports_missing_extra_and_moved_packages() {
        let project = Project::new("kinds");
        project.lock(
            &format!(
                "{}, {}",
                package("acme/widgets", "dev-main", "aaa"),
                package("acme/new", "v1.0.0", "ccc")
            ),
            "",
        );
        project.installed(
            &format!(
                "{}, {}",
                package("acme/widgets", "dev-main", "bbb"),
                package("acme/old", "v3.0.0", "ddd")
            ),
            true,
        );
        let reason = bash_in(&project.app(), "php artisan test").unwrap();
        assert!(
            reason.contains("acme/widgets: locked dev-main at a different commit than installed")
        );
        assert!(reason.contains("acme/new: locked v1.0.0, not installed"));
        assert!(reason.contains("acme/old: installed v3.0.0, no longer locked"));
    }

    #[test]
    fn ignores_dev_packages_on_a_no_dev_install() {
        let project = Project::new("nodev");
        let widgets = package("acme/widgets", "v2.0.0", "aaa");
        project.lock(&widgets, &package("acme/faker", "v1.0.0", "bbb"));
        project.installed(&widgets, false);
        assert!(bash_in(&project.app(), "php artisan test").is_none());
    }

    #[test]
    fn denies_when_vendor_is_missing_and_summarizes_long_lists() {
        let project = Project::new("missing");
        project.lock(&package("acme/widgets", "v2.0.0", "aaa"), "");
        let reason = bash_in(&project.app(), "php artisan test").unwrap();
        assert!(reason.contains("vendor/ is not installed"));

        let many: Vec<String> = (0..8)
            .map(|i| package(&format!("acme/p{i}"), "v2.0.0", "aaa"))
            .collect();
        project.lock(&many.join(", "), "");
        project.installed("", true);
        let reason = bash_in(&project.app(), "php artisan test").unwrap();
        assert!(reason.contains("and 3 more"));
    }
}
