//! `scan`: repository guardrails against the committed base, then every source
//! file through its language's project-wide tools. Also `init`.

use crate::config::{self, Config};
use crate::git::{self, FileChange, git_output};
use crate::hook::{self, run_command};
use crate::proc::{self, Deadline};
use crate::rules;
use crate::{CheckError, MAX_VIOLATIONS};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const COMMAND_GROUPS: [&str; 4] = ["contract", "property", "differential", "mutation"];

fn configured_commands(config: &Config, group: &str) -> Vec<Vec<String>> {
    config
        .get("commands")
        .and_then(|c| c.get(group))
        .and_then(Value::as_array)
        .map(|commands| {
            commands
                .iter()
                .map(|c| {
                    c.as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Net-new built-in content findings across changed text files.
fn changed_content_violations(changes: &[FileChange]) -> Result<Vec<String>, CheckError> {
    let mut pairs = Vec::new();
    for change in changes {
        let Some(after) = &change.after else { continue };
        if after.len() > 4 * 1024 * 1024 {
            continue;
        }
        let before = String::from_utf8(change.before.clone().unwrap_or_default());
        let after = String::from_utf8(after.clone());
        if let (Ok(before), Ok(after)) = (before, after) {
            pairs.push((change.path.clone(), before, after));
        }
    }
    rules::content_rule_violations(&pairs, false)
}

fn expand_command(command: &[String], base: Option<&str>, paths: &[String]) -> Option<Vec<String>> {
    let mut expanded = Vec::new();
    for part in command {
        match part.as_str() {
            "{base}" => expanded.push(base.filter(|b| !b.is_empty())?.to_string()),
            "{files}" => expanded.extend(paths.iter().cloned()),
            _ => expanded.push(part.clone()),
        }
    }
    Some(expanded)
}

fn wrap_mutation_command(mut bounded: Vec<String>) -> Result<Vec<String>, String> {
    if proc::which("systemd-run").is_none() {
        return Err("mutation: systemd-run is required for the 8 GB memory limit".into());
    }
    if bounded.iter().any(|p| p == "mutmut") && bounded.iter().any(|p| p == "run") {
        while let Some(index) = bounded.iter().position(|p| p == "--max-children") {
            bounded.drain(index..(index + 2).min(bounded.len()));
        }
        bounded.extend(["--max-children".to_string(), "2".into()]);
    }
    Ok(["systemd-run", "--user", "--scope", "--quiet", "-p", "MemoryMax=8G"]
        .iter()
        .map(|s| s.to_string())
        .chain(bounded)
        .collect())
}

fn run_guardrail_command(
    root: &Path,
    group: &str,
    command: &[String],
    base: Option<&str>,
    paths: &[String],
) -> Vec<String> {
    if command.iter().any(|p| p == "{files}") && paths.is_empty() {
        println!("NOT APPLICABLE {group}: no changed files");
        return vec![];
    }
    let Some(mut expanded) = expand_command(command, base, paths) else {
        return vec![format!("{group}: command requires --base")];
    };
    if group == "mutation" {
        expanded = match wrap_mutation_command(expanded) {
            Ok(wrapped) => wrapped,
            Err(message) => return vec![message],
        };
    }
    run_command(&expanded, root, &format!("{group}: {}", command[0]), Deadline::none())
}

fn command_guardrail_violations(root: &Path, config: &Config, base: Option<&str>, paths: &[String]) -> Vec<String> {
    let mut violations = Vec::new();
    for group in COMMAND_GROUPS {
        for command in configured_commands(config, group) {
            violations.extend(run_guardrail_command(root, group, &command, base, paths));
        }
    }
    violations
}

fn repository_violations(
    root: &Path,
    config: &Config,
    base: Option<&str>,
    changes: &[FileChange],
) -> Result<Vec<String>, CheckError> {
    let protected = git::protected_change_violations(changes, config)?;
    if !protected.is_empty() {
        return Ok(protected);
    }
    let paths: Vec<String> = changes.iter().map(|c| c.path.clone()).collect();
    let all: Vec<&FileChange> = changes.iter().collect();
    let mut violations = hook::test_integrity_violations(&all)?;
    violations.extend(hook::dependency_policy_violations(root, config));
    violations.extend(hook::lockfile_violations(root, changes));
    violations.extend(changed_content_violations(changes)?);
    if configured_commands(config, "contract").is_empty()
        && changes
            .iter()
            .any(|c| hook::MANIFESTS.contains(&c.path.as_str()) && c.before != c.after)
    {
        println!("NOT CHECKED lock synchronization: configure a frozen-lock command in commands.contract");
    }
    if violations.is_empty() {
        violations.extend(command_guardrail_violations(root, config, base, &paths));
    }
    violations.truncate(MAX_VIOLATIONS);
    Ok(violations)
}

/// `iter_source_files`: `os.walk` order, skipped directories pruned.
fn iter_source_files(root: &Path) -> Vec<PathBuf> {
    fn visit(root: &Path, directory: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        let mut directories = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !crate::slop::SKIP_DIRECTORIES.contains(&name.as_str()) {
                    directories.push((path.clone(), entry.file_type().is_ok_and(|t| t.is_symlink())));
                }
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map(|r| r.to_string_lossy().into_owned())
                .unwrap_or_default();
            if relative == ".pi/extensions/loki.ts" || relative == ".omp/extensions/loki.ts" {
                continue;
            }
            if rules::language(&name).is_some() {
                found.push(path);
            }
        }
        for (directory, link) in directories {
            if !link {
                visit(root, &directory, found);
            }
        }
    }
    let mut found = Vec::new();
    visit(root, root, &mut found);
    found
}

fn mix_project(path: &Path, root: &Path) -> Option<PathBuf> {
    let root = crate::resolve(root);
    let mut project = crate::resolve(path.parent()?);
    loop {
        if project.join("mix.exs").is_file() {
            return Some(project);
        }
        if project == root {
            return None;
        }
        project = project.parent()?.to_path_buf();
    }
}

fn relative_files(files: &[PathBuf], root: &Path) -> Vec<String> {
    files.iter().map(|f| hook::relative_display(f, root)).collect()
}

/// `scan_command`: the missing tool, or the project-wide commands to run.
fn scan_command(language: &str, files: &[PathBuf], root: &Path) -> (Option<&'static str>, Vec<Vec<String>>) {
    let words = |items: &[&str]| -> Vec<String> { items.iter().map(|s| s.to_string()).collect() };
    match language {
        "python" => {
            let Some(ruff) = hook::ruff_command(root) else {
                return (Some("ruff"), vec![]);
            };
            let files = relative_files(files, root);
            let check = [ruff.clone(), words(&["check"]), files.clone()].concat();
            let format = [ruff, words(&["format", "--check"]), files].concat();
            (None, vec![check, format])
        }
        "typescript" => match hook::resolve_tool(root, "oxlint") {
            None => (Some("oxlint"), vec![]),
            Some(oxlint) => (
                None,
                vec![std::iter::once(oxlint).chain(relative_files(files, root)).collect()],
            ),
        },
        "go" => {
            if proc::which("golangci-lint").is_none() {
                return (Some("golangci-lint"), vec![]);
            }
            (None, vec![words(&["golangci-lint", "run"])])
        }
        "rust" => {
            if proc::which("cargo").is_none() {
                return (Some("cargo"), vec![]);
            }
            (
                None,
                vec![words(&[
                    "cargo",
                    "clippy",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                    "-D",
                    "clippy::todo",
                    "-D",
                    "clippy::unimplemented",
                    "-D",
                    "clippy::unwrap_used",
                    "-D",
                    "clippy::expect_used",
                ])],
            )
        }
        _ => (Some("toolchain"), vec![]),
    }
}

fn check_repository_changes(
    root: &Path,
    config: &mut Config,
    base: Option<&str>,
) -> Result<Option<Vec<String>>, CheckError> {
    let (resolved, changes) = git::git_changes(root, base, Deadline::none())?;
    let policy = git::base_policy(root, resolved.as_deref(), Deadline::none())?;
    let protected = git::protected_change_violations(&changes, &policy.clone().unwrap_or_default())?;
    if !protected.is_empty() {
        return Ok(Some(protected));
    }
    if let Some(policy) = policy {
        *config = policy;
    }
    let findings = repository_violations(root, config, resolved.as_deref(), &changes)?;
    Ok((!findings.is_empty()).then_some(findings))
}

fn scan_repository(root: &Path, config: &mut Config, strict: bool, base: Option<&str>) -> Result<bool, CheckError> {
    match git_output(root, &["rev-parse", "--show-toplevel"], Deadline::none(), None) {
        Err(CheckError::Value(error)) => {
            if strict || base.is_some() {
                println!("{error}");
                return Ok(true);
            }
            println!("NOT CHECKED repository: git repository required");
            return Ok(false);
        }
        Err(other) => return Err(other),
        Ok(_) => {}
    }
    match check_repository_changes(root, config, base) {
        Ok(Some(findings)) => {
            println!("{}", findings.join("\n"));
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(error) if matches!(error, CheckError::Value(_)) || error.is_os() => {
            println!("loki: {}", error.message());
            Ok(true)
        }
        Err(other) => Err(other),
    }
}

fn group_source_files(root: &Path, config: &Config) -> Vec<(&'static str, Vec<PathBuf>)> {
    let mut grouped: Vec<(&'static str, Vec<PathBuf>)> = Vec::new();
    for path in iter_source_files(root) {
        let Some(language) = rules::language(&path.to_string_lossy()) else {
            continue;
        };
        if !config::language_enabled(config, language) {
            continue;
        }
        match grouped.iter_mut().find(|(l, _)| *l == language) {
            Some((_, files)) => files.push(path),
            None => grouped.push((language, vec![path])),
        }
    }
    grouped
}

fn violations_entry<'a>(violations: &'a mut Vec<(String, Vec<String>)>, language: &str) -> &'a mut Vec<String> {
    let index = match violations.iter().position(|(l, _)| l == language) {
        Some(index) => index,
        None => {
            violations.push((language.to_string(), Vec::new()));
            violations.len() - 1
        }
    };
    &mut violations[index].1
}

fn scan_elixir_project(
    root: &Path,
    project: &Path,
    strict: bool,
    violations: &mut Vec<(String, Vec<String>)>,
) {
    let report = crate::elixir::elixir_analysis(project, "project", &[]).unwrap_or_default();
    let relative = project
        .strip_prefix(crate::resolve(root))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let prefix = if relative.is_empty() { "." } else { &relative };
    for crate::elixir::Check {
        tool, status, output, ..
    } in report
    {
        let label = format!("{prefix}:{tool}");
        println!("[{label}] {status}");
        if status == "FAIL" || (strict && status == "NOT CHECKED") {
            violations_entry(violations, "elixir").push(format!("{label}: {output}"));
        } else if !output.is_empty() {
            println!("{output}");
        }
    }
}

fn scan_elixir(
    root: &Path,
    files: &[PathBuf],
    strict: bool,
    violations: &mut Vec<(String, Vec<String>)>,
) {
    let projects: Vec<Option<PathBuf>> = files.iter().map(|f| mix_project(f, root)).collect();
    if projects.iter().any(Option::is_none) {
        println!("NOT CHECKED elixir: source files without an enclosing Mix project");
        if strict {
            violations_entry(violations, "elixir").push("Mix project required".into());
        }
    }
    let unique: BTreeSet<PathBuf> = projects.into_iter().flatten().collect();
    for project in unique {
        scan_elixir_project(root, &project, strict, violations);
    }
}

fn scan_python_ast(
    root: &Path,
    files: &[PathBuf],
    python: Option<&str>,
    strict: bool,
    list: &mut Vec<String>,
) -> Result<(), CheckError> {
    let dependencies = hook::declared_python_dependencies(root);
    let mut notices = Vec::new();
    for path in files {
        let found = hook::python_ast_violations(
            path,
            root,
            Some(&dependencies),
            "",
            python,
            strict,
            &mut notices,
            Deadline::none(),
        )?;
        list.extend(found);
        if list.len() >= MAX_VIOLATIONS {
            break;
        }
    }
    let mut seen = BTreeSet::new();
    list.retain(|item| seen.insert(item.clone()));
    for notice in notices {
        println!("{notice}");
    }
    Ok(())
}

fn scan_language(
    root: &Path,
    language: &str,
    files: &[PathBuf],
    python: Option<&str>,
    strict: bool,
    violations: &mut Vec<(String, Vec<String>)>,
) -> Result<(), CheckError> {
    if language == "elixir" {
        scan_elixir(root, files, strict, violations);
        return Ok(());
    }
    let (missing, commands) = scan_command(language, files, root);
    if let Some(missing) = missing {
        println!("SKIP {language} (no {missing})");
        if strict {
            violations_entry(violations, language).push(format!("loki: missing {missing}"));
        }
    }
    for command in &commands {
        let found = run_command(command, root, &command[0], Deadline::none());
        violations_entry(violations, language).extend(found);
    }
    if language == "python" {
        scan_python_ast(root, files, python, strict, violations_entry(violations, language))?;
    }
    Ok(())
}

fn report_scan_violations(violations: &[(String, Vec<String>)]) -> i32 {
    let mut failed = false;
    for (language, messages) in violations {
        if messages.is_empty() {
            continue;
        }
        failed = true;
        println!("[{language}]");
        for message in messages.iter().take(MAX_VIOLATIONS) {
            println!("{message}");
        }
    }
    i32::from(failed)
}

fn scan_typescript_and_online(
    root: &Path,
    config: &Config,
    has_typescript: bool,
    online: bool,
    violations: &mut Vec<(String, Vec<String>)>,
) -> Result<(), CheckError> {
    if has_typescript {
        let mut notices = Vec::new();
        let found = crate::typescript::typescript_findings(root, config, Deadline::none(), &mut notices)?;
        for notice in notices {
            eprintln!("{notice}");
        }
        violations_entry(violations, "typescript").extend(found);
    }
    if online {
        let issues = crate::registry::slopsquatting_violations(root, config);
        if !issues.is_empty() {
            *violations_entry(violations, "dependencies") = issues;
        }
    }
    Ok(())
}

/// `loki scan`: exit status 1 on any finding.
pub fn scan(
    root: &Path,
    config: &Config,
    online: bool,
    strict: bool,
    base: Option<&str>,
    python: Option<&str>,
) -> Result<i32, CheckError> {
    let mut config = config.clone();
    if scan_repository(root, &mut config, strict, base)? {
        return Ok(1);
    }
    let grouped = group_source_files(root, &config);
    let files_of = |language: &str| {
        grouped
            .iter()
            .find(|(l, _)| *l == language)
            .map(|(_, f)| f.as_slice())
            .unwrap_or(&[])
    };
    let mut violations: Vec<(String, Vec<String>)> = Vec::new();
    for language in ["python", "typescript", "go", "rust", "elixir"] {
        let files = files_of(language);
        if !files.is_empty() {
            scan_language(root, language, files, python, strict, &mut violations)?;
        }
    }
    scan_typescript_and_online(
        root,
        &config,
        !files_of("typescript").is_empty(),
        online,
        &mut violations,
    )?;
    Ok(report_scan_violations(&violations))
}

pub(crate) const TEMPLATE: &[u8] = include_bytes!("../templates/loki.json");

/// `init --minimal`: the engine and default policy in `.loki/`, nothing else.
pub fn install_minimal(target: &str, force: bool) -> Result<(), CheckError> {
    install_minimal_files(target, force)?;
    println!("Installed loki engine and policy in .loki/ (minimal).");
    println!(
        "Commit .loki/: policy is read from the committed version; scan reports it as awaiting review until then."
    );
    Ok(())
}

/// The line `loki init` prints to stderr for `error` (after which it exits with status 1).
pub fn init_error_line(error: &CheckError) -> String {
    match error {
        CheckError::Value(m) => format!("loki: {m}"),
        other if other.is_os() => format!("loki: {}", other.message()),
        other => format!("loki: {}", other.describe()),
    }
}

/// [`install_minimal`] without its report: the files only.
pub fn install_minimal_files(target: &str, force: bool) -> Result<(), CheckError> {
    let os = |e: std::io::Error, name: &Path| CheckError::os(&e, name.to_str());
    let expanded = match (target.strip_prefix('~'), std::env::var("HOME")) {
        (Some(rest), Ok(home)) if rest.is_empty() || rest.starts_with('/') => format!("{home}{rest}"),
        _ => target.to_string(),
    };
    let target = crate::resolve(Path::new(&expanded));
    std::fs::create_dir_all(&target).map_err(|e| os(e, &target))?;
    let directory = target.join(".loki");
    std::fs::create_dir_all(&directory).map_err(|e| os(e, &directory))?;
    let config = directory.join("loki.json");
    if !config.exists() || force {
        std::fs::write(&config, TEMPLATE).map_err(|e| os(e, &config))?;
    }
    Ok(())
}
