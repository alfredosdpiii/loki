//! Elixir analysis (loki.py `elixir_analysis`, `credo_new_violations`, `sobelow_new_violations`,
//! `sobelow_findings`): the `elixir` command's tiers of Mix checks (format, Credo, compile, Sobelow, Dialyzer), and
//! the post-write check of a changed Elixir file: `mix format` on it, plus the Credo issues (and with the `phoenix`
//! rule pack the Sobelow findings) the work tree adds over its committed base. Credo and Sobelow run from the
//! project's compiled dev build on two isolated copies (the base, and the base with the changes), so candidate Mix
//! aliases and configuration never execute.

use crate::config::{self, Config};
use crate::git::{self, FileChange, git_output};
use crate::proc::{self, Deadline};
use crate::py::{self, Counter};
use crate::{CheckError, evidence, resolve};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::time::Instant;

const SECURITY_LEVELS: [&str; 4] = ["none", "low", "medium", "high"];

use crate::invalid;

fn os(error: &std::io::Error) -> CheckError {
    CheckError::os(error, None)
}

/// `mix_project`: the nearest directory with a `mix.exs` from `path` up to the repository root.
pub fn mix_project(path: &Path, root: &Path) -> Result<Option<PathBuf>, CheckError> {
    let root = resolve(root);
    let mut project = resolve(path.parent().unwrap_or(&root));
    if !project.starts_with(&root) {
        return Err(invalid("Mix project target outside repository"));
    }
    loop {
        if project.join("mix.exs").is_file() {
            return Ok(Some(project));
        }
        if project == root {
            return Ok(None);
        }
        project = match project.parent() {
            Some(parent) => parent.to_path_buf(),
            None => return Ok(None),
        };
    }
}

/// One analyzer's line of an `elixir` report.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub tool: String,
    pub status: String,
    pub output: String,
    pub duration_ms: f64,
}

impl Check {
    pub fn to_json(&self) -> Value {
        json!({ "tool": self.tool, "status": self.status, "output": self.output, "duration_ms": self.duration_ms })
    }
}

/// `elixir_analysis`: the checks of `tier` (`fast`: format and Credo; `project`: also compile and Sobelow;
/// `deep`: also Dialyzer) on the Mix project, limited to `files` where a check takes files.
pub fn elixir_analysis(project: &Path, tier: &str, files: &[String]) -> Result<Vec<Check>, CheckError> {
    let project = resolve(project);
    if !["fast", "project", "deep"].contains(&tier) {
        return Err(invalid("unknown Elixir analysis tier"));
    }
    if !project.join("mix.exs").is_file() {
        return Err(invalid("Mix project required; use --project api for nested projects"));
    }
    let mut selected = Vec::new();
    for path in files {
        let candidate = resolve(&project.join(path));
        if !candidate.is_file() {
            return Err(invalid(format!("Elixir target is not a file: {path}")));
        }
        match candidate.strip_prefix(&project) {
            Ok(relative) => selected.push(relative.to_string_lossy().into_owned()),
            Err(_) => return Err(invalid("Elixir target outside Mix project")),
        }
    }
    let with = |base: &[&str]| -> Vec<String> {
        base.iter()
            .map(|s| s.to_string())
            .chain(selected.iter().cloned())
            .collect()
    };
    let words = |base: &[&str]| -> Vec<String> { base.iter().map(|s| s.to_string()).collect() };
    let mut checks: Vec<(&str, Vec<String>, Option<&str>)> = vec![
        ("format", with(&["mix", "format", "--check-formatted"]), None),
        (
            "credo",
            with(&["mix", "credo", "--strict", "--format", "json"]),
            Some("credo"),
        ),
    ];
    if tier != "fast" {
        checks.push(("compile", words(&["mix", "compile", "--warnings-as-errors"]), None));
        checks.push((
            "sobelow",
            words(&["mix", "sobelow", "--private", "--format", "json", "--exit", "high"]),
            Some("sobelow"),
        ));
    }
    if tier == "deep" {
        checks.push((
            "dialyzer",
            words(&["mix", "dialyzer", "--format", "short"]),
            Some("dialyxir"),
        ));
    }
    let mut report = Vec::new();
    for (tool, command, dependency) in checks {
        let start = Instant::now();
        let (status, output) = if proc::which("mix").is_none() {
            ("NOT CHECKED".to_string(), "mix is missing".to_string())
        } else if let Some(dependency) = dependency.filter(|d| !project.join("deps").join(d).join("mix.exs").is_file())
        {
            (
                "NOT CHECKED".to_string(),
                format!("required analyzer dependency missing: {dependency}"),
            )
        } else {
            run_check(tool, &command, &project)
        };
        let duration_ms = (start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
        if status != "PASS" {
            evidence::finding(
                &format!("elixir:{tool}:{}", status.to_lowercase().replace(' ', "-")),
                None,
            );
        }
        report.push(Check {
            tool: tool.to_string(),
            status,
            output,
            duration_ms,
        });
    }
    Ok(report)
}

/// One Mix check: PASS or FAIL by its exit status; Credo and Sobelow must answer with a JSON object.
fn run_check(tool: &str, command: &[String], project: &Path) -> (String, String) {
    let result = Deadline::none()
        .timeout()
        .and_then(|t| proc::run(command, project, None, &[("MIX_ENV", "dev")], t).map_err(CheckError::from));
    let result = match result {
        Ok(result) => result,
        Err(error) => return ("NOT CHECKED".into(), error.message().to_string()),
    };
    let stdout = proc::text(&result.stdout);
    let stderr = proc::text(&result.stderr);
    let output: String = [&stdout, &stderr]
        .iter()
        .map(|part| py::strip(part))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let status = if result.code == 0 { "PASS" } else { "FAIL" };
    if !["credo", "sobelow"].contains(&tool) {
        return (status.into(), output);
    }
    let Ok(payload) = serde_json::from_str::<Value>(&stdout) else {
        return (
            "NOT CHECKED".into(),
            format!("analyzer did not return valid JSON: {output}"),
        );
    };
    let Some(payload) = payload.as_object() else {
        return ("NOT CHECKED".into(), "analyzer JSON must be an object".into());
    };
    // The issues' rules and files are evidence (`--record`).
    let missing = |key: &str| ("NOT CHECKED".to_string(), format!("'{key}'"));
    if tool == "credo" {
        for issue in payload.get("issues").and_then(Value::as_array).into_iter().flatten() {
            let Some(check) = issue.get("check") else {
                return missing("check");
            };
            evidence::finding(&py_str(check), issue.get("filename").and_then(Value::as_str));
        }
    } else {
        for (confidence, issues) in payload.get("findings").and_then(Value::as_object).into_iter().flatten() {
            for issue in issues.as_array().into_iter().flatten() {
                let Some(kind) = issue.get("type") else {
                    return missing("type");
                };
                evidence::finding(
                    &format!("sobelow:{confidence}:{}", py_str(kind)),
                    issue.get("file").and_then(Value::as_str),
                );
            }
        }
    }
    (status.into(), output)
}

/// `str()` of a JSON value as an f-string prints it.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        other => py::dumps(other),
    }
}

/// The repository root of a Mix project (`git rev-parse --show-toplevel` there).
fn repository_root(project: &Path, deadline: Deadline) -> Result<PathBuf, CheckError> {
    let top = git_output(project, &["rev-parse", "--show-toplevel"], deadline, None)?;
    Ok(resolve(Path::new(String::from_utf8_lossy(&top).trim())))
}

/// `(relative / name).as_posix()`.
fn join_posix(relative: &Path, name: &str) -> String {
    let relative = relative.to_string_lossy();
    if relative.is_empty() || relative == "." {
        name.to_string()
    } else {
        format!("{relative}/{name}")
    }
}

/// The base and the base with the work tree's changes, as two private trees.
fn isolated(
    root: &Path,
    base: &str,
    changes: &[FileChange],
    directory: &Path,
    deadline: Deadline,
) -> Result<(PathBuf, PathBuf), CheckError> {
    let before = directory.join("before");
    git::materialize_base(root, base, &before, deadline)?;
    let after = directory.join("after");
    copy_tree(&before, &after)?;
    for change in changes {
        crate::apply::apply_snapshot_change(&after, change)?;
    }
    Ok((before, after))
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), CheckError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(to).map_err(|e| os(&e))?;
    for entry in std::fs::read_dir(from).map_err(|e| os(&e))?.flatten() {
        let (source, target) = (entry.path(), to.join(entry.file_name()));
        if entry.file_type().map_err(|e| os(&e))?.is_dir() {
            copy_tree(&source, &target)?;
        } else {
            std::fs::copy(&source, &target).map_err(|e| os(&e))?;
            let mode = std::fs::metadata(&source).map_err(|e| os(&e))?.permissions().mode();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).map_err(|e| os(&e))?;
        }
    }
    Ok(())
}

/// The trimmed line `number` (1-based) of a file in a workspace, and the file's workspace-relative name.
fn source_line(workspace: &Path, filename: &str, number: i64) -> Result<(String, String, usize), CheckError> {
    let path = resolve(&workspace.join(filename));
    let name = path
        .strip_prefix(resolve(workspace))
        .map_err(|_| {
            invalid(format!(
                "{} is not in the subpath of {}",
                py::repr_str(&path.to_string_lossy()),
                py::repr_str(&workspace.to_string_lossy())
            ))
        })?
        .to_string_lossy()
        .into_owned();
    let text = proc::read_text(&path).map_err(invalid)?;
    let lines = py::splitlines(&text, false);
    let line = if number > 0 && number as usize <= lines.len() {
        py::strip(lines[number as usize - 1]).to_string()
    } else {
        String::new()
    };
    Ok((name, line, lines.len()))
}

/// `credo_new_violations`: the Credo issues the work tree's changes add, from the compiled dev Credo with the
/// committed `.credo.exs`.
pub fn credo_new_violations(project: &Path, deadline: Deadline) -> Result<Vec<String>, CheckError> {
    let project = resolve(project);
    let root = repository_root(&project, deadline)?;
    let (base, changes) = git::git_changes(&root, None, deadline)?;
    let Some(base) = base else {
        return Err(invalid("Credo comparison requires committed base"));
    };
    for change in &changes {
        let name = change.path.rsplit('/').next().unwrap_or(&change.path);
        if [".credo.exs", "mix.exs", "mix.lock"].contains(&name) {
            return Err(invalid(format!(
                "{}: analyzer configuration change requires review",
                change.path
            )));
        }
    }
    let policy = git::base_policy(&root, Some(&base), deadline)?.unwrap_or_default();
    let protected = git::protected_change_violations(&changes, &policy)?;
    if !protected.is_empty() {
        return Ok(protected);
    }
    let relative = project.strip_prefix(&root).unwrap_or(Path::new("")).to_path_buf();
    let config_path = join_posix(&relative, ".credo.exs");
    let raw = git_output(&root, &["show", &format!("{base}:{config_path}")], deadline, None)?;
    evidence::policy("base", &config_path, Some(&raw), Some(&base));
    let directory = tempfile::Builder::new()
        .prefix("loki-credo-")
        .tempdir()
        .map_err(|e| os(&e))?;
    let (before, after) = isolated(&root, &base, &changes, directory.path(), deadline)?;
    // Run the same trusted compiled analyzer without evaluating candidate mix.exs.
    let mut ebin: Vec<PathBuf> = std::fs::read_dir(project.join("_build/dev/lib"))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path().join("ebin"))
                .filter(|path| std::fs::symlink_metadata(path).is_ok())
                .collect()
        })
        .unwrap_or_default();
    ebin.sort();
    if !ebin
        .iter()
        .any(|path| path.parent().and_then(Path::file_name).is_some_and(|n| n == "credo"))
    {
        return Err(invalid("compiled dev Credo required; prepare dependencies first"));
    }
    let runner = "Application.ensure_all_started(:credo); Credo.CLI.main(System.argv())";
    let mut counts = Vec::new();
    for workspace in [before.join(&relative), after.join(&relative)] {
        let mut command = vec!["elixir".to_string()];
        for path in &ebin {
            command.extend(["-pa".to_string(), path.to_string_lossy().into_owned()]);
        }
        command.extend(["-e", runner, "--", "--strict", "--format", "json", "--config-file"].map(String::from));
        command.push(before.join(&relative).join(".credo.exs").to_string_lossy().into_owned());
        let result = proc::run(&command, &workspace, None, &[], deadline.timeout()?).map_err(CheckError::from)?;
        let (stdout, stderr) = (proc::text(&result.stdout), proc::text(&result.stderr));
        let issues = serde_json::from_str::<Value>(&stdout)
            .ok()
            .and_then(|payload| payload.get("issues").cloned())
            .and_then(|issues| issues.as_array().cloned())
            .ok_or_else(|| invalid(format!("Credo unavailable: {stderr}{stdout}")))?;
        if result.code != 0 && issues.is_empty() {
            return Err(invalid("Credo failed without diagnostics"));
        }
        let mut counter = Counter::new();
        for issue in &issues {
            let filename = issue
                .get("filename")
                .and_then(Value::as_str)
                .ok_or_else(|| CheckError::Guard("KeyError".into(), "'filename'".into()))?;
            let line = issue.get("line_no").and_then(Value::as_i64).unwrap_or(0);
            let (name, text, _) = source_line(&workspace, filename, line)?;
            let check = issue.get("check").map(py_str).unwrap_or_default();
            let message = issue.get("message").map(py_str).unwrap_or_default();
            counter.add((name, check, message, text));
        }
        counts.push(counter);
    }
    let mut findings = Vec::new();
    for ((path, check, message, _), count) in counts[1].minus(&counts[0]) {
        evidence::finding(&check, Some(&path));
        for _ in 0..count {
            findings.push(format!("{path}: {check}: {message}"));
        }
    }
    Ok(findings)
}

/// `severity_matches`: `confidence` at or above `threshold` (never for `none`).
pub fn severity_matches(confidence: &str, threshold: &str) -> bool {
    let index = |level: &str| SECURITY_LEVELS.iter().position(|l| *l == level).unwrap_or(0);
    threshold != "none" && index(confidence) >= index(threshold)
}

type SobelowKey = (String, String, String, String, String);

/// `sobelow_findings`: a Sobelow JSON report's findings, each keyed by its confidence, file, rule, line text and
/// other details (never the line number, which moves as the file is edited).
pub fn sobelow_findings(output: &str, workspace: &Path) -> Result<Vec<(SobelowKey, i64)>, CheckError> {
    let unavailable = |error: String| invalid(format!("Sobelow unavailable: invalid report ({error})"));
    let payload: Value =
        serde_json::from_str(output).map_err(|e| unavailable(crate::pyjson::error_text(output, &e)))?;
    let groups = payload
        .get("findings")
        .ok_or_else(|| unavailable("'findings'".into()))?;
    let expected = ["low_confidence", "medium_confidence", "high_confidence"];
    let groups = groups
        .as_object()
        .filter(|g| g.len() == 3 && expected.iter().all(|k| g.contains_key(*k)))
        .ok_or_else(|| unavailable("invalid confidence groups".into()))?;
    let mut findings = Vec::new();
    for confidence in ["high", "medium", "low"] {
        let items = groups[&format!("{confidence}_confidence")]
            .as_array()
            .ok_or_else(|| unavailable("findings must be arrays".into()))?;
        for item in items {
            let item = item
                .as_object()
                .ok_or_else(|| unavailable("finding must be an object".into()))?;
            for key in ["file", "type", "line"] {
                if !item.contains_key(key) {
                    return Err(unavailable(format!("'{key}'")));
                }
            }
            let filename = item["file"].as_str().filter(|f| !f.is_empty());
            let rule = item["type"].as_str().filter(|r| !r.is_empty());
            let (Some(filename), Some(rule)) = (filename, rule) else {
                return Err(unavailable("invalid finding path or rule".into()));
            };
            let line = item["line"]
                .as_i64()
                .filter(|l| *l >= 0 && item["line"].is_i64())
                .ok_or_else(|| unavailable("invalid finding line".into()))?;
            let (name, text, count) =
                source_line(workspace, filename, line).map_err(|e| unavailable(e.message().to_string()))?;
            if line as usize > count {
                return Err(unavailable("finding line outside source".into()));
            }
            let details: Map<String, Value> = item
                .iter()
                .filter(|(k, _)| !["file", "line", "column", "type", "fingerprint"].contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let details = py::dumps_sorted(&Value::Object(details));
            let text = if line == 0 { String::new() } else { text };
            findings.push(((confidence.to_string(), name, rule.to_string(), text, details), line));
        }
    }
    Ok(findings)
}

/// `sobelow_new_violations`: the Sobelow findings the work tree's changes add; at the policy's block level they
/// block, below it they are notes (`NOT BLOCKED WARN|INFO ...`) in `warnings`.
pub fn sobelow_new_violations(
    project: &Path,
    config: &Config,
    deadline: Deadline,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>, CheckError> {
    let (block, warn) = config::security_policy(config).map_err(invalid)?;
    let project = resolve(project);
    let root = repository_root(&project, deadline)?;
    let (base, changes) = git::git_changes(&root, None, deadline)?;
    let Some(base) = base else {
        return Err(invalid("Sobelow comparison requires committed base"));
    };
    let policy = git::base_policy(&root, Some(&base), deadline)?.unwrap_or_default();
    let protected = git::protected_change_violations(&changes, &policy)?;
    if !protected.is_empty() {
        return Ok(protected);
    }
    let relative = project.strip_prefix(&root).unwrap_or(Path::new("")).to_path_buf();
    for change in &changes {
        let path = Path::new(&change.path);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let config_dir = relative.join("config");
        if ["mix.exs", "mix.lock", ".sobelow-conf", ".sobelow-skips"].contains(&name.as_str())
            || path.starts_with(&config_dir)
        {
            return Err(invalid(format!(
                "{}: analyzer configuration change requires review",
                change.path
            )));
        }
    }
    let ebin = project.join("_build/dev/lib/sobelow/ebin");
    if !ebin.is_dir() {
        return Err(invalid("compiled dev Sobelow required; prepare dependencies first"));
    }
    // Execute only the prepared analyzer, never candidate Mix aliases or configs.
    let command: Vec<String> = [
        "elixir".to_string(),
        "-pa".into(),
        ebin.to_string_lossy().into_owned(),
        "-pa".into(),
        project.join("_build/dev/lib/jason/ebin").to_string_lossy().into_owned(),
        "-e".into(),
        "Mix.start(); Mix.Tasks.Sobelow.run(System.argv())".into(),
        "--".into(),
    ]
    .into_iter()
    .chain(
        [
            "--private",
            "--strict",
            "--no-config",
            "--ignore",
            "Vuln",
            "--format",
            "json",
            "--threshold",
            "low",
        ]
        .map(String::from),
    )
    .collect();
    let directory = tempfile::Builder::new()
        .prefix("loki-sobelow-")
        .tempdir()
        .map_err(|e| os(&e))?;
    let (before, after) = isolated(&root, &base, &changes, directory.path(), deadline)?;
    let mut reports = Vec::new();
    let mut notices: Vec<String> = Vec::new();
    for workspace in [before.join(&relative), after.join(&relative)] {
        let result = proc::run(&command, &workspace, None, &[], deadline.timeout()?).map_err(CheckError::from)?;
        if result.code != 0 {
            return Err(invalid(format!("Sobelow failed (exit {})", result.code)));
        }
        let stderr = proc::text(&result.stderr);
        if !py::strip(&stderr).is_empty() {
            let notice = format!("NOT CHECKED Sobelow coverage: {}", py::strip(&stderr));
            if !notices.contains(&notice) {
                notices.push(notice);
            }
        }
        reports.push(sobelow_findings(&proc::text(&result.stdout), &workspace)?);
    }
    notices.sort();
    warnings.extend(notices);
    let mut old: Counter<SobelowKey> = Counter::new();
    for (key, _) in &reports[0] {
        old.add(key.clone());
    }
    let mut findings = Vec::new();
    for (key, location) in &reports[1] {
        if old.get(key) > 0 {
            old.decrement(key);
            continue;
        }
        let (confidence, path, rule, _, _) = key;
        let shown = join_posix(&relative, path);
        let family = rule.split_once(':').map_or(rule.as_str(), |(head, _)| head);
        evidence::finding(&format!("sobelow:{confidence}:{family}"), Some(&shown));
        let message = format!("{shown}:{location}: Sobelow {confidence}: {rule}");
        if severity_matches(confidence, &block) {
            findings.push(message);
        } else {
            let label = if severity_matches(confidence, &warn) {
                "WARN"
            } else {
                "INFO"
            };
            warnings.push(format!("NOT BLOCKED {label} {message}"));
        }
    }
    Ok(findings)
}

/// The post-write check of a changed Elixir file in `project` (`check_file`'s Elixir branch): `mix format` on it,
/// then (once per project) Credo and, with the `phoenix` rule pack, Sobelow, all side by side; an analyzer that
/// cannot run is a `NOT CHECKED` note (a violation with `strict`).
pub fn check_elixir_file(
    path: &Path,
    project: &Path,
    config: &Config,
    strict: bool,
    deadline: Deadline,
    warnings: &mut Vec<String>,
    reused: bool,
) -> Result<Vec<String>, CheckError> {
    let mut analyzers: Vec<&str> = Vec::new();
    if !reused {
        analyzers.push("Credo");
        if config::rule_packs(config)
            .map_err(invalid)?
            .iter()
            .any(|p| p == "phoenix")
        {
            analyzers.push("Sobelow");
        }
    }
    // Format, Credo and Sobelow each start a BEAM; run them side by side (on threads of their own, so what they
    // find is not recorded as evidence, as in loki.py's thread pool).
    let format_command = vec![
        "mix".to_string(),
        "format".into(),
        "--check-formatted".into(),
        path.to_string_lossy().into_owned(),
    ];
    let (formatting, jobs) = std::thread::scope(|scope| {
        let formatting = scope.spawn(|| crate::hook::run_command(&format_command, project, "mix format", deadline));
        let jobs: Vec<_> = analyzers
            .iter()
            .map(|name| {
                let name = *name;
                scope.spawn(move || {
                    let mut notes = Vec::new();
                    let result = if name == "Credo" {
                        credo_new_violations(project, deadline)
                    } else {
                        sobelow_new_violations(project, config, deadline, &mut notes)
                    };
                    (name, result, notes)
                })
            })
            .collect();
        (
            formatting.join().unwrap_or_default(),
            jobs.into_iter().filter_map(|job| job.join().ok()).collect::<Vec<_>>(),
        )
    });
    let mut violations = formatting;
    if reused {
        violations.truncate(crate::MAX_VIOLATIONS);
        return Ok(violations);
    }
    for (analyzer, result, notes) in jobs {
        match result {
            Ok(found) => {
                violations.extend(found);
                for note in notes {
                    if strict && note.starts_with("NOT CHECKED") {
                        violations.push(note);
                    } else {
                        warnings.push(note);
                    }
                }
            }
            Err(error) if matches!(error, CheckError::Value(_)) || error.is_os() || error.is_timeout() => {
                let message = format!("NOT CHECKED {analyzer}: {}", error.message());
                if strict {
                    violations.push(message);
                } else {
                    warnings.push(message);
                }
            }
            Err(other) => return Err(other),
        }
    }
    Ok(violations)
}
