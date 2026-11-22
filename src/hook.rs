//! `hook`: post-write checks of changed files against the committed base.

use crate::config::{self, Config};
use crate::git::{self, FileChange, git_output, head_text};
use crate::proc::{self, Deadline};
use crate::py::{self, Counter};
use crate::pyast;
use crate::rules;
use crate::{CheckError, MAX_VIOLATIONS, path_matches, protect_path, resolve};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use crate::invalid;

macro_rules! re {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).expect("static pattern"));
    };
}

re!(
    TEST_PATH,
    r"(?i)(^|/)(tests?|spec)(/|$)|(^|/)(test_[^/]+|[^/]+_(?:test|spec))\.[^.]+$|\.(?:test|spec)\.[^.]+$"
);
re!(
    TEST_DECLARATION,
    r#"^\s*(?:(?:async\s+)?def\s+test_|func\s+Test|(?:it|test|describe)\s*\(|test\s+")"#
);
re!(
    ASSERTION,
    r"\b(?:assert\w*|expect|refute|should|require\.(?:Equal|NoError|Error))\b"
);
re!(
    SKIP,
    r"(?:pytest\.mark\.(?:skip|xfail)|unittest\.skip|\b(?:it|test|describe)\.skip\s*\(|\bt\.Skipf?\s*\(|#\s*\[ignore\]|@Ignore\b|@tag\s+:skip\b)"
);
re!(
    QUALITY_POLICY,
    r"(?:fail_under|coverageThreshold|mutation(?:Score|Threshold)|mutate_only_covered_lines|max-children|MemoryMax)"
);
re!(DEPENDENCY_NAME, r"^\s*([A-Za-z0-9_.-]+)");
re!(GO_REQUIRE, r"^require\s+([^\s]+)\s+v");
re!(GO_REQUIRE_LINE, r"^([^\s]+)\s+v");
re!(MIX_DEPENDENCY, r#"\{\s*:([a-zA-Z0-9_]+)\s*,\s*["']"#);
re!(
    MYPY_LINE,
    r"^(?P<path>[^:\n]+):(?P<line>\d+): error: (?P<message>.*?)(?:  \[(?P<code>[\w-]+)\])?$"
);
re!(OXLINT_FINDING, r"\[(?:Error|Warning)/");

pub const QUALITY_POLICY_PATHS: [&str; 6] = [
    "pyproject.toml",
    ".coveragerc",
    "**/stryker*.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
];
pub const MANIFEST_LOCKFILES: [(&str, &[&str]); 5] = [
    (
        "npm",
        &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
        ],
    ),
    ("pypi", &["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"]),
    ("go", &["go.sum"]),
    ("crates", &["Cargo.lock"]),
    ("hex", &["mix.lock"]),
];

pub fn ecosystem_manifest(ecosystem: &str) -> &'static str {
    match ecosystem {
        "npm" => "package.json",
        "pypi" => "pyproject.toml",
        "go" => "go.mod",
        "crates" => "Cargo.toml",
        _ => "mix.exs",
    }
}

pub const MANIFESTS: [&str; 5] = ["package.json", "pyproject.toml", "go.mod", "Cargo.toml", "mix.exs"];

pub fn is_test_path(path: &str) -> bool {
    TEST_PATH.is_match(path)
}

fn regular(mode: &Option<String>) -> bool {
    matches!(mode.as_deref(), Some("100644" | "100755"))
}

type AddedTest = ((Vec<u8>, String), Vec<String>);

fn added_test_files(changes: &[&FileChange]) -> Vec<AddedTest> {
    let mut additions: Vec<AddedTest> = Vec::new();
    for change in changes {
        if is_test_path(&change.path)
            && change.before.is_none()
            && regular(&change.after_mode)
            && let (Some(after), Some(mode)) = (&change.after, &change.after_mode)
        {
            let key = (after.clone(), mode.clone());
            match additions.iter_mut().find(|(k, _)| *k == key) {
                Some((_, paths)) => paths.push(change.path.clone()),
                None => additions.push((key, vec![change.path.clone()])),
            }
        }
    }
    additions
}

fn moved_test_paths(changes: &[&FileChange]) -> HashSet<String> {
    let mut additions = added_test_files(changes);
    let mut moved: HashSet<String> = HashSet::new();
    for change in changes {
        if is_test_path(&change.path)
            && change.after.is_none()
            && regular(&change.before_mode)
            && let (Some(before), Some(mode)) = (&change.before, &change.before_mode)
            && let Some((_, destinations)) = additions.iter_mut().find(|(k, _)| *k == (before.clone(), mode.clone()))
            && let Some(destination) = destinations.pop()
        {
            moved.insert(change.path.clone());
            moved.insert(destination);
        }
    }
    moved
}

fn decode_change_bytes(bytes: &Option<Vec<u8>>, path: &str) -> Result<String, CheckError> {
    String::from_utf8(bytes.clone().unwrap_or_default())
        .map_err(|_| invalid(format!("loki: cannot inspect non-UTF-8 test/config: {path}")))
}

fn diff_lines<'a>(before: &'a [&'a str], after: &'a [&'a str]) -> (Vec<&'a str>, Vec<&'a str>) {
    let (mut removed, mut added) = (Vec::new(), Vec::new());
    for (tag, i, j, a, b) in py::opcodes(before, after) {
        if tag != "equal" {
            removed.extend(&before[i..j]);
            added.extend(&after[a..b]);
        }
    }
    (removed, added)
}

fn check_test_change(change: &FileChange, removed: &[&str], added: &[&str], violations: &mut Vec<String>) {
    let path = &change.path;
    if change.before.is_some() && change.after.is_none() {
        crate::evidence::finding("test-file-deleted", Some(path));
        violations.push(format!("{path}: test file deleted"));
    }
    let count = |lines: &[&str], re: &Regex| lines.iter().filter(|l| re.is_match(l)).count();
    if count(removed, &TEST_DECLARATION) > count(added, &TEST_DECLARATION) {
        crate::evidence::finding("test-deleted", Some(path));
        violations.push(format!("{path}: test deleted"));
    }
    if count(removed, &ASSERTION) > count(added, &ASSERTION) {
        crate::evidence::finding("assertion-removed", Some(path));
        violations.push(format!("{path}: assertion removed"));
    }
    if added.iter().any(|l| SKIP.is_match(l)) {
        crate::evidence::finding("test-skip-added", Some(path));
        violations.push(format!("{path}: test skip added"));
    }
}

/// Deleted tests, removed assertions, added skips and changed quality thresholds.
pub fn test_integrity_violations(changes: &[&FileChange]) -> Result<Vec<String>, CheckError> {
    let mut violations = Vec::new();
    let moved = moved_test_paths(changes);
    for change in changes {
        let path = &change.path;
        if moved.contains(path) {
            continue;
        }
        let test = is_test_path(path);
        let quality = QUALITY_POLICY_PATHS.iter().any(|p| path_matches(path, p));
        if !test && !quality {
            continue;
        }
        let before_text = decode_change_bytes(&change.before, path)?;
        let after_text = decode_change_bytes(&change.after, path)?;
        let before = py::splitlines(&before_text, false);
        let after = py::splitlines(&after_text, false);
        let (removed, added) = diff_lines(&before, &after);
        if test {
            check_test_change(change, &removed, &added, &mut violations);
        }
        if quality && removed.iter().chain(&added).any(|l| QUALITY_POLICY.is_match(l)) {
            crate::evidence::finding("quality-threshold-changed", Some(path));
            violations.push(format!("{path}: quality threshold changed"));
        }
    }
    violations.truncate(MAX_VIOLATIONS);
    Ok(violations)
}

/// `dependency_name`: the normalized distribution name of a requirement.
pub fn dependency_name(requirement: &str) -> Option<String> {
    DEPENDENCY_NAME
        .captures(requirement)
        .map(|c| c[1].to_lowercase().replace('-', "_"))
}

fn toml_table(path: &Path) -> Option<toml::Table> {
    let text = proc::read_text(path).ok()?;
    text.parse::<toml::Table>().ok()
}

fn requirement_files(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return vec![];
    };
    entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            name.starts_with("requirements") && name.ends_with(".txt") && name.len() >= "requirements.txt".len()
        })
        .map(|name| root.join(name))
        .collect()
}

fn requirement_names(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for file in requirement_files(root) {
        let Ok(text) = proc::read_text(&file) else { continue };
        for line in py::splitlines(&text, false) {
            let stripped = py::strip(line);
            if stripped.is_empty() || stripped.starts_with('#') || stripped.starts_with('-') {
                continue;
            }
            names.extend(dependency_name(stripped));
        }
    }
    names
}

fn pyproject_names(root: &Path) -> Vec<String> {
    let path = root.join("pyproject.toml");
    if !path.is_file() {
        return vec![];
    }
    let Some(data) = toml_table(&path) else { return vec![] };
    let Some(toml::Value::Table(project)) = data.get("project") else {
        return vec![];
    };
    let Some(toml::Value::Array(values)) = project.get("dependencies") else {
        return vec![];
    };
    values
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(dependency_name)
        .collect()
}

/// Dependencies the project declares for Python: pyproject.toml and requirements*.txt.
pub fn declared_python_dependencies(root: &Path) -> BTreeSet<String> {
    pyproject_names(root)
        .into_iter()
        .chain(requirement_names(root))
        .collect()
}

fn npm_manifest_deps(root: &Path, found: &mut BTreeSet<(String, String)>) {
    let package = root.join("package.json");
    if package.is_file()
        && let Ok(text) = proc::read_text(&package)
        && let Ok(Value::Object(data)) = serde_json::from_str::<Value>(&text)
    {
        for field in ["dependencies", "devDependencies"] {
            if let Some(Value::Object(values)) = data.get(field) {
                found.extend(values.keys().map(|name| ("npm".to_string(), name.clone())));
            }
        }
    }
}

fn go_manifest_deps(root: &Path, found: &mut BTreeSet<(String, String)>) {
    let go_mod = root.join("go.mod");
    if !go_mod.is_file() {
        return;
    }
    let Ok(text) = proc::read_text(&go_mod) else { return };
    let mut in_require = false;
    for raw in py::splitlines(&text, false) {
        let line = py::strip(raw);
        if line == "require (" {
            in_require = true;
            continue;
        }
        if in_require && line == ")" {
            in_require = false;
            continue;
        }
        let pattern = if in_require { &GO_REQUIRE_LINE } else { &GO_REQUIRE };
        if let Some(caps) = pattern.captures(line) {
            found.insert(("go".into(), caps[1].to_string()));
        }
    }
}

fn cargo_manifest_deps(root: &Path, found: &mut BTreeSet<(String, String)>) {
    let cargo = root.join("Cargo.toml");
    if cargo.is_file()
        && let Some(data) = toml_table(&cargo)
        && let Some(toml::Value::Table(values)) = data.get("dependencies")
    {
        found.extend(values.keys().map(|name| ("crates".to_string(), name.clone())));
    }
}

fn mix_manifest_deps(root: &Path, found: &mut BTreeSet<(String, String)>) {
    let mix = root.join("mix.exs");
    if mix.is_file()
        && let Ok(text) = proc::read_text(&mix)
    {
        for caps in MIX_DEPENDENCY.captures_iter(&text) {
            found.insert(("hex".into(), caps[1].to_string()));
        }
    }
}

/// `(ecosystem, name)` of every manifest dependency, sorted.
pub fn manifest_dependencies(root: &Path) -> Vec<(String, String)> {
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    npm_manifest_deps(root, &mut found);
    for name in pyproject_names(root).into_iter().chain(requirement_names(root)) {
        found.insert(("pypi".into(), name.replace('_', "-")));
    }
    go_manifest_deps(root, &mut found);
    cargo_manifest_deps(root, &mut found);
    mix_manifest_deps(root, &mut found);
    found.into_iter().collect()
}

/// Manifest dependencies missing from `approved_dependencies`.
pub fn dependency_policy_violations(root: &Path, config: &Config) -> Vec<String> {
    let Some(approved) = config.get("approved_dependencies").filter(|v| !v.is_null()) else {
        return vec![];
    };
    let Some(items) = approved.as_array().filter(|items| items.iter().all(Value::is_string)) else {
        return vec!["loki: approved_dependencies must be a list of ecosystem:name strings".into()];
    };
    let allowed: HashSet<&str> = items.iter().filter_map(Value::as_str).collect();
    manifest_dependencies(root)
        .into_iter()
        .filter(|(ecosystem, name)| !allowed.contains(format!("{ecosystem}:{name}").as_str()))
        .map(|(ecosystem, name)| {
            format!(
                "{}: unapproved dependency: {ecosystem}:{name}",
                ecosystem_manifest(&ecosystem)
            )
        })
        .collect()
}

/// Deleted lockfiles whose manifest remains, and non-regular lockfiles.
pub fn lockfile_violations(root: &Path, changes: &[FileChange]) -> Vec<String> {
    let changed: HashMap<&str, &FileChange> = changes.iter().map(|c| (c.path.as_str(), c)).collect();
    let mut violations = Vec::new();
    for (ecosystem, lockfiles) in MANIFEST_LOCKFILES {
        let remains = std::fs::symlink_metadata(root.join(ecosystem_manifest(ecosystem))).is_ok_and(|m| m.is_file());
        for lockfile in lockfiles {
            let Some(change) = changed.get(lockfile) else { continue };
            if change.after_mode.is_some() && !regular(&change.after_mode) {
                violations.push(format!("loki: unsupported changed file type: {lockfile}"));
            } else if change.before.is_some() && change.after.is_none() && remains {
                violations.push(format!("{lockfile}: tracked lockfile deleted"));
            }
        }
    }
    violations
}

fn report_repository_gap(gap: &str, warnings: Option<&mut Vec<String>>) -> Vec<String> {
    let message = format!("NOT CHECKED repository changes: {gap}");
    if crate::strict() {
        return vec![message];
    }
    if let Some(warnings) = warnings {
        if !warnings.contains(&message) {
            warnings.push(message);
        }
    } else {
        eprintln!("{message}");
    }
    vec![]
}

fn load_guardrail_changes(
    root: &Path,
    touched: &HashSet<String>,
    deadline: Deadline,
    warnings: Option<&mut Vec<String>>,
) -> Result<(Option<String>, Vec<FileChange>), CheckError> {
    match git::git_changes(root, None, deadline) {
        Err(error) if git::snapshot_too_large(&error) => {
            let mut note = format!(
                "NOT CHECKED repository changes: {}; protected-file, test and lockfile checks covered only the files this write changed",
                error.message()
            );
            let narrowed = match git::git_changes_only(root, None, deadline, Some(touched)) {
                Err(written) if git::snapshot_too_large(&written) => {
                    note = format!("NOT CHECKED repository changes: {}", written.message());
                    (None, Vec::new())
                }
                other => other?,
            };
            if let Some(warnings) = warnings {
                warnings.push(note);
            }
            Ok(narrowed)
        }
        other => other,
    }
}

fn check_write_guardrails(
    paths: &[PathBuf],
    root: &Path,
    config: &Config,
    deadline: Deadline,
    warnings: Option<&mut Vec<String>>,
) -> Result<Vec<String>, CheckError> {
    let resolved = resolve(root);
    let touched: HashSet<String> = paths
        .iter()
        .filter_map(|p| p.strip_prefix(&resolved).ok().map(|r| r.to_string_lossy().into_owned()))
        .collect();
    let (base, changes) = load_guardrail_changes(root, &touched, deadline, warnings)?;
    let policy = git::base_policy(root, base.as_deref(), deadline)?;
    let protected = git::protected_change_violations(&changes, &policy.unwrap_or_default())?;
    if !protected.is_empty() {
        return Ok(protected);
    }
    let selected: Vec<&FileChange> = changes.iter().filter(|c| touched.contains(&c.path)).collect();
    let mut violations = test_integrity_violations(&selected)?;
    violations.extend(lockfile_violations(&resolved, &changes));
    if MANIFESTS.iter().any(|m| touched.contains(*m)) {
        violations.extend(dependency_policy_violations(&resolved, config));
    }
    violations.truncate(MAX_VIOLATIONS);
    Ok(violations)
}

/// `write_guardrail_violations`: protected, test-integrity, lockfile and dependency policy.
/// A snapshot of every change too large to take (`SnapshotTooLarge`) narrows to the written files, with a
/// `NOT CHECKED repository changes` note in `warnings`, so the per-file checks still run.
pub fn write_guardrail_violations(
    paths: &[PathBuf],
    root: &Path,
    config: &Config,
    deadline: Deadline,
    warnings: Option<&mut Vec<String>>,
) -> Result<Vec<String>, CheckError> {
    if let Some(gap) = git::repository_gap(root, deadline)? {
        return Ok(report_repository_gap(&gap, warnings));
    }
    match check_write_guardrails(paths, root, config, deadline, warnings) {
        Err(error) if matches!(error, CheckError::Value(_)) || error.is_os() => Ok(vec![error.message().to_string()]),
        other => other,
    }
}

/// `relative_display`: the resolved path relative to the root, else as given.
pub fn relative_display(path: &Path, root: &Path) -> String {
    match resolve(path).strip_prefix(resolve(root)) {
        Ok(relative) if relative.as_os_str().is_empty() => ".".into(),
        Ok(relative) => relative.to_string_lossy().into_owned(),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

/// `line_text`: the stripped text of a 1-based line, or "".
pub fn line_text(content: &str, number: i64) -> String {
    let lines = py::splitlines(content, false);
    if number > 0 && number as usize <= lines.len() {
        py::strip(lines[number as usize - 1]).to_string()
    } else {
        String::new()
    }
}

/// `written_content_violations`: net-new built-in findings in a written file.
pub fn written_content_violations(
    path: &Path,
    root: &Path,
    relative: &str,
    fallback: bool,
    deadline: Deadline,
) -> Result<Vec<String>, CheckError> {
    let size = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(_) => return Ok(vec![]),
    };
    if size > 4 * 1024 * 1024 {
        return Ok(vec![]);
    }
    let before = match head_text(root, relative, deadline) {
        Ok(text) => text,
        Err(e) if matches!(e, CheckError::Value(_)) || e.is_os() => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let Ok(after) = proc::read_text(path) else {
        return Ok(vec![]);
    };
    let change = [(relative.to_string(), before, after)];
    let mut violations = rules::content_rule_violations(&change, false)?;
    if fallback {
        violations.extend(rules::content_rule_violations(&change, true)?);
    }
    Ok(violations)
}

/// Where unavailable coverage goes: a failure in strict mode, else a warning.
pub fn not_checked(message: String, strict: bool, warnings: &mut Vec<String>) -> Vec<String> {
    if strict {
        return vec![message];
    }
    if !warnings.contains(&message) {
        warnings.push(message);
    }
    vec![]
}

fn net_new(found: Vec<(i64, String)>, prior: &[(i64, String)], after: &str, before: &str) -> Vec<(i64, String)> {
    let mut seen: Counter<(String, String)> = Counter::new();
    for (line, name) in prior {
        seen.add((name.clone(), line_text(before, *line)));
    }
    found
        .into_iter()
        .filter(|(line, name)| {
            let key = (name.clone(), line_text(after, *line));
            if seen.get(&key) > 0 {
                seen.decrement(&key);
                false
            } else {
                true
            }
        })
        .collect()
}

const IMPORT_PROBE: &str = "\nimport json, sys\ntry:\n    from importlib.util import find_spec as find\nexcept ImportError:\n    from pkgutil import find_loader as find\nmissing = []\nfor name in sys.argv[1:]:\n    try:\n        found = find(name) is not None\n    except Exception:\n        found = False\n    if not found:\n        missing.append(name)\nprint(json.dumps(missing))\n";

type ImportMemo = HashMap<(String, String), HashMap<String, bool>>;

static IMPORT_MEMO: LazyLock<Mutex<ImportMemo>> = LazyLock::new(Default::default);

/// The interpreter the project runs on, never the one running Loki.
pub fn project_python(root: &Path, explicit: Option<&str>) -> Option<String> {
    if let Some(named) = explicit.filter(|s| !s.is_empty()) {
        return Some(named.to_string());
    }
    if let Ok(named) = std::env::var("LOKI_PYTHON")
        && !named.is_empty()
    {
        return Some(named);
    }
    let mut prefixes: Vec<PathBuf> = ["VIRTUAL_ENV", "CONDA_PREFIX"]
        .iter()
        .filter_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()).map(PathBuf::from))
        .collect();
    prefixes.push(root.join(".venv"));
    prefixes.push(root.join("venv"));
    for prefix in prefixes {
        for relative in ["bin/python", "bin/python3", "Scripts/python.exe"] {
            if prefix.join(relative).is_file() {
                return Some(prefix.join(relative).to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn probe_missing_imports(
    interpreter: &str,
    root: &Path,
    asked: &[String],
    deadline: Deadline,
) -> Result<HashSet<String>, CheckError> {
    let mut command = vec![interpreter.to_string(), "-c".into(), IMPORT_PROBE.into()];
    command.extend(asked.iter().cloned());
    let timeout = deadline.timeout()?.min(15.0);
    let unavailable = |reason: String| invalid(format!("project interpreter {interpreter} unavailable: {reason}"));
    let result = proc::run(&command, root, None, &[], timeout).map_err(|e| unavailable(e.to_string()))?;
    let stdout = proc::text(&result.stdout);
    let missing = if result.code == 0 {
        match serde_json::from_str::<Value>(&stdout) {
            Ok(value) => Some(value),
            Err(e) => return Err(unavailable(crate::pyjson::error_text(&stdout, &e))),
        }
    } else {
        None
    };
    let Some(Value::Array(missing)) = missing else {
        let stderr = proc::text(&result.stderr);
        let reason: String = py::strip(&stderr).chars().take(200).collect();
        let reason = if reason.is_empty() {
            format!("exited {}", result.code)
        } else {
            reason
        };
        return Err(unavailable(reason));
    };
    Ok(missing.iter().filter_map(Value::as_str).map(String::from).collect())
}

/// The modules the project's interpreter cannot import.
fn resolve_imports(
    root: &Path,
    modules: &BTreeSet<String>,
    python: Option<&str>,
    deadline: Deadline,
) -> Result<BTreeSet<String>, CheckError> {
    if modules.is_empty() {
        return Ok(BTreeSet::new());
    }
    let Some(interpreter) = project_python(root, python) else {
        return Err(invalid(
            "no project interpreter found (set LOKI_PYTHON or pass --python)",
        ));
    };
    let memo_key = (interpreter.clone(), root.to_string_lossy().into_owned());
    let asked: Vec<String> = {
        let memo = IMPORT_MEMO.lock().map_err(|_| invalid("import memo poisoned"))?;
        let known = memo.get(&memo_key);
        modules
            .iter()
            .filter(|m| known.is_none_or(|k| !k.contains_key(*m)))
            .cloned()
            .collect()
    };
    if !asked.is_empty() {
        let missing = probe_missing_imports(&interpreter, root, &asked, deadline)?;
        let mut memo = IMPORT_MEMO.lock().map_err(|_| invalid("import memo poisoned"))?;
        let known = memo.entry(memo_key.clone()).or_default();
        for module in &asked {
            known.insert(module.clone(), !missing.contains(module));
        }
    }
    let memo = IMPORT_MEMO.lock().map_err(|_| invalid("import memo poisoned"))?;
    let known = &memo[&memo_key];
    Ok(modules
        .iter()
        .filter(|m| known.get(*m) == Some(&false))
        .cloned()
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn append_unresolved_imports(
    display: &str,
    root: &Path,
    imports: &[(i64, String)],
    python: Option<&str>,
    strict: bool,
    warnings: &mut Vec<String>,
    deadline: Deadline,
    violations: &mut Vec<String>,
) -> Result<(), CheckError> {
    let modules: BTreeSet<String> = imports.iter().map(|(_, m)| m.clone()).collect();
    match resolve_imports(root, &modules, python, deadline) {
        Ok(missing) => violations.extend(
            imports
                .iter()
                .filter(|(_, m)| missing.contains(m))
                .map(|(line, m)| format!("{display}:{line}: python-ast: unresolved import {m}")),
        ),
        Err(CheckError::Value(error)) => violations.extend(not_checked(
            format!("NOT CHECKED python imports: {error}"),
            strict,
            warnings,
        )),
        Err(other) => return Err(other),
    }
    Ok(())
}

/// Placeholder bodies and unresolvable imports in a Python file.
#[allow(clippy::too_many_arguments)]
pub fn python_ast_violations(
    path: &Path,
    root: &Path,
    dependencies: Option<&BTreeSet<String>>,
    base: &str,
    python: Option<&str>,
    strict: bool,
    warnings: &mut Vec<String>,
    deadline: Deadline,
) -> Result<Vec<String>, CheckError> {
    let display = relative_display(path, root);
    let Some(old) = pyast::parse(base)? else {
        return Ok(not_checked(
            format!("NOT CHECKED python ast: {display} does not parse at the base"),
            strict,
            warnings,
        ));
    };
    let source = match proc::read_text(path) {
        Ok(source) => source,
        Err(error) => {
            crate::evidence::finding("python-syntax", Some(&display));
            return Ok(vec![format!("{display}: python-ast: {error}")]);
        }
    };
    let tree = match pyast::parse_named(&source, Some(&path.to_string_lossy()))? {
        pyast::Parsed::Tree(tree) => tree,
        pyast::Parsed::Error(error) => {
            crate::evidence::finding("python-syntax", Some(&display));
            return Ok(vec![format!("{display}: python-ast: {error}")]);
        }
    };
    let declared = dependencies
        .cloned()
        .unwrap_or_else(|| declared_python_dependencies(root));
    let directory = resolve(path).parent().map(Path::to_path_buf).unwrap_or_default();
    let stubs = net_new(pyast::python_stubs(&tree), &pyast::python_stubs(&old), &source, base);
    let imports = net_new(
        pyast::python_unknown_imports(&tree, root, &directory, &declared)?,
        &pyast::python_unknown_imports(&old, root, &directory, &declared)?,
        &source,
        base,
    );
    let mut violations: Vec<String> = stubs
        .iter()
        .map(|(line, name)| format!("{display}:{line}: python-ast: stub body in {name}"))
        .collect();
    append_unresolved_imports(
        &display,
        root,
        &imports,
        python,
        strict,
        warnings,
        deadline,
        &mut violations,
    )?;
    violations.truncate(MAX_VIOLATIONS);
    Ok(violations)
}

/// `resolve_tool`: the project's pinned Node tool, then the same tool on PATH.
pub fn resolve_tool(root: &Path, name: &str) -> Option<String> {
    let local = root.join("node_modules").join(".bin").join(name);
    if local.is_file() {
        return Some(local.to_string_lossy().into_owned());
    }
    proc::which(name)
}

/// `ruff_command`: Ruff from the project's .venv or venv, PATH, then the project's `-m ruff`; never installs.
pub fn ruff_command(root: &Path) -> Option<Vec<String>> {
    for prefix in [".venv", "venv"] {
        let local = root.join(prefix).join("bin/ruff");
        if local.is_file() {
            return Some(vec![local.to_string_lossy().into_owned()]);
        }
    }
    if proc::which("ruff").is_some() {
        return Some(vec!["ruff".into()]);
    }
    let wanted = BTreeSet::from(["ruff".to_string()]);
    let python = project_python(root, None)?;
    resolve_imports(root, &wanted, None, Deadline::none())
        .is_ok_and(|missing| missing.is_empty())
        .then(|| vec![python, "-m".into(), "ruff".into()])
}

fn missing_tool(language: &str, root: &Path) -> Option<&'static str> {
    match language {
        "python" => ruff_command(root).is_none().then_some("ruff"),
        "typescript" => resolve_tool(root, "oxlint").is_none().then_some("oxlint"),
        "go" => {
            if proc::which("gofmt").is_none() {
                Some("gofmt")
            } else {
                proc::which("go").is_none().then_some("go")
            }
        }
        "rust" => proc::which("rustfmt").is_none().then_some("rustfmt"),
        "elixir" => proc::which("mix").is_none().then_some("mix"),
        _ => Some("toolchain"),
    }
}

re!(ANSI_ESCAPE, r"\x1b\[[0-?]*[ -/]*[@-~]");

/// `command_output`: non-empty stripped lines of stdout then stderr, without terminal colors.
pub fn command_output(stdout: &str, stderr: &str) -> Vec<String> {
    let parts = [stdout, stderr].map(|p| ANSI_ESCAPE.replace_all(p, "").into_owned());
    let text = parts
        .iter()
        .map(|p| py::strip(p))
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    py::splitlines(&text, false)
        .iter()
        .map(|l| py::strip(l))
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// `run_command`: a failing command's output lines, labelled.
pub fn run_command(command: &[String], root: &Path, label: &str, deadline: Deadline) -> Vec<String> {
    let result = deadline
        .timeout()
        .and_then(|t| proc::run(command, root, None, &[], t).map_err(CheckError::from));
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            crate::evidence::finding("checker-unavailable", None);
            return vec![format!("{label}: {}", error.message())];
        }
    };
    if output.code == 0 {
        return vec![];
    }
    crate::evidence::finding("external-check-failed", None);
    let mut lines = command_output(&proc::text(&output.stdout), &proc::text(&output.stderr));
    if lines.is_empty() {
        lines = vec![format!("exited {}", output.code)];
    }
    lines.into_iter().map(|line| format!("{label}: {line}")).collect()
}

/// `str()` of a JSON value as Python prints it in an f-string.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        other => py::dumps(other),
    }
}

fn validate_ruff_config(raw: &[u8]) -> Result<(), CheckError> {
    let text = proc::decode(raw).map_err(invalid)?;
    let config: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| invalid(e.message().to_string()))?;
    if config.contains_key("extend") {
        return Err(invalid("net-new Ruff requires self-contained base .ruff.toml"));
    }
    Ok(())
}

fn run_ruff_check(
    ruff: &[String],
    trusted: &Path,
    directory: &Path,
    path: &str,
    content: &[u8],
    deadline: Deadline,
) -> Result<Counter<(String, String, String)>, CheckError> {
    let command: Vec<String> = ruff
        .iter()
        .map(String::as_str)
        .chain([
            "check",
            "--no-cache",
            "--no-respect-gitignore",
            "--config",
            &trusted.to_string_lossy(),
            "--output-format",
            "json",
            "--stdin-filename",
            path,
            "-",
        ])
        .map(String::from)
        .collect();
    let result = proc::run(&command, directory, Some(content), &[], deadline.timeout()?)?;
    if result.code != 0 && result.code != 1 {
        return Err(invalid(format!(
            "Ruff unavailable: {}",
            String::from_utf8_lossy(&result.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let diagnostics: Value =
        serde_json::from_str(&stdout).map_err(|e| invalid(crate::pyjson::error_text(&stdout, &e)))?;
    let source = proc::decode(content).map_err(invalid)?;
    let lines = py::splitlines(&source, false);
    let mut counter = Counter::new();
    for item in diagnostics.as_array().into_iter().flatten() {
        let row = item["location"]["row"].as_i64().unwrap_or(0);
        let line = if 0 < row && row as usize <= lines.len() {
            py::strip(lines[row as usize - 1]).to_string()
        } else {
            String::new()
        };
        counter.add((py_str(&item["code"]), py_str(&item["message"]), line));
    }
    Ok(counter)
}

/// Ruff findings present in each candidate but not its base, by line text.
pub fn ruff_delta(
    raw: &[u8],
    pairs: &[(String, Vec<u8>, Vec<u8>)],
    deadline: Deadline,
    ruff: &[String],
) -> Result<Vec<String>, CheckError> {
    validate_ruff_config(raw)?;
    let directory = tempfile::Builder::new()
        .prefix("loki-ruff-")
        .tempdir()
        .map_err(|e| CheckError::os(&e, None))?;
    let trusted = directory.path().join("ruff.toml");
    std::fs::write(&trusted, raw).map_err(|e| CheckError::os(&e, None))?;
    let mut violations = Vec::new();
    for (path, before, after) in pairs {
        let prior = run_ruff_check(ruff, &trusted, directory.path(), path, before, deadline)?;
        let current = run_ruff_check(ruff, &trusted, directory.path(), path, after, deadline)?;
        for ((code, message, _), count) in current.minus(&prior) {
            crate::evidence::finding(&format!("ruff:{code}"), Some(path));
            for _ in 0..count {
                violations.push(format!("{path}: {code}: {message}"));
            }
        }
    }
    Ok(violations)
}

/// Why net-new Ruff could not run: `MissingRuffConfig` (no committed base or config) or another error.
pub enum RuffError {
    MissingConfig(String),
    Other(CheckError),
}

impl From<CheckError> for RuffError {
    fn from(error: CheckError) -> Self {
        RuffError::Other(error)
    }
}

fn committed_ruff_config(root: &Path, base: &str, deadline: Deadline) -> Result<Vec<u8>, RuffError> {
    let listed = git_output(
        root,
        &["ls-tree", "--name-only", base, "--", ".ruff.toml"],
        deadline,
        None,
    )?;
    if py::strip(&String::from_utf8_lossy(&listed)).is_empty() {
        return Err(RuffError::MissingConfig("no committed .ruff.toml".into()));
    }
    let raw = git_output(root, &["show", &format!("{base}:.ruff.toml")], deadline, None)?;
    crate::evidence::policy("base", ".ruff.toml", Some(&raw), Some(base));
    Ok(raw)
}

fn python_change_pairs(changes: Vec<FileChange>, paths: Option<&HashSet<String>>) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    changes
        .into_iter()
        .filter(|c| paths.is_none_or(|p| p.contains(&c.path)) && c.path.ends_with(".py"))
        .filter_map(|c| c.after.map(|after| (c.path, c.before.unwrap_or_default(), after)))
        .collect()
}

/// Net-new Ruff findings of changed Python files against the committed config.
pub fn ruff_new_violations(
    root: &Path,
    reference: Option<&str>,
    paths: Option<&HashSet<String>>,
    deadline: Deadline,
) -> Result<Vec<String>, RuffError> {
    if let Some(gap) = git::repository_gap(root, deadline)? {
        return Err(RuffError::MissingConfig(gap));
    }
    let (base, changes) = git::git_changes(root, reference, deadline)?;
    let Some(base) = base else {
        return Err(RuffError::MissingConfig(
            "net-new Ruff requires a committed base".into(),
        ));
    };
    let policy = git::base_policy(root, Some(&base), deadline)?;
    let protected = git::protected_change_violations(&changes, &policy.unwrap_or_default())?;
    if !protected.is_empty() {
        return Ok(protected);
    }
    let raw = committed_ruff_config(root, &base, deadline)?;
    let pairs = python_change_pairs(changes, paths);
    let ruff = ruff_command(root).unwrap_or_else(|| vec!["ruff".into()]);
    Ok(ruff_delta(&raw, &pairs, deadline, &ruff)?)
}

/// Pre-write net-new Ruff with the committed config; post-write reports gaps.
pub fn preview_ruff(
    root: &Path,
    changes: &[(String, String, String)],
    deadline: Deadline,
) -> Result<Vec<String>, CheckError> {
    let pairs: Vec<(String, Vec<u8>, Vec<u8>)> = changes
        .iter()
        .filter(|(path, _, _)| path.ends_with(".py"))
        .map(|(path, old, new)| (path.clone(), old.clone().into_bytes(), new.clone().into_bytes()))
        .collect();
    let Some(ruff) = ruff_command(root).filter(|_| !pairs.is_empty()) else {
        return Ok(vec![]);
    };
    let result = git_output(root, &["show", "HEAD:.ruff.toml"], deadline, None).and_then(|raw| {
        crate::evidence::policy("base", ".ruff.toml", Some(&raw), Some("HEAD"));
        ruff_delta(&raw, &pairs, deadline, &ruff)
    });
    match result {
        Err(e) if matches!(e, CheckError::Value(_)) || e.is_os() || e.is_timeout() => Ok(vec![]),
        other => other,
    }
}

fn mypy_binary(root: &Path) -> Option<String> {
    for prefix in [".venv", "venv"] {
        let local = root.join(prefix).join("bin/mypy");
        if local.is_file() {
            return Some(local.to_string_lossy().into_owned());
        }
    }
    proc::which("mypy")
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into()))
}

fn mypy_state(root: &Path) -> Result<PathBuf, CheckError> {
    let identity = crate::compat::sha256_hex(resolve(root).as_os_str().as_encoded_bytes());
    let state = home().join(".cache/loki/mypy").join(&identity[..16]);
    std::fs::create_dir_all(&state).map_err(|e| CheckError::os(&e, state.to_str()))?;
    let config = state.join("mypy.ini");
    if !config.is_file() {
        std::fs::write(&config, "[mypy]\n").map_err(|e| CheckError::os(&e, config.to_str()))?;
    }
    Ok(state)
}

fn mypy_run(root: &Path, paths: &[String], deadline: Deadline, shadows: &[String]) -> Result<String, CheckError> {
    let Some(mypy) = mypy_binary(root) else {
        return Err(invalid("mypy unavailable"));
    };
    let state = mypy_state(root)?;
    let state_text = state.to_string_lossy();
    let mut command: Vec<String> = vec![
        mypy,
        "--config-file".into(),
        format!("{state_text}/mypy.ini"),
        "--cache-dir".into(),
        format!("{state_text}/cache"),
        "--no-error-summary".into(),
        "--show-error-codes".into(),
        "--no-color-output".into(),
        "--hide-error-context".into(),
        "--no-pretty".into(),
        "--ignore-missing-imports".into(),
        "--follow-imports=silent".into(),
        "--explicit-package-bases".into(),
    ];
    command.extend(shadows.iter().cloned());
    command.extend(paths.iter().cloned());
    let result = proc::run(&command, root, None, &[], deadline.timeout()?)?;
    let stdout = proc::text(&result.stdout);
    if result.code != 0 && result.code != 1 {
        let stderr = proc::text(&result.stderr);
        let reason = py::strip(if stderr.is_empty() { &stdout } else { &stderr }).to_string();
        return Err(invalid(if reason.is_empty() {
            format!("mypy exited {}", result.code)
        } else {
            reason
        }));
    }
    Ok(stdout)
}

type Fingerprint = (String, String, String, String);

fn mypy_errors(output: &str, contents: &HashMap<String, String>) -> (Counter<Fingerprint>, HashMap<Fingerprint, i64>) {
    let mut found = Counter::new();
    let mut lines = HashMap::new();
    for line in py::splitlines(output, false) {
        let Some(caps) = MYPY_LINE.captures(line) else { continue };
        let Some(content) = contents.get(&caps["path"]) else {
            continue;
        };
        let number: i64 = caps["line"].parse().unwrap_or(0);
        let key = (
            caps["path"].to_string(),
            caps.name("code").map_or("misc", |m| m.as_str()).to_string(),
            caps["message"].to_string(),
            line_text(content, number),
        );
        found.add(key.clone());
        lines.entry(key).or_insert(number);
    }
    (found, lines)
}

/// Whether any finding's source line also appears in its committed text.
pub fn possibly_existing<'a>(keys: impl Iterator<Item = (&'a str, &'a str)>, texts: &HashMap<String, String>) -> bool {
    let mut cache: HashMap<&str, HashSet<String>> = HashMap::new();
    for (path, text) in keys {
        if text.is_empty() {
            return true;
        }
        let lines = cache.entry(path).or_insert_with(|| {
            py::splitlines(texts.get(path).map_or("", String::as_str), false)
                .iter()
                .map(|l| py::strip(l).to_string())
                .collect()
        });
        if lines.contains(text) {
            return true;
        }
    }
    false
}

fn any_annotated_python(after: &HashMap<String, String>, paths: &[String]) -> Result<bool, CheckError> {
    let texts: Vec<&str> = after.values().map(String::as_str).collect();
    pyast::prefetch(&texts)?;
    for name in paths {
        if pyast::annotated_python(&after[name])? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn mypy_previous_errors(
    root: &Path,
    paths: &[String],
    before: &HashMap<String, String>,
    deadline: Deadline,
) -> Result<Counter<Fingerprint>, CheckError> {
    let directory = tempfile::Builder::new()
        .prefix("loki-mypy-")
        .tempdir()
        .map_err(|e| CheckError::os(&e, None))?;
    let mut shadows = Vec::new();
    for (index, name) in paths.iter().enumerate() {
        let shadow = directory.path().join(format!("{index}.py"));
        std::fs::write(&shadow, &before[name]).map_err(|e| CheckError::os(&e, None))?;
        shadows.extend([
            "--shadow-file".to_string(),
            name.clone(),
            shadow.to_string_lossy().into_owned(),
        ]);
    }
    Ok(mypy_errors(&mypy_run(root, paths, deadline, &shadows)?, before).0)
}

fn read_worktree_texts(root: &Path, paths: &[String]) -> Result<HashMap<String, String>, CheckError> {
    let mut texts = HashMap::new();
    for name in paths {
        texts.insert(name.clone(), proc::read_text(&root.join(name)).map_err(invalid)?);
    }
    Ok(texts)
}

fn format_mypy_violations(
    current: &Counter<Fingerprint>,
    previous: &Counter<Fingerprint>,
    numbers: &HashMap<Fingerprint, i64>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for (key, count) in current.minus(previous) {
        crate::evidence::finding(&format!("mypy:{}", key.1), Some(&key.0));
        for _ in 0..count {
            violations.push(format!("{}:{}: mypy[{}]: {}", key.0, numbers[&key], key.1, key.2));
        }
    }
    violations.truncate(MAX_VIOLATIONS);
    violations
}

fn read_head_texts(root: &Path, paths: &[String], deadline: Deadline) -> Result<HashMap<String, String>, CheckError> {
    let mut texts = HashMap::new();
    for name in paths {
        texts.insert(name.clone(), head_text(root, name, deadline)?);
    }
    Ok(texts)
}

fn mypy_baseline_errors(
    root: &Path,
    paths: &[String],
    current: &Counter<Fingerprint>,
    deadline: Deadline,
) -> Result<Counter<Fingerprint>, CheckError> {
    let before = read_head_texts(root, paths, deadline)?;
    if !possibly_existing(current.keys().map(|k| (k.0.as_str(), k.3.as_str())), &before) {
        return Ok(Counter::new());
    }
    mypy_previous_errors(root, paths, &before, deadline)
}

/// Net-new mypy errors in written files, against their committed text.
fn mypy_violations(root: &Path, paths: &[String], deadline: Deadline) -> Result<Vec<String>, CheckError> {
    if paths.is_empty() || mypy_binary(root).is_none() {
        return Ok(vec![]);
    }
    let after = read_worktree_texts(root, paths)?;
    if !any_annotated_python(&after, paths)? {
        return Ok(vec![]);
    }
    let (current, numbers) = mypy_errors(&mypy_run(root, paths, deadline, &[])?, &after);
    if current.is_empty() {
        return Ok(vec![]);
    }
    let previous = mypy_baseline_errors(root, paths, &current, deadline)?;
    Ok(format_mypy_violations(&current, &previous, &numbers))
}

fn oxlint_violations(root: &Path, display: &str, deadline: Deadline, warnings: &mut Vec<String>) -> Vec<String> {
    let binary = resolve_tool(root, "oxlint").unwrap_or_else(|| "None".into());
    let command: Vec<String> = vec![binary, "--fix".into(), "--format".into(), "unix".into(), display.into()];
    let result = deadline
        .timeout()
        .and_then(|t| proc::run(&command, root, None, &[], t).map_err(CheckError::from));
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            crate::evidence::finding("checker-unavailable", None);
            return vec![format!("oxlint: {}", error.message())];
        }
    };
    let stdout = proc::text(&output.stdout);
    let findings: Vec<String> = py::splitlines(&stdout, false)
        .iter()
        .filter(|line| OXLINT_FINDING.is_match(line))
        .map(|line| py::strip(line).to_string())
        .collect();
    let advisory: Vec<&String> = findings.iter().filter(|l| l.contains("[Warning/")).collect();
    if !advisory.is_empty() {
        let extra = if advisory.len() > 10 {
            format!("\n... {} more", advisory.len() - 10)
        } else {
            String::new()
        };
        let shown: Vec<&str> = advisory.iter().take(10).map(|s| s.as_str()).collect();
        warnings.push(format!("oxlint advisory (not blocking):\n{}{extra}", shown.join("\n")));
    }
    if output.code == 0 {
        return vec![];
    }
    crate::evidence::finding("external-check-failed", None);
    let errors: Vec<String> = findings.iter().filter(|l| l.contains("[Error/")).cloned().collect();
    let lines = if errors.is_empty() {
        command_output(&stdout, &proc::text(&output.stderr))
    } else {
        errors
    };
    lines.into_iter().map(|line| format!("oxlint: {line}")).collect()
}

/// The nearest enclosing Cargo project inside the root.
fn cargo_project(path: &Path, root: &Path) -> Option<PathBuf> {
    let root = resolve(root);
    let mut project = resolve(path.parent()?);
    while project.starts_with(&root) {
        if project.join("Cargo.toml").is_file() {
            return Some(project);
        }
        if project == root {
            break;
        }
        project = project.parent()?.to_path_buf();
    }
    None
}

/// `cargo_edition`: the crate's Rust edition from Cargo.toml, following `edition.workspace = true` up to the
/// workspace's `[workspace.package]`.
fn cargo_edition(krate: Option<&Path>, root: &Path) -> Option<String> {
    let root = resolve(root);
    let mut directory = resolve(krate?);
    let mut inherit = false;
    while directory.starts_with(&root) {
        let data: toml::Table = std::fs::read_to_string(directory.join("Cargo.toml"))
            .ok()
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default();
        let table = if inherit {
            data.get("workspace").and_then(|w| w.get("package"))
        } else {
            data.get("package")
        };
        match table.and_then(|t| t.as_table()).and_then(|t| t.get("edition")) {
            Some(toml::Value::String(edition)) => return Some(edition.clone()),
            Some(toml::Value::Table(edition)) if edition.get("workspace") == Some(&toml::Value::Boolean(true)) => {
                inherit = true;
            }
            _ => {}
        }
        if directory == root {
            break;
        }
        directory = directory.parent()?.to_path_buf();
    }
    None
}

/// The rustfmt command for `path`: with the crate's edition, which rustfmt does not read from Cargo.toml itself.
fn rustfmt_command(path: &Path, krate: Option<&Path>, root: &Path) -> Vec<String> {
    let mut command = vec!["rustfmt".to_string()];
    if let Some(edition) = cargo_edition(krate, root) {
        command.extend(["--edition".to_string(), edition]);
    }
    command.push(path.to_string_lossy().into_owned());
    command
}

/// Why clippy failed without diagnostics, from its stderr.
fn clippy_failure(stderr: &str, code: i64) -> String {
    let stderr = py::strip(stderr);
    if stderr.contains("--offline was specified") || stderr.contains("no matching package named") {
        return "cargo clippy needs dependencies that are not downloaded yet; run `cargo fetch` once to check this crate"
            .into();
    }
    if stderr.contains("either src/lib.rs, src/main.rs, a [lib] section") {
        return "the crate has no library or binary target yet".into();
    }
    let lines = py::splitlines(stderr, false);
    let reason = lines.last().map_or_else(|| format!("exit {code}"), |l| l.to_string());
    format!("cargo clippy failed: {reason}")
}

type Diagnostic = ((String, String, String, String), i64);

fn clippy_command(target: &Path) -> Vec<String> {
    let mut command: Vec<String> = [
        "cargo",
        "clippy",
        "--offline",
        "--all-targets",
        "--message-format=json",
        "--target-dir",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    command.push(target.to_string_lossy().into_owned());
    command.push("--".into());
    for lint in [
        "clippy::todo",
        "clippy::unimplemented",
        "clippy::unwrap_used",
        "clippy::expect_used",
    ] {
        command.extend(["-W".to_string(), lint.to_string()]);
    }
    command
}

fn parse_clippy_line(line: &str, krate: &Path, crate_root: &Path) -> Result<Option<Diagnostic>, CheckError> {
    let Ok(item) = serde_json::from_str::<Value>(line) else {
        return Ok(None);
    };
    if item["reason"] != "compiler-message" {
        return Ok(None);
    }
    let message = &item["message"];
    if !message.is_object() || !matches!(message["level"].as_str(), Some("error" | "warning")) {
        return Ok(None);
    }
    let Some(span) = message["spans"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["is_primary"] == true)
    else {
        return Ok(None);
    };
    let source = resolve(&krate.join(span["file_name"].as_str().unwrap_or("")));
    let Ok(relative) = source.strip_prefix(crate_root) else {
        return Ok(None);
    };
    let line_number = span["line_start"].as_i64().unwrap_or(0);
    let text = line_text(&proc::read_text(&source).map_err(invalid)?, line_number);
    let code = message["code"]["code"]
        .as_str()
        .filter(|c| !c.is_empty())
        .unwrap_or(message["level"].as_str().unwrap_or(""))
        .to_string();
    Ok(Some((
        (
            relative.to_string_lossy().into_owned(),
            code,
            message["message"].as_str().unwrap_or("").to_string(),
            text,
        ),
        line_number,
    )))
}

fn clippy_diagnostics(krate: &Path, target: &Path, deadline: Deadline) -> Result<Vec<Diagnostic>, CheckError> {
    let command = clippy_command(target);
    let result = proc::run(&command, krate, None, &[], deadline.timeout()?)?;
    let crate_root = resolve(krate);
    let mut found = Vec::new();
    for line in py::splitlines(&proc::text(&result.stdout), false) {
        if let Some(diagnostic) = parse_clippy_line(line, krate, &crate_root)? {
            found.push(diagnostic);
        }
    }
    if result.code != 0 && found.is_empty() {
        return Err(invalid(clippy_failure(
            &proc::text(&result.stderr),
            i64::from(result.code),
        )));
    }
    Ok(found)
}

fn join_posix(prefix: &Path, relative: &str) -> String {
    if prefix.as_os_str().is_empty() {
        relative.to_string()
    } else {
        format!("{}/{relative}", prefix.to_string_lossy())
    }
}

fn clippy_base_diagnostics(
    root: &Path,
    prefix: &Path,
    target: &Path,
    deadline: Deadline,
) -> Result<Vec<Diagnostic>, CheckError> {
    let directory = tempfile::Builder::new()
        .prefix("loki-clippy-")
        .tempdir()
        .map_err(|e| CheckError::os(&e, None))?;
    let base = directory.path().join("base");
    let commit = git_output(root, &["rev-parse", "--verify", "HEAD^{commit}"], deadline, None)?;
    git::materialize_base(root, String::from_utf8_lossy(&commit).trim(), &base, deadline)?;
    let base_crate = base.join(prefix);
    if base_crate.join("Cargo.toml").is_file() {
        clippy_diagnostics(&base_crate, target, deadline)
    } else {
        Ok(Vec::new())
    }
}

fn collect_new_clippy_violations(
    current: Vec<Diagnostic>,
    previous: Vec<Diagnostic>,
    prefix: &Path,
) -> Vec<String> {
    let mut remaining: Counter<(String, String, String, String)> = Counter::new();
    for (key, _) in previous {
        remaining.add(key);
    }
    let mut violations = Vec::new();
    for (key, line) in current {
        if remaining.get(&key) != 0 {
            remaining.decrement(&key);
            continue;
        }
        let name = join_posix(prefix, &key.0);
        crate::evidence::finding(&format!("clippy:{}", key.1), Some(&name));
        violations.push(format!("{name}:{line}: {}: {}", key.1, key.2));
    }
    violations.truncate(MAX_VIOLATIONS);
    violations
}

fn clippy_violations(path: &Path, root: &Path, deadline: Deadline) -> Result<Vec<String>, CheckError> {
    let Some(krate) = cargo_project(path, root) else {
        return Ok(vec![]);
    };
    if proc::which("cargo").is_none() {
        return Ok(vec![]);
    }
    let target = krate.join("target");
    let current = clippy_diagnostics(&krate, &target, deadline)?;
    if current.is_empty() {
        return Ok(vec![]);
    }
    let prefix = resolve(&krate)
        .strip_prefix(resolve(root))
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let mut texts = HashMap::new();
    for (key, _) in &current {
        if !texts.contains_key(&key.0) {
            texts.insert(key.0.clone(), head_text(root, &join_posix(&prefix, &key.0), deadline)?);
        }
    }
    let previous = if possibly_existing(current.iter().map(|(k, _)| (k.0.as_str(), k.3.as_str())), &texts) {
        clippy_base_diagnostics(root, &prefix, &target, deadline)?
    } else {
        Vec::new()
    };
    Ok(collect_new_clippy_violations(current, previous, &prefix))
}

fn golangci_violations(root: &Path, package: &str, deadline: Deadline) -> Result<Vec<String>, CheckError> {
    let Some(binary) = proc::which("golangci-lint") else {
        return Ok(vec![]);
    };
    let command: Vec<String> = [
        binary.as_str(),
        "run",
        "--new-from-rev=HEAD",
        "--output.text.path=stdout",
        "--output.text.colors=false",
        "--output.text.print-issued-lines=false",
        "--show-stats=false",
        package,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let result = proc::run(&command, root, None, &[], deadline.timeout()?)?;
    if result.code == 0 {
        return Ok(vec![]);
    }
    let stdout = proc::text(&result.stdout);
    let issues: Vec<String> = py::splitlines(&stdout, false)
        .iter()
        .map(|l| py::strip(l))
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    if result.code != 1 || issues.is_empty() {
        let stderr = proc::text(&result.stderr);
        let reason = py::strip(if stderr.is_empty() { &stdout } else { &stderr }).to_string();
        return Err(invalid(if reason.is_empty() {
            format!("golangci-lint exited {}", result.code)
        } else {
            reason
        }));
    }
    let mut found: Vec<String> = issues.into_iter().map(|i| format!("golangci-lint: {i}")).collect();
    found.truncate(MAX_VIOLATIONS);
    Ok(found)
}

/// Per-hook state shared by every target: projects already analyzed.
#[derive(Default)]
pub struct Batch {
    pub checked: HashSet<(String, PathBuf)>,
}

/// An analyzer whose absence or failure is reported, never hidden.
fn optional(
    label: &str,
    result: Result<Vec<String>, CheckError>,
    strict: bool,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<(), CheckError> {
    match result {
        Ok(found) => violations.extend(found),
        Err(error) if matches!(error, CheckError::Value(_)) || error.is_os() || error.is_timeout() => {
            let text: String = py::strip(error.message()).chars().take(300).collect();
            let message = format!("NOT CHECKED {label}: {text}");
            if strict {
                violations.push(message);
            } else {
                warnings.push(message);
            }
        }
        Err(other) => return Err(other),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_python_batch(
    root: &Path,
    display: &str,
    batch_paths: &[PathBuf],
    strict: bool,
    deadline: Deadline,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
    batch: &mut Batch,
) -> Result<(), CheckError> {
    let key = ("python".to_string(), root.to_path_buf());
    if batch.checked.contains(&key) {
        return Ok(());
    }
    let mut names: Vec<String> = batch_paths
        .iter()
        .filter(|item| item.extension().is_some_and(|e| e == "py") && item.is_file())
        .filter_map(|item| item.strip_prefix(root).ok().map(|r| r.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    let selected: HashSet<String> = names.iter().cloned().collect();
    match ruff_new_violations(root, None, Some(&selected), deadline) {
        Ok(found) => violations.extend(found),
        Err(RuffError::Other(error)) if git::snapshot_too_large(&error) => {
            let message = format!("NOT CHECKED python ruff: {}", error.message());
            violations.extend(not_checked(message, strict, warnings));
        }
        Err(RuffError::MissingConfig(error)) => {
            if strict {
                violations.push(format!("{display}: loki: {error}"));
            } else {
                warnings.push(format!("NOT CHECKED python ruff: {error}"));
            }
        }
        Err(RuffError::Other(error)) => return Err(error),
    }
    if violations.is_empty() {
        optional(
            "python types",
            mypy_violations(root, &names, deadline),
            strict,
            violations,
            warnings,
        )?;
    }
    batch.checked.insert(key);
    Ok(())
}

fn check_go_file(
    path: &Path,
    root: &Path,
    strict: bool,
    deadline: Deadline,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
    batch: &mut Batch,
) -> Result<(), CheckError> {
    violations.extend(run_command(
        &["gofmt".into(), "-w".into(), path.to_string_lossy().into_owned()],
        root,
        "gofmt",
        deadline,
    ));
    let directory = resolve(path.parent().unwrap_or(root))
        .strip_prefix(resolve(root))
        .map(|r| {
            if r.as_os_str().is_empty() {
                ".".to_string()
            } else {
                r.to_string_lossy().into_owned()
            }
        })
        .unwrap_or_else(|_| ".".into());
    let package = if directory == "." {
        "./".to_string()
    } else {
        format!("./{directory}")
    };
    let key = ("go".to_string(), root.join(&directory));
    let lint = if !batch.checked.contains(&key) {
        batch.checked.insert(key);
        Some(golangci_violations(root, &package, deadline))
    } else {
        None
    };
    let vet_command = vec!["go".to_string(), "vet".into(), package];
    violations.extend(run_command(&vet_command, root, "go vet", deadline));
    if let Some(lint) = lint
        && violations.is_empty()
    {
        optional("golangci-lint", lint, strict, violations, warnings)?;
    }
    Ok(())
}

fn check_rust_file(
    path: &Path,
    root: &Path,
    strict: bool,
    deadline: Deadline,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
    batch: &mut Batch,
) -> Result<(), CheckError> {
    let krate = cargo_project(path, root);
    violations.extend(run_command(
        &rustfmt_command(path, krate.as_deref(), root),
        root,
        "rustfmt",
        deadline,
    ));
    let key = ("rust".to_string(), krate.unwrap_or_else(|| root.to_path_buf()));
    if !batch.checked.contains(&key) {
        optional(
            "clippy",
            clippy_violations(path, root, deadline),
            strict,
            violations,
            warnings,
        )?;
        batch.checked.insert(key);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_elixir_dispatch(
    path: &Path,
    root: &Path,
    config: &Config,
    strict: bool,
    deadline: Deadline,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
    batch: &mut Batch,
) -> Result<Option<Vec<String>>, CheckError> {
    let Some(project) = crate::elixir::mix_project(path, root)? else {
        let message = "NOT CHECKED elixir: enclosing Mix project required".to_string();
        if strict {
            return Ok(Some(vec![message]));
        }
        warnings.push(message);
        return Ok(Some(vec![]));
    };
    let key = ("elixir".to_string(), project.clone());
    let reused = batch.checked.contains(&key);
    violations.extend(crate::elixir::check_elixir_file(
        path, &project, config, strict, deadline, warnings, reused,
    )?);
    if reused {
        violations.truncate(MAX_VIOLATIONS);
        return Ok(Some(std::mem::take(violations)));
    }
    batch.checked.insert(key);
    Ok(None)
}

fn check_python_ast_file(
    path: &Path,
    root: &Path,
    display: &str,
    python: Option<&str>,
    strict: bool,
    deadline: Deadline,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>, CheckError> {
    let base = match head_text(root, display, deadline) {
        Ok(text) => text,
        Err(CheckError::Value(_)) => String::new(),
        Err(other) => return Err(other),
    };
    python_ast_violations(path, root, None, &base, python, strict, warnings, deadline)
}

#[allow(clippy::too_many_arguments)]
fn check_language_file(
    language: &str,
    path: &Path,
    root: &Path,
    display: &str,
    config: &Config,
    strict: bool,
    deadline: Deadline,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
    batch_paths: &[PathBuf],
    batch: &mut Batch,
) -> Result<Option<Vec<String>>, CheckError> {
    match language {
        "python" => check_python_batch(
            root,
            display,
            batch_paths,
            strict,
            deadline,
            violations,
            warnings,
            batch,
        )?,
        "typescript" => violations.extend(oxlint_violations(root, display, deadline, warnings)),
        "go" => check_go_file(path, root, strict, deadline, violations, warnings, batch)?,
        "rust" => check_rust_file(path, root, strict, deadline, violations, warnings, batch)?,
        "elixir" => {
            return check_elixir_dispatch(path, root, config, strict, deadline, violations, warnings, batch);
        }
        _ => {}
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn run_enabled_language(
    language: &str,
    path: &Path,
    root: &Path,
    display: &str,
    config: &Config,
    strict: bool,
    deadline: Deadline,
    warnings: &mut Vec<String>,
    batch_paths: &[PathBuf],
    batch: &mut Batch,
    python: Option<&str>,
) -> Result<Vec<String>, CheckError> {
    let missing = missing_tool(language, root);
    let mut violations = written_content_violations(
        path,
        root,
        display,
        language == "typescript" && missing.is_some(),
        deadline,
    )?;
    if let Some(missing) = missing {
        if strict {
            violations.push(format!("{display}: loki: missing {missing}"));
        } else {
            warnings.push(format!("NOT CHECKED {language}: missing {missing}"));
        }
    } else if let Some(early) = check_language_file(
        language,
        path,
        root,
        display,
        config,
        strict,
        deadline,
        &mut violations,
        warnings,
        batch_paths,
        batch,
    )? {
        return Ok(early);
    }
    if language == "python" {
        violations.extend(check_python_ast_file(
            path, root, display, python, strict, deadline, warnings,
        )?);
    }
    violations.truncate(MAX_VIOLATIONS);
    Ok(violations)
}

/// `check_file`: one written file through its language's analyzers.
#[allow(clippy::too_many_arguments)]
pub fn check_file(
    path: &Path,
    root: &Path,
    config: &Config,
    strict: bool,
    deadline: Deadline,
    warnings: &mut Vec<String>,
    batch_paths: &[PathBuf],
    batch: &mut Batch,
    python: Option<&str>,
) -> Result<Vec<String>, CheckError> {
    if let Some(message) = protect_path(&path.to_string_lossy(), root, config)? {
        return Ok(vec![message]);
    }
    let language = rules::language(&path.to_string_lossy());
    if !path.is_file() {
        return Ok(vec![]);
    }
    let display = relative_display(path, root);
    let Some(language) = language.filter(|l| config::language_enabled(config, l)) else {
        return written_content_violations(path, root, &display, false, deadline);
    };
    run_enabled_language(
        language,
        path,
        root,
        &display,
        config,
        strict,
        deadline,
        warnings,
        batch_paths,
        batch,
        python,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn write(root: &Path, relative: &str, content: &[u8]) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    /// loki.py test_rust_formatter_uses_the_crate_edition: `edition.workspace = true` reads the workspace's
    /// `[workspace.package].edition`; a crate's own edition wins; no Cargo.toml, no flag.
    #[test]
    fn loki_rustfmt_gets_the_crate_edition() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        write(&root, "Cargo.toml", b"[workspace.package]\nedition = \"2024\"\n");
        write(
            &root,
            "crates/a/Cargo.toml",
            b"[package]\nname = \"a\"\nedition.workspace = true\n",
        );
        let path = write(&root, "crates/a/src/lib.rs", b"pub fn f() {}\n");
        let krate = cargo_project(&path, &root);
        assert_eq!(krate.as_deref(), Some(root.join("crates/a").as_path()));
        let shown = path.to_string_lossy().into_owned();
        assert_eq!(
            rustfmt_command(&path, krate.as_deref(), &root),
            ["rustfmt", "--edition", "2024", &shown]
        );
        write(
            &root,
            "crates/a/Cargo.toml",
            b"[package]\nname = \"a\"\nedition = \"2021\"\n",
        );
        assert_eq!(cargo_edition(krate.as_deref(), &root).as_deref(), Some("2021"));
        write(&root, "crates/a/Cargo.toml", b"[package]\nname = \"a\"\n");
        assert_eq!(cargo_edition(krate.as_deref(), &root), None);
        assert_eq!(rustfmt_command(&path, None, &root), ["rustfmt", &shown]);
    }

    /// loki.py clippy_diagnostics: missing offline dependencies and a crate without targets get plain reasons.
    #[test]
    fn loki_clippy_failure_reasons() {
        assert_eq!(
            clippy_failure(
                "error: failed to get `serde` as a dependency\nCaused by: attempting to make an HTTP request, but --offline was specified\n",
                101
            ),
            "cargo clippy needs dependencies that are not downloaded yet; run `cargo fetch` once to check this crate"
        );
        assert_eq!(
            clippy_failure("error: no matching package named `serde` found\n", 101),
            "cargo clippy needs dependencies that are not downloaded yet; run `cargo fetch` once to check this crate"
        );
        assert_eq!(
            clippy_failure(
                "error: failed to parse manifest\nCaused by: no targets specified in the manifest\n  either src/lib.rs, src/main.rs, a [lib] section, or [[bin]] section must be present\n",
                101
            ),
            "the crate has no library or binary target yet"
        );
        assert_eq!(
            clippy_failure("warning: x\nerror: boom\n", 101),
            "cargo clippy failed: error: boom"
        );
        assert_eq!(clippy_failure("", 101), "cargo clippy failed: exit 101");
    }

    /// loki.py test_oversized_snapshot_checks_the_written_files: a snapshot of every change too large to take
    /// narrows to the written files with a NOT CHECKED note, so the per-file checks still run; a written file too
    /// large itself leaves only the note. `git_changes` (what `scan` uses) still fails.
    #[test]
    fn loki_oversized_snapshot_checks_the_written_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        git(&root, &["init", "-q"]);
        let test = write(&root, "tests/test_a.py", b"def test_a():\n    assert value\n");
        git(&root, &["add", "."]);
        git(&root, &["commit", "-q", "-m", "base"]);
        write(&root, "tests/test_a.py", b"def test_a():\n    pass\n");
        let big = write(&root, "big.bin", &vec![b'x'; git::SNAPSHOT_LIMIT + 1]);
        let error = git::git_changes(&root, None, Deadline::none()).unwrap_err();
        assert_eq!(error.message(), "git: snapshot content exceeds 64 MiB");
        let config = Config::default();
        let mut warnings = Vec::new();
        let findings =
            write_guardrail_violations(&[test], &root, &config, Deadline::none(), Some(&mut warnings)).unwrap();
        assert_eq!(findings, ["tests/test_a.py: assertion removed"]);
        assert_eq!(
            warnings,
            [
                "NOT CHECKED repository changes: git: snapshot content exceeds 64 MiB; protected-file, test and lockfile checks covered only the files this write changed"
            ]
        );
        let mut warnings = Vec::new();
        let findings =
            write_guardrail_violations(&[big], &root, &config, Deadline::none(), Some(&mut warnings)).unwrap();
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            warnings,
            ["NOT CHECKED repository changes: git: snapshot content exceeds 64 MiB"]
        );
    }

    /// loki.py test_exact_paths_empty_tree_modes_and_git_errors: no repository, or a root below the repository
    /// top, is a NOT CHECKED note rather than a finding.
    #[test]
    fn loki_repository_gap_is_not_checked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let config = Config::default();
        let mut warnings = Vec::new();
        let file = write(&root, "a.txt", b"x\n");
        let findings =
            write_guardrail_violations(&[file], &root, &config, Deadline::none(), Some(&mut warnings)).unwrap();
        assert!(findings.is_empty(), "{findings:?}");
        assert!(
            warnings[0].starts_with("NOT CHECKED repository changes: git:"),
            "{warnings:?}"
        );
        git(&root, &["init", "-q"]);
        let sub = root.join("sub");
        let file = write(&root, "sub/a.txt", b"x\n");
        let mut warnings = Vec::new();
        write_guardrail_violations(&[file], &sub, &config, Deadline::none(), Some(&mut warnings)).unwrap();
        assert_eq!(
            warnings,
            ["NOT CHECKED repository changes: git: project root must be the repository root"]
        );
    }

    /// loki.py test_oversized_snapshot_skips_net_new_ruff: a snapshot too large for net-new Ruff leaves a
    /// NOT CHECKED note, not an invalid-hook-input error.
    #[test]
    fn loki_oversized_snapshot_skips_net_new_ruff() {
        if proc::which("ruff").is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        git(&root, &["init", "-q"]);
        write(&root, ".ruff.toml", b"");
        let source = write(&root, "a.py", b"x = 1\n");
        git(&root, &["add", "."]);
        git(&root, &["commit", "-q", "-m", "base"]);
        write(&root, "a.py", b"x = 2\n");
        write(&root, "big.bin", &vec![b'x'; git::SNAPSHOT_LIMIT + 1]);
        let report = crate::run::hook(&root, &[source.to_string_lossy().into_owned()], None).unwrap();
        assert!(!report.blocked(), "{report:?}");
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("NOT CHECKED python ruff: git: snapshot content exceeds 64 MiB")),
            "{report:?}"
        );
    }
}
