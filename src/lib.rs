//! Rust port of Loki (`packages/coding-agent/src/ultron/loki-engine/loki.py`).
//!
//! Ported: config validation, protected paths, `protect` (every preview harness,
//! all language rule packs, Ruff/Oxlint/TypeScript previews), `hook` (git
//! snapshots, test integrity, lockfile and dependency policy, written slop and the
//! per-language analyzers), `scan`, `slop`, `init` (with and without `--minimal`), `context`, `shell`,
//! `shell-writes` and `explain`. Python source is parsed by CPython (`pyast`), as
//! loki.py does.

pub mod analyzers;
pub mod apply;
pub mod auto_setup;
pub mod child;
pub mod compat;
pub mod config;
pub mod daemon;
pub mod elixir;
pub mod evidence;
pub mod git;
pub mod hook;
pub mod hygiene;
pub mod hygiene_model;
pub mod init;
pub mod installation;
pub mod jsrules;
pub mod langrules;
pub mod nits;
pub mod proc;
pub mod project;
pub mod py;
pub mod pyast;
pub mod pyjson;
pub mod registry;
pub mod rules;
pub mod run;
pub mod scan;
pub mod settings;
pub mod shell;
pub mod slop;
pub mod text;
pub mod typescript;

use config::Config;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_VIOLATIONS: usize = 40;
const PREVIEW_LIMIT: usize = 4 * 1024 * 1024;

/// `LOKI_STRICT=1`: a check that cannot run (`NOT CHECKED ...`) blocks instead of warning.
pub fn strict() -> bool {
    std::env::var("LOKI_STRICT").as_deref() == Ok("1")
}

/// An error raised by a check: loki.py's `ValueError` or another exception type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    Value(String),
    Guard(String, String),
}

impl CheckError {
    /// An `OSError` subclass, named the way CPython names it for the errno.
    pub fn os(error: &std::io::Error, filename: Option<&str>) -> Self {
        CheckError::Guard(os_kind(error).into(), py::os_error(error, filename))
    }

    /// `except OSError` (including `subprocess.TimeoutExpired` when `timeouts`).
    pub fn is_os(&self) -> bool {
        matches!(self, CheckError::Guard(kind, _) if OS_KINDS.contains(&kind.as_str()))
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, CheckError::Guard(kind, _) if kind == "TimeoutExpired")
    }

    /// `str(error)`.
    pub fn message(&self) -> &str {
        match self {
            CheckError::Value(m) | CheckError::Guard(_, m) => m,
        }
    }

    /// `prefix: error` as loki.py prints it after `loki: `.
    pub fn describe(&self) -> String {
        match self {
            CheckError::Value(m) => format!("invalid hook input: {m}"),
            CheckError::Guard(kind, m) => format!("guard error: {kind}: {m}"),
        }
    }
}

/// A check's `ValueError`.
pub(crate) fn invalid(message: impl Into<String>) -> CheckError {
    CheckError::Value(message.into())
}

const OS_KINDS: [&str; 7] = [
    "OSError",
    "FileNotFoundError",
    "PermissionError",
    "IsADirectoryError",
    "NotADirectoryError",
    "FileExistsError",
    "InterruptedError",
];

/// The `OSError` subclass CPython raises for an errno.
pub fn os_kind(error: &std::io::Error) -> &'static str {
    match error.raw_os_error() {
        Some(2) => "FileNotFoundError",
        Some(1 | 13) => "PermissionError",
        Some(21) => "IsADirectoryError",
        Some(20) => "NotADirectoryError",
        Some(17) => "FileExistsError",
        Some(4) => "InterruptedError",
        _ => "OSError",
    }
}

impl From<proc::RunError> for CheckError {
    fn from(error: proc::RunError) -> Self {
        match error {
            proc::RunError::Os(kind, message) => CheckError::Guard(kind.into(), message),
            proc::RunError::Timeout(message) => CheckError::Guard("TimeoutExpired".into(), message),
        }
    }
}

/// `os.path.abspath(base / path)` without `~` expansion.
pub fn abspath(base: &Path, path: impl AsRef<Path>) -> PathBuf {
    let mut out = PathBuf::from("/");
    for component in base.join(path).components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
            _ => {}
        }
    }
    out
}

/// `os.path.abspath(root / path.expanduser())`.
pub fn lexical_path(root: &Path, path: &str) -> PathBuf {
    let expanded = match (path.strip_prefix('~'), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            format!("{}{rest}", home.to_string_lossy())
        }
        _ => path.to_string(),
    };
    let mut out = PathBuf::from("/");
    for component in root.join(expanded).components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
            _ => {}
        }
    }
    out
}

/// `Path.resolve()` (non-strict): symlinks of the existing prefix resolved.
/// Dangling links resolve to their target, like `os.path.realpath`.
pub fn resolve(path: &Path) -> PathBuf {
    let absolute = std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf());
    let mut pending: std::collections::VecDeque<PathBuf> =
        absolute.components().map(|c| PathBuf::from(c.as_os_str())).collect();
    let mut out = PathBuf::from("/");
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        match part.components().next() {
            Some(Component::ParentDir) => {
                out.pop();
            }
            Some(Component::Normal(name)) => {
                let next = out.join(name);
                match std::fs::read_link(&next) {
                    Ok(target) if hops < 40 => {
                        hops += 1;
                        if target.is_absolute() {
                            out = PathBuf::from("/");
                        }
                        for component in target.components().rev() {
                            pending.push_front(PathBuf::from(component.as_os_str()));
                        }
                    }
                    _ => out = next,
                }
            }
            _ => {}
        }
    }
    out
}

fn relative_posix(path: &Path, root: &Path) -> Option<String> {
    path.strip_prefix(root).ok().map(|p| p.to_string_lossy().into_owned())
}

/// `path_matches`: `/**` suffix matches a subtree, otherwise `fnmatch`.
pub fn path_matches(path: &str, pattern: &str) -> bool {
    let path = path.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");
    let path = path.strip_prefix("./").unwrap_or(&path);
    let pattern = pattern.strip_prefix("./").unwrap_or(&pattern);
    if let Some(prefix) = pattern.strip_suffix("/**") {
        let prefix = prefix.trim_end_matches('/');
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    py::fnmatch(path, pattern)
}

pub fn valid_path(path: &str) -> Result<(), CheckError> {
    if path.is_empty() || path.contains('\0') {
        return Err(CheckError::Value("path must be a nonempty string without NUL".into()));
    }
    Ok(())
}

/// `protect_path`: root confinement, directory targets and protected files.
pub fn protect_path(path: &str, root: &Path, config: &Config) -> Result<Option<String>, CheckError> {
    protect_path_with(path, root, config, true)
}

/// [`protect_path`]; without `allow_override`, `LOKI_ALLOW_PROTECTED=1` does not lift the protection (`apply`).
pub fn protect_path_with(
    path: &str,
    root: &Path,
    config: &Config,
    allow_override: bool,
) -> Result<Option<String>, CheckError> {
    valid_path(path)?;
    let patterns = config::protected_patterns(config).map_err(CheckError::Value)?;
    let root = resolve(root);
    let lexical = lexical_path(&root, path);
    let resolved = resolve(&lexical);
    let (Some(first), Some(second)) = (relative_posix(&lexical, &root), relative_posix(&resolved, &root)) else {
        evidence::finding("root-confinement", Some(path));
        return Ok(Some(format!("loki: outside project root: {path}")));
    };
    let relatives = [
        if first.is_empty() { ".".into() } else { first },
        if second.is_empty() { ".".into() } else { second },
    ];
    if resolved.is_dir() {
        evidence::finding("directory-target", Some(path));
        return Ok(Some(format!("loki: directory target is not a file: {path}")));
    }
    if allow_override && std::env::var("LOKI_ALLOW_PROTECTED").as_deref() == Ok("1") {
        return Ok(None);
    }
    if relatives.iter().any(|r| patterns.iter().any(|p| path_matches(r, p))) {
        evidence::finding("protected-path", Some(&relatives[0]));
        return Ok(Some(format!("{PROTECTED_FILE}{}{PROTECTED_FILE_HINT}", relatives[0])));
    }
    Ok(None)
}

const PROTECTED_FILE: &str = "loki: protected file: ";
const PROTECTED_FILE_HINT: &str = " (set LOKI_ALLOW_PROTECTED=1 to override)";

static FINDING_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^:\s][^:\n]*?)(?::\d+)?: ").expect("static pattern"));

/// A finding's file and its identity without the line number, which moves as the file is edited. The engine's own
/// `loki: ...` lines name no file at their start: a protected-file refusal belongs to the file it names, the others
/// to no file. A tool or engine prefix (`git: ...`, `typescript: ...`) names no file either, so a prefix with no
/// `.` or `/` that is no file under `root` is none. No file: an empty path.
pub fn finding_key(root: &Path, finding: &str) -> (String, String) {
    if finding.starts_with("loki: ") {
        let path = finding
            .strip_prefix(PROTECTED_FILE)
            .map(|named| named.split(PROTECTED_FILE_HINT).next().unwrap_or(named));
        return (path.unwrap_or_default().to_string(), finding.to_string());
    }
    match FINDING_PATH.captures(finding) {
        Some(found) if !found[1].contains(['.', '/']) && !root.join(&found[1]).exists() => {
            (String::new(), finding.to_string())
        }
        Some(found) => {
            let path = found[1].to_string();
            let rest = &finding[found[0].len()..];
            (path.clone(), format!("{path}: {rest}"))
        }
        None => (String::new(), finding.to_string()),
    }
}

fn is_known_preview_tool(harness: &str, name: &str) -> bool {
    matches!(
        (harness, name),
        ("claude" | "codex", "Write" | "Edit")
            | ("claude", "MultiEdit")
            | ("factory", "Create" | "Edit")
            | ("agy", "write_file" | "edit_file")
            | ("pi", "write" | "edit")
            | ("omp" | "ultron", "write")
    )
}

fn extract_write_content(old: &str, data: &Map<String, Value>, harness: &str) -> Result<Option<String>, CheckError> {
    let key = if harness == "agy" { "Content" } else { "content" };
    let text = match data.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(CheckError::Value("preview content must be text".into())),
    };
    if harness == "agy" && data.get("Append") == Some(&Value::Bool(true)) {
        return Ok(Some(format!("{old}{text}")));
    }
    Ok(Some(text))
}

fn resolve_replace_all(edit: &Map<String, Value>, field: &str) -> Result<bool, CheckError> {
    if field == "*" {
        return Ok(true);
    }
    match edit.get(field) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(CheckError::Value("replacement mode must be boolean".into())),
    }
}

fn apply_preview_edit(
    content: &str,
    edit: &Value,
    fields: (&str, &str, &str),
) -> Result<Option<String>, CheckError> {
    let Some(edit) = edit.as_object() else {
        return Err(CheckError::Value("invalid edit preview".into()));
    };
    let (Some(Value::String(source)), Some(Value::String(replacement))) = (edit.get(fields.0), edit.get(fields.1))
    else {
        return Ok(None);
    };
    if source.is_empty() {
        return Ok(None);
    }
    let replace_all = resolve_replace_all(edit, fields.2)?;
    let matches = content.matches(source.as_str()).count();
    if matches == 0 || (matches != 1 && !replace_all) {
        return Ok(None);
    }
    let size = content.len() as i64 + matches as i64 * (replacement.len() as i64 - source.len() as i64);
    if size > PREVIEW_LIMIT as i64 {
        return Err(CheckError::Value("preview exceeds 4 MiB".into()));
    }
    Ok(Some(if replace_all {
        content.replace(source.as_str(), replacement)
    } else {
        content.replacen(source.as_str(), replacement, 1)
    }))
}

fn apply_preview_edits(
    old: &str,
    data: &Map<String, Value>,
    name: &str,
    harness: &str,
    deadline: proc::Deadline,
) -> Result<Option<String>, CheckError> {
    let single = [Value::Object(data.clone())];
    let edits: &[Value] = if name == "MultiEdit" {
        match data.get("edits") {
            Some(Value::Array(items)) if (1..=256).contains(&items.len()) => items,
            _ => return Err(CheckError::Value("edit preview requires 1 to 256 edits".into())),
        }
    } else {
        &single
    };
    let fields = match harness {
        "pi" => ("oldText", "newText", "replace_all"),
        "factory" => ("old_str", "new_str", "change_all"),
        "agy" => ("Target", "Replacement", "*"),
        _ => ("old_string", "new_string", "replace_all"),
    };
    let mut content = old.to_string();
    for edit in edits {
        deadline.timeout()?;
        let Some(next) = apply_preview_edit(&content, edit, fields)? else {
            return Ok(None);
        };
        content = next;
    }
    Ok(Some(content))
}

fn load_preview_base(root: &Path, paths: &[String]) -> Result<(String, Option<Vec<u8>>, String), CheckError> {
    if paths.len() != 1 {
        return Err(CheckError::Value("single-file preview requires one target".into()));
    }
    let root = resolve(root);
    let path = lexical_path(&root, &paths[0]);
    let relative = relative_posix(&path, &root).ok_or_else(|| CheckError::Value("invalid preview envelope".into()))?;
    if resolve(&path) != path {
        return Err(CheckError::Value(
            "preview through symlinked paths is unsupported".into(),
        ));
    }
    let (before, mode) = git::candidate_content(&root, &relative, PREVIEW_LIMIT)?;
    if !matches!(mode.as_deref(), None | Some("100644" | "100755")) {
        return Err(CheckError::Value("preview requires a regular file".into()));
    }
    let old = match &before {
        Some(bytes) => proc::decode(bytes).map_err(CheckError::Value)?,
        None => String::new(),
    };
    Ok((relative, before, old))
}

fn compute_preview_content(
    old: &str,
    before: &Option<Vec<u8>>,
    data: &Map<String, Value>,
    name: &str,
    harness: &str,
    deadline: proc::Deadline,
) -> Result<Option<String>, CheckError> {
    if matches!(name, "Write" | "Create" | "write" | "write_file") {
        return extract_write_content(old, data, harness);
    }
    if before.is_none() {
        return Err(CheckError::Value("edit preview requires an existing file".into()));
    }
    apply_preview_edits(old, data, name, harness, deadline)
}

type ToolCall<'a> = (&'a str, &'a Map<String, Value>);

fn extract_agy_tool_call(object: &Map<String, Value>) -> Option<ToolCall<'_>> {
    let call = object.get("toolCall")?.as_object()?;
    let name = call.get("name")?.as_str().filter(|n| !n.is_empty())?;
    let args = call.get("args")?.as_object()?;
    Some((name, args))
}

fn extract_tool_call<'a>(payload: &'a Value, harness: &str) -> Option<ToolCall<'a>> {
    let object = payload.as_object()?;
    if harness == "agy" {
        return extract_agy_tool_call(object);
    }
    let name = object.get("tool_name")?.as_str().filter(|n| !n.is_empty())?;
    let input = object.get("tool_input")?.as_object()?;
    Some((name, input))
}

fn extract_preview_call<'a>(payload: &'a Value, harness: &str) -> Result<Option<ToolCall<'a>>, CheckError> {
    if harness == "agy" {
        return extract_tool_call(payload, harness)
            .map(Some)
            .ok_or_else(|| CheckError::Value("invalid preview envelope".into()));
    }
    let data = payload
        .as_object()
        .and_then(|p| p.get("tool_input"))
        .and_then(Value::as_object)
        .ok_or_else(|| CheckError::Value("invalid preview envelope".into()))?;
    let name = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
    if payload.get("tool_name").is_some_and(|n| !n.is_string()) {
        return Ok(None);
    }
    Ok(Some((name, data)))
}

/// `preview_changes`: the exact post-write content of a host write or edit.
fn preview_changes(
    root: &Path,
    paths: &[String],
    payload: &Value,
    harness: &str,
    deadline: proc::Deadline,
) -> Result<Option<Vec<rules::Change>>, CheckError> {
    let Some((name, data)) = extract_preview_call(payload, harness)? else {
        return Ok(None);
    };
    if !is_known_preview_tool(harness, name) {
        return Ok(None);
    }
    let (relative, before, old) = load_preview_base(root, paths)?;
    let Some(content) = compute_preview_content(&old, &before, data, name, harness, deadline)? else {
        return Ok(None);
    };
    if content.len() > PREVIEW_LIMIT {
        return Err(CheckError::Value("preview exceeds 4 MiB".into()));
    }
    Ok(Some(vec![(relative, old, content)]))
}

const JS_PREVIEW_RULES: [&str; 11] = [
    "no-empty",
    "no-async-promise-executor",
    "no-promise-executor-return",
    "no-unsafe-finally",
    "no-unsafe-optional-chaining",
    "no-constant-binary-expression",
    "no-debugger",
    "jest/no-disabled-tests",
    "vitest/no-disabled-tests",
    "jest/no-focused-tests",
    "vitest/no-focused-tests",
];

type OxlintPrint = (String, String, String, String, String);
type OxlintFile = (String, (&'static str, String, String));

fn exact_int(v: &Value) -> Option<i64> {
    v.as_i64().filter(|_| v.is_i64() || v.is_u64())
}

fn write_oxlint_workspace(
    work: &Path,
    changes: &[(String, String, String)],
) -> Result<(PathBuf, Vec<OxlintFile>), CheckError> {
    let os = |e: std::io::Error| CheckError::os(&e, None);
    let config = work.join("config.json");
    let rules: Map<String, Value> = JS_PREVIEW_RULES
        .iter()
        .map(|r| (r.to_string(), json!("error")))
        .collect();
    let document = json!({"plugins": ["jest", "vitest"], "categories": {"correctness": "off"}, "rules": rules});
    std::fs::write(&config, py::dumps(&document)).map_err(os)?;
    let mut files: Vec<OxlintFile> = Vec::new();
    for (index, (relative, old, new)) in changes.iter().enumerate() {
        for (side, content) in [("before", old), ("after", new)] {
            let content = content.replace("eslint", "xslint").replace("oxlint", "xxlint");
            let filename = relative.rsplit('/').next().unwrap_or(relative);
            let name = format!("{side}/{index}/{filename}");
            let path = work.join(&name);
            std::fs::create_dir_all(path.parent().unwrap_or(work)).map_err(os)?;
            std::fs::write(&path, &content).map_err(os)?;
            files.push((name, (side, relative.clone(), content)));
        }
    }
    Ok((config, files))
}

fn extract_oxlint_span(span: &Value, content: &str) -> Result<(i64, String, String), CheckError> {
    let lines = py::splitlines(content, false);
    let encoded = content.as_bytes();
    let (Some(offset), Some(length), Some(line)) = (
        exact_int(&span["offset"]),
        exact_int(&span["length"]),
        exact_int(&span["line"]),
    ) else {
        return Err(invalid("invalid Oxlint preview diagnostic span"));
    };
    if offset < 0 || length < 0 || offset + length > encoded.len() as i64 || line < 1 || line > lines.len() as i64 {
        return Err(invalid("invalid Oxlint preview diagnostic span"));
    }
    let snippet = proc::decode(&encoded[offset as usize..(offset + length) as usize]).map_err(CheckError::Value)?;
    Ok((line, py::strip(lines[line as usize - 1]).to_string(), snippet))
}

fn parse_oxlint_diagnostic<'a>(
    item: &Value,
    files: &'a [OxlintFile],
) -> Result<(&'a str, OxlintPrint, i64), CheckError> {
    let Some((_, (side, relative, content))) = item
        .get("filename")
        .and_then(Value::as_str)
        .and_then(|f| files.iter().find(|(name, _)| name == f))
    else {
        return Err(invalid("invalid Oxlint preview diagnostic"));
    };
    let code = item.get("code").and_then(Value::as_str).filter(|s| !s.is_empty());
    let message = item.get("message").and_then(Value::as_str).filter(|s| !s.is_empty());
    let span = item
        .get("labels")
        .and_then(Value::as_array)
        .and_then(|l| l.first())
        .and_then(|l| l.get("span"))
        .filter(|s| s.is_object());
    let (Some(code), Some(message), Some(span)) = (code, message, span) else {
        return Err(invalid("unpositioned Oxlint preview diagnostic"));
    };
    let (line, line_text, snippet) = extract_oxlint_span(span, content)?;
    let key = (relative.clone(), code.to_string(), message.to_string(), line_text, snippet);
    Ok((*side, key, line))
}

fn collect_oxlint_violations(
    diagnostics: &[Value],
    files: &[OxlintFile],
) -> Result<Vec<String>, CheckError> {
    let mut before: py::Counter<OxlintPrint> = py::Counter::new();
    let mut after: py::Counter<OxlintPrint> = py::Counter::new();
    let mut locations: std::collections::HashMap<OxlintPrint, i64> = std::collections::HashMap::new();
    for item in diagnostics {
        let (side, key, line) = parse_oxlint_diagnostic(item, files)?;
        if side == "before" {
            before.add(key.clone());
        } else {
            after.add(key.clone());
        }
        locations.insert(key, line);
    }
    let mut violations = Vec::new();
    for (key, count) in after.minus(&before) {
        evidence::finding(&format!("preview-{}", key.1), Some(&key.0));
        for _ in 0..count {
            violations.push(format!("{}:{}: {}: {}", key.0, locations[&key], key.1, key.2));
        }
    }
    violations.truncate(MAX_VIOLATIONS);
    Ok(violations)
}

fn parse_oxlint_report(result: &proc::Output, expected_files: usize) -> Result<Vec<Value>, CheckError> {
    if !(result.code == 0 || result.code == 1) || !py::strip(&proc::text(&result.stderr)).is_empty() {
        return Err(invalid("Oxlint preview failed or reported incomplete coverage"));
    }
    let stdout = proc::text(&result.stdout);
    let report: Value =
        serde_json::from_str(&stdout).map_err(|e| CheckError::Value(pyjson::error_text(&stdout, &e)))?;
    let complete = report.is_object()
        && exact_int(&report["number_of_files"]) == Some(expected_files as i64)
        && exact_int(&report["number_of_rules"]) == Some(JS_PREVIEW_RULES.len() as i64)
        && report["diagnostics"].is_array();
    if !complete {
        return Err(invalid("invalid or incomplete Oxlint preview report"));
    }
    let diagnostics = report["diagnostics"].as_array().cloned().unwrap_or_default();
    if diagnostics.is_empty() != (result.code == 0) {
        return Err(invalid("Oxlint preview status disagrees with diagnostics"));
    }
    Ok(diagnostics)
}

/// Oxlint's preview rules over before and after copies; net-new findings block.
fn preview_oxlint(
    root: &Path,
    changes: &[(String, String, String)],
    deadline: proc::Deadline,
) -> Result<Vec<String>, CheckError> {
    let Some(binary) = hook::resolve_tool(root, "oxlint") else {
        return Err(invalid("missing oxlint for content preview"));
    };
    let directory = tempfile::Builder::new()
        .prefix("loki-preview-")
        .tempdir()
        .map_err(|e| CheckError::os(&e, None))?;
    let work = directory.path();
    let (config, files) = write_oxlint_workspace(work, changes)?;
    let mut command: Vec<String> = vec![
        resolve(Path::new(&binary)).to_string_lossy().into_owned(),
        "-c".into(),
        config.to_string_lossy().into_owned(),
        "--disable-nested-config".into(),
        "--no-ignore".into(),
        "--threads".into(),
        "1".into(),
        "--format".into(),
        "json".into(),
    ];
    command.extend(files.iter().map(|(name, _)| work.join(name).to_string_lossy().into_owned()));
    let result = proc::run(&command, work, None, &[], deadline.timeout()?)?;
    let diagnostics = parse_oxlint_report(&result, files.len())?;
    collect_oxlint_violations(&diagnostics, &files)
}

fn recoverable(error: &CheckError) -> bool {
    matches!(error, CheckError::Value(_)) || error.is_os() || error.is_timeout()
}

fn run_javascript_preview(
    root: &Path,
    config: &config::Config,
    changes: &[rules::Change],
    deadline: proc::Deadline,
    violations: &mut Vec<String>,
) -> Result<(), CheckError> {
    if violations.is_empty() {
        violations.extend(typescript::preview_typescript(root, config, changes, deadline)?);
    }
    match preview_oxlint(root, changes, deadline) {
        Ok(found) => {
            violations.extend(found);
            Ok(())
        }
        Err(error) if recoverable(&error) => {
            violations.extend(rules::content_rule_violations(changes, true)?);
            Err(error)
        }
        Err(other) => Err(other),
    }
}

fn handle_preview_error(
    error: CheckError,
    javascript: bool,
    previewed: bool,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<bool, CheckError> {
    if !recoverable(&error) {
        return Err(error);
    }
    if !javascript {
        return Ok(true);
    }
    evidence::finding("preview-unavailable", None);
    let suffix = if previewed {
        "; built-in fallback rules applied"
    } else {
        ""
    };
    let message = format!("NOT CHECKED pre-write content: {}{suffix}", error.message());
    if crate::strict() {
        violations.push(message);
        return Ok(true);
    }
    warnings.push(message);
    Ok(false)
}

/// `preview_violations`: net-new findings in the previewed content.
pub fn preview_violations(
    root: &Path,
    paths: &[String],
    payload: Option<&Value>,
    harness: &str,
    deadline: proc::Deadline,
    warnings: &mut Vec<String>,
    config: &config::Config,
) -> Result<Vec<String>, CheckError> {
    let Some(payload) = payload else { return Ok(vec![]) };
    let javascript = paths.iter().any(|p| rules::language(p) == Some("typescript"));
    let mut violations: Vec<String> = Vec::new();
    let mut previewed = false;
    let attempt = (|| -> Result<(), CheckError> {
        let Some(changes) = preview_changes(root, paths, payload, harness, deadline)? else {
            return Err(CheckError::Value("host operation has no exact content preview".into()));
        };
        previewed = true;
        violations.extend(rules::content_rule_violations(&changes, false)?);
        violations.extend(hook::preview_ruff(root, &changes, deadline)?);
        if javascript {
            run_javascript_preview(root, config, &changes, deadline, &mut violations)?;
        }
        Ok(())
    })();
    if let Err(error) = attempt
        && handle_preview_error(error, javascript, previewed, &mut violations, warnings)?
    {
        return Ok(violations);
    }
    violations.truncate(MAX_VIOLATIONS);
    Ok(violations)
}

fn patch_header_op(line: &str) -> Option<&'static str> {
    ["Add", "Update", "Delete"]
        .into_iter()
        .find(|op| line.starts_with(&format!("*** {op} File: ")))
}

fn consume_update_line(line: &str, content: &mut usize, pending: &mut bool, ended: &mut bool) -> Result<(), CheckError> {
    if line == "@@" || line.starts_with("@@ ") {
        if *pending {
            return Err(invalid("empty change hunk"));
        }
        *pending = true;
    } else if line.starts_with(['+', '-', ' ']) {
        *content += 1;
        *pending = false;
    } else if line == "*** End of File" && *content > 0 && !*pending {
        *ended = true;
    } else {
        return Err(invalid("unknown patch structural marker"));
    }
    Ok(())
}

fn consume_patch_line(
    line: &str,
    operation: &str,
    content: &mut usize,
    pending: &mut bool,
    ended: &mut bool,
) -> Result<(), CheckError> {
    if *ended || operation == "Delete" {
        return Err(invalid("unexpected patch body"));
    }
    if operation == "Add" {
        if !line.starts_with('+') {
            return Err(invalid("Add requires added content lines"));
        }
        *content += 1;
        return Ok(());
    }
    consume_update_line(line, content, pending, ended)
}

fn consume_patch_body(lines: &[&str], index: &mut usize, operation: &str, moved: bool) -> Result<(), CheckError> {
    let (mut content, mut pending, mut ended) = (0, false, false);
    while *index < lines.len() - 1 {
        let line = lines[*index];
        if patch_header_op(line).is_some() {
            break;
        }
        consume_patch_line(line, operation, &mut content, &mut pending, &mut ended)?;
        *index += 1;
    }
    if pending || (operation == "Add" && content == 0) || (operation == "Update" && content == 0 && !moved) {
        return Err(invalid("empty patch operation"));
    }
    Ok(())
}

fn parse_patch_operation(lines: &[&str], index: &mut usize, paths: &mut Vec<String>) -> Result<(), CheckError> {
    let header = lines[*index];
    let Some(operation) = patch_header_op(header) else {
        return Err(invalid("unknown patch operation"));
    };
    let target = &header[format!("*** {operation} File: ").len()..];
    valid_path(target)?;
    paths.push(target.to_string());
    *index += 1;
    let mut moved = false;
    if operation == "Update" && lines[*index].starts_with("*** Move to: ") {
        let target = &lines[*index]["*** Move to: ".len()..];
        valid_path(target)?;
        paths.push(target.to_string());
        moved = true;
        *index += 1;
    }
    consume_patch_body(lines, index, operation, moved)
}

/// `patch_paths`: the files a Codex `apply_patch` envelope touches.
pub fn patch_paths(patch: &Value) -> Result<Vec<String>, CheckError> {
    let Some(patch) = patch.as_str().filter(|p| !p.contains('\0')) else {
        return Err(invalid("patch must be a string without NUL"));
    };
    let mut lines: Vec<&str> = patch.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    if lines.len() < 3 || lines[0] != "*** Begin Patch" || lines[lines.len() - 1] != "*** End Patch" {
        return Err(invalid("invalid patch boundaries"));
    }
    let mut paths: Vec<String> = Vec::new();
    let mut index = 1;
    while index < lines.len() - 1 {
        parse_patch_operation(&lines, &mut index, &mut paths)?;
    }
    let mut unique = Vec::new();
    for path in paths {
        if !unique.contains(&path) {
            unique.push(path);
        }
    }
    Ok(unique)
}

fn supported_harness_tools(harness: &str) -> &'static [&'static str] {
    match harness {
        "claude" => &["Write", "Edit", "MultiEdit", "NotebookEdit"],
        "codex" => &["apply_patch", "Write", "Edit"],
        "factory" => &["Create", "Edit", "ApplyPatch"],
        "agy" => &["write_file", "edit_file"],
        _ => &[],
    }
}

fn raw_target_path<'a>(harness: &str, tool_name: &str, input: &'a Map<String, Value>) -> Option<&'a Value> {
    match (harness, tool_name) {
        ("agy", _) => input.get("Path").or_else(|| input.get("path")),
        (_, "NotebookEdit") => input.get("notebook_path").or_else(|| input.get("file_path")),
        _ => input.get("file_path"),
    }
}

fn extract_harness_target_paths(
    harness: &str,
    tool_name: &str,
    input: &Map<String, Value>,
) -> Result<Vec<String>, CheckError> {
    if harness == "codex" && tool_name == "apply_patch" {
        let patch = input
            .get("command")
            .or_else(|| input.get("input"))
            .or_else(|| input.get("patch"))
            .unwrap_or(&Value::Null);
        return patch_paths(patch);
    }
    match raw_target_path(harness, tool_name, input) {
        Some(Value::String(p)) if !p.is_empty() && !p.contains('\0') => Ok(vec![p.clone()]),
        _ => Err(invalid("path must be a nonempty string without NUL")),
    }
}

fn extract_harness_cwd(object: &Map<String, Value>, harness: &str) -> Result<String, CheckError> {
    let raw = object.get("cwd").or_else(|| {
        (harness == "agy")
            .then(|| {
                object
                    .get("workspacePaths")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
            })
            .flatten()
    });
    let cwd = match raw {
        Some(Value::String(cwd)) if !cwd.is_empty() && !cwd.contains('\0') => cwd.clone(),
        _ => return Err(invalid("path must be a nonempty string without NUL")),
    };
    if !cwd.starts_with('/') {
        return Err(invalid("cwd must be absolute"));
    }
    Ok(cwd)
}

fn validate_harness_envelope<'a>(
    payload: &'a Value,
    harness: &str,
) -> Result<(String, &'a str, &'a Map<String, Value>), CheckError> {
    let Some(object) = payload.as_object() else {
        return Err(invalid("hook envelope must be an object"));
    };
    let cwd = extract_harness_cwd(object, harness)?;
    let Some((name, input)) = extract_tool_call(payload, harness) else {
        let msg = if harness == "agy" {
            "toolCall.name and object toolCall.args are required"
        } else {
            "tool_name and object tool_input are required"
        };
        return Err(invalid(msg));
    };
    if !supported_harness_tools(harness).contains(&name) {
        return Err(invalid(format!("loki: unsupported {harness} tool: {name}")));
    }
    if harness == "factory" && name == "ApplyPatch" {
        return Err(invalid("loki: unsupported factory ApplyPatch payload"));
    }
    Ok((cwd, name, input))
}

/// `harness_paths`: absolute targets of a Claude, Codex, Factory or Antigravity hook envelope.
pub fn harness_paths(payload: &Value, harness: &str) -> Result<Vec<String>, CheckError> {
    let (cwd, tool_name, input) = validate_harness_envelope(payload, harness)?;
    let paths = extract_harness_target_paths(harness, tool_name, input)?;
    let mut unique = Vec::new();
    for path in paths {
        let absolute = abspath(Path::new(&cwd), &path).to_string_lossy().into_owned();
        if !unique.contains(&absolute) {
            unique.push(absolute);
        }
    }
    Ok(unique)
}

static FINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<path>[^:\s][^:\n]*?)(?::(?P<line>\d+))?: (?P<rule>[^:\s][^:\n]*?): ").expect("static pattern")
});

/// `hook_report`: the `--format json` document.
pub fn hook_report(command: &str, messages: &[String], warnings: &[String], error: Option<&str>) -> Value {
    let entry = |text: &String| {
        let mut item = Map::new();
        item.insert("text".into(), json!(text));
        if let Some(caps) = FINDING_RE.captures(text) {
            item.insert("path".into(), json!(&caps["path"]));
            if let Some(line) = caps.name("line").and_then(|m| m.as_str().parse::<u64>().ok()) {
                item.insert("line".into(), json!(line));
            }
            item.insert("rule".into(), json!(&caps["rule"]));
        }
        Value::Object(item)
    };
    let status = if error.is_some() {
        "error"
    } else if messages.is_empty() {
        "passed"
    } else {
        "blocked"
    };
    let mut report = json!({
        "loki": VERSION,
        "command": command,
        "status": status,
        "blocking": messages.iter().take(MAX_VIOLATIONS).map(entry).collect::<Vec<_>>(),
        "advisory": warnings.iter().filter(|w| !w.starts_with("NOT CHECKED")).map(entry).collect::<Vec<_>>(),
        "not_checked": warnings.iter().filter(|w| w.starts_with("NOT CHECKED")).collect::<Vec<_>>(),
    });
    if let (Some(error), Some(map)) = (error, report.as_object_mut()) {
        map.insert("error".into(), json!(error));
    }
    report
}

/// The policy note an Ultron session's prompt carries for the policy under `root` (loki.ts `readContext`): none when
/// the policy cannot be read (the guard still runs and reports it).
pub fn session_note(root: &std::path::Path) -> Option<String> {
    let config = config::load_config(root).ok()?;
    injected_context(&config, Some("ultron")).ok()
}

fn ultron_context(packs: &[String]) -> String {
    let checks = [
        ("core", "secrets, security rules, protected files"),
        ("python", "Ruff (Python)"),
        ("typescript", "Oxlint and type checks (TS/JS)"),
        ("phoenix", "Credo and Sobelow (Elixir)"),
    ];
    let listed: Vec<&str> = checks
        .iter()
        .filter(|(p, _)| packs.iter().any(|name| name == p))
        .map(|(_, c)| *c)
        .collect();
    let mut text = String::from(
        "LOKI guardrails: edit() and write() are checked before the file changes. Change source and configuration with edit()/write(): a bash() command that writes them (redirect, tee, sed -i, cp/mv) is refused. Other writes (Path.write_text, programs) are checked after the cell. A blocked write raises ValueError with the finding: fix the cause and retry. Never weaken Loki, its policy (.loki/), tests or hooks.",
    );
    if !listed.is_empty() {
        text.push_str(&format!(" Checks: {}.", listed.join("; ")));
    }
    text
}

fn phoenix_context(config: &Config) -> Result<Vec<String>, String> {
    let (block, warn) = config::security_policy(config)?;
    let first = if block == "none" {
        "Sobelow blocking is disabled; ".to_string()
    } else {
        format!("Sobelow {block} confidence findings block; ")
    };
    let second = if warn == "none" {
        "warnings are disabled. Lower levels remain visible as info.".to_string()
    } else {
        format!("{warn} findings warn. Lower levels remain visible.")
    };
    Ok(vec![
        "Phoenix/Elixir hooks check formatting, net-new Credo and source-security Sobelow findings. Compilation and HEEx component checks require the project tier; they do not run on every write.".into(),
        first + &second,
        "Use Ecto parameterization, supervised processes, validated changesets and assigns-based authorization.".into(),
    ])
}

/// `injected_context`: session guidance for the configured rule packs.
pub fn injected_context(config: &Config, host: Option<&str>) -> Result<String, String> {
    let packs = config::rule_packs(config)?;
    let has = |name: &str| packs.iter().any(|p| p == name);
    if host == Some("ultron") {
        return Ok(ultron_context(&packs));
    }
    let mut lines = vec![
        "LOKI POLICY GUIDANCE. This describes configured policy, not proof that hooks or analyzers are active. NOT CHECKED means coverage is unavailable.".to_string(),
        "When a rule reports a violation, fix it and retry. Do not weaken the checker, policy, tests or hooks.".into(),
        "Use verified file tools. Do not route writes through shell commands to bypass checks.".into(),
    ];
    for (pack, line) in [
        ("core", "Protected policy, hook, workflow and quality files require independent review."),
        ("python", "Python edits must introduce no new Ruff findings and preserve meaningful tests."),
        ("typescript", "TypeScript edits must pass Oxlint and enabled project-wide type checks, including consumers."),
    ] {
        if has(pack) {
            lines.push(line.into());
        }
    }
    if has("phoenix") {
        lines.extend(phoenix_context(config)?);
    }
    if has("shell") {
        lines.push("Shell redirects, substitutions, compound commands and destructive Git operations require review when the optional shell guard is installed. Selecting this guidance pack does not install that guard.".into());
    }
    Ok(lines.join("\n"))
}
