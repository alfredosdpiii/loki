//! Project-wide TypeScript checks: net-new compiler and type-aware diagnostics,
//! run through the project's own `typescript.js` with loki.py's checker script.

use crate::config::Config;
use crate::git::{self, FileChange, git_output};
use crate::hook::possibly_existing;
use crate::proc::{self, Deadline};
use crate::py::{self, Counter};
use crate::{CheckError, resolve};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const TYPESCRIPT_SUFFIXES: [&str; 8] = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

const CHECKER: &str = r#"
const path = require('node:path');
const fs = require('node:fs');
const compilers = new Map();
const parsedFiles = new Map();

function isThenable(checker, type) {
  return (type.isUnion() ? type.types : [type]).some(part => {
    const then = part.getProperty('then');
    return then !== undefined && checker.getTypeOfSymbol(then).getCallSignatures().length > 0;
  });
}

// Type-aware findings that plain linters without type information cannot see.
function semanticFindings(ts, program, root) {
  const checker = program.getTypeChecker();
  const found = [];
  for (const file of program.getSourceFiles()) {
    const relative = path.relative(root, file.fileName);
    if (file.isDeclarationFile || relative.startsWith('..') ||
        relative.split(path.sep).includes('node_modules')) continue;
    const visit = node => {
      if (ts.isExpressionStatement(node)) {
        const expression = node.expression;
        const callee = ts.isCallExpression(expression) &&
          ts.isPropertyAccessExpression(expression.expression)
          ? expression.expression.name.text : '';
        const handled = callee === 'catch' ||
          (callee === 'then' && expression.arguments.length > 1);
        if (!ts.isVoidExpression(expression) && !ts.isAwaitExpression(expression) &&
            !handled && (ts.isCallExpression(expression) || ts.isNewExpression(expression)) &&
            isThenable(checker, checker.getTypeAtLocation(expression))) {
          found.push([file, node, 'loki/floating-promise',
            'floating promise: this Promise is not awaited, returned, voided or ' +
            'handled with .catch, so its rejection is lost']);
        }
      }
      if (ts.isCallExpression(node) && node.arguments.length === 0 &&
          ts.isPropertyAccessExpression(node.expression) &&
          node.expression.name.text === 'sort') {
        const receiver = checker.getTypeAtLocation(node.expression.expression);
        const element = checker.isArrayType(receiver)
          ? checker.getTypeArguments(receiver)[0] : undefined;
        if (element && (element.flags & (ts.TypeFlags.NumberLike | ts.TypeFlags.BigIntLike))) {
          found.push([file, node, 'loki/numeric-sort',
            'numeric array sorted without a comparator is ordered lexicographically ' +
            '(10 before 9); pass (a, b) => a - b']);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  return found.map(([file, node, code, message]) => {
    const line = file.getLineAndCharacterOfPosition(node.getStart(file)).line;
    return [path.relative(root, file.fileName), code, message,
      file.text.split(/\r?\n/)[line].trim(), line];
  });
}

function check(compilerPath, root, trusted, overridesPath, shadow) {
  if (!compilers.has(compilerPath)) compilers.set(compilerPath, require(compilerPath));
  const ts = compilers.get(compilerPath);
  const configPath = path.join(root, 'tsconfig.json');
  const read = ts.readConfigFile(configPath, file => file === configPath && trusted
    ? fs.readFileSync(trusted, 'utf8') : ts.sys.readFile(file));
  if (read.error) throw new Error(
    ts.flattenDiagnosticMessageText(read.error.messageText, '\n'));
  const confined = file => {
    const relative = path.relative(root, path.resolve(file));
    if (relative === '..' || relative.startsWith('../') || path.isAbsolute(relative))
      throw new Error('TypeScript configuration escapes isolated workspace');
  };
  const configHost = {...ts.sys,
    readFile(file) { confined(file); return ts.sys.readFile(file); },
    fileExists(file) { confined(file); return ts.sys.fileExists(file); }
  };
  const parsed = ts.parseJsonConfigFileContent(read.config, configHost, root,
    {noEmit:true, incremental:false}, configPath);
  if (parsed.errors.length) throw new Error(parsed.errors.map(d =>
    ts.flattenDiagnosticMessageText(d.messageText, '\n')).join('\n'));
  // Default type roots walk up past the repository; keep them inside it.
  if (parsed.options.typeRoots === undefined)
    parsed.options.typeRoots = [path.join(root, 'node_modules', '@types')];
  const host = ts.createCompilerHost(parsed.options);
  const compilerRoot = path.dirname(path.dirname(path.resolve(compilerPath)));
  const readable = file => {
    const full = path.resolve(file);
    if (full.startsWith(compilerRoot + path.sep)) return;
    confined(full);
  };
  // Proposed contents for pre-write checks, keyed by absolute path; never written.
  const overrides = overridesPath ? JSON.parse(fs.readFileSync(overridesPath, 'utf8')) : {};
  const proposed = file => Object.hasOwn(overrides, path.resolve(file));
  const originalRead = host.readFile;
  const originalExists = host.fileExists;
  host.fileExists = file => {
    if (proposed(file)) return true;
    try { readable(file); } catch { return false; }
    return originalExists(file);
  };
  host.readFile = file => {
    if (proposed(file)) return overrides[path.resolve(file)];
    readable(file);
    return originalRead(file);
  };
  // A long-lived checker reuses parsed files, including the standard library.
  host.getSourceFile = (file, version) => {
    const text = host.readFile(file);
    if (text === undefined) return undefined;
    const key = `${version}\0${file}`;
    const cached = parsedFiles.get(key);
    if (cached !== undefined && cached.text === text) return cached;
    if (parsedFiles.size > 20000) parsedFiles.clear();
    const parsedFile = ts.createSourceFile(file, text, version);
    parsedFiles.set(key, parsedFile);
    return parsedFile;
  };
  // New proposed files: match them against include/exclude from an empty shadow tree.
  if (shadow) {
    try {
      const extra = ts.parseJsonConfigFileContent(read.config, ts.sys, shadow,
        {noEmit:true}, path.join(shadow, 'tsconfig.json'));
      for (const file of extra.fileNames) {
        const real = path.join(root, path.relative(shadow, file));
        if (proposed(real) && !parsed.fileNames.includes(real)) parsed.fileNames.push(real);
      }
    } catch {
      // Unmatched new files are reported as uncovered and checked after the write.
    }
  }
  const program = ts.createProgram(parsed.fileNames, parsed.options, host);
  const uncovered = Object.keys(overrides).filter(file =>
    /\.[cm]?tsx?$/.test(file) && !program.getSourceFile(file));
  const diagnostics = ts.getPreEmitDiagnostics(program).map(d => {
    const file = d.file ? path.relative(root, d.file.fileName) : '';
    const line = d.file && d.start !== undefined
      ? d.file.getLineAndCharacterOfPosition(d.start).line : -1;
    const text = line >= 0 ? d.file.text.split(/\r?\n/)[line].trim() : '';
    return [file, d.code, ts.flattenDiagnosticMessageText(d.messageText, '\n'), text,
      line];
  });
  return {diagnostics: [...diagnostics, ...semanticFindings(ts, program, root)], uncovered};
}

if (process.argv[1] === '--serve') {
  const lines = require('node:readline').createInterface({input: process.stdin});
  lines.on('line', line => {
    const {id, args} = JSON.parse(line);
    let reply;
    try { reply = {id, result: check(...args)}; }
    catch (error) { reply = {id, error: String(error && error.message || error)}; }
    process.stdout.write(JSON.stringify(reply) + '\n');
  });
} else {
  console.log(JSON.stringify(check(...process.argv.slice(1, 6))));
}
"#;

use crate::invalid;

/// The project's `typescript.js`, else the one beside `tsc` on PATH.
pub fn typescript_compiler(root: &Path) -> Option<PathBuf> {
    let local = root.join("node_modules/typescript/lib/typescript.js");
    if local.is_file() {
        return Some(local);
    }
    let tsc = proc::which("tsc")?;
    let compiler = resolve(Path::new(&tsc)).parent()?.parent()?.join("lib/typescript.js");
    compiler.is_file().then_some(compiler)
}

/// `(file, code, message, line text)`; code is the JSON value (number or rule name).
type Key = (String, String, String, String);

struct Report {
    found: Counter<Key>,
    lines: HashMap<Key, i64>,
    uncovered: Vec<Value>,
}

fn code_text(code: &Value) -> String {
    match code {
        Value::String(s) => format!("s:{s}"),
        other => format!("n:{other}"),
    }
}

fn diagnostics(
    compiler: &Path,
    workspace: &Path,
    trusted: Option<&Path>,
    deadline: Deadline,
    overrides: Option<&Path>,
    shadow: Option<&Path>,
) -> Result<Report, CheckError> {
    let text = |p: Option<&Path>| p.map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let command = vec![
        "node".to_string(),
        "-e".into(),
        CHECKER.into(),
        resolve(compiler).to_string_lossy().into_owned(),
        workspace.to_string_lossy().into_owned(),
        text(trusted),
        text(overrides),
        text(shadow),
    ];
    let result = proc::run(&command, workspace, None, &[], deadline.timeout()?)?;
    if result.code != 0 {
        return Err(invalid(format!(
            "typescript: checker unavailable: {}",
            py::strip(&proc::text(&result.stderr))
        )));
    }
    let stdout = proc::text(&result.stdout);
    let report: Value = serde_json::from_str(&stdout).map_err(|e| invalid(crate::pyjson::error_text(&stdout, &e)))?;
    let mut found = Counter::new();
    let mut lines = HashMap::new();
    for item in report["diagnostics"].as_array().into_iter().flatten() {
        let key = (
            item[0].as_str().unwrap_or("").to_string(),
            code_text(&item[1]),
            item[2].as_str().unwrap_or("").to_string(),
            item[3].as_str().unwrap_or("").to_string(),
        );
        found.add(key.clone());
        lines.entry(key).or_insert(item[4].as_i64().unwrap_or(0) + 1);
    }
    let uncovered = report["uncovered"].as_array().cloned().unwrap_or_default();
    Ok(Report {
        found,
        lines,
        uncovered,
    })
}

/// The marker naming one exact candidate tree: base, config and changes.
fn typescript_state(
    root: &Path,
    base: &str,
    config: &[u8],
    changes: &[FileChange],
    overrides: Option<&BTreeMap<String, String>>,
) -> PathBuf {
    use sha2::{Digest, Sha256};
    let mut files: BTreeMap<String, Option<Vec<u8>>> =
        changes.iter().map(|c| (c.path.clone(), c.after.clone())).collect();
    for (name, text) in overrides.into_iter().flatten() {
        files.insert(name.clone(), Some(text.clone().into_bytes()));
    }
    let mut digest = Sha256::new();
    digest.update(format!("{base}\0").as_bytes());
    digest.update(crate::compat::sha256(config));
    for (name, content) in &files {
        digest.update(crate::compat::sha256(name.as_bytes()));
        match content {
            None => digest.update(b"-"),
            Some(bytes) => digest.update(crate::compat::sha256(bytes)),
        }
    }
    let identity = crate::compat::sha256_hex(resolve(root).as_os_str().as_encoded_bytes());
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into()));
    home.join(".cache/loki/typescript")
        .join(&identity[..16])
        .join(crate::compat::hex(&digest.finalize()))
}

static JSONC_TOKEN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r#"(?s)"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/|,\s*[}\]]"#).expect("valid regex")
});

/// `strip_jsonc`: tsconfig's JSON dialect as plain JSON: comments and trailing commas dropped.
pub fn strip_jsonc(text: &str) -> String {
    JSONC_TOKEN
        .replace_all(text, |c: &regex::Captures<'_>| match c[0].as_bytes()[0] {
            b'"' => c[0].to_string(),
            b',' => c[0][1..].to_string(),
            _ => String::new(),
        })
        .into_owned()
}

/// `typescript_extends`: repository paths the committed tsconfig.json extends; None when unreadable.
/// Package names resolve into node_modules, which is refused separately.
fn typescript_extends(raw: Option<&[u8]>) -> Option<HashSet<String>> {
    let config: Value = serde_json::from_str(&strip_jsonc(&String::from_utf8_lossy(raw?))).ok()?;
    let targets = match config.get("extends") {
        Some(Value::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
        None => vec![],
    };
    let mut names = HashSet::new();
    for target in targets.iter().filter_map(Value::as_str).filter(|t| t.starts_with('.')) {
        let path = crate::slop::normpath(target);
        names.insert(format!("{path}.json"));
        names.insert(path);
    }
    Some(names)
}

/// `typescript_config_json`: whether a JSON file can change compiler options or module resolution.
/// An unreadable committed tsconfig.json (comments, say) keeps every JSON file.
fn typescript_config_json(name: &str, extends: Option<&HashSet<String>>) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    name.ends_with(".json")
        && extends.is_none_or(|extends| {
            extends.contains(name)
                || base == "package.json"
                || base.starts_with("tsconfig")
                || base.starts_with("jsconfig")
        })
}

fn report_setup(notices: Option<&mut Vec<String>>, message: String) -> Vec<String> {
    match notices {
        None => vec![message],
        Some(list) => {
            list.push(message);
            vec![]
        }
    }
}

fn read_base_file(root: &Path, base: &str, path: &str, deadline: Deadline) -> Result<Option<Vec<u8>>, CheckError> {
    match git_output(root, &["show", &format!("{base}:{path}")], deadline, None) {
        Ok(raw) => Ok(Some(raw)),
        Err(CheckError::Value(_)) => Ok(None),
        Err(other) => Err(other),
    }
}

fn check_config_and_deps(
    changes: &[FileChange],
    overrides: Option<&BTreeMap<String, String>>,
    extends: Option<&HashSet<String>>,
) -> Option<String> {
    let names = changes
        .iter()
        .map(|c| c.path.as_str())
        .chain(overrides.into_iter().flatten().map(|(k, _)| k.as_str()));
    for name in names {
        if typescript_config_json(name, extends) {
            return Some(format!("{name}: JSON/config change requires separate review"));
        }
        if name.starts_with("node_modules/") {
            return Some("typescript: dependency changes require separate review".into());
        }
    }
    None
}

enum Prepared {
    Ready {
        compiler: PathBuf,
        base: String,
        raw: Vec<u8>,
        changes: Vec<FileChange>,
    },
    Setup(String),
    Findings(Vec<String>),
}

fn load_base_tsconfig(
    root: &Path,
    base: &str,
    changes: &[FileChange],
    overrides: Option<&BTreeMap<String, String>>,
    deadline: Deadline,
) -> Result<Result<Vec<u8>, String>, CheckError> {
    let raw = read_base_file(root, base, "tsconfig.json", deadline)?;
    let extends = typescript_extends(raw.as_deref());
    if let Some(message) = check_config_and_deps(changes, overrides, extends.as_ref()) {
        return Ok(Err(message));
    }
    match raw {
        Some(raw) => Ok(Ok(raw)),
        None => Ok(Err("typescript: committed tsconfig.json required".into())),
    }
}

fn prepare_typescript_check(
    root: &Path,
    overrides: Option<&BTreeMap<String, String>>,
    deadline: Deadline,
) -> Result<Prepared, CheckError> {
    let Some(compiler) = typescript_compiler(root) else {
        return Ok(Prepared::Setup(
            "typescript: required TypeScript compiler is missing".into(),
        ));
    };
    let (base, changes) = git::git_changes(root, None, deadline)?;
    let Some(base) = base else {
        return Ok(Prepared::Setup("typescript: committed base required".into()));
    };
    let policy = git::base_policy(root, Some(&base), deadline)?.unwrap_or_default();
    let findings = git::protected_change_violations(&changes, &policy)?;
    if !findings.is_empty() {
        return Ok(Prepared::Findings(findings));
    }
    match load_base_tsconfig(root, &base, &changes, overrides, deadline)? {
        Ok(raw) => Ok(Prepared::Ready {
            compiler,
            base,
            raw,
            changes,
        }),
        Err(message) => Ok(Prepared::Setup(message)),
    }
}

fn write_overrides(
    root: &Path,
    dir: &Path,
    overrides: &BTreeMap<String, String>,
) -> Result<(PathBuf, Option<PathBuf>), CheckError> {
    let os = |e: std::io::Error| CheckError::os(&e, None);
    let path = dir.join("overrides.json");
    let map: Map<String, Value> = overrides
        .iter()
        .map(|(name, text)| {
            (
                root.join(name).to_string_lossy().into_owned(),
                Value::String(text.clone()),
            )
        })
        .collect();
    std::fs::write(&path, py::dumps(&Value::Object(map))).map_err(os)?;
    let tree = dir.join("shadow");
    for name in overrides.keys() {
        if !root.join(name).exists() {
            let file = tree.join(name);
            if let Some(parent) = file.parent() {
                std::fs::create_dir_all(parent).map_err(os)?;
            }
            std::fs::write(&file, b"").map_err(os)?;
        }
    }
    Ok((path, tree.is_dir().then_some(tree)))
}

fn touch_marker(marker: &Path) -> Result<(), CheckError> {
    let os = |e: std::io::Error| CheckError::os(&e, None);
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent).map_err(os)?;
    }
    std::fs::write(marker, b"").map_err(os)
}

fn load_base_texts(
    root: &Path,
    base: &str,
    found: &Counter<Key>,
    deadline: Deadline,
) -> Result<HashMap<String, String>, CheckError> {
    let mut texts = HashMap::new();
    for key in found.keys() {
        if key.0.is_empty() || texts.contains_key(&key.0) {
            continue;
        }
        let text = read_base_file(root, base, &key.0, deadline)?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        texts.insert(key.0.clone(), text);
    }
    Ok(texts)
}

fn baseline_diagnostics(
    root: &Path,
    base: &str,
    compiler: &Path,
    dir: &Path,
    after: &Report,
    deadline: Deadline,
) -> Result<Counter<Key>, CheckError> {
    let texts = load_base_texts(root, base, &after.found, deadline)?;
    if !possibly_existing(after.found.keys().map(|k| (k.0.as_str(), k.3.as_str())), &texts) {
        return Ok(Counter::new());
    }
    let before = dir.join("before");
    git::materialize_base(root, base, &before, deadline)?;
    if root.join("node_modules").is_dir() {
        std::os::unix::fs::symlink(resolve(&root.join("node_modules")), before.join("node_modules"))
            .map_err(|e| CheckError::os(&e, None))?;
    }
    Ok(diagnostics(compiler, &before, None, deadline, None, None)?.found)
}

fn format_findings(after: &Report, previous: &Counter<Key>) -> Vec<String> {
    let mut findings = Vec::new();
    for (key, count) in after.found.minus(previous) {
        let (label, code) = match key.1.split_once(':') {
            Some(("s", name)) => (name.to_string(), name),
            Some((_, number)) => (format!("TS{number}"), number),
            None => (key.1.clone(), key.1.as_str()),
        };
        crate::evidence::finding(&format!("typescript:{code}"), Some(&key.0));
        for _ in 0..count {
            findings.push(format!("{}:{}: {label}: {}", key.0, after.lines[&key], key.2));
        }
    }
    findings
}

fn prepare_check_dir(
    root: &Path,
    raw: &[u8],
    overrides: Option<&BTreeMap<String, String>>,
) -> Result<(tempfile::TempDir, PathBuf, Option<PathBuf>, Option<PathBuf>), CheckError> {
    let os = |e: std::io::Error| CheckError::os(&e, None);
    let directory = tempfile::Builder::new()
        .prefix("loki-typescript-")
        .tempdir()
        .map_err(os)?;
    let trusted = directory.path().join("tsconfig.json");
    std::fs::write(&trusted, raw).map_err(os)?;
    let (proposed, shadow) = match overrides {
        Some(overrides) => {
            let (p, s) = write_overrides(root, directory.path(), overrides)?;
            (Some(p), s)
        }
        None => (None, None),
    };
    Ok((directory, trusted, proposed, shadow))
}

fn run_typescript_check(
    root: &Path,
    compiler: &Path,
    base: &str,
    raw: &[u8],
    marker: &Path,
    overrides: Option<&BTreeMap<String, String>>,
    deadline: Deadline,
) -> Result<Vec<String>, CheckError> {
    let (directory, trusted, proposed, shadow) = prepare_check_dir(root, raw, overrides)?;
    let after = diagnostics(
        compiler,
        root,
        Some(&trusted),
        deadline,
        proposed.as_deref(),
        shadow.as_deref(),
    )?;
    if after.found.is_empty() {
        if overrides.is_some() && after.uncovered.is_empty() {
            touch_marker(marker)?;
        }
        return Ok(vec![]);
    }
    let previous = baseline_diagnostics(root, base, compiler, directory.path(), &after, deadline)?;
    Ok(format_findings(&after, &previous))
}

/// Net-new project type errors, using the committed tsconfig.json.
pub fn typescript_violations(
    root: &Path,
    deadline: Deadline,
    notices: Option<&mut Vec<String>>,
    overrides: Option<&BTreeMap<String, String>>,
) -> Result<Vec<String>, CheckError> {
    let (compiler, base, raw, changes) = match prepare_typescript_check(root, overrides, deadline)? {
        Prepared::Ready {
            compiler,
            base,
            raw,
            changes,
        } => (compiler, base, raw, changes),
        Prepared::Setup(message) => return Ok(report_setup(notices, message)),
        Prepared::Findings(findings) => return Ok(findings),
    };
    crate::evidence::policy("base", "tsconfig.json", Some(&raw), Some(&base));
    let marker = typescript_state(root, &base, &raw, &changes, overrides);
    if overrides.is_none() && marker.is_file() {
        return Ok(vec![]);
    }
    run_typescript_check(root, &compiler, &base, &raw, &marker, overrides, deadline)
}

/// Type-check proposed TypeScript before it lands.
pub fn preview_typescript(
    root: &Path,
    config: &Config,
    changes: &[(String, String, String)],
    deadline: Deadline,
) -> Result<Vec<String>, CheckError> {
    if config.get("typescript_check") == Some(&Value::Bool(false)) || !root.join("tsconfig.json").is_file() {
        return Ok(vec![]);
    }
    let overrides: BTreeMap<String, String> = changes
        .iter()
        .filter(|(name, _, _)| crate::rules::suffix(name).is_some_and(|s| TYPESCRIPT_SUFFIXES.contains(&s.as_str())))
        .map(|(name, _, new)| (name.clone(), new.clone()))
        .collect();
    if overrides.is_empty() {
        return Ok(vec![]);
    }
    let mut notices = Vec::new();
    match typescript_violations(root, deadline, Some(&mut notices), Some(&overrides)) {
        Err(e) if matches!(e, CheckError::Value(_)) || e.is_os() || e.is_timeout() => Ok(vec![]),
        other => other,
    }
}

/// `typescript_findings`: explicit true/false wins; by default, committed projects.
pub fn typescript_findings(
    root: &Path,
    config: &Config,
    deadline: Deadline,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>, CheckError> {
    if let Some(setting) = config.get("typescript_check") {
        return if setting == &Value::Bool(true) {
            typescript_violations(root, deadline, None, None)
        } else {
            Ok(vec![])
        };
    }
    if !root.join("tsconfig.json").is_file() {
        return Ok(vec![]);
    }
    let mut notices = Vec::new();
    let findings = match typescript_violations(root, deadline, Some(&mut notices), None) {
        Ok(findings) => findings,
        Err(e) if matches!(e, CheckError::Value(_)) || e.is_os() || e.is_timeout() => {
            notices.push(py::strip(e.message()).chars().take(300).collect());
            vec![]
        }
        Err(other) => return Err(other),
    };
    let messages: Vec<String> = notices
        .iter()
        .map(|n| format!("NOT CHECKED typescript types: {n}"))
        .collect();
    if crate::strict() {
        return Ok(findings.into_iter().chain(messages).collect());
    }
    warnings.extend(messages);
    Ok(findings)
}

#[cfg(test)]
mod jsonc_tests {
    #[test]
    fn commented_tsconfig_still_names_its_extends() {
        let raw = b"{\n  // base\n  \"extends\": \"./base\", /* \"./x\" */\n  \"a\": \"//no\",\n}";
        let names = super::typescript_extends(Some(raw)).expect("parses");
        assert_eq!(names, ["base".to_string(), "base.json".to_string()].into());
    }
}
