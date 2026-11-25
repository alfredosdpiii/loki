//! `shell`, `shell-writes` and `explain`: loki.py's shell guards and event log.

use crate::config::{self, Config};
use crate::{CheckError, lexical_path, protect_path, py, resolve};
use regex::Regex;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;

const PUNCTUATION: &str = "();<>|&";
const TEXT_REDIRECT_SUFFIXES: [&str; 7] = [".txt", ".md", ".log", ".rst", ".csv", ".tsv", ".adoc"];
const WRITE_DATA_EXTRA: [&str; 4] = [".patch", ".diff", ".out", ".err"];
const WRITE_SINKS: [&str; 4] = ["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"];
const COMMAND_PREFIXES: [&str; 7] = ["sudo", "env", "command", "time", "nice", "nohup", "exec"];

use crate::invalid;

fn is_shlex_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn is_shlex_punct(c: char) -> bool {
    PUNCTUATION.contains(c)
}

struct TokenState {
    token: String,
    quoted: bool,
    state: char,
    escaped: char,
}

impl TokenState {
    fn new() -> Self {
        Self {
            token: String::new(),
            quoted: false,
            state: ' ',
            escaped: 'a',
        }
    }

    fn has_token(&self) -> bool {
        !self.token.is_empty() || self.quoted
    }
}

struct PunctuatedLexer<'a> {
    chars: &'a [char],
    i: usize,
    comments: bool,
}

impl PunctuatedLexer<'_> {
    fn skip_comment(&mut self) {
        while self.i <= self.chars.len() && self.chars.get(self.i - 1) != Some(&'\n') {
            self.i += 1;
        }
    }

    fn step_space(&mut self, st: &mut TokenState, next: Option<char>) -> bool {
        match next {
            None => return true,
            Some(c) if is_shlex_space(c) => return st.has_token(),
            Some('#') if self.comments => self.skip_comment(),
            Some('\\') => {
                st.escaped = 'a';
                st.state = '\\';
            }
            Some(c) if is_shlex_punct(c) => {
                st.token.push(c);
                st.state = 'c';
            }
            Some(c @ ('\'' | '"')) => st.state = c,
            Some(c) => {
                st.token.push(c);
                st.state = 'a';
            }
        }
        false
    }

    fn step_punct(&mut self, st: &mut TokenState, next: Option<char>) -> bool {
        match next {
            None => true,
            Some(c) if is_shlex_space(c) => {
                st.state = ' ';
                st.has_token()
            }
            Some('#') if self.comments => {
                self.skip_comment();
                st.state = ' ';
                st.has_token()
            }
            Some(c) if is_shlex_punct(c) => {
                st.token.push(c);
                false
            }
            Some(_) => {
                self.i -= 1;
                true
            }
        }
    }

    fn step_word(&mut self, st: &mut TokenState, next: Option<char>) -> bool {
        match next {
            None => return true,
            Some(c) if is_shlex_space(c) => {
                st.state = ' ';
                return st.has_token();
            }
            Some('#') if self.comments => {
                self.skip_comment();
                st.state = ' ';
                return st.has_token();
            }
            Some(c @ ('\'' | '"')) => st.state = c,
            Some('\\') => {
                st.escaped = 'a';
                st.state = '\\';
            }
            Some(c) if !is_shlex_punct(c) => st.token.push(c),
            Some(_) => {
                self.i -= 1;
                st.state = ' ';
                return st.has_token();
            }
        }
        false
    }

    fn step_escape(&mut self, st: &mut TokenState, next: Option<char>) -> Result<(), String> {
        let Some(c) = next else {
            return Err("No escaped character".into());
        };
        if st.escaped == '"' && c != '\\' && c != '"' {
            st.token.push('\\');
        }
        st.token.push(c);
        st.state = st.escaped;
        Ok(())
    }

    fn step_quote(&mut self, st: &mut TokenState, quote: char, next: Option<char>) -> Result<(), String> {
        st.quoted = true;
        match next {
            None => return Err("No closing quotation".into()),
            Some(c) if c == quote => st.state = 'a',
            Some('\\') if quote == '"' => {
                st.escaped = '"';
                st.state = '\\';
            }
            Some(c) => st.token.push(c),
        }
        Ok(())
    }

    fn next_token(&mut self) -> Result<Option<String>, String> {
        let mut st = TokenState::new();
        loop {
            let next = self.chars.get(self.i).copied();
            self.i += 1;
            let done = match st.state {
                ' ' => self.step_space(&mut st, next),
                'c' => self.step_punct(&mut st, next),
                'a' => self.step_word(&mut st, next),
                '\\' => {
                    self.step_escape(&mut st, next)?;
                    false
                }
                quote => {
                    self.step_quote(&mut st, quote, next)?;
                    false
                }
            };
            if done {
                break;
            }
        }
        Ok(st.has_token().then_some(st.token))
    }
}

/// `shlex.shlex(s, posix=True, punctuation_chars=True)` with `whitespace_split`;
/// `comments` keeps the default `#` commenter.
pub fn shlex_punctuated(s: &str, comments: bool) -> Result<Vec<String>, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut lexer = PunctuatedLexer {
        chars: &chars,
        i: 0,
        comments,
    };
    let mut tokens = Vec::new();
    while let Some(token) = lexer.next_token()? {
        tokens.push(token);
    }
    Ok(tokens)
}

fn punctuation_only(token: &str) -> bool {
    token.chars().all(|c| PUNCTUATION.contains(c))
}

/// `shlex.quote`.
pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c)) {
        return s.into();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// `command > target` or `>>` when that is the only operator.
pub fn shell_redirect(command: &str) -> Option<(String, String)> {
    let tokens = shlex_punctuated(command, true).ok()?;
    let operators: Vec<&String> = tokens.iter().filter(|t| punctuation_only(t)).collect();
    let n = tokens.len();
    if n < 3 || operators != [&tokens[n - 2]] || !matches!(tokens[n - 2].as_str(), ">" | ">>") {
        return None;
    }
    let printer = tokens[..n - 2]
        .iter()
        .map(|t| shlex_quote(t))
        .collect::<Vec<_>>()
        .join(" ");
    Some((printer, tokens[n - 1].clone()))
}

/// `path.suffix.lower()` (Python 3.14 `PurePath.suffix`): from the last dot of the name, unless only dots precede it;
/// so `a.` has the suffix `.` and `..c` has none.
fn suffix(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name.rfind('.') {
        Some(i) if !name[..i].chars().all(|c| c == '.') => name[i..].to_lowercase(),
        _ => String::new(),
    }
}

/// `os.path.abspath(cwd / target)`: lexical, no `~` expansion.
fn abspath(cwd: &Path, target: &str) -> PathBuf {
    let mut out = PathBuf::from("/");
    for component in cwd.join(target).components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(part) => out.push(part),
            _ => {}
        }
    }
    out
}

fn relative_of(path: &Path, root: &Path) -> Option<String> {
    path.strip_prefix(root).ok().map(|p| p.to_string_lossy().into_owned())
}

fn hidden(relative: &str) -> bool {
    relative.split('/').any(|part| part.starts_with('.'))
}

/// Printing into project notes is allowed; source and policy writes are not.
fn redirect_violation(target: &str, root: &Path, cwd: &Path) -> Result<Option<String>, CheckError> {
    let path = abspath(cwd, target);
    if !path.starts_with(root) || resolve(&path) != path {
        crate::evidence::finding("shell-redirect-outside", None);
        return Ok(Some("loki: shell redirect target escapes the repository root".into()));
    }
    if let Some(message) = protect_path(&path.to_string_lossy(), root, &crate::run::load(root)?)? {
        return Ok(Some(message));
    }
    let relative = relative_of(&path, root).unwrap_or_default();
    let shown = if relative.is_empty() {
        ".".to_string()
    } else {
        relative.clone()
    };
    if !TEXT_REDIRECT_SUFFIXES.contains(&suffix(&path).as_str()) || hidden(&relative) || path.is_dir() {
        crate::evidence::finding("shell-redirect-write", Some(&shown));
        return Ok(Some(format!(
            "loki: shell redirect into {shown} bypasses write checks; use file edit tools for source and configuration files"
        )));
    }
    Ok(None)
}

fn is_destructive_clean(options: &[&str]) -> bool {
    options
        .iter()
        .any(|o| o.starts_with('-') && !o.starts_with("--") && o.contains('f'))
        || options.contains(&"--force")
}

fn is_destructive_push(options: &[&str]) -> bool {
    options
        .iter()
        .any(|o| ["-f", "--force", "--force-with-lease", "--delete", "--mirror"].contains(o) || o.starts_with([':', '+']))
}

fn is_destructive_branch(options: &[&str]) -> bool {
    options.contains(&"-D") || (options.contains(&"--delete") && options.contains(&"--force"))
}

/// `destructive_git`: Git commands that discard work or rewrite history.
pub fn destructive_git(words: &[String]) -> bool {
    let command = words.get(1).map_or("", String::as_str);
    let options: Vec<&str> = words.iter().skip(2).map(String::as_str).collect();
    let any = |set: &[&str]| options.iter().any(|o| set.contains(o));
    match command {
        "reset" => any(&["--hard", "--merge", "--keep"]),
        "clean" => is_destructive_clean(&options),
        "push" => is_destructive_push(&options),
        "branch" => is_destructive_branch(&options),
        "stash" => any(&["drop", "clear"]),
        "checkout" => any(&["--", ".", "-f", "--force"]),
        _ => matches!(command, "restore" | "rebase" | "filter-branch" | "update-ref"),
    }
}

fn redirect_shell_violation(text: &str, root: &Path, cwd: &Path) -> Option<Result<Option<String>, CheckError>> {
    let (printer, target) = shell_redirect(text)?;
    // loki.py's `try` also covers the redirect check: its `ValueError`s fall through.
    if config::simple_shell_words(&Value::String(printer))
        .is_ok_and(|words| matches!(words[0].as_str(), "echo" | "printf"))
    {
        match redirect_violation(&target, root, cwd) {
            Err(CheckError::Value(_)) => {}
            other => return Some(other),
        }
    }
    crate::evidence::finding("shell-redirect-write", None);
    Some(Ok(Some(
        "loki: shell redirect from a command other than echo/printf requires review; use file edit tools for writes"
            .into(),
    )))
}

fn readonly_git_violation(words: &[String]) -> Option<Option<String>> {
    if words.len() < 2 || !matches!(words[1].as_str(), "status" | "diff" | "log" | "show" | "rev-parse") {
        return None;
    }
    let unsafe_opt = words[2..].iter().any(|w| {
        ["--output", "--ext-diff", "--textconv", "--exec"]
            .iter()
            .any(|p| w.starts_with(p))
    });
    if unsafe_opt {
        crate::evidence::finding("shell-option-review", None);
        return Some(Some("loki: shell Git option requires review".into()));
    }
    Some(None)
}

fn is_safe_builtin(words: &[String]) -> bool {
    let first = words[0].as_str();
    (matches!(first, "pwd" | "whoami") && words.len() == 1) || matches!(first, "echo" | "printf")
}

/// `shell_violation`: the default-deny shell guard.
pub fn shell_violation(command: &Value, root: &Path, cwd: &Path) -> Result<Option<String>, CheckError> {
    if let Some(text) = command.as_str()
        && let Some(result) = redirect_shell_violation(text, root, cwd)
    {
        return result;
    }
    let words = match config::simple_shell_words(command) {
        Ok(words) => words,
        Err(message) => {
            crate::evidence::finding("shell-syntax-review", None);
            return Ok(Some(message));
        }
    };
    let first = words[0].as_str();
    if first == "git"
        && let Some(result) = readonly_git_violation(&words)
    {
        return Ok(result);
    }
    if is_safe_builtin(&words) {
        return Ok(None);
    }
    if first == "git" && destructive_git(&words) {
        let shown = words.iter().take(4).cloned().collect::<Vec<_>>().join(" ");
        crate::evidence::finding("shell-destructive-git", None);
        return Ok(Some(format!(
            "loki: blocked destructive Git command `{shown}`: it can discard uncommitted work or rewrite history; ask the user to run it"
        )));
    }
    if first != "git" {
        return reviewed_shell_violation(command.as_str().unwrap_or(""), root, cwd);
    }
    crate::evidence::finding("shell-command-review", None);
    Ok(Some(
        "loki: shell command requires review; use verified file tools for writes".into(),
    ))
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, CheckError> {
    let output = Command::new("git")
        .arg("--literal-pathspecs")
        .args(args)
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| invalid(format!("git: {e}")))?;
    if !output.status.success() {
        let reason = py::strip(&String::from_utf8_lossy(&output.stderr)).to_string();
        let reason = if reason.is_empty() {
            format!("exited {}", output.status.code().unwrap_or(-1))
        } else {
            reason
        };
        return Err(invalid(format!("git: {reason}")));
    }
    Ok(output.stdout)
}

/// `ls-tree -z` rows: path to (mode, kind, oid).
fn tree_entries(root: &Path, base: &str, paths: &[String]) -> Result<Vec<(String, [String; 3])>, CheckError> {
    let mut args = vec!["ls-tree", "-z", base, "--"];
    args.extend(paths.iter().map(String::as_str));
    let raw = git(root, &args)?;
    let mut entries = Vec::new();
    for row in raw.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let text = String::from_utf8_lossy(row);
        let (metadata, path) = text
            .split_once('\t')
            .ok_or_else(|| invalid("git: invalid tree entry"))?;
        let fields: Vec<String> = metadata.split_whitespace().map(str::to_string).collect();
        let [mode, kind, oid] = <[String; 3]>::try_from(fields).map_err(|_| invalid("git: invalid tree entry"))?;
        entries.push((path.to_string(), [mode, kind, oid]));
    }
    Ok(entries)
}

/// `base_policy`: the committed `.loki/loki.json` at `base`.
fn base_policy(root: &Path, base: &str) -> Result<Option<Config>, CheckError> {
    let entries = tree_entries(root, base, &[".loki/loki.json".into()])?;
    let Some((_, [mode, kind, oid])) = entries.into_iter().next() else {
        return Ok(None);
    };
    if !matches!(mode.as_str(), "100644" | "100755") || kind != "blob" {
        return Err(invalid("loki: base policy must be a regular file"));
    }
    let raw = git(root, &["cat-file", "blob", &oid])?;
    let value: Value = serde_json::from_slice(&raw).map_err(|e| invalid(e.to_string()))?;
    config::validate_config(&value).map(Some).map_err(CheckError::Value)
}

/// Working-tree content and Git mode of a candidate, without following a final symlink.
fn worktree_entry(path: &Path, name: &str) -> Result<Option<(Vec<u8>, &'static str)>, CheckError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(invalid(e.to_string())),
    };
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(path).map_err(|e| invalid(e.to_string()))?;
        return Ok(Some((target.into_os_string().into_encoded_bytes(), "120000")));
    }
    if !meta.is_file() {
        return Err(invalid(format!("loki: unsupported changed file type: {name}")));
    }
    let content = std::fs::read(path).map_err(|e| invalid(e.to_string()))?;
    let mode = if meta.permissions().mode() & 0o100 != 0 {
        "100755"
    } else {
        "100644"
    };
    Ok(Some((content, mode)))
}

fn grant_input_paths(grant: &Value) -> Vec<String> {
    let mut paths = vec![".loki/loki.json".to_string()];
    for input in grant["inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !paths.iter().any(|p| p == input) {
            paths.push(input.to_string());
        }
    }
    paths
}

fn check_grant_input(root: &Path, name: &str, entry: &[String; 3]) -> Result<Option<String>, CheckError> {
    let path = root.join(name);
    if resolve(&path) != path {
        return Err(invalid(format!("shell permission input is symlinked: {name}")));
    }
    let [mode, _, oid] = entry;
    let blob = git(root, &["cat-file", "blob", oid])?;
    let current = worktree_entry(&path, name)?;
    if current
        .as_ref()
        .is_none_or(|(content, m)| *content != blob || m != mode)
    {
        crate::evidence::finding("shell-permission-input-changed", Some(name));
        return Ok(Some(format!("loki: shell permission input differs from base: {name}")));
    }
    Ok(None)
}

fn verify_grant_inputs(root: &Path, base: &str, paths: &[String]) -> Result<Option<String>, CheckError> {
    let entries = tree_entries(root, base, paths)?;
    let entry = |name: &str| entries.iter().find(|(p, _)| p == name).map(|(_, e)| e);
    if paths.iter().any(|name| {
        entry(name).is_none_or(|[mode, kind, _]| !matches!(mode.as_str(), "100644" | "100755") || kind != "blob")
    }) {
        return Err(invalid("shell permission inputs must be committed regular files"));
    }
    for name in paths {
        if let Some(violation) = check_grant_input(root, name, entry(name).expect("checked above"))? {
            return Ok(Some(violation));
        }
    }
    Ok(None)
}

/// `reviewed_shell_violation`: an exact committed grant whose inputs are unchanged.
fn reviewed_shell_violation(command: &str, root: &Path, cwd: &Path) -> Result<Option<String>, CheckError> {
    let top = String::from_utf8_lossy(&git(root, &["rev-parse", "--show-toplevel"])?)
        .trim_end_matches('\n')
        .to_string();
    if resolve(Path::new(&top)) != root {
        return Err(invalid("shell permissions require the repository root"));
    }
    let base = String::from_utf8_lossy(&git(
        root,
        &["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"],
    )?)
    .trim()
    .to_string();
    let policy = base_policy(root, &base)?.unwrap_or_default();
    config::shell_permissions(&policy).map_err(CheckError::Value)?;
    let grants = policy
        .get("shell_commands")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let grant = grants.iter().find(|g| {
        g["command"].as_str() == Some(command) && g["cwd"].as_str().is_some_and(|d| lexical_path(root, d) == cwd)
    });
    let Some(grant) = grant else {
        crate::evidence::finding("shell-command-review", None);
        return Ok(Some(
            "loki: no committed permission for this exact shell command and cwd".into(),
        ));
    };
    let paths = grant_input_paths(grant);
    verify_grant_inputs(root, &base, &paths)
}

fn extract_shell_call<'a>(payload: &'a Value, harness: &str) -> Result<(&'a str, &'a serde_json::Map<String, Value>), CheckError> {
    if harness == "agy" {
        let call = payload["toolCall"]
            .as_object()
            .ok_or_else(|| invalid("invalid shell envelope"))?;
        let name = call.get("name").and_then(Value::as_str).unwrap_or("");
        let args = call
            .get("args")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("invalid shell envelope"))?;
        return Ok((name, args));
    }
    let name = payload["tool_name"].as_str().unwrap_or("");
    let input = payload["tool_input"]
        .as_object()
        .ok_or_else(|| invalid("invalid shell envelope"))?;
    Ok((name, input))
}

fn validate_shell_envelope(payload: &Value, harness: &str) -> Result<(), CheckError> {
    let names: &[&str] = match harness {
        "agy" => &["run_command"],
        "claude" => &["Bash"],
        "codex" => &["Bash", "exec_command", "shell"],
        "factory" => &["Execute"],
        _ => &["bash", "Bash"],
    };
    let (name, input) = extract_shell_call(payload, harness)?;
    if !names.contains(&name) {
        return Err(invalid("unexpected shell tool name"));
    }
    const FIELDS: [&str; 24] = [
        "command",
        "cmd",
        "workdir",
        "login",
        "tty",
        "yield_time_ms",
        "max_output_tokens",
        "sandbox_permissions",
        "justification",
        "shell",
        "dangerouslyDisableSandbox",
        "description",
        "timeout",
        "run_in_background",
        "summary",
        "riskLevel",
        "riskLevelReason",
        "fireAndForget",
        "CommandLine",
        "WaitMsBeforeAsync",
        "NotificationTimeoutSeconds",
        "IsDaemon",
        "BypassSandbox",
        "toolSummary",
    ];
    if input.keys().any(|k| !FIELDS.contains(&k.as_str())) {
        return Err(invalid("unsupported shell input fields"));
    }
    Ok(())
}

/// Extract the command JSON value from a shell hook envelope.
pub fn shell_command<'a>(payload: &'a Value, harness: &str) -> Result<&'a Value, CheckError> {
    let (_, input) = extract_shell_call(payload, harness)?;
    let value = if harness == "agy" {
        input.get("CommandLine")
    } else if harness == "codex" {
        input.get("command").or_else(|| input.get("cmd"))
    } else {
        input.get("command")
    };
    Ok(value.unwrap_or(&Value::Null))
}

fn raw_shell_cwd<'a>(payload: &'a Value, harness: &str) -> Option<&'a str> {
    let raw = payload
        .get("cwd")
        .or_else(|| {
            (harness == "agy")
                .then(|| payload.get("workspacePaths").and_then(Value::as_array).and_then(|a| a.first()))
                .flatten()
        })
        .or_else(|| {
            (harness == "codex")
                .then(|| payload.get("tool_input").and_then(|v| v.get("workdir")))
                .flatten()
        });
    raw.and_then(Value::as_str).filter(|d| !d.is_empty() && !d.contains('\0'))
}

/// `shell_cwd`: the hook's working directory, which must be a real directory inside the root.
pub fn shell_cwd(payload: &Value, harness: &str, root: &Path) -> Result<PathBuf, CheckError> {
    validate_shell_envelope(payload, harness)?;
    let Some(directory) = raw_shell_cwd(payload, harness) else {
        return Err(invalid("shell cwd must be an absolute directory"));
    };
    // pathlib equality ignores `.` components and trailing slashes, not `..`.
    let cwd: PathBuf = Path::new(directory).components().collect();
    if !cwd.is_absolute() || resolve(&cwd) != cwd || !cwd.starts_with(root) || !cwd.is_dir() {
        return Err(invalid("shell cwd must be a non-symlinked directory inside the root"));
    }
    Ok(cwd)
}

static HEREDOC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<<-?\s*(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|([A-Za-z_][A-Za-z0-9_]*))"#)
        .expect("static pattern")
});

/// Drop here-document bodies, which are data, so the rest parses as shell words.
pub fn strip_heredocs(command: &str) -> String {
    let (mut out, mut delimiter) = (Vec::new(), None::<String>);
    for line in command.split('\n') {
        if let Some(d) = &delimiter {
            if py::strip(line) == d {
                delimiter = None;
            }
            continue;
        }
        out.push(line);
        if let Some(caps) = HEREDOC.captures(line) {
            delimiter = (1..=3).find_map(|g| caps.get(g)).map(|m| m.as_str().to_string());
        }
    }
    out.join("\n")
}

/// `Path(path).name`: the last component once empty and `.` components are dropped (`..` is a name).
fn file_name(path: &str) -> &str {
    path.split('/')
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or("")
}

/// `str(Path(directory) / Path(source).name)`: pathlib drops empty and `.` components and a trailing slash, keeps a
/// leading `//`, and prints an empty relative path as `.`.
fn join_name(directory: &str, source: &str) -> String {
    let mut parts: Vec<&str> = directory
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let name = file_name(source);
    if !name.is_empty() {
        parts.push(name);
    }
    let anchor = if directory.starts_with("//") && !directory.starts_with("///") {
        "//"
    } else if directory.starts_with('/') {
        "/"
    } else {
        ""
    };
    let body = parts.join("/");
    if anchor.is_empty() && body.is_empty() {
        ".".into()
    } else {
        format!("{anchor}{body}")
    }
}

static PERL_INPLACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-[a-zA-Z]*i\S*$").expect("static pattern"));

/// `os.path.join(directory, path)`: an absolute `path` replaces `directory`.
fn os_path_join(directory: &str, path: &str) -> String {
    if path.starts_with('/') || directory.is_empty() {
        path.to_string()
    } else if directory.ends_with('/') {
        format!("{directory}{path}")
    } else {
        format!("{directory}/{path}")
    }
}

/// Where the parsed command currently runs: the directory a literal `cd`/`pushd` moved to, relative to the command's
/// cwd ("$CD" when the shell decides it, so the targets are skipped like `$VAR` ones), and the ones `(` saved.
#[derive(Default)]
struct Moves {
    moved: String,
    scopes: Vec<String>,
    placed: usize,
}

impl Moves {
    /// Join the targets found since the last call to the directory the command moved to.
    fn place(&mut self, targets: &mut [(String, String)]) {
        if !self.moved.is_empty() {
            for (target, _) in &mut targets[self.placed..] {
                *target = os_path_join(&self.moved, target);
            }
        }
        self.placed = targets.len();
    }
}

fn handle_cd_command(name: &str, args: &[String], moves: &mut Moves) {
    let changes: Vec<&String> = args
        .iter()
        .filter(|a| !matches!(a.as_str(), "-L" | "-P" | "-e" | "-@" | "--"))
        .collect();
    moves.moved = if name != "popd" && changes.len() == 1 && changes[0] != "-" {
        os_path_join(&moves.moved, changes[0])
    } else {
        "$CD".into()
    };
}

fn sed_inplace_targets(args: &[String], targets: &mut Vec<(String, String)>) {
    if !args.iter().any(|a| a.starts_with("-i") || a.starts_with("--in-place")) {
        return;
    }
    let (mut files, mut scripted, mut skip) = (Vec::new(), false, false);
    for arg in args {
        if skip {
            skip = false;
        } else if matches!(arg.as_str(), "-e" | "-f" | "--expression" | "--file") {
            scripted = true;
            skip = true;
        } else if !arg.starts_with('-') {
            files.push(arg.clone());
        }
    }
    let skip_script = usize::from(!scripted);
    for file in files.into_iter().skip(skip_script) {
        targets.push((file, "sed -i".to_string()));
    }
}

fn perl_inplace_targets(args: &[String], targets: &mut Vec<(String, String)>) {
    if !args.iter().any(|a| PERL_INPLACE.is_match(a)) {
        return;
    }
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
        } else if matches!(arg.as_str(), "-e" | "-E") {
            skip = true;
        } else if !arg.starts_with('-') {
            targets.push((arg.clone(), "perl -i".to_string()));
        }
    }
}

fn copy_move_targets(
    name: &str,
    args: &[String],
    plain: &[&String],
    base: &Path,
    targets: &mut Vec<(String, String)>,
) {
    let flag = args.iter().position(|a| a == "-t");
    if let Some(directory) = flag.and_then(|i| args.get(i + 1)) {
        for source in plain.iter().filter(|a| *a != &directory) {
            targets.push((join_name(directory, source), name.to_string()));
        }
        return;
    }
    if plain.len() < 2 {
        return;
    }
    let destination = plain[plain.len() - 1];
    if plain.len() > 2 || destination.ends_with('/') || base.join(destination).is_dir() {
        for source in &plain[..plain.len() - 1] {
            targets.push((join_name(destination, source), name.to_string()));
        }
    } else {
        targets.push((destination.clone(), name.to_string()));
    }
}

fn is_command_prefix(word: &str) -> bool {
    (word.contains('=') && !word.starts_with('-')) || COMMAND_PREFIXES.contains(&word)
}

fn command_targets(words: &mut Vec<String>, targets: &mut Vec<(String, String)>, base: &Path, moves: &mut Moves) {
    while words.first().is_some_and(|w| is_command_prefix(w)) {
        words.remove(0);
    }
    if words.is_empty() {
        return;
    }
    let (name, args) = (file_name(&words[0]).to_string(), &words[1..]);
    if matches!(name.as_str(), "cd" | "pushd" | "popd") {
        handle_cd_command(&name, args, moves);
        words.clear();
        return;
    }
    let plain: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    match name.as_str() {
        "tee" => plain.iter().for_each(|a| targets.push((a.to_string(), "tee".into()))),
        "sed" => sed_inplace_targets(args, targets),
        "perl" => perl_inplace_targets(args, targets),
        "cp" | "mv" | "install" => copy_move_targets(&name, args, &plain, base, targets),
        "dd" => args
            .iter()
            .filter_map(|a| a.strip_prefix("of="))
            .for_each(|t| targets.push((t.into(), "dd".into()))),
        _ => {}
    }
    moves.place(targets);
    words.clear();
}

fn is_redirect_token(token: &str) -> bool {
    matches!(token, ">" | ">>" | ">|" | "&>" | "&>>")
        || ((token.ends_with('>') || token.ends_with(">>")) && punctuation_only(token))
}

fn is_fd_prefix(tokens: &[String], index: usize) -> bool {
    let token = tokens[index].as_str();
    !token.is_empty()
        && token.chars().all(char::is_numeric)
        && tokens.get(index + 1).is_some_and(|n| n == ">" || n == ">>")
}

fn apply_subshell_scopes(token: &str, moves: &mut Moves) {
    for ch in token.chars() {
        if ch == '(' {
            moves.scopes.push(moves.moved.clone());
        } else if ch == ')'
            && let Some(saved) = moves.scopes.pop()
        {
            moves.moved = saved;
        }
    }
}

/// `shell_write_targets`: the files a shell command writes, as `(target, how)`; `None` when it cannot be parsed.
/// `base` is the directory loki.py's `Path(destination).is_dir()` resolves against: the engine's working directory.
pub fn shell_write_targets(command: &str, base: &Path) -> Option<Vec<(String, String)>> {
    let tokens = shlex_punctuated(&strip_heredocs(command), false).ok()?;
    let (mut targets, mut words) = (Vec::new(), Vec::new());
    let mut moves = Moves::default();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if is_redirect_token(token) {
            if let Some(next) = tokens.get(index + 1) {
                targets.push((next.clone(), "redirect".to_string()));
                moves.place(&mut targets);
            }
            index += 2;
        } else if punctuation_only(token) {
            command_targets(&mut words, &mut targets, base, &mut moves);
            apply_subshell_scopes(token, &mut moves);
            index += 1;
        } else if is_fd_prefix(&tokens, index) {
            index += 1;
        } else {
            words.push(token.to_string());
            index += 1;
        }
    }
    command_targets(&mut words, &mut targets, base, &mut moves);
    targets.retain(|(t, _)| {
        !WRITE_SINKS.contains(&t.as_str()) && !t.starts_with("/dev/fd/") && !t.starts_with("/proc/self/fd/")
    });
    Some(targets)
}

fn git_ignored(root: &Path, relative: &str) -> bool {
    Command::new("git")
        .args(["-C", &root.to_string_lossy(), "check-ignore", "-q", "--", relative])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn check_write_target(
    target: &str,
    how: &str,
    root: &Path,
    cwd: &Path,
    config: &Config,
) -> Result<Option<String>, CheckError> {
    if target.contains(['$', '`', '*', '?', '~']) {
        return Ok(None);
    }
    let path = abspath(cwd, target);
    let Some(relative) = relative_of(&path, root) else {
        return Ok(None);
    };
    if let Some(message) = protect_path(&path.to_string_lossy(), root, config)? {
        return Ok(Some(message));
    }
    let ext = suffix(&path);
    let data = TEXT_REDIRECT_SUFFIXES.contains(&ext.as_str()) || WRITE_DATA_EXTRA.contains(&ext.as_str());
    if data && !hidden(&relative) {
        return Ok(None);
    }
    let shown = if relative.is_empty() { ".".to_string() } else { relative };
    if git_ignored(root, &shown) {
        return Ok(None);
    }
    crate::evidence::finding("shell-write", Some(&shown));
    Ok(Some(format!(
        "loki: `{how}` into {shown} would skip Loki's write check; write source and configuration files with the file edit tools (Ultron: edit()/write())"
    )))
}

/// `shell_writes_violation`: deny shell writes of source or configuration inside the project.
/// `base` is the engine's working directory (see `shell_write_targets`).
pub fn shell_writes_violation(
    command: &Value,
    root: &Path,
    cwd: &Path,
    base: &Path,
) -> Result<Option<String>, CheckError> {
    let Some(command) = command.as_str().filter(|c| !py::strip(c).is_empty()) else {
        return Ok(None);
    };
    let Some(targets) = shell_write_targets(command, base).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    let root = resolve(root);
    let config = crate::run::load(&root)?;
    for (target, how) in targets {
        if let Some(message) = check_write_target(&target, &how, &root, cwd, &config)? {
            return Ok(Some(message));
        }
    }
    Ok(None)
}

/// `loki --root ROOT shell-writes` on a parsed envelope `{command, cwd?}`, from the engine's working directory `base`.
pub fn shell_writes(root: &Path, payload: &Value, base: &Path) -> Result<Option<String>, CheckError> {
    if !payload.is_object() {
        return Err(invalid("invalid shell envelope"));
    }
    let root = resolve(root);
    let cwd = match payload.get("cwd") {
        Some(Value::String(cwd)) if !cwd.is_empty() => resolve(Path::new(cwd)),
        _ => root.clone(),
    };
    shell_writes_violation(payload.get("command").unwrap_or(&Value::Null), &root, &cwd, base)
}

/// Why a check result refuses: the refusal itself, or (as loki.py reports them) a `ValueError` or `OSError` as
/// invalid shell input and another exception as a guard error. None: allowed.
fn refusal(result: Result<Option<String>, CheckError>) -> Option<String> {
    match result {
        Ok(reason) => reason,
        Err(error @ CheckError::Value(_)) => Some(format!("loki: invalid shell input: {}", error.message())),
        Err(error) if error.is_os() => Some(format!("loki: invalid shell input: {}", error.message())),
        Err(error) => Some(format!("loki: {}", error.describe())),
    }
}

/// The exit status and stderr of `shell` and `shell-writes` for a check result.
pub fn shell_report(result: Result<Option<String>, CheckError>) -> (u8, String) {
    match refusal(result) {
        None => (0, String::new()),
        Some(text) => (2, format!("{text}\n")),
    }
}

/// `shell-writes` in-process, as a host runs it: with the project root as the engine's working directory (Ultron's
/// `beforeShell` spawns it with `cwd: root`), why `command` run in `cwd` is refused, or None.
pub fn command_refusal(root: &Path, command: &str, cwd: &Path) -> Option<String> {
    let root = resolve(root);
    let cwd = if cwd.as_os_str().is_empty() {
        root.clone()
    } else {
        resolve(cwd)
    };
    refusal(shell_writes_violation(&Value::from(command), &root, &cwd, &root))
}

/// `event_path`: `~/.local/state/loki/<sha256(root)>/events.jsonl`.
pub fn event_path(root: &Path) -> PathBuf {
    let identity = crate::compat::sha256_hex(resolve(root).as_os_str().as_encoded_bytes());
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join(".local/state/loki").join(identity).join("events.jsonl")
}

fn sort_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| crate::compat::utf16_cmp(&a.0, &b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sort_keys(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

/// `explain`: the last `limit` recorded events, one sorted-key JSON object per line.
pub fn explain(root: &Path, limit: i64) -> Result<Vec<String>, String> {
    if !(1..=1000).contains(&limit) {
        return Err("limit must be between 1 and 1000".into());
    }
    let path = event_path(root);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let start = lines.len().saturating_sub(limit as usize);
    lines[start..]
        .iter()
        .map(|line| {
            let value: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
            Ok(py::dumps(&sort_keys(value)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn loki_shell_shlex_punctuated_matches_python() {
        // python3: l = shlex.shlex(s, posix=True, punctuation_chars=True); l.whitespace_split = True; list(l)
        assert_eq!(
            shlex_punctuated("a>b;c&&d|e", true).unwrap(),
            words(&["a", ">", "b", ";", "c", "&&", "d", "|", "e"])
        );
        assert_eq!(
            shlex_punctuated(r#"echo "x\y\$" 2>&1 # c"#, true).unwrap(),
            words(&["echo", r"x\y\$", "2", ">&", "1"])
        );
        assert_eq!(shlex_punctuated("a#b c", false).unwrap(), words(&["a#b", "c"]));
        assert_eq!(shlex_punctuated("x '' y", true).unwrap(), words(&["x", "", "y"]));
        assert_eq!(shlex_punctuated("echo 'a", true).unwrap_err(), "No closing quotation");
    }

    #[test]
    fn loki_shell_quote_matches_python() {
        // python3 -c 'import shlex; print([shlex.quote(s) for s in ["", "a-b/c.d", "it'"'"'s", "a b"]])'
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(shlex_quote("a-b/c.d"), "a-b/c.d");
        assert_eq!(shlex_quote("it's"), r#"'it'"'"'s'"#);
        assert_eq!(shlex_quote("a b"), "'a b'");
    }

    #[test]
    fn loki_shell_strip_heredocs_drops_bodies() {
        assert_eq!(
            strip_heredocs("cat > a <<'EOF'\nx > y\n  EOF  \necho z"),
            "cat > a <<'EOF'\necho z"
        );
        assert_eq!(strip_heredocs("cat <<-\"END\"\nbody"), "cat <<-\"END\"");
    }

    #[test]
    fn loki_shell_write_targets_cover_writers() {
        let found = shell_write_targets(
            "sed -i -e s/a/b/ x.py y.py; dd of=z.img; make 2>/dev/null | tee -a log.txt",
            Path::new("/nonexistent"),
        )
        .unwrap();
        let expected = [
            ("x.py", "sed -i"),
            ("y.py", "sed -i"),
            ("z.img", "dd"),
            ("log.txt", "tee"),
        ];
        assert_eq!(found, expected.map(|(t, h)| (t.to_string(), h.to_string())));
        assert_eq!(shell_write_targets("echo 'x > a.py", Path::new("/nonexistent")), None);
    }

    /// loki.py test_targets_follow_cd: targets follow a literal `cd`/`pushd`; a `( … )` subshell restores the
    /// directory; bare `cd`, `cd -` and `popd` leave it unknown ("$CD", skipped like `$VAR` targets).
    #[test]
    fn loki_shell_write_targets_follow_cd() {
        let cases: [(&str, &[(&str, &str)]); 11] = [
            ("cd src && echo x > a.py", &[("src/a.py", "redirect")]),
            ("cd /srv/x; printf a > Cargo.toml", &[("/srv/x/Cargo.toml", "redirect")]),
            (
                "(cd /srv && echo 1 > a.rs); echo 2 > b.py",
                &[("/srv/a.rs", "redirect"), ("b.py", "redirect")],
            ),
            ("cd src; cp a.py b.py", &[("src/b.py", "cp")]),
            ("echo x > a.py; cd /srv", &[("a.py", "redirect")]),
            ("cd -- lib && mv -t dst a.py", &[("lib/dst/a.py", "mv")]),
            ("cd $DIR && echo x > a.py", &[("$DIR/a.py", "redirect")]),
            ("cd; echo x > a.py", &[("$CD/a.py", "redirect")]),
            ("cd - && echo x > a.py", &[("$CD/a.py", "redirect")]),
            ("pushd a && popd && echo x > b.py", &[("$CD/b.py", "redirect")]),
            ("cd a && cd /b && cd c; tee t.py", &[("/b/c/t.py", "tee")]),
        ];
        for (command, expected) in cases {
            let expected: Vec<(String, String)> =
                expected.iter().map(|(t, h)| (t.to_string(), h.to_string())).collect();
            assert_eq!(
                shell_write_targets(command, Path::new("/nonexistent")).unwrap(),
                expected,
                "{command}"
            );
        }
    }

    #[test]
    fn loki_shell_destructive_git_cases() {
        assert!(destructive_git(&words(&["git", "clean", "-xdf"])));
        assert!(!destructive_git(&words(&["git", "clean", "--dry-run"])));
        assert!(destructive_git(&words(&["git", "branch", "--force", "--delete", "x"])));
        assert!(!destructive_git(&words(&["git", "branch", "--force", "x"])));
        assert!(destructive_git(&words(&["git", "update-ref", "-d", "x"])));
    }
}
