//! Code hygiene: the vendored codehygiene model (`vendor/codehygiene`, see its UPSTREAM.md) run over the files a cell
//! wrote. It reports as advisories the lines the change added, never the debt a file already had: upstream gates on
//! the whole file, which flags most reviewed code (long lines and four indent levels count as squiggles).
//!
//! The 1.58-bit ternary model runs in-process in pure Rust ([`crate::hygiene_model`]) with no Python or NumPy
//! dependency. [`crate::nits`] reads the same files with a parser, and its findings are reported beside the model's.

use crate::git::{git_output, text_at};
use crate::proc::{self, Deadline, RunError};
use crate::{nits, py, resolve};
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// `off`, `on` (the default kinds) or `all` (every kind); over the `hygiene` setting.
pub const HYGIENE_ENV: &str = "LOKI_HYGIENE";

/// The kinds reported by default. `dense_line`, `deep_nesting` and `cramped_layout` fire on formatter-clean code
/// (lines past ~96 columns, four indent levels), and `poor_naming` on long test names; `all` adds them.
pub const DEFAULT_KINDS: [&str; 4] = ["swallowed_error", "noisy_comment", "duplicate_block", "special_casing"];

/// The languages upstream's circuits are written for.
const SUFFIXES: [&str; 19] = [
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".go", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
    ".zig", ".java", ".cs", ".lua",
];
const SECONDS: f64 = 20.0;
const MAX_NOTES: usize = 10;
const SNIPPET_CHARS: usize = 80;
/// The driver's exit when a Python check itself failed (3: missing import in that Python).
const FAILED: i32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Off,
    On,
    All,
}

/// `LOKI_HYGIENE`, else the saved `loki.hygiene` setting, else on.
pub fn level(env: Option<&str>, settings: &Map<String, Value>) -> Level {
    let named = env
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
        .or_else(|| settings.get("hygiene").and_then(Value::as_str).map(String::from));
    match named.as_deref() {
        Some("all") => Level::All,
        Some("off" | "0" | "false" | "no" | "none") => Level::Off,
        _ => Level::On,
    }
}

/// One line the model flags: its 1-based line, upstream's kind and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Squiggle {
    pub line: usize,
    pub kind: String,
    pub message: String,
}

fn squiggles_from_reply(reply: Vec<Vec<(usize, String, String)>>) -> Vec<Vec<Squiggle>> {
    let squiggle = |(line, kind, message)| Squiggle { line, kind, message };
    reply
        .into_iter()
        .map(|file| file.into_iter().map(squiggle).collect())
        .collect()
}

fn parse(stdout: &[u8]) -> Option<Vec<Vec<Squiggle>>> {
    let reply: Vec<Vec<(usize, String, String)>> = serde_json::from_slice(stdout).ok()?;
    Some(squiggles_from_reply(reply))
}

/// Runs `driver`, with `request` on its stdin, in the first of `launchers` whose Python has what the driver imports
/// (it exits 3 when it does not, and [`FAILED`] when the check itself broke); `missing` is the answer when none has.
pub(crate) fn drive(
    launchers: &[Vec<String>],
    driver: &str,
    request: &str,
    deadline: Deadline,
    missing: &str,
) -> Result<Vec<Vec<Squiggle>>, String> {
    // One BLAS thread: the check runs in the background beside the session's own work.
    let env = [("OMP_NUM_THREADS", "1"), ("OPENBLAS_NUM_THREADS", "1")];
    for launcher in launchers {
        let mut command = launcher.clone();
        command.extend(["-I", "-c", driver].map(String::from));
        let timeout = deadline.timeout().map_err(|_| "timed out".to_string())?;
        match proc::run(&command, &std::env::temp_dir(), Some(request.as_bytes()), &env, timeout) {
            Ok(out) if out.code == 0 => return parse(&out.stdout).ok_or_else(|| "unreadable reply".to_string()),
            Ok(out) if out.code == FAILED => {
                let stderr = proc::text(&out.stderr);
                return Err(stderr
                    .trim()
                    .lines()
                    .last()
                    .unwrap_or("failed")
                    .chars()
                    .take(200)
                    .collect());
            }
            Err(RunError::Timeout(_)) => return Err("timed out".into()),
            // The import is missing there (the driver's exit 3, or uv without it cached), or no such launcher: try
            // the next.
            Ok(_) | Err(RunError::Os(..)) => {}
        }
    }
    Err(missing.into())
}

pub(crate) struct WarmWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    sequence: u64,
}

impl WarmWorker {
    pub(crate) fn start(launchers: &[Vec<String>], driver: &str, handshake: Value) -> Option<Self> {
        for launcher in launchers {
            let Some((program, args)) = launcher.split_first() else {
                continue;
            };
            let Ok(mut child) = Command::new(program)
                .args(args)
                .args(["-I", "-c", driver])
                .current_dir(std::env::temp_dir())
                .env("OMP_NUM_THREADS", "1")
                .env("OPENBLAS_NUM_THREADS", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            else {
                continue;
            };
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                let _ = child.kill();
                let _ = child.wait();
                continue;
            };
            let mut worker = Self {
                child,
                stdin,
                stdout: BufReader::new(stdout),
                sequence: 0,
            };
            if worker.request(handshake.clone()).is_ok() {
                return Some(worker);
            }
            worker.close();
        }
        None
    }

    pub(crate) fn request(&mut self, args: Value) -> Result<Value, String> {
        self.sequence += 1;
        let id = self.sequence.to_string();
        let line = json!({"id": id, "args": args}).to_string();
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|()| self.stdin.write_all(b"\n"))
            .and_then(|()| self.stdin.flush())
            .map_err(|error| error.to_string())?;
        let mut reply = String::new();
        let read = self.stdout.read_line(&mut reply).map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("worker exited".into());
        }
        let parsed: Value = serde_json::from_str(&reply).map_err(|error| error.to_string())?;
        if let Some(error) = parsed.get("error").and_then(Value::as_str) {
            return Err(error.to_string());
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| "unreadable reply".to_string())
    }

    pub(crate) fn close(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for WarmWorker {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) fn parse_value(value: Value) -> Option<Vec<Vec<Squiggle>>> {
    let reply: Vec<Vec<(usize, String, String)>> = serde_json::from_value(value).ok()?;
    Some(squiggles_from_reply(reply))
}

/// The model's squiggles for each text, evaluated in-process in pure Rust.
pub fn score(texts: &[&str], _deadline: Deadline) -> Result<Vec<Vec<Squiggle>>, String> {
    texts.iter().map(|text| crate::hygiene_model::score_code(text)).collect()
}

/// The 1-based lines of `after` that are not in `before`.
fn added_lines(before: &str, after: &str) -> HashSet<usize> {
    let (old, new) = (py::splitlines(before, false), py::splitlines(after, false));
    py::opcodes(&old, &new)
        .into_iter()
        .filter(|(tag, ..)| *tag != "equal")
        .flat_map(|(_, _, _, from, to)| from + 1..=to)
        .collect()
}

fn note(name: &str, after: &str, tool: &str, squiggle: &Squiggle) -> String {
    let line = crate::hook::line_text(after, squiggle.line as i64);
    let snippet: String = line.chars().take(SNIPPET_CHARS).collect();
    let kind = squiggle.kind.replace('_', "-");
    format!(
        "{name}:{}: loki/{tool}-{kind}: {}: `{snippet}`",
        squiggle.line, squiggle.message
    )
}

/// The advisory lines for `name`, over the lines the change from `before` to `after` added: every nits finding, then
/// the model's squiggles of `level`'s kinds that nits did not already report (same line, same kind). Each carries
/// the start of its line, so two findings of one kind in a file stay distinct to the host.
pub fn merged(
    name: &str,
    before: &str,
    after: &str,
    model: &[Squiggle],
    nits: &[Squiggle],
    level: Level,
) -> Vec<String> {
    if level == Level::Off {
        return vec![];
    }
    let added = added_lines(before, after);
    let nits: Vec<&Squiggle> = nits.iter().filter(|s| added.contains(&s.line)).collect();
    let model = model
        .iter()
        .filter(|s| added.contains(&s.line))
        .filter(|s| level == Level::All || DEFAULT_KINDS.contains(&s.kind.as_str()))
        .filter(|s| !nits.iter().any(|n| n.line == s.line && n.kind == s.kind));
    nits.iter()
        .map(|s| note(name, after, "nits", s))
        .chain(model.map(|s| note(name, after, "hygiene", s)))
        .collect()
}

/// [`merged`] for the model alone.
pub fn notes(name: &str, before: &str, after: &str, squiggles: &[Squiggle], level: Level) -> Vec<String> {
    merged(name, before, after, squiggles, &[], level)
}

/// Whether hygiene reads `name` (repository-relative): a language the model knows, outside vendored and generated code.
fn checked(name: &str) -> bool {
    crate::rules::suffix(name).is_some_and(|suffix| SUFFIXES.contains(&suffix.as_str()))
        && crate::slop::slop_included(name)
}

/// Hygiene advisories for the written `files` (repository-relative) against their committed text, from the model
/// and from nits, with one `NOT CHECKED <hygiene|nits>: ...` line for each of the two that could not run.
pub fn written(root: &Path, files: &[String], level: Level) -> Vec<String> {
    against(root, files, "HEAD", level, &nits::launchers())
}

/// [`written`], with nits run by `nits_launchers`.
pub fn written_with(root: &Path, files: &[String], level: Level, nits_launchers: &[Vec<String>]) -> Vec<String> {
    against(root, files, "HEAD", level, nits_launchers)
}

/// Files the working tree adds or modifies against `base`, at most this many, are read by [`changed`].
const MAX_CHANGED_FILES: usize = 40;

/// Hygiene advisories for every line the working tree adds against `base` (a revision): the whole change, where
/// [`written`] sees one cell's files against HEAD and so nothing of what is already committed.
pub fn changed(root: &Path, base: &str, level: Level) -> Vec<String> {
    if level == Level::Off {
        return vec![];
    }
    let resolved = resolve(root);
    let deadline = Deadline::after(SECONDS);
    let arguments = ["diff", "--name-only", "-z", "--diff-filter=AM", base, "--"];
    let listed = match git_output(&resolved, &arguments, deadline, None) {
        Ok(listed) => listed,
        Err(error) => return vec![format!("NOT CHECKED hygiene: {}", error.message())],
    };
    let untracked = match git_output(
        &resolved,
        &["ls-files", "--others", "--exclude-standard", "-z"],
        deadline,
        None,
    ) {
        Ok(untracked) => untracked,
        Err(error) => return vec![format!("NOT CHECKED hygiene: {}", error.message())],
    };
    let mut unique = BTreeSet::new();
    for raw in [&listed, &untracked] {
        for name in String::from_utf8_lossy(raw).split('\0').filter(|name| !name.is_empty()) {
            unique.insert(name.to_string());
        }
    }
    let files: Vec<String> = unique.into_iter().take(MAX_CHANGED_FILES).collect();
    against(root, &files, base, level, &nits::launchers())
}

fn against(root: &Path, files: &[String], base: &str, level: Level, nits_launchers: &[Vec<String>]) -> Vec<String> {
    if level == Level::Off {
        return vec![];
    }
    let root = resolve(root);
    let sources: Vec<(&str, String)> = files
        .iter()
        .filter(|name| checked(name))
        .filter_map(|name| proc::read_text(&root.join(name)).ok().map(|text| (name.as_str(), text)))
        .collect();
    if sources.is_empty() {
        return vec![];
    }
    let deadline = Deadline::after(SECONDS);
    let mut gaps = Vec::new();
    let mut settle = |tool: &str, scored: Result<Vec<Vec<Squiggle>>, String>| {
        scored.unwrap_or_else(|reason| {
            gaps.push(format!("NOT CHECKED {tool}: {reason}"));
            vec![vec![]; sources.len()]
        })
    };
    // nits first: it answers in a fraction of a second, the model can take most of the deadline.
    let parsed = if sources.iter().any(|(name, _)| nits::reads(name)) {
        settle(
            "nits",
            nits::score(nits_launchers, &sources, level == Level::All, deadline),
        )
    } else {
        vec![vec![]; sources.len()]
    };
    let texts: Vec<&str> = sources.iter().map(|(_, text)| text.as_str()).collect();
    let scored = settle("hygiene", score(&texts, deadline));
    let mut found = Vec::new();
    for (((name, after), model), nits) in sources.iter().zip(&scored).zip(&parsed) {
        if model.is_empty() && nits.is_empty() {
            continue;
        }
        match text_at(&root, base, name, deadline) {
            Ok(before) => found.extend(merged(name, &before, after, model, nits, level)),
            Err(error) => {
                found.clear();
                gaps.push(format!("NOT CHECKED hygiene: {}", error.message()));
                break;
            }
        }
    }
    if found.len() > MAX_NOTES {
        let more = found.len() - MAX_NOTES;
        found.truncate(MAX_NOTES);
        found.push(format!("... {more} more hygiene notes"));
    }
    found.extend(gaps);
    found
}
