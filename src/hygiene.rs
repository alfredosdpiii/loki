//! Code hygiene: the vendored codehygiene model (`vendor/codehygiene`, see its UPSTREAM.md) run over the files a cell
//! wrote. It reports as advisories the lines the change added, never the debt a file already had: upstream gates on
//! the whole file, which flags most reviewed code (long lines and four indent levels count as squiggles).
//!
//! The 1.58-bit ternary model runs in-process in pure Rust ([`crate::hygiene_model`]) with no Python or NumPy
//! dependency. [`crate::nits`] reads the same files with a parser, and its findings are reported beside the model's.

use crate::git::{git_output, texts_at};
use crate::proc::{self, Deadline, RunError};
use crate::{nits, py, resolve};
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
const CHANGED_SECONDS: f64 = 60.0;
const MAX_NOTES: usize = 10;
const MAX_WORKERS: usize = 4;
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

type ScoreSlot = std::sync::Mutex<Option<Result<Vec<Squiggle>, String>>>;
type ParallelScores = (Vec<Option<Vec<Squiggle>>>, usize);

/// Scores each `(text, added_lines)` pair in parallel (up to `MAX_WORKERS` threads), stopping
/// before new files once `deadline` expires so partial results are preserved instead of discarded.
fn score_windowed_parallel(items: &[(&str, &HashSet<usize>)], deadline: Deadline) -> Result<ParallelScores, String> {
    if items.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .clamp(1, MAX_WORKERS)
        .min(items.len());
    let next = AtomicUsize::new(0);
    let timed_out = AtomicBool::new(false);
    let results: Vec<ScoreSlot> = (0..items.len()).map(|_| std::sync::Mutex::new(None)).collect();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    if deadline.timeout().is_err() {
                        timed_out.store(true, Ordering::Relaxed);
                        break;
                    }
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    if idx >= items.len() {
                        break;
                    }
                    let (text, added) = items[idx];
                    let res = crate::hygiene_model::score_code_windowed(text, added);
                    if let Ok(mut slot) = results[idx].lock() {
                        *slot = Some(res);
                    }
                }
            });
        }
    });

    let mut scored = Vec::with_capacity(items.len());
    let mut completed = 0usize;
    for slot in results {
        match slot.into_inner().ok().flatten() {
            Some(Ok(sq)) => {
                completed += 1;
                scored.push(Some(sq));
            }
            Some(Err(err)) => return Err(err),
            None => scored.push(None),
        }
    }
    let _ = timed_out.load(Ordering::Relaxed);
    Ok((scored, completed))
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

/// Collects a multiset of contiguous 3-line normalized shingles from removed hunks in
/// `git diff -U0 base --`. Requiring 3 consecutive non-blank lines prevents single deleted lines
/// (like `return None` or `pass`) from ever masking real new issues elsewhere.
fn removed_shingles_pool(root: &Path, base: &str, deadline: Deadline) -> HashMap<[String; 3], usize> {
    let Ok(raw) = git_output(root, &["diff", "-U0", "--no-color", base, "--"], deadline, None) else {
        return HashMap::new();
    };
    let mut pool = HashMap::new();
    let mut run: Vec<String> = Vec::new();
    let flush = |run: &mut Vec<String>, pool: &mut HashMap<[String; 3], usize>| {
        for win in run.windows(3) {
            let key = [win[0].clone(), win[1].clone(), win[2].clone()];
            *pool.entry(key).or_insert(0) += 1;
        }
        run.clear();
    };
    for line in String::from_utf8_lossy(&raw).lines() {
        if let Some(removed) = line.strip_prefix('-')
            && !removed.starts_with("-- ")
            && !removed.starts_with("--\t")
        {
            let trimmed = removed.trim();
            if !trimmed.is_empty() {
                run.push(trimmed.to_string());
            }
        } else if !run.is_empty() {
            flush(&mut run, &mut pool);
        }
    }
    flush(&mut run, &mut pool);
    pool
}

/// Returns the subset of 1-based line numbers in `added` that belong to a contiguous 3+ line
/// non-blank block moved verbatim from `removed_shingles` (consuming shingle counts so moving
/// one copy suppresses one copy while duplicating it still flags the second).
fn moved_block_lines(
    after: &str,
    added: &HashSet<usize>,
    removed_shingles: &mut HashMap<[String; 3], usize>,
) -> HashSet<usize> {
    let mut moved = HashSet::new();
    if added.is_empty() || removed_shingles.is_empty() {
        return moved;
    }
    let lines = py::splitlines(after, false);
    let mut sorted: Vec<usize> = added.iter().copied().collect();
    sorted.sort_unstable();
    // Collect non-blank added lines in file order: (1-based line_no, trimmed_text).
    let non_blank: Vec<(usize, String)> = sorted
        .into_iter()
        .filter_map(|line_no| {
            let trimmed = lines.get(line_no.saturating_sub(1))?.trim();
            (!trimmed.is_empty()).then(|| (line_no, trimmed.to_string()))
        })
        .collect();
    for win in non_blank.windows(3) {
        let key = [win[0].1.clone(), win[1].1.clone(), win[2].1.clone()];
        if let Some(count) = removed_shingles.get_mut(&key)
            && *count > 0
        {
            *count -= 1;
            moved.insert(win[0].0);
            moved.insert(win[1].0);
            moved.insert(win[2].0);
        }
    }
    moved
}

/// Model kinds that are refactor-noisy on verbatim moved blocks. `swallowed_error`,
/// `noisy_comment`, and all `nits` parser findings are never suppressed by move detection.
fn is_refactor_noisy_kind(kind: &str) -> bool {
    matches!(
        kind,
        "duplicate_block" | "special_casing" | "deep_nesting" | "cramped_layout" | "dense_line" | "poor_naming"
    )
}

fn indent_width(line: &str) -> usize {
    line.bytes()
        .take_while(|&b| b == b' ' || b == b'\t')
        .map(|b| if b == b'\t' { 4 } else { 1 })
        .sum()
}

fn parse_python_except_var(header: &str) -> Option<&str> {
    let code = header.split('#').next().unwrap_or(header).trim();
    let rest = code.strip_prefix("except")?;
    if !rest.is_empty() && !rest.starts_with([' ', '\t', ':', '(', '*']) {
        return None;
    }
    let before_colon = rest.trim_end().strip_suffix(':')?;
    let (_, var_part) = before_colon.rsplit_once(" as ")?;
    let var = var_part.trim();
    if !var.is_empty() && var.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        Some(var)
    } else {
        None
    }
}

fn is_python_except_header(trimmed: &str) -> bool {
    let code = trimmed.split('#').next().unwrap_or(trimmed).trim();
    let Some(rest) = code.strip_prefix("except") else {
        return false;
    };
    (rest.is_empty() || rest.starts_with([' ', '\t', ':', '(', '*'])) && code.ends_with(':')
}

fn line_uses_ident(line: &str, ident: &str) -> bool {
    let bytes = line.as_bytes();
    let needle = ident.as_bytes();
    if needle.is_empty() || bytes.len() < needle.len() {
        return false;
    }
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    for start in 0..=bytes.len() - needle.len() {
        if &bytes[start..start + needle.len()] == needle {
            let left_ok = start == 0 || !is_word(bytes[start - 1]);
            let right_ok = start + needle.len() == bytes.len() || !is_word(bytes[start + needle.len()]);
            if left_ok && right_ok {
                return true;
            }
        }
    }
    false
}

/// Structural check for Python neural `swallowed_error` squiggles:
/// - Drops hits outside any `except` handler (e.g. `spec.get("finderModels") or []`).
/// - Drops hits inside `except` handlers that propagate, log, warn, or record the error
///   (e.g. appending to `incomplete`/`not_checked` or passing the bound exception variable).
fn is_python_real_swallowed_error(after: &str, line_no: usize) -> bool {
    let lines = py::splitlines(after, false);
    let idx = line_no.saturating_sub(1);
    let Some(target) = lines.get(idx) else {
        return false;
    };
    let target_trimmed = target.trim();
    if target_trimmed.is_empty() || target_trimmed.starts_with('#') {
        return false;
    }
    let target_indent = indent_width(target);

    // Find the enclosing `except ...:` header (either this line itself or an ancestor at strictly smaller indent).
    let except_idx = if is_python_except_header(target_trimmed) {
        Some(idx)
    } else {
        let mut found = None;
        let mut min_indent = target_indent;
        for i in (0..idx).rev() {
            let t = lines[i].trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let ind = indent_width(lines[i]);
            if ind < min_indent {
                min_indent = ind;
                if is_python_except_header(t) {
                    found = Some(i);
                    break;
                }
                // Stopped at another compound block header (def/class/if/for/while/with/try/else/finally).
                if t.ends_with(':') {
                    break;
                }
            }
        }
        found
    };
    let Some(header_idx) = except_idx else {
        return false;
    };

    let header_indent = indent_width(lines[header_idx]);
    let bound_var = parse_python_except_var(lines[header_idx]);

    // Collect the indented body of this `except` handler.
    let mut body_lines = Vec::new();
    for line in &lines[header_idx + 1..] {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if indent_width(line) <= header_indent {
            break;
        }
        let code = t.split('#').next().unwrap_or(t).trim();
        if !code.is_empty() {
            body_lines.push(code);
        }
    }

    // If the body propagates, logs, warns, or records the failure, it is not swallowed.
    for code in &body_lines {
        if code.starts_with("raise")
            && (code.len() == 5 || code.as_bytes()[5].is_ascii_whitespace() || code.as_bytes()[5] == b'(')
        {
            return false;
        }
        if bound_var.is_some_and(|var| line_uses_ident(code, var)) {
            return false;
        }
        const HANDLED_MARKERS: [&str; 13] = [
            "logging.",
            "logger.",
            "log.",
            "warnings.warn",
            "sys.stderr",
            "print(",
            ".append(",
            ".extend(",
            ".add(",
            ".setdefault(",
            "incomplete",
            "not_checked",
            "errors",
        ];
        if HANDLED_MARKERS.iter().any(|m| code.contains(m)) {
            return false;
        }
    }
    true
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

fn merged_with_added(
    name: &str,
    after: &str,
    added: &HashSet<usize>,
    moved: &HashSet<usize>,
    model: &[Squiggle],
    nits: &[Squiggle],
    level: Level,
) -> Vec<String> {
    if level == Level::Off || added.is_empty() {
        return vec![];
    }
    let is_python = crate::rules::suffix(name).as_deref() == Some(".py");
    let nits: Vec<&Squiggle> = nits.iter().filter(|s| added.contains(&s.line)).collect();
    let model = model
        .iter()
        .filter(|s| added.contains(&s.line))
        .filter(|s| level == Level::All || DEFAULT_KINDS.contains(&s.kind.as_str()))
        .filter(|s| !(moved.contains(&s.line) && is_refactor_noisy_kind(&s.kind)))
        .filter(|s| !(is_python && s.kind == "swallowed_error" && !is_python_real_swallowed_error(after, s.line)))
        .filter(|s| !nits.iter().any(|n| n.line == s.line && n.kind == s.kind));
    nits.iter()
        .map(|s| note(name, after, "nits", s))
        .chain(model.map(|s| note(name, after, "hygiene", s)))
        .collect()
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
    merged_with_added(name, after, &added, &HashSet::new(), model, nits, level)
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
    against(root, files, "HEAD", level, &nits::launchers(), SECONDS)
}

/// [`written`], with nits run by `nits_launchers`.
pub fn written_with(root: &Path, files: &[String], level: Level, nits_launchers: &[Vec<String>]) -> Vec<String> {
    against(root, files, "HEAD", level, nits_launchers, SECONDS)
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
    let deadline = Deadline::after(CHANGED_SECONDS);
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
    against(root, &files, base, level, &nits::launchers(), CHANGED_SECONDS)
}

fn against(
    root: &Path,
    files: &[String],
    base: &str,
    level: Level,
    nits_launchers: &[Vec<String>],
    budget_seconds: f64,
) -> Vec<String> {
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
    let deadline = Deadline::after(budget_seconds);

    // Fetch all base texts in one batched git call and compute net-new lines (minus moved lines)
    // before scoring, so untouched/moved files skip inference completely.
    let names: Vec<&str> = sources.iter().map(|(name, _)| *name).collect();
    let before_map = match texts_at(&root, base, &names, deadline) {
        Ok(map) => map,
        Err(error) => return vec![format!("NOT CHECKED hygiene: {}", error.message())],
    };
    let mut removed_shingles = removed_shingles_pool(&root, base, deadline);

    let mut active: Vec<(&str, String, HashSet<usize>, HashSet<usize>)> = Vec::new();
    for (name, after) in sources {
        let before = before_map.get(name).map_or("", String::as_str);
        let added = added_lines(before, &after);
        if added.is_empty() {
            continue;
        }
        let moved = moved_block_lines(&after, &added, &mut removed_shingles);
        active.push((name, after, added, moved));
    }
    if active.is_empty() {
        return vec![];
    }

    let mut gaps = Vec::new();
    let active_sources: Vec<(&str, String)> = active.iter().map(|(n, a, _, _)| (*n, a.clone())).collect();
    // nits first: it answers in a fraction of a second, the model can take most of the deadline.
    let parsed = if active_sources.iter().any(|(name, _)| nits::reads(name)) {
        nits::score(nits_launchers, &active_sources, level == Level::All, deadline).unwrap_or_else(|reason| {
            gaps.push(format!("NOT CHECKED nits: {reason}"));
            vec![vec![]; active.len()]
        })
    } else {
        vec![vec![]; active.len()]
    };

    let score_inputs: Vec<(&str, &HashSet<usize>)> = active
        .iter()
        .map(|(_, after, added, _)| (after.as_str(), added))
        .collect();
    let (scored, completed) = match score_windowed_parallel(&score_inputs, deadline) {
        Ok(res) => res,
        Err(reason) => {
            gaps.push(format!("NOT CHECKED hygiene: {reason}"));
            (vec![None; active.len()], 0)
        }
    };
    if completed < active.len() && !gaps.iter().any(|g| g.starts_with("NOT CHECKED hygiene:")) {
        gaps.push(format!(
            "NOT CHECKED hygiene: loki: hook deadline exceeded ({completed}/{} files scored)",
            active.len()
        ));
    }

    let mut found = Vec::new();
    for (((name, after, added, moved), model_opt), nits_list) in active.iter().zip(&scored).zip(&parsed) {
        let model = model_opt.as_deref().unwrap_or(&[]);
        if model.is_empty() && nits_list.is_empty() {
            continue;
        }
        found.extend(merged_with_added(name, after, added, moved, model, nits_list, level));
    }
    if found.len() > MAX_NOTES {
        let more = found.len() - MAX_NOTES;
        found.truncate(MAX_NOTES);
        found.push(format!("... {more} more hygiene notes"));
    }
    found.extend(gaps);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_swallowed_error_ignores_dict_fallback_and_recording_except() {
        let code = "\
def collect(spec):
    models = spec.get(\"finderModels\") or []
    incomplete = []
    try:
        load(models)
    except Exception as exc:
        incomplete.append(f\"load failed: {exc}\")
    try:
        other()
    except Exception:
        incomplete.append(\"other failed\")
    try:
        silent()
    except Exception:
        pass
    try:
        fallback()
    except OSError:
        return None
";
        assert!(!is_python_real_swallowed_error(code, 2));
        assert!(!is_python_real_swallowed_error(code, 6));
        assert!(!is_python_real_swallowed_error(code, 7));
        assert!(!is_python_real_swallowed_error(code, 10));
        assert!(!is_python_real_swallowed_error(code, 11));
        assert!(is_python_real_swallowed_error(code, 14));
        assert!(is_python_real_swallowed_error(code, 15));
        assert!(is_python_real_swallowed_error(code, 18));
        assert!(is_python_real_swallowed_error(code, 19));
    }

    #[test]
    fn moved_block_lines_requires_3_line_shingle_and_never_hides_swallowed_error() {
        let after = "\
fn a() {
    let x = step_one();
    let y = step_two(x);
    let z = step_three(y);
}
fn b() {
    let x = step_one();
    let y = step_two(x);
    let z = step_three(y);
}
";
        let added: HashSet<usize> = (1..=10).collect();
        let mut pool = HashMap::from([(
            [
                "let x = step_one();".to_string(),
                "let y = step_two(x);".to_string(),
                "let z = step_three(y);".to_string(),
            ],
            1usize,
        )]);
        let moved = moved_block_lines(after, &added, &mut pool);
        assert!(moved.contains(&2) && moved.contains(&3) && moved.contains(&4));
        assert!(!moved.contains(&7) && !moved.contains(&8) && !moved.contains(&9));

        let model = vec![
            Squiggle {
                line: 2,
                kind: "duplicate_block".into(),
                message: "dup".into(),
            },
            Squiggle {
                line: 2,
                kind: "swallowed_error".into(),
                message: "swallowed".into(),
            },
            Squiggle {
                line: 7,
                kind: "duplicate_block".into(),
                message: "dup".into(),
            },
        ];
        let notes = merged_with_added("a.rs", after, &added, &moved, &model, &[], Level::On);
        assert!(
            !notes.iter().any(|n| n.starts_with("a.rs:2: loki/hygiene-duplicate-block")),
            "moved block should suppress duplicate-block: {notes:?}"
        );
        assert!(
            notes.iter().any(|n| n.starts_with("a.rs:2: loki/hygiene-swallowed-error")),
            "moved block must NEVER suppress swallowed-error: {notes:?}"
        );
        assert!(
            notes.iter().any(|n| n.starts_with("a.rs:7: loki/hygiene-duplicate-block")),
            "duplicated second copy must still flag duplicate-block: {notes:?}"
        );
    }
}
