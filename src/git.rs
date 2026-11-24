//! Git snapshots: the committed base, the working-tree candidate and the changes
//! between them (`git_changes`, `git_blobs`, `candidate_content`, `base_policy`).

use crate::config::{self, Config};
use crate::proc::{self, Deadline, RunError};
use crate::{CheckError, path_matches, py, resolve};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const SNAPSHOT_LIMIT: usize = 64 * 1024 * 1024;

use crate::invalid;

const TOO_MANY_OBJECTS: &str = "git: snapshot exceeds 100000 base objects";
const BASE_TOO_LARGE: &str = "git: snapshot base content exceeds 64 MiB";
const CONTENT_TOO_LARGE: &str = "git: snapshot content exceeds 64 MiB";

/// loki.py's `SnapshotTooLarge` (a `ValueError`): the working tree's changes are too big to snapshot in one check.
pub fn snapshot_too_large(error: &CheckError) -> bool {
    matches!(error, CheckError::Value(m) if [TOO_MANY_OBJECTS, BASE_TOO_LARGE, CONTENT_TOO_LARGE].contains(&m.as_str()))
}

/// One changed path: committed and candidate bytes and modes.
#[derive(Clone, Debug, PartialEq)]
pub struct FileChange {
    pub path: String,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
    pub before_mode: Option<String>,
    pub after_mode: Option<String>,
}

fn git_env() -> [(&'static str, &'static str); 1] {
    [("GIT_OPTIONAL_LOCKS", "0")]
}

fn raw_git(root: &Path, arguments: &[&str], deadline: Deadline) -> Result<proc::Output, CheckError> {
    let command: Vec<String> = std::iter::once("git")
        .chain(arguments.iter().copied())
        .map(String::from)
        .collect();
    proc::run(&command, root, None, &git_env(), deadline.timeout()?).map_err(|e| invalid(format!("git: {e}")))
}

/// `git --literal-pathspecs ...`: stdout, or a `git: ...` error.
pub fn git_output(
    root: &Path,
    arguments: &[&str],
    deadline: Deadline,
    input: Option<&[u8]>,
) -> Result<Vec<u8>, CheckError> {
    let command: Vec<String> = ["git", "--literal-pathspecs"]
        .into_iter()
        .chain(arguments.iter().copied())
        .map(String::from)
        .collect();
    let output = proc::run(
        &command,
        root,
        Some(input.unwrap_or(b"")),
        &git_env(),
        deadline.timeout()?,
    )
    .map_err(|e: RunError| invalid(format!("git: {e}")))?;
    if output.code != 0 {
        let reason = py::strip(&String::from_utf8_lossy(&output.stderr)).to_string();
        let reason = if reason.is_empty() {
            format!("exited {}", output.code)
        } else {
            reason
        };
        return Err(invalid(format!("git: {reason}")));
    }
    Ok(output.stdout)
}

fn split_fields(row: &[u8]) -> Vec<&[u8]> {
    row.split(|b| b.is_ascii_whitespace())
        .filter(|f| !f.is_empty())
        .collect()
}

fn parse_blob_header(fields: &[&[u8]], oid: &str, err_msg: &str) -> Result<usize, CheckError> {
    let digits = |f: &[u8]| !f.is_empty() && f.iter().all(u8::is_ascii_digit);
    if fields.len() != 3 || fields[0] != oid.as_bytes() || fields[1] != b"blob" || !digits(fields[2]) {
        return Err(invalid(err_msg));
    }
    Ok(String::from_utf8_lossy(fields[2])
        .parse::<usize>()
        .unwrap_or(usize::MAX))
}

fn check_blob_metadata(root: &Path, unique: &[&String], request: &[u8], deadline: Deadline) -> Result<(), CheckError> {
    let metadata = git_output(root, &["cat-file", "--batch-check"], deadline, Some(request))?;
    let rows: Vec<&[u8]> = py_splitlines_bytes(&metadata);
    if rows.len() != unique.len() {
        return Err(invalid("git: invalid batch metadata response"));
    }
    let mut total = 0usize;
    for (oid, row) in unique.iter().zip(rows) {
        let fields = split_fields(row);
        total += parse_blob_header(&fields, oid, "git: invalid batch metadata response")?;
        if total > SNAPSHOT_LIMIT {
            return Err(invalid(BASE_TOO_LARGE));
        }
    }
    Ok(())
}

fn read_batch_blobs(
    root: &Path,
    unique: &[&String],
    request: &[u8],
    deadline: Deadline,
) -> Result<HashMap<String, Vec<u8>>, CheckError> {
    let data = git_output(root, &["cat-file", "--batch"], deadline, Some(request))?;
    let mut blobs = HashMap::new();
    let mut offset = 0usize;
    for oid in unique {
        let end = data[offset.min(data.len())..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| p + offset)
            .ok_or_else(|| invalid("git: invalid batch blob response"))?;
        let header = split_fields(&data[offset..end]);
        let size = parse_blob_header(&header, oid, "git: invalid batch blob response")?;
        let start = end + 1;
        let stop = start.saturating_add(size);
        if stop >= data.len() || data[stop] != b'\n' {
            return Err(invalid("git: truncated batch blob response"));
        }
        blobs.insert((*oid).clone(), data[start..stop].to_vec());
        offset = stop + 1;
    }
    if offset != data.len() {
        return Err(invalid("git: unexpected batch blob response"));
    }
    Ok(blobs)
}

/// Blob contents by object id, read in two batches with size limits.
pub fn git_blobs(root: &Path, oids: &[String], deadline: Deadline) -> Result<HashMap<String, Vec<u8>>, CheckError> {
    let mut unique: Vec<&String> = Vec::new();
    for oid in oids {
        if !unique.contains(&oid) {
            unique.push(oid);
        }
    }
    if unique.is_empty() {
        return Ok(HashMap::new());
    }
    if unique.len() > 100_000 {
        return Err(invalid(TOO_MANY_OBJECTS));
    }
    let request: Vec<u8> = unique.iter().flat_map(|o| format!("{o}\n").into_bytes()).collect();
    check_blob_metadata(root, &unique, &request, deadline)?;
    read_batch_blobs(root, &unique, &request, deadline)
}

/// `bytes.splitlines()`: \n, \r and \r\n.
fn py_splitlines_bytes(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < data.len() {
        match data[i] {
            b'\n' => {
                lines.push(&data[start..i]);
                start = i + 1;
            }
            b'\r' => {
                lines.push(&data[start..i]);
                if data.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

fn read_symlink_candidate(path: &Path, remaining: usize) -> Result<(Option<Vec<u8>>, Option<String>), CheckError> {
    let link = std::fs::read_link(path).map_err(|e| invalid(py::os_error(&e, None)))?;
    let content = link.as_os_str().as_encoded_bytes().to_vec();
    if content.len() > remaining {
        return Err(invalid(CONTENT_TOO_LARGE));
    }
    Ok((Some(content), Some("120000".into())))
}

fn read_regular_candidate(
    path: &Path,
    meta: &std::fs::Metadata,
    remaining: usize,
) -> Result<(Option<Vec<u8>>, Option<String>), CheckError> {
    use std::os::unix::fs::PermissionsExt;
    if meta.len() as usize > remaining {
        return Err(invalid(CONTENT_TOO_LARGE));
    }
    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, None)),
        Err(e) => return Err(invalid(py::os_error(&e, None))),
    };
    if content.len() > remaining {
        return Err(invalid(CONTENT_TOO_LARGE));
    }
    let mode = if meta.permissions().mode() & 0o100 != 0 {
        "100755"
    } else {
        "100644"
    };
    Ok((Some(content), Some(mode.into())))
}

/// The candidate's bytes and Git mode, without following a final symlink.
pub fn candidate_content(
    root: &Path,
    name: &str,
    remaining: usize,
) -> Result<(Option<Vec<u8>>, Option<String>), CheckError> {
    let target = root.join(name);
    let parent = resolve(target.parent().unwrap_or(root));
    if parent.strip_prefix(root).is_err() {
        return Err(invalid(format!(
            "{} is not in the subpath of {}",
            py::repr_str(&parent.to_string_lossy()),
            py::repr_str(&root.to_string_lossy())
        )));
    }
    let Some(filename) = target.file_name() else {
        return Ok((None, None));
    };
    let path = parent.join(filename);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, None)),
        Err(e) => return Err(invalid(py::os_error(&e, Some(&filename.to_string_lossy())))),
    };
    if meta.file_type().is_symlink() {
        return read_symlink_candidate(&path, remaining);
    }
    if !meta.is_file() {
        return Err(invalid(format!("loki: unsupported changed file type: {name}")));
    }
    read_regular_candidate(&path, &meta, remaining)
}

fn lines_z(data: &[u8]) -> Vec<String> {
    data.split(|&b| b == 0)
        .filter(|n| !n.is_empty())
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .collect()
}

fn tree_entries(
    root: &Path,
    commit: &str,
    deadline: Deadline,
) -> Result<Vec<(String, String, String, String)>, CheckError> {
    let listing = git_output(root, &["ls-tree", "-r", "-z", commit], deadline, None)?;
    let mut entries = Vec::new();
    for entry in listing.split(|&b| b == 0).filter(|e| !e.is_empty()) {
        let tab = entry
            .iter()
            .position(|&b| b == b'\t')
            .ok_or_else(|| invalid("git: invalid tree entry"))?;
        let metadata = String::from_utf8_lossy(&entry[..tab]).into_owned();
        let parts: Vec<&str> = metadata.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(invalid("git: invalid tree entry"));
        }
        let path = String::from_utf8_lossy(&entry[tab + 1..]).into_owned();
        entries.push((path, parts[0].to_string(), parts[1].to_string(), parts[2].to_string()));
    }
    Ok(entries)
}

/// `(resolved base, changes)`: every path that differs from the base commit.
pub fn git_changes(
    root: &Path,
    base: Option<&str>,
    deadline: Deadline,
) -> Result<(Option<String>, Vec<FileChange>), CheckError> {
    git_changes_only(root, base, deadline, None)
}

/// `repository_gap`: why git cannot compare root (no repository, or a subdirectory of one), else None.
pub fn repository_gap(root: &Path, deadline: Deadline) -> Result<Option<String>, CheckError> {
    let top = match git_output(root, &["rev-parse", "--show-toplevel"], deadline, None) {
        Ok(top) => top,
        Err(CheckError::Value(message)) => return Ok(Some(message)),
        Err(error) => return Err(error),
    };
    let top = String::from_utf8_lossy(&top).trim_end_matches('\n').to_string();
    if resolve(Path::new(&top)) != resolve(root) {
        return Ok(Some("git: project root must be the repository root".into()));
    }
    Ok(None)
}

fn verify_unborn_head(root: &Path, deadline: Deadline) -> Result<(), CheckError> {
    let symbolic = raw_git(root, &["symbolic-ref", "-q", "HEAD"], deadline)?;
    if symbolic.code != 0 || !symbolic.stdout.starts_with(b"refs/heads/") {
        return Err(invalid("git: cannot resolve HEAD"));
    }
    let name = String::from_utf8_lossy(&symbolic.stdout)
        .trim_end_matches('\n')
        .to_string();
    let exists = raw_git(root, &["show-ref", "--verify", "--quiet", &name], deadline)?;
    if exists.code != 1 {
        return Err(invalid("git: cannot resolve HEAD commit"));
    }
    Ok(())
}

fn resolve_base_commit(root: &Path, base: Option<&str>, deadline: Deadline) -> Result<Option<String>, CheckError> {
    if base == Some("") {
        return Err(invalid("git: empty base reference"));
    }
    let zero = base.is_some_and(|b| (b.len() == 40 || b.len() == 64) && b.chars().all(|c| c == '0'));
    if zero {
        return Ok(None);
    }
    let reference = format!("{}^{{commit}}", base.unwrap_or("HEAD"));
    let commit = raw_git(
        root,
        &["rev-parse", "--verify", "--end-of-options", &reference],
        deadline,
    )?;
    if commit.code == 0 {
        return Ok(Some(String::from_utf8_lossy(&commit.stdout).trim().to_string()));
    }
    if base.is_none() {
        verify_unborn_head(root, deadline)?;
        return Ok(None);
    }
    Err(invalid("git: invalid base reference"))
}

fn check_dir_entries(root: &Path, parent: &str, filenames: &BTreeSet<String>) -> Result<(), CheckError> {
    let directory = resolve(&root.join(parent));
    if directory.strip_prefix(root).is_err() {
        return Err(invalid(format!("loki: outside project root: {parent}")));
    }
    let Ok(children) = std::fs::read_dir(&directory) else {
        return Ok(());
    };
    for child in children.flatten() {
        let name = child.file_name().to_string_lossy().into_owned();
        if !filenames.contains(&name) {
            continue;
        }
        let Ok(kind) = child.file_type() else { continue };
        if !kind.is_file() && !kind.is_symlink() {
            let shown = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };
            return Err(invalid(format!("loki: unsupported changed file type: {shown}")));
        }
    }
    Ok(())
}

fn group_parent_filenames(listed: &[(String, String, String, String)]) -> Vec<(String, BTreeSet<String>)> {
    let mut parents: Vec<(String, BTreeSet<String>)> = Vec::new();
    for (path, mode, _, _) in listed {
        if mode == "160000" {
            continue;
        }
        let (parent, filename) = match path.rfind('/') {
            Some(i) => (path[..i].to_string(), path[i + 1..].to_string()),
            None => (String::new(), path.clone()),
        };
        match parents.iter_mut().find(|(p, _)| *p == parent) {
            Some((_, names)) => {
                names.insert(filename);
            }
            None => parents.push((parent, BTreeSet::from([filename]))),
        }
    }
    parents
}

type TreeEntryMap = HashMap<String, (String, String, String)>;

fn collect_changed_names(
    root: &Path,
    resolved: Option<&str>,
    deadline: Deadline,
) -> Result<(TreeEntryMap, Vec<u8>), CheckError> {
    let Some(commit) = resolved else {
        let names = git_output(
            root,
            &["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            deadline,
            None,
        )?;
        return Ok((HashMap::new(), names));
    };
    let listed = tree_entries(root, commit, deadline)?;
    let entries: TreeEntryMap = listed
        .iter()
        .map(|(path, mode, kind, oid)| (path.clone(), (mode.clone(), kind.clone(), oid.clone())))
        .collect();
    for (parent, filenames) in &group_parent_filenames(&listed) {
        deadline.timeout()?;
        check_dir_entries(root, parent, filenames)?;
    }
    let mut names = git_output(
        root,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            commit,
            "--",
        ],
        deadline,
        None,
    )?;
    names.extend(git_output(
        root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
        deadline,
        None,
    )?);
    Ok((entries, names))
}

fn build_file_change(
    root: &Path,
    name: String,
    entries: &TreeEntryMap,
    blobs: &HashMap<String, Vec<u8>>,
    remaining: &mut usize,
) -> Result<Option<FileChange>, CheckError> {
    let path = root.join(&name);
    let lexical = crate::lexical_path(root, &name);
    if lexical.strip_prefix(root).is_err() || resolve(path.parent().unwrap_or(root)).strip_prefix(root).is_err() {
        return Err(invalid(format!("loki: outside project root: {name}")));
    }
    let (mut before, mut before_mode) = (None, None);
    if let Some((mode, kind, oid)) = entries.get(&name) {
        if kind != "blob" || !["100644", "100755", "120000"].contains(&mode.as_str()) {
            return Err(invalid(format!("loki: unsupported changed file type: {name}")));
        }
        before = blobs.get(oid).cloned();
        before_mode = Some(mode.clone());
    }
    let (after, after_mode) = candidate_content(root, &name, *remaining)?;
    *remaining = remaining.saturating_sub(after.as_ref().map_or(0, Vec::len));
    if before == after && before_mode == after_mode {
        return Ok(None);
    }
    Ok(Some(FileChange {
        path: name,
        before,
        after,
        before_mode,
        after_mode,
    }))
}

fn collect_file_changes(
    root: &Path,
    changed: BTreeSet<String>,
    entries: &TreeEntryMap,
    deadline: Deadline,
) -> Result<Vec<FileChange>, CheckError> {
    let oids: Vec<String> = changed
        .iter()
        .filter_map(|name| entries.get(name).filter(|e| e.1 == "blob").map(|e| e.2.clone()))
        .collect();
    let blobs = git_blobs(root, &oids, deadline)?;
    let mut remaining = SNAPSHOT_LIMIT.saturating_sub(blobs.values().map(Vec::len).sum());
    let mut changes = Vec::new();
    for name in changed {
        if let Some(change) = build_file_change(root, name, entries, &blobs, &mut remaining)? {
            changes.push(change);
        }
    }
    Ok(changes)
}

/// `git_changes(..., only=...)`: the changes against base, limited to `only` (repository-relative paths) when given.
pub fn git_changes_only(
    root: &Path,
    base: Option<&str>,
    deadline: Deadline,
    only: Option<&HashSet<String>>,
) -> Result<(Option<String>, Vec<FileChange>), CheckError> {
    let root = resolve(root);
    if let Some(gap) = repository_gap(&root, deadline)? {
        return Err(invalid(gap));
    }
    if !git_output(&root, &["ls-files", "--unmerged", "-z"], deadline, None)?.is_empty() {
        return Err(invalid("loki: unresolved index conflict"));
    }
    let resolved = resolve_base_commit(&root, base, deadline)?;
    let (entries, names_raw) = collect_changed_names(&root, resolved.as_deref(), deadline)?;
    let changed: BTreeSet<String> = lines_z(&names_raw)
        .into_iter()
        .filter(|name| only.is_none_or(|only| only.contains(name)))
        .collect();
    let changes = collect_file_changes(&root, changed, &entries, deadline)?;
    Ok((resolved, changes))
}

/// The committed `.loki/loki.json` of `base`, validated.
pub fn base_policy(root: &Path, base: Option<&str>, deadline: Deadline) -> Result<Option<Config>, CheckError> {
    let Some(base) = base else {
        crate::evidence::policy("base", ".loki/loki.json", None, None);
        return Ok(None);
    };
    let entry = git_output(root, &["ls-tree", "-z", base, "--", ".loki/loki.json"], deadline, None)?;
    if entry.is_empty() {
        crate::evidence::policy("base", ".loki/loki.json", None, Some(base));
        return Ok(None);
    }
    let trimmed: &[u8] = entry.strip_suffix(b"\0").unwrap_or(&entry);
    let tab = trimmed.iter().position(|&b| b == b'\t').unwrap_or(trimmed.len());
    let metadata = String::from_utf8_lossy(&trimmed[..tab]).into_owned();
    let parts: Vec<&str> = metadata.split_whitespace().collect();
    if parts.len() != 3 || !["100644", "100755"].contains(&parts[0]) || parts[1] != "blob" {
        return Err(invalid("loki: base policy must be a regular file"));
    }
    let raw = git_output(root, &["cat-file", "blob", parts[2]], deadline, None)?;
    crate::evidence::policy("base", ".loki/loki.json", Some(&raw), Some(base));
    let text = proc::decode(&raw).map_err(invalid)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| invalid(crate::pyjson::error_text(&text, &e)))?;
    config::validate_config(&value).map(Some).map_err(invalid)
}

const PROTECTED_CHANGE: &str = ": protected content changed";

/// Whether `finding` reports a changed `.loki/` policy file: a check against the committed policy reports that
/// (and nothing else) until `.loki/` is committed.
pub fn is_policy_change(finding: &str) -> bool {
    finding
        .trim()
        .strip_suffix(PROTECTED_CHANGE)
        .and_then(|path| path.strip_prefix(".loki/"))
        .is_some_and(|rest| !rest.contains(char::is_whitespace))
}

/// `protected_change_violations`: changes to protected files of the base policy.
pub fn protected_change_violations(changes: &[FileChange], base: &Config) -> Result<Vec<String>, CheckError> {
    let patterns = config::protected_patterns(base).map_err(invalid)?;
    Ok(changes
        .iter()
        .filter(|c| patterns.iter().any(|p| path_matches(&c.path, p)))
        .map(|c| {
            crate::evidence::finding("protected-content", Some(&c.path));
            format!("{}{PROTECTED_CHANGE}", c.path)
        })
        .collect())
}

/// Committed HEAD text, or empty text for a file absent from HEAD.
pub fn head_text(root: &Path, relative: &str, deadline: Deadline) -> Result<String, CheckError> {
    text_at(root, "HEAD", relative, deadline)
}

/// The file's text at `revision`, or empty text for a file absent from it.
pub fn text_at(root: &Path, revision: &str, relative: &str, deadline: Deadline) -> Result<String, CheckError> {
    let mut map = texts_at(root, revision, &[relative], deadline)?;
    Ok(map.remove(relative).unwrap_or_default())
}

/// Batch size for streaming base blobs without holding an entire large repository in memory at once.
const MATERIALIZE_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// Batch-read the text of multiple `relatives` at `revision` using a single `ls-tree` and
/// chunked `cat-file --batch` calls. Missing or non-blob paths map to an empty string.
pub fn texts_at(
    root: &Path,
    revision: &str,
    relatives: &[&str],
    deadline: Deadline,
) -> Result<HashMap<String, String>, CheckError> {
    if relatives.is_empty() {
        return Ok(HashMap::new());
    }
    let mut args: Vec<&str> = Vec::with_capacity(relatives.len() + 4);
    args.extend(["ls-tree", "-z", revision, "--"]);
    args.extend(relatives.iter().copied());
    let output = git_output(root, &args, deadline, None)?;
    let mut path_oids: Vec<(String, String)> = Vec::new();
    for row in output.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let tab = row.iter().position(|&b| b == b'\t').unwrap_or(row.len());
        let metadata = String::from_utf8_lossy(&row[..tab]);
        let parts: Vec<&str> = metadata.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(CheckError::Value(format!(
                "not enough values to unpack (expected 3, got {})",
                parts.len()
            )));
        }
        if parts[1] != "blob" {
            continue;
        }
        let name = String::from_utf8_lossy(&row[(tab + 1).min(row.len())..]).into_owned();
        path_oids.push((name, parts[2].to_string()));
    }
    let oids: Vec<String> = path_oids.iter().map(|(_, oid)| oid.clone()).collect();
    let blobs = read_blobs_chunked(root, &oids, deadline)?;
    let mut out = HashMap::with_capacity(relatives.len());
    for (name, oid) in path_oids {
        if let Some(bytes) = blobs.get(&oid) {
            out.insert(name, String::from_utf8_lossy(bytes).into_owned());
        }
    }
    Ok(out)
}

/// Read blob sizes via `cat-file --batch-check` without enforcing the 64 MiB aggregate cap.
pub fn blob_sizes(root: &Path, oids: &[String], deadline: Deadline) -> Result<HashMap<String, usize>, CheckError> {
    let mut unique: Vec<&String> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for oid in oids {
        if seen.insert(oid.as_str()) {
            unique.push(oid);
        }
    }
    if unique.is_empty() {
        return Ok(HashMap::new());
    }
    if unique.len() > 100_000 {
        return Err(invalid(TOO_MANY_OBJECTS));
    }
    let request: Vec<u8> = unique.iter().flat_map(|o| format!("{o}\n").into_bytes()).collect();
    let metadata = git_output(root, &["cat-file", "--batch-check"], deadline, Some(&request))?;
    let rows: Vec<&[u8]> = py_splitlines_bytes(&metadata);
    if rows.len() != unique.len() {
        return Err(invalid("git: invalid batch metadata response"));
    }
    let mut sizes = HashMap::with_capacity(unique.len());
    for (oid, row) in unique.iter().zip(rows) {
        let fields = split_fields(row);
        let size = parse_blob_header(&fields, oid, "git: invalid batch metadata response")?;
        sizes.insert((*oid).clone(), size);
    }
    Ok(sizes)
}

/// Read blobs in bounded batches (suitable for targeted subsets of source files).
fn read_blobs_chunked(
    root: &Path,
    oids: &[String],
    deadline: Deadline,
) -> Result<HashMap<String, Vec<u8>>, CheckError> {
    let sizes = blob_sizes(root, oids, deadline)?;
    let mut out = HashMap::with_capacity(sizes.len());
    let mut batch: Vec<&String> = Vec::new();
    let mut batch_bytes = 0usize;
    let unique: Vec<&String> = sizes.keys().collect();
    for oid in unique {
        let size = sizes[oid];
        if !batch.is_empty() && batch_bytes.saturating_add(size) > MATERIALIZE_BATCH_BYTES {
            let req: Vec<u8> = batch.iter().flat_map(|o| format!("{o}\n").into_bytes()).collect();
            out.extend(read_batch_blobs(root, &batch, &req, deadline)?);
            batch.clear();
            batch_bytes = 0;
        }
        batch.push(oid);
        batch_bytes = batch_bytes.saturating_add(size);
    }
    if !batch.is_empty() {
        let req: Vec<u8> = batch.iter().flat_map(|o| format!("{o}\n").into_bytes()).collect();
        out.extend(read_batch_blobs(root, &batch, &req, deadline)?);
    }
    Ok(out)
}

fn validate_base_entry(name: &str, mode: &str, kind: &str) -> Result<(), CheckError> {
    if kind != "blob" || !["100644", "100755"].contains(&mode) {
        return Err(invalid(format!("isolated checks: unsupported base entry: {name}")));
    }
    if name.starts_with('/') || name.split('/').any(|p| p == "..") || name.starts_with("node_modules/") {
        return Err(invalid(format!("isolated checks: unsupported base path: {name}")));
    }
    Ok(())
}

fn write_base_file(destination: &Path, base: &str, name: &str, mode: &str, content: &[u8]) -> Result<(), CheckError> {
    use std::os::unix::fs::PermissionsExt;
    let os = |e: std::io::Error| invalid(py::os_error(&e, None));
    let file_name = name.rsplit('/').next().unwrap_or(name);
    if file_name.starts_with("tsconfig") && name.ends_with(".json") {
        crate::evidence::policy("base", name, Some(content), Some(base));
    }
    let path: PathBuf = destination.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(os)?;
    }
    std::fs::write(&path, content).map_err(os)?;
    let bits = if mode == "100755" { 0o755 } else { 0o644 };
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bits)).map_err(os)
}

/// Write the base commit's regular files into `destination`, streaming blobs in bounded batches
/// so repositories larger than `SNAPSHOT_LIMIT` can still be materialized without exhausting RAM.
pub fn materialize_base(root: &Path, base: &str, destination: &Path, deadline: Deadline) -> Result<(), CheckError> {
    std::fs::create_dir(destination).map_err(|e| invalid(py::os_error(&e, None)))?;
    let mut entries = Vec::new();
    for (name, mode, kind, oid) in tree_entries(root, base, deadline)? {
        validate_base_entry(&name, &mode, &kind)?;
        entries.push((name, mode, oid));
    }
    if entries.is_empty() {
        return Ok(());
    }
    let oids: Vec<String> = entries.iter().map(|e| e.2.clone()).collect();
    let sizes = blob_sizes(root, &oids, deadline)?;
    // Group entries into batches of ~MATERIALIZE_BATCH_BYTES by unique oid size, writing each
    // batch to disk and dropping its memory before reading the next.
    let mut batch_entries: Vec<(String, String, String)> = Vec::new();
    let mut batch_oids: Vec<String> = Vec::new();
    let mut batch_seen: HashSet<String> = HashSet::new();
    let mut batch_bytes = 0usize;
    let flush = |batch_entries: &mut Vec<(String, String, String)>,
                 batch_oids: &mut Vec<String>,
                 batch_seen: &mut HashSet<String>,
                 batch_bytes: &mut usize|
     -> Result<(), CheckError> {
        if batch_entries.is_empty() {
            return Ok(());
        }
        let oid_refs: Vec<&String> = batch_oids.iter().collect();
        let req: Vec<u8> = oid_refs.iter().flat_map(|o| format!("{o}\n").into_bytes()).collect();
        let blobs = read_batch_blobs(root, &oid_refs, &req, deadline)?;
        for (name, mode, oid) in batch_entries.drain(..) {
            write_base_file(destination, base, &name, &mode, &blobs[&oid])?;
        }
        batch_oids.clear();
        batch_seen.clear();
        *batch_bytes = 0;
        Ok(())
    };
    for (name, mode, oid) in entries {
        let size = sizes.get(&oid).copied().unwrap_or(0);
        let added_bytes = if batch_seen.contains(&oid) { 0 } else { size };
        if !batch_entries.is_empty() && batch_bytes.saturating_add(added_bytes) > MATERIALIZE_BATCH_BYTES {
            flush(&mut batch_entries, &mut batch_oids, &mut batch_seen, &mut batch_bytes)?;
        }
        if batch_seen.insert(oid.clone()) {
            batch_oids.push(oid.clone());
            batch_bytes = batch_bytes.saturating_add(size);
        }
        batch_entries.push((name, mode, oid));
    }
    flush(&mut batch_entries, &mut batch_oids, &mut batch_seen, &mut batch_bytes)?;
    Ok(())
}
