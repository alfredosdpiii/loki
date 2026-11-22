//! `loki apply --manifest M [--check-only]` (loki.py `apply_transaction`): a list of `write` / `delete` / `move`
//! operations checked as one candidate before any file changes. The candidate (the committed base, the work tree's
//! existing changes, then the operations) is built in a private directory and checked there by the write
//! guardrails, the TypeScript checks and the Python analyzers (strict); the repository must not have changed in
//! the meantime. The targets are then written one by one (each atomically), and a failed write rolls back the ones
//! before it. Not an OS-atomic multi-file commit.

use crate::config::Config;
use crate::git::{FileChange, candidate_content, git_changes, git_output, materialize_base};
use crate::proc::Deadline;
use crate::{CheckError, hook, py, resolve, typescript};
use serde_json::Value;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const MAX_MANIFEST: u64 = 4 * 1024 * 1024;
const MAX_CONTENT: usize = 64 * 1024 * 1024;

use crate::invalid;

fn os(error: &std::io::Error, name: Option<&str>) -> CheckError {
    CheckError::os(error, name)
}

/// `Path(text).as_posix()`: repeated and trailing slashes and `.` parts dropped (a lone `.` stays, and POSIX keeps
/// exactly two leading slashes).
pub fn as_posix(text: &str) -> String {
    let prefix = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = text.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    let joined = format!("{prefix}{}", parts.join("/"));
    if joined.is_empty() { ".".into() } else { joined }
}

fn parts(name: &str) -> Vec<&str> {
    name.split('/').filter(|p| !p.is_empty() && *p != ".").collect()
}

fn valid_path(value: Option<&Value>) -> Result<String, CheckError> {
    match value.and_then(Value::as_str) {
        Some(path) if !path.is_empty() && !path.contains('\0') => Ok(path.to_string()),
        _ => Err(invalid("path must be a nonempty string without NUL")),
    }
}

type Original = (Option<Vec<u8>>, Option<String>);

/// The transaction's targets in operation order: their desired content (none: deleted) and Git mode, and what
/// each held before.
struct Plan {
    desired: Vec<(String, Option<Vec<u8>>)>,
    modes: Vec<(String, String)>,
    originals: Vec<(String, Original)>,
}

impl Plan {
    fn desired(&self, name: &str) -> Option<&Option<Vec<u8>>> {
        self.desired.iter().find(|(n, _)| n == name).map(|(_, c)| c)
    }
    fn set_desired(&mut self, name: &str, content: Option<Vec<u8>>) {
        match self.desired.iter_mut().find(|(n, _)| n == name) {
            Some(entry) => entry.1 = content,
            None => self.desired.push((name.to_string(), content)),
        }
    }
    fn mode(&self, name: &str) -> &str {
        self.modes
            .iter()
            .find(|(n, _)| n == name)
            .map_or("100644", |(_, m)| m.as_str())
    }
    fn set_mode(&mut self, name: &str, mode: String) {
        match self.modes.iter_mut().find(|(n, _)| n == name) {
            Some(entry) => entry.1 = mode,
            None => self.modes.push((name.to_string(), mode)),
        }
    }
    fn original(&self, name: &str) -> &Original {
        &self
            .originals
            .iter()
            .find(|(n, _)| n == name)
            .expect("every target has its original")
            .1
    }
}

/// `apply_transaction`: check (and unless `check_only`, write) the operations of `manifest`; what it prints on
/// success is returned.
pub fn apply_transaction(root: &Path, manifest: &Path, check_only: bool) -> Result<String, CheckError> {
    let shown = manifest.to_string_lossy().into_owned();
    let size = std::fs::metadata(manifest).map_err(|e| os(&e, Some(&shown)))?.len();
    if size > MAX_MANIFEST {
        return Err(invalid("transaction manifest exceeds 4 MiB"));
    }
    let raw = std::fs::read(manifest).map_err(|e| os(&e, Some(&shown)))?;
    let text = crate::proc::decode(&raw).map_err(invalid)?;
    let operations: Value = serde_json::from_str(&text).map_err(|e| invalid(crate::pyjson::error_text(&text, &e)))?;
    let operations = match operations.as_array() {
        Some(list) if !list.is_empty() => list.clone(),
        _ => return Err(invalid("transaction requires a nonempty operation list")),
    };
    let deadline = Deadline::after(20.0);
    let (base, existing) = git_changes(root, None, deadline)?;
    let Some(base) = base else {
        return Err(invalid("transaction requires committed base"));
    };
    let config: Config = match crate::git::base_policy(root, Some(&base), deadline)? {
        Some(policy) if !policy.is_empty() => policy,
        _ => crate::run::load(root)?,
    };
    let blocked = crate::git::protected_change_violations(&existing, &config)?;
    if !blocked.is_empty() {
        return Err(invalid(blocked.join("; ")));
    }
    let root = resolve(root);
    let mut plan = Plan {
        desired: Vec::new(),
        modes: Vec::new(),
        originals: Vec::new(),
    };
    for operation in &operations {
        let op = operation.get("op").and_then(Value::as_str);
        let Some(op) = op
            .filter(|op| ["write", "delete", "move"].contains(op))
            .filter(|_| operation.is_object())
        else {
            return Err(invalid("operation must be write, delete or move"));
        };
        let path = valid_path(operation.get("path"))?;
        if as_posix(&path) != path {
            return Err(invalid("transaction paths must use canonical POSIX spelling"));
        }
        let mut names = vec![path.clone()];
        if op == "move" {
            let to = valid_path(operation.get("to"))?;
            if to == path || as_posix(&to) != to {
                return Err(invalid("move requires a distinct canonical destination"));
            }
            names.push(to);
        }
        for name in &names {
            let pieces = parts(name);
            if name.starts_with('/') || pieces.contains(&"..") {
                return Err(invalid("transaction paths must be repository-relative"));
            }
            if pieces
                .first()
                .is_some_and(|first| [".git", "node_modules"].contains(first))
            {
                return Err(invalid("transaction cannot mutate Git metadata or dependencies"));
            }
            let target = root.join(name);
            let parent = target.parent().unwrap_or(&root).to_path_buf();
            if resolve(&parent) != parent {
                return Err(invalid("transaction symlinked parents are unsupported"));
            }
            if plan.desired(name).is_some() {
                return Err(invalid(format!("duplicate transaction target: {name}")));
            }
            if let Some(reason) = crate::protect_path_with(name, &root, &config, false)? {
                return Err(invalid(reason));
            }
            let original = candidate_content(&root, name, MAX_CONTENT)?;
            if original.1.as_deref() == Some("120000") {
                return Err(invalid("transaction symlink targets are unsupported"));
            }
            let mode = original.1.clone().unwrap_or_else(|| "100644".into());
            plan.originals.retain(|(n, _)| n != name);
            plan.originals.push((name.clone(), original));
            plan.set_mode(name, mode);
        }
        if op == "write" {
            let Some(content) = operation.get("content").and_then(Value::as_str) else {
                return Err(invalid("write content must be a string"));
            };
            plan.set_desired(&path, Some(content.as_bytes().to_vec()));
        } else {
            let source = plan.original(&path).clone();
            if source.0.is_none() {
                return Err(invalid(format!("transaction source is missing: {path}")));
            }
            plan.set_desired(&path, None);
            if op == "move" {
                let destination = names[1].clone();
                if plan.original(&destination).0.is_some() {
                    return Err(invalid("move destination already exists"));
                }
                plan.set_desired(&destination, source.0.clone());
                plan.set_mode(&destination, source.1.unwrap_or_else(|| "100644".into()));
            }
        }
    }
    let git_dir = git_output(&root, &["rev-parse", "--absolute-git-dir"], deadline, None)?;
    let git_dir = PathBuf::from(String::from_utf8_lossy(&git_dir).trim());
    let lock_path = git_dir.join("loki-transaction.lock");
    let lock = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&lock_path)
        .map_err(|e| os(&e, Some(&lock_path.to_string_lossy())))?;
    lock.try_lock().map_err(|e| match e {
        // EAGAIN: another Loki writer holds the lock.
        std::fs::TryLockError::WouldBlock => os(&std::io::Error::from_raw_os_error(11), None),
        std::fs::TryLockError::Error(e) => os(&e, None),
    })?;
    let directory = tempfile::Builder::new()
        .prefix("loki-transaction-")
        .tempdir()
        .map_err(|e| os(&e, None))?;
    check_candidate(&root, &base, &existing, &plan, &config, directory.path(), deadline)?;
    let (current_base, current_changes) = git_changes(&root, None, deadline)?;
    if current_base.as_deref() != Some(base.as_str()) || current_changes != existing {
        return Err(invalid("concurrent repository modification; retry transaction"));
    }
    // Recheck targets before mutation; the lock serializes Loki writers.
    for (name, original) in &plan.originals {
        if candidate_content(&root, name, MAX_CONTENT)? != *original {
            return Err(invalid(format!("concurrent target modification: {name}")));
        }
    }
    if check_only {
        return Ok("Transaction checks passed; no files written\n".into());
    }
    write_targets(&root, &plan)?;
    Ok(format!(
        "Applied {} targets; not an OS-atomic multi-file commit\n",
        plan.desired.len()
    ))
}

/// The candidate tree in `directory`: the base, the existing changes and the desired targets over it, with the
/// base as its only commit; then the guardrails, TypeScript and the Python analyzers on the targets.
fn check_candidate(
    root: &Path,
    base: &str,
    existing: &[FileChange],
    plan: &Plan,
    config: &Config,
    directory: &Path,
    deadline: Deadline,
) -> Result<(), CheckError> {
    let workspace = directory.join("candidate");
    materialize_base(root, base, &workspace, deadline)?;
    for change in existing {
        apply_snapshot_change(&workspace, change)?;
    }
    for (name, content) in &plan.desired {
        let original = plan.original(name);
        let change = FileChange {
            path: name.clone(),
            before: original.0.clone(),
            after: content.clone(),
            before_mode: original.1.clone(),
            after_mode: content.as_ref().map(|_| plan.mode(name).to_string()),
        };
        apply_snapshot_change(&workspace, &change)?;
    }
    git_output(&workspace, &["init"], deadline, None)?;
    let baseline = directory.join("baseline");
    materialize_base(root, base, &baseline, deadline)?;
    git_output(&baseline, &["init"], deadline, None)?;
    git_output(&baseline, &["add", "."], deadline, None)?;
    git_output(
        &baseline,
        &[
            "-c",
            "user.name=Loki",
            "-c",
            "user.email=loki@example.invalid",
            "commit",
            "-m",
            "isolated base",
        ],
        deadline,
        None,
    )?;
    std::fs::remove_dir_all(workspace.join(".git")).map_err(|e| os(&e, None))?;
    copy_tree(&baseline.join(".git"), &workspace.join(".git"))?;
    if root.join("node_modules").is_dir() {
        std::os::unix::fs::symlink(resolve(&root.join("node_modules")), workspace.join("node_modules"))
            .map_err(|e| os(&e, None))?;
    }
    let targets: Vec<PathBuf> = plan.desired.iter().map(|(name, _)| workspace.join(name)).collect();
    let mut findings = hook::write_guardrail_violations(&targets, &workspace, config, deadline, None)?;
    let mut warnings = Vec::new();
    let typescript = plan.desired.iter().any(|(name, _)| {
        let file = name.rsplit('/').next().unwrap_or(name);
        file.rfind('.')
            .filter(|&i| i > 0)
            .is_some_and(|i| typescript::TYPESCRIPT_SUFFIXES.contains(&&file[i..]))
    });
    if typescript {
        findings.extend(typescript::typescript_findings(
            &workspace,
            config,
            deadline,
            &mut warnings,
        )?);
        flush(&mut warnings);
    }
    let python: Vec<PathBuf> = plan
        .desired
        .iter()
        .filter(|(name, content)| content.is_some() && name.ends_with(".py"))
        .map(|(name, _)| workspace.join(name))
        .collect();
    let mut batch = hook::Batch::default();
    for target in &python {
        findings.extend(hook::check_file(
            target,
            &workspace,
            config,
            true,
            deadline,
            &mut warnings,
            &python,
            &mut batch,
            None,
        )?);
        flush(&mut warnings);
    }
    if !findings.is_empty() {
        return Err(invalid(findings.join("; ")));
    }
    Ok(())
}

/// loki.py's checks print their notes to stderr when no list collects them.
fn flush(warnings: &mut Vec<String>) {
    for warning in warnings.drain(..) {
        eprintln!("{warning}");
    }
}

/// `shutil.copytree` of a `.git` directory (no symlinks in one written by `git init` and a commit).
fn copy_tree(from: &Path, to: &Path) -> Result<(), CheckError> {
    std::fs::create_dir_all(to).map_err(|e| os(&e, None))?;
    for entry in std::fs::read_dir(from).map_err(|e| os(&e, None))?.flatten() {
        let source = entry.path();
        let target = to.join(entry.file_name());
        let kind = entry.file_type().map_err(|e| os(&e, None))?;
        if kind.is_dir() {
            copy_tree(&source, &target)?;
        } else if kind.is_symlink() {
            let link = std::fs::read_link(&source).map_err(|e| os(&e, None))?;
            std::os::unix::fs::symlink(link, &target).map_err(|e| os(&e, None))?;
        } else {
            std::fs::copy(&source, &target).map_err(|e| os(&e, None))?;
        }
    }
    Ok(())
}

/// `apply_snapshot_change`: one change written into an isolated tree.
pub fn apply_snapshot_change(root: &Path, change: &FileChange) -> Result<(), CheckError> {
    let path = root.join(&change.path);
    match (&change.after, change.after_mode.as_deref()) {
        (None, _) => match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(os(&e, None)),
            _ => Ok(()),
        },
        (Some(content), Some(mode @ ("100644" | "100755"))) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| os(&e, None))?;
            }
            std::fs::write(&path, content).map_err(|e| os(&e, None))?;
            let bits = if mode == "100755" { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bits)).map_err(|e| os(&e, None))
        }
        _ => Err(invalid(format!(
            "isolated checks: unsupported candidate entry: {}",
            change.path
        ))),
    }
}

/// Write each target (atomically: a private temporary file renamed over it); a failure restores the targets
/// already written unless they changed again since.
fn write_targets(root: &Path, plan: &Plan) -> Result<(), CheckError> {
    let mut applied: Vec<&str> = Vec::new();
    for (name, content) in &plan.desired {
        let target = root.join(name);
        let written = match content {
            None => std::fs::remove_file(&target),
            Some(content) => write_atomically(&target, content, plan.mode(name)),
        };
        if let Err(failure) = written {
            let mut unrecovered = Vec::new();
            for done in applied.iter().rev() {
                let expected: Original = match plan.desired(done).and_then(Option::as_ref) {
                    Some(content) => (Some(content.clone()), Some(plan.mode(done).to_string())),
                    None => (None, None),
                };
                match candidate_content(root, done, MAX_CONTENT) {
                    Ok(current) if current != expected => {
                        unrecovered.push(format!("{done}: changed after application"));
                        continue;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        unrecovered.push(format!("{done}: {}", error.message()));
                        continue;
                    }
                }
                let (original, mode) = plan.original(done);
                let restored = match original {
                    None => match std::fs::remove_file(root.join(done)) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                        _ => Ok(()),
                    },
                    Some(bytes) => std::fs::write(root.join(done), bytes).and_then(|()| {
                        let bits = if mode.as_deref() == Some("100755") {
                            0o755
                        } else {
                            0o644
                        };
                        std::fs::set_permissions(root.join(done), std::fs::Permissions::from_mode(bits))
                    }),
                };
                if let Err(error) = restored {
                    unrecovered.push(format!("{done}: {}", py::os_error(&error, None)));
                }
            }
            let failure = py::os_error(&failure, None);
            if !unrecovered.is_empty() {
                return Err(invalid(format!(
                    "transaction failed: {failure}; rollback incomplete: {}",
                    unrecovered.join("; ")
                )));
            }
            return Err(CheckError::Guard("OSError".into(), failure));
        }
        applied.push(name);
    }
    Ok(())
}

fn write_atomically(target: &Path, content: &[u8], mode: &str) -> std::io::Result<()> {
    let parent = target.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new().prefix(".loki-write-").tempfile_in(parent)?;
    temporary.write_all(content)?;
    let bits = if mode == "100755" { 0o755 } else { 0o644 };
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(bits))?;
    temporary.persist(target).map_err(|e| e.error)?;
    Ok(())
}
