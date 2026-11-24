//! The `loki` checks as library calls, for a host that runs the engine in-process instead of as
//! `python loki.py ...`: each returns a [`Report`] or the [`CheckError`] that stopped it; `main.rs` renders them.

use crate::config::{self, Config};
use crate::{CheckError, MAX_VIOLATIONS, hook_report, protect_path, resolve};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// What a finished check found: findings that block, then warnings (advisories and `NOT CHECKED` notes, in the
/// order the checks made them, each once). Blocking findings stop at [`MAX_VIOLATIONS`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub blocking: Vec<String>,
    pub warnings: Vec<String>,
}

pub const NOT_CHECKED: &str = "NOT CHECKED";
/// The line a failed check puts between its blocking findings and its advisories.
const ADVISORY_LABEL: &str = "loki: advisory (not blocking):";

impl Report {
    pub fn new(mut blocking: Vec<String>, mut warnings: Vec<String>) -> Self {
        blocking.truncate(MAX_VIOLATIONS);
        let mut seen = Vec::new();
        warnings.retain(|w| {
            !seen.contains(w) && {
                seen.push(w.clone());
                true
            }
        });
        Report { blocking, warnings }
    }

    pub fn blocked(&self) -> bool {
        !self.blocking.is_empty()
    }

    /// Blocked only by changes to the `.loki/` policy itself (see [`crate::git::is_policy_change`]).
    pub fn blocked_by_policy_changes(&self) -> bool {
        self.blocked()
            && self
                .blocking
                .iter()
                .all(|finding| crate::git::is_policy_change(finding))
    }

    /// Warnings that are findings, not missing coverage.
    pub fn advisory(&self) -> impl Iterator<Item = &String> {
        self.warnings.iter().filter(|w| !w.starts_with(NOT_CHECKED))
    }

    /// Checks that could not run (`NOT CHECKED ...`).
    pub fn not_checked(&self) -> impl Iterator<Item = &String> {
        self.warnings.iter().filter(|w| w.starts_with(NOT_CHECKED))
    }

    /// What a blocked check says: the blocking findings, then (labelled) the advisories, then the unchecked notes,
    /// at most [`MAX_VIOLATIONS`] lines.
    pub fn refusal_lines(&self) -> Vec<String> {
        let advisory: Vec<&String> = self.advisory().collect();
        let label = (!advisory.is_empty()).then(|| ADVISORY_LABEL.to_string());
        self.blocking
            .iter()
            .cloned()
            .chain(label)
            .chain(advisory.into_iter().cloned())
            .chain(self.not_checked().cloned())
            .take(MAX_VIOLATIONS)
            .collect()
    }

    /// The `--format json` document of `command`.
    pub fn json(&self, command: &str) -> Value {
        hook_report(command, &self.blocking, &self.warnings, None)
    }
}

/// The evidence of a check that raised: `kind` for a `ValueError` (`invalid-input`, `invalid-policy`), else
/// `guard-error`.
pub fn failure_evidence(error: &CheckError, kind: &str) {
    crate::evidence::finding(
        if matches!(error, CheckError::Value(_)) {
            kind
        } else {
            "guard-error"
        },
        None,
    );
}

/// `load_config` with loki.py's error kinds.
pub fn load(root: &Path) -> Result<Config, CheckError> {
    config::load_config(root).map_err(|e| match e {
        config::ConfigError::Invalid(m) => CheckError::Value(m),
        config::ConfigError::Guard(kind, m) => CheckError::Guard(kind, m),
    })
}

/// A write's preview: the harness `mode` (`ultron`, `claude`, ...) and its envelope.
pub type Preview<'a> = (&'a str, &'a Value);

/// `loki --root ROOT protect --file F... [--preview HOST]`: refuse protected or out-of-root targets, then preview
/// the write.
pub fn protect(root: &Path, files: &[String], preview: Option<Preview>) -> Result<Report, CheckError> {
    let root = resolve(root);
    let config = load(&root).inspect_err(|error| failure_evidence(error, "invalid-policy"))?;
    protect_with(&root, &config, files, preview)
}

/// [`protect`] of a host's write of `content` to `file` (relative to `root`): the preview checks the content the
/// file would have.
pub fn protect_write(root: &Path, file: &str, content: &str) -> Result<Report, CheckError> {
    let envelope = serde_json::json!({"tool_name": "write", "tool_input": {"content": content}});
    protect(root, &[file.to_string()], Some(("ultron", &envelope)))
}

/// [`protect`] with the policy already loaded from the resolved `root`.
pub fn protect_with(
    root: &Path,
    config: &Config,
    files: &[String],
    preview: Option<Preview>,
) -> Result<Report, CheckError> {
    let checked = || -> Result<Report, CheckError> {
        let deadline = crate::proc::Deadline::after(20.0);
        let paths = file_paths(files)?;
        crate::evidence::targets(&paths);
        let mut warnings = Vec::new();
        let messages = protect_violations(
            root,
            config,
            &paths,
            preview.map(|(_, payload)| payload),
            preview.map_or("", |(mode, _)| mode),
            deadline,
            &mut warnings,
        )?;
        Ok(Report::new(messages, warnings))
    };
    checked().inspect_err(|error| failure_evidence(error, "invalid-input"))
}

/// The `--file` arguments, validated, without repeats.
pub fn file_paths(files: &[String]) -> Result<Vec<String>, CheckError> {
    let mut paths: Vec<String> = Vec::new();
    for path in files {
        crate::valid_path(path)?;
        if !paths.contains(path) {
            paths.push(path.clone());
        }
    }
    Ok(paths)
}

fn has_typescript_target(targets: &[PathBuf]) -> bool {
    targets.iter().any(|t| {
        let name = t
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        name.rfind('.')
            .filter(|&i| i > 0)
            .is_some_and(|i| crate::typescript::TYPESCRIPT_SUFFIXES.contains(&&name[i..]))
    })
}

fn collect_written_slop(
    root: &Path,
    config: &Config,
    targets: &[PathBuf],
    deadline: crate::proc::Deadline,
    messages: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<(), CheckError> {
    let excludes = config::slop_excludes(config).map_err(CheckError::Value)?;
    let notes = match crate::slop::written_slop_with(root, targets, &excludes, deadline) {
        Ok(notes) => notes,
        Err(error) if matches!(error, CheckError::Value(_)) || error.is_os() => {
            vec![format!("NOT CHECKED slop: {}", error.message())]
        }
        Err(other) => return Err(other),
    };
    if !config::slop_block(config).map_err(CheckError::Value)? {
        warnings.extend(notes);
        return Ok(());
    }
    for note in notes {
        if note.contains("NOT CHECKED") {
            warnings.push(note);
        } else {
            messages.push(note);
        }
    }
    Ok(())
}

fn check_targets(
    root: &Path,
    config: &Config,
    targets: &[PathBuf],
    python: Option<&str>,
    deadline: crate::proc::Deadline,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>, CheckError> {
    let strict = crate::strict();
    let mut batch = crate::hook::Batch::default();
    let mut messages = Vec::new();
    for target in targets {
        messages.extend(crate::hook::check_file(
            target, root, config, strict, deadline, warnings, targets, &mut batch, python,
        )?);
    }
    Ok(messages)
}

/// `hook`'s check of written files: protected paths, then (when none is protected) the write guardrails, the
/// TypeScript checks, written slop and each file's analyzers. `python` is `--python`.
pub fn hook_violations(
    root: &Path,
    config: &Config,
    paths: &[String],
    python: Option<&str>,
    deadline: crate::proc::Deadline,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>, CheckError> {
    let mut messages = protected(root, config, paths)?;
    if !messages.is_empty() {
        return Ok(messages);
    }
    let targets: Vec<PathBuf> = paths.iter().map(|p| crate::abspath(root, p)).collect();
    messages.extend(crate::hook::write_guardrail_violations(
        &targets,
        root,
        config,
        deadline,
        Some(&mut *warnings),
    )?);
    if messages.is_empty() && has_typescript_target(&targets) {
        messages.extend(crate::typescript::typescript_findings(
            root, config, deadline, warnings,
        )?);
    }
    if messages.is_empty() {
        collect_written_slop(root, config, &targets, deadline, &mut messages, warnings)?;
        messages.extend(check_targets(root, config, &targets, python, deadline, warnings)?);
    }
    Ok(messages)
}

/// `loki --root ROOT hook --file F... [--python P]`: the post-write check of written files. `python` is the
/// project's interpreter (`LOKI_PYTHON` of the engine's environment), which import checks ask.
pub fn hook(root: &Path, files: &[String], python: Option<&str>) -> Result<Report, CheckError> {
    let root = resolve(root);
    let config = load(&root).inspect_err(|error| failure_evidence(error, "invalid-policy"))?;
    let mut warnings = Vec::new();
    file_paths(files)
        .and_then(|paths| {
            crate::evidence::targets(&paths);
            hook_violations(
                &root,
                &config,
                &paths,
                python,
                crate::proc::Deadline::after(20.0),
                &mut warnings,
            )
        })
        .map(|messages| Report::new(messages, warnings))
        .inspect_err(|error| failure_evidence(error, "invalid-input"))
}

/// The protected-path refusals for `paths`.
pub fn protected(root: &Path, config: &Config, paths: &[String]) -> Result<Vec<String>, CheckError> {
    let mut messages = Vec::new();
    for path in paths {
        messages.extend(protect_path(path, root, config)?);
    }
    Ok(messages)
}

/// `protect`'s check: protected paths, then (when none is protected) the preview of the write in `mode`.
pub fn protect_violations(
    root: &Path,
    config: &Config,
    paths: &[String],
    payload: Option<&Value>,
    mode: &str,
    deadline: crate::proc::Deadline,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>, CheckError> {
    let mut messages = protected(root, config, paths)?;
    if messages.is_empty() {
        messages.extend(crate::preview_violations(
            root, paths, payload, mode, deadline, warnings, config,
        )?);
    }
    Ok(messages)
}
