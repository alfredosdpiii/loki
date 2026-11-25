//! Evidence of one `--record` run (loki.py `ACTIVE_EVIDENCE`, `evidence_policy`, `evidence_finding`, `record_event`):
//! the policies a check read and the rules it applied, appended to `~/.local/state/loki/<sha256(root)>/events.jsonl`
//! for `loki explain`. Collection is per thread, as Python's context variable is per thread: checks a run hands to a
//! worker thread record nothing, there as here.

use serde_json::{Map, Value, json};
use std::cell::RefCell;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Evidence {
    pub policies: Vec<Value>,
    pub findings: Vec<Value>,
    pub targets: Vec<String>,
}

thread_local! {
    static ACTIVE: RefCell<Option<Evidence>> = const { RefCell::new(None) };
}

/// Collect evidence on this thread until [`take`].
pub fn start() {
    ACTIVE.with(|active| *active.borrow_mut() = Some(Evidence::default()));
}

/// The evidence collected since [`start`] (none when not recording), and stop collecting.
pub fn take() -> Option<Evidence> {
    ACTIVE.with(|active| active.borrow_mut().take())
}

pub fn active() -> bool {
    ACTIVE.with(|active| active.borrow().is_some())
}

/// Merge evidence collected on a worker thread into this thread's active recorder.
pub fn merge(other: Evidence) {
    ACTIVE.with(|active| {
        if let Some(evidence) = active.borrow_mut().as_mut() {
            for policy in other.policies {
                if !evidence.policies.contains(&policy) {
                    evidence.policies.push(policy);
                }
            }
            evidence.findings.extend(other.findings);
        }
    });
}

/// `evidence_policy`: a policy file the check read (`raw` none: absent), once.
pub fn policy(source: &str, path: &str, raw: Option<&[u8]>, base: Option<&str>) {
    ACTIVE.with(|active| {
        if let Some(evidence) = active.borrow_mut().as_mut() {
            let item =
                json!({ "source": source, "path": path, "base": base, "sha256": raw.map(crate::compat::sha256_hex) });
            if !evidence.policies.contains(&item) {
                evidence.policies.push(item);
            }
        }
    });
}

/// `evidence_finding`: a rule the check applied, and the file it applied to.
pub fn finding(rule: &str, path: Option<&str>) {
    ACTIVE.with(|active| {
        if let Some(evidence) = active.borrow_mut().as_mut() {
            evidence.findings.push(json!({ "rule": rule, "path": path }));
        }
    });
}

pub fn targets(paths: &[String]) {
    ACTIVE.with(|active| {
        if let Some(evidence) = active.borrow_mut().as_mut() {
            evidence.targets = paths.to_vec();
        }
    });
}

/// SHA-256 of the running `loki` binary (falls back to version string if unreadable).
pub fn engine_sha256() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::read(path).ok())
        .map_or_else(
            || crate::compat::sha256_hex(crate::VERSION.as_bytes()),
            crate::compat::sha256_hex,
        )
}

fn now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn build_event(operation: &str, outcome: &str, started: Instant, evidence: &Evidence) -> Value {
    let duration = (started.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
    let mut event = Map::new();
    for (key, value) in [
        ("time", json!(now_seconds())),
        ("operation", json!(operation)),
        ("outcome", json!(outcome)),
        ("targets", json!(evidence.targets)),
        ("duration_ms", json!(duration)),
        ("scope", json!("delivered event only")),
        ("engine_sha256", json!(engine_sha256())),
        (
            "resolution",
            json!("inspect diagnostic; protected changes need independent review"),
        ),
        ("schema_version", json!(2)),
        ("findings", Value::from(evidence.findings.clone())),
        ("policies", Value::from(evidence.policies.clone())),
    ] {
        event.insert(key.into(), value);
    }
    Value::Object(event)
}

fn append_event(path: &Path, event: &Value) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    file.lock()?;
    if file.metadata()?.len() > 4 * 1024 * 1024 {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        let reset = json!({ "event": "retention-reset", "time": now_seconds() });
        writeln!(file, "{}", crate::py::dumps(&reset))?;
    }
    writeln!(file, "{}", crate::py::dumps(event))
}

/// `record_event`: append one event for `root` (the file locked; over 4 MiB it restarts with a retention-reset
/// line).
pub fn record_event(
    root: &Path,
    operation: &str,
    outcome: &str,
    started: Instant,
    evidence: &Evidence,
) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let path = crate::shell::event_path(root);
    // O_NOFOLLOW: a symlink planted at the log is never written through.
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other("events log is a symlink"));
    }
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    }
    let event = build_event(operation, outcome, started, evidence);
    append_event(&path, &event)
}
