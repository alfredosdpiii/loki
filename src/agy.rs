//! Antigravity (`agy`) post-write diagnostic spool: `PostToolUse` only accepts `{}` on stdout, so Loki
//! spools blocking findings and advisories keyed by `conversationId` and drains them into `injectSteps`
//! on `PreInvocation` (and forces one continuation on `PostInvocation` if blocking findings remain
//! unresolved).

use serde_json::{Value, json};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

fn spool_dir(root: &Path) -> PathBuf {
    let identity = crate::compat::sha256_hex(crate::resolve(root).as_os_str().as_encoded_bytes());
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join(".local/state/loki").join(identity).join("agy")
}

fn sanitize_id(conversation_id: Option<&str>) -> String {
    let raw = conversation_id.map(str::trim).filter(|s| !s.is_empty());
    match raw {
        None => "default".into(),
        Some(id)
            if id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
        {
            id.to_string()
        }
        Some(id) => crate::compat::sha256_hex(id.as_bytes())[..32].to_string(),
    }
}

fn spool_paths(root: &Path, conversation_id: Option<&str>) -> (PathBuf, PathBuf) {
    let dir = spool_dir(root);
    let id = sanitize_id(conversation_id);
    (dir.join(format!("{id}.json")), dir.join(format!("{id}.unresolved.json")))
}

fn read_lines(path: &Path) -> (Vec<String>, Vec<String>) {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return (Vec::new(), Vec::new());
    };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else {
        return (Vec::new(), Vec::new());
    };
    let get = |key: &str| {
        val.get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>()
    };
    (get("blocking"), get("warnings"))
}

fn write_atomic(path: &Path, blocking: &[String], warnings: &[String]) {
    let Some(parent) = path.parent() else { return };
    let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent);
    let tmp = parent.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        path.file_name().and_then(|n| n.to_str()).unwrap_or("spool")
    ));
    let payload = json!({ "blocking": blocking, "warnings": warnings }).to_string();
    if std::fs::write(&tmp, payload).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn extend_unique(dst: &mut Vec<String>, src: &[String]) {
    for item in src {
        if !dst.contains(item) {
            dst.push(item.clone());
        }
    }
}

/// Extract `conversationId` from an `agy` hook JSON payload.
pub fn conversation_id(payload: Option<&Value>) -> Option<String> {
    payload
        .and_then(|v| v.get("conversationId"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Called by `loki hook --harness agy` (`PostToolUse`): record blocking/warning diagnostics for the
/// upcoming `PreInvocation`, or clear the unresolved stop-gate when a write passes cleanly.
pub fn record_post_tool(root: &Path, conversation_id: Option<&str>, blocking: &[String], warnings: &[String]) {
    let (pending_path, unresolved_path) = spool_paths(root, conversation_id);
    if blocking.is_empty() {
        let _ = std::fs::remove_file(&unresolved_path);
        if warnings.is_empty() {
            return;
        }
    }
    let (mut cur_blocking, mut cur_warnings) = read_lines(&pending_path);
    extend_unique(&mut cur_blocking, blocking);
    extend_unique(&mut cur_warnings, warnings);
    write_atomic(&pending_path, &cur_blocking, &cur_warnings);
}

fn format_diagnostics(blocking: &[String], warnings: &[String], header: &str) -> String {
    let mut lines = Vec::new();
    if !blocking.is_empty() {
        lines.push(header.to_string());
        lines.extend(blocking.iter().cloned());
        if !warnings.is_empty() {
            lines.push("loki: advisory (not blocking):".to_string());
            lines.extend(warnings.iter().cloned());
        }
    } else {
        lines.push("loki: post-write advisories:".to_string());
        lines.extend(warnings.iter().cloned());
    }
    lines.join("\n")
}

/// Called by `loki context --event PreInvocation --host agy`: atomically drain any spooled
/// diagnostics for `conversation_id`. Blocking findings are remembered as unresolved until a clean
/// `PostToolUse` or a single `PostInvocation` continuation clears them.
pub fn drain_pre_invocation(root: &Path, conversation_id: Option<&str>) -> Option<String> {
    let (pending_path, unresolved_path) = spool_paths(root, conversation_id);
    let (blocking, warnings) = read_lines(&pending_path);
    let _ = std::fs::remove_file(&pending_path);
    if blocking.is_empty() && warnings.is_empty() {
        return None;
    }
    if !blocking.is_empty() {
        write_atomic(&unresolved_path, &blocking, &[]);
    }
    Some(format_diagnostics(
        &blocking,
        &warnings,
        "loki: post-write check failed; fix these issues before continuing:",
    ))
}

/// Called by `loki context --event PostInvocation --host agy`: if blocking post-write findings were
/// never resolved by a subsequent clean write, drain them once so the host forces continuation.
pub fn drain_post_invocation(root: &Path, conversation_id: Option<&str>) -> Option<String> {
    let (pending_path, unresolved_path) = spool_paths(root, conversation_id);
    let (mut blocking, warnings) = read_lines(&pending_path);
    let _ = std::fs::remove_file(&pending_path);
    let (unresolved, _) = read_lines(&unresolved_path);
    let _ = std::fs::remove_file(&unresolved_path);
    extend_unique(&mut blocking, &unresolved);
    if blocking.is_empty() {
        return None;
    }
    Some(format_diagnostics(
        &blocking,
        &warnings,
        "loki: unresolved post-write gate failure; fix these issues before finishing:",
    ))
}
