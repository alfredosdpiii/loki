//! `verify-installation` (loki.py `installation_violations`): an engine and its hook registrations an agent cannot
//! rewrite. Every path must be a regular, non-symlinked file, and neither it nor any ancestor directory may be
//! owned by the agent's uid, group- or world-writable, or a symlink. Ownership and modes only: ACLs, privileged
//! access and host activation need an operator.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The findings for `paths` against `agent_uid` (none: the ownership and mode checks pass).
pub fn installation_violations(paths: &[PathBuf], agent_uid: i64) -> Vec<String> {
    if agent_uid == 0 {
        return vec!["root agents cannot be confined by ownership checks".into()];
    }
    let mut findings = Vec::new();
    for path in paths {
        let symlink = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
        if symlink || !path.is_file() {
            findings.push(format!("{}: regular non-symlink file required", path.display()));
            continue;
        }
        let absolute = absolute(path);
        for candidate in absolute.ancestors() {
            let Ok(metadata) = std::fs::symlink_metadata(candidate) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                findings.push(format!("{}: symlinked installation ancestor", candidate.display()));
                break;
            }
            if i64::from(metadata.uid()) == agent_uid || metadata.mode() & 0o022 != 0 {
                findings.push(format!("{}: agent-owned or group/world writable", candidate.display()));
                break;
            }
        }
    }
    findings
}

/// `Path.absolute()`: joined to the working directory, not resolved.
fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    }
}
