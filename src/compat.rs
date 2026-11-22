//! Small standalone helpers that replace Ultron workspace crates (`jsrt`, `kernel`).

use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt::Write as _;

pub const WORKTREE_ENV: &str = "ULTRON_WORKTREE";
pub const WORKTREES_DIR: &str = "worktrees";

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex(&sha256(bytes.as_ref()))
}

pub fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

pub fn python_interpreter() -> String {
    for key in ["LOKI_PYTHON", "ULTRON_LOKI_PYTHON", "ULTRON_PYTHON"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    for candidate in ["python3", "python"] {
        if let Some(found) = crate::proc::which(candidate) {
            return found;
        }
    }
    "python3".to_string()
}

pub fn which_in(command: &str, path: &str) -> Option<std::path::PathBuf> {
    if command.contains('/') {
        let candidate = std::path::PathBuf::from(command);
        return candidate.is_file().then_some(candidate);
    }
    for dir in std::env::split_paths(path) {
        let candidate = dir.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
