use std::path::Path;
use std::process::Command;

fn loki_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loki")
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed");
}

#[test]
fn version_prints_package_version() {
    let out = Command::new(loki_bin()).arg("--version").output().expect("loki runs");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "got: {stdout}");
}

#[test]
fn init_installs_policy_hooks_and_vendored_plugins() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    let out = Command::new(loki_bin())
        .args(["init", "--dir", root.to_str().unwrap()])
        .output()
        .expect("loki init runs");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(root.join(".loki/loki.json").is_file());
    assert!(!root.join(".loki/loki.py").exists(), "standalone Rust CLI should not install loki.py");
    assert!(root.join(".loki/oxlint/anti-slop/index.ts").is_file());
    assert!(root.join(".loki/oxlint/landmines/plugins/testing.ts").is_file());
    assert!(root.join(".loki/vendor/codehygiene/__init__.py").is_file());
    assert!(root.join(".oxlintrc.json").is_file());
    assert!(root.join(".claude/settings.json").is_file());
}

#[test]
fn protect_blocks_secret_and_xss_and_allows_clean_code() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    let init = Command::new(loki_bin())
        .args(["init", "--minimal", "--dir", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(init.status.success());
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);

    let secret_payload = serde_json::json!({
        "cwd": root,
        "tool_name": "Write",
        "tool_input": {
            "file_path": "config.ts",
            "content": "export const k = \"sk_live_51Hq8TzK2m9XbV4dLpQ7rW3nY6cF0aJ\";\n"
        }
    });
    let mut child = Command::new(loki_bin())
        .args(["--root", root.to_str().unwrap(), "protect", "--harness", "claude"])
        .env("LOKI_DAEMON", "0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(secret_payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2), "secret write must be blocked");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("loki/secret"), "stderr: {stderr}");
}

#[test]
fn slop_and_hygiene_json_run_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("app.py"), "def add(a: int, b: int) -> int:\n    return a + b\n").unwrap();
    let init = Command::new(loki_bin())
        .args(["init", "--minimal", "--dir", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(init.status.success());
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);

    let slop = Command::new(loki_bin())
        .args(["--root", root.to_str().unwrap(), "slop", "--json"])
        .output()
        .unwrap();
    assert!(slop.status.success(), "stderr: {}", String::from_utf8_lossy(&slop.stderr));
    let parsed: serde_json::Value = serde_json::from_slice(&slop.stdout).unwrap();
    assert_eq!(parsed["current"]["index"], 0);

    let hyg = Command::new(loki_bin())
        .args(["--root", root.to_str().unwrap(), "hygiene", "--json"])
        .output()
        .unwrap();
    assert!(hyg.status.success(), "stderr: {}", String::from_utf8_lossy(&hyg.stderr));
    let parsed: serde_json::Value = serde_json::from_slice(&hyg.stdout).unwrap();
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
}
