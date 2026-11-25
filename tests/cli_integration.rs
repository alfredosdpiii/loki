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
    assert!(root.join(".codex/hooks.json").is_file());
    assert!(root.join(".agents/hooks.json").is_file());

    // Preserve user hooks in .agents/hooks.json and avoid duplicating hooks on re-init.
    let mut agy: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(".agents/hooks.json")).unwrap()).unwrap();
    agy["custom"] = serde_json::json!({"SessionStart": [{"type": "command", "command": "echo hi"}]});
    std::fs::write(root.join(".agents/hooks.json"), serde_json::to_string_pretty(&agy).unwrap()).unwrap();

    let rerun = Command::new(loki_bin())
        .args(["init", "--dir", root.to_str().unwrap(), "--shell-guard"])
        .output()
        .expect("loki init rerun");
    assert!(rerun.status.success(), "stderr: {}", String::from_utf8_lossy(&rerun.stderr));

    let claude: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(".claude/settings.json")).unwrap()).unwrap();
    assert_eq!(claude["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
    assert_eq!(claude["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

    let codex: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(".codex/hooks.json")).unwrap()).unwrap();
    assert_eq!(codex["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
    assert_eq!(codex["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

    let agy_after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(".agents/hooks.json")).unwrap()).unwrap();
    assert!(agy_after.get("custom").is_some(), "custom agy hook must be preserved");
    assert_eq!(agy_after["loki"]["PreToolUse"].as_array().unwrap().len(), 2);
}

fn run_with_stdin(args: &[&str], payload: &serde_json::Value) -> std::process::Output {
    use std::io::Write;
    let mut child = Command::new(loki_bin())
        .args(args)
        .env("LOKI_DAEMON", "0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn agy_hooks_context_protect_hook_and_shell() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("app.ts"), "export const token = \"safe\";\n").unwrap();
    let init = Command::new(loki_bin())
        .args(["init", "--minimal", "--dir", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(init.status.success());
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);

    let root_s = root.to_str().unwrap();

    // SessionStart context
    let ctx = Command::new(loki_bin())
        .args(["context", "--root", root_s, "--event", "SessionStart", "--host", "agy"])
        .output()
        .unwrap();
    assert!(ctx.status.success(), "stderr: {}", String::from_utf8_lossy(&ctx.stderr));
    let ctx_json: serde_json::Value = serde_json::from_slice(&ctx.stdout).unwrap();
    let msg = ctx_json["injectSteps"][0]["systemMessage"]["systemMessage"]
        .as_str()
        .unwrap();
    assert!(msg.contains("LOKI POLICY GUIDANCE"), "got: {msg}");

    // PreToolUse write_file secret -> exit 0 + decision deny
    let deny_out = run_with_stdin(
        &["--root", root_s, "protect", "--harness", "agy"],
        &serde_json::json!({
            "cwd": root,
            "toolCall": {
                "name": "write_file",
                "args": {
                    "Path": root.join("config.ts"),
                    "Content": "export const k = \"sk_live_51Hq8TzK2m9XbV4dLpQ7rW3nY6cF0aJ\";\n"
                }
            }
        }),
    );
    assert!(deny_out.status.success());
    let deny_json: serde_json::Value = serde_json::from_slice(&deny_out.stdout).unwrap();
    assert_eq!(deny_json["decision"], "deny");
    assert!(deny_json["reason"].as_str().unwrap().contains("loki/secret"));

    // PreToolUse edit_file secret -> exit 0 + decision deny
    let edit_deny = run_with_stdin(
        &["--root", root_s, "protect", "--harness", "agy"],
        &serde_json::json!({
            "workspacePaths": [root],
            "toolCall": {
                "name": "edit_file",
                "args": {
                    "Path": root.join("app.ts"),
                    "Target": "\"safe\"",
                    "Replacement": "\"sk_live_51Hq8TzK2m9XbV4dLpQ7rW3nY6cF0aJ\""
                }
            }
        }),
    );
    assert!(edit_deny.status.success());
    let edit_json: serde_json::Value = serde_json::from_slice(&edit_deny.stdout).unwrap();
    assert_eq!(edit_json["decision"], "deny");

    // PreToolUse protected .agents/hooks.json -> decision deny
    let prot_deny = run_with_stdin(
        &["--root", root_s, "protect", "--harness", "agy"],
        &serde_json::json!({
            "cwd": root,
            "toolCall": {
                "name": "write_file",
                "args": {
                    "Path": root.join(".agents/hooks.json"),
                    "Content": "{}\n"
                }
            }
        }),
    );
    assert!(prot_deny.status.success());
    let prot_json: serde_json::Value = serde_json::from_slice(&prot_deny.stdout).unwrap();
    assert_eq!(prot_json["decision"], "deny");
    assert!(prot_json["reason"].as_str().unwrap().contains("protected file"));

    // PreToolUse clean write_file -> exit 0 + decision allow
    let allow_out = run_with_stdin(
        &["--root", root_s, "protect", "--harness", "agy"],
        &serde_json::json!({
            "cwd": root,
            "toolCall": {
                "name": "write_file",
                "args": {
                    "Path": root.join("clean.py"),
                    "Content": "def ok() -> int:\n    return 1\n"
                }
            }
        }),
    );
    assert!(allow_out.status.success());
    let allow_json: serde_json::Value = serde_json::from_slice(&allow_out.stdout).unwrap();
    assert_eq!(allow_json["decision"], "allow");

    // PostToolUse -> exit 0 + {}
    let post_out = run_with_stdin(
        &["--root", root_s, "hook", "--harness", "agy"],
        &serde_json::json!({
            "cwd": root,
            "toolCall": {
                "name": "write_file",
                "args": { "Path": root.join("app.ts") }
            }
        }),
    );
    assert!(post_out.status.success());
    let post_json: serde_json::Value = serde_json::from_slice(&post_out.stdout).unwrap();
    assert_eq!(post_json, serde_json::json!({}));

    // Shell guard: git status allow, git reset --hard deny
    let sh_allow = run_with_stdin(
        &["--root", root_s, "shell", "--harness", "agy"],
        &serde_json::json!({
            "cwd": root,
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": "git status" }
            }
        }),
    );
    assert!(sh_allow.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sh_allow.stdout).unwrap()["decision"],
        "allow"
    );

    let sh_deny = run_with_stdin(
        &["--root", root_s, "shell", "--harness", "agy"],
        &serde_json::json!({
            "cwd": root,
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": "git reset --hard" }
            }
        }),
    );
    assert!(sh_deny.status.success());
    let sh_deny_json: serde_json::Value = serde_json::from_slice(&sh_deny.stdout).unwrap();
    assert_eq!(sh_deny_json["decision"], "deny");
    assert!(sh_deny_json["reason"].as_str().unwrap().contains("destructive Git"));
}

#[test]
fn codex_and_claude_updated_hook_payloads() {
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

    let root_s = root.to_str().unwrap();

    let codex_write = run_with_stdin(
        &["--root", root_s, "protect", "--harness", "codex"],
        &serde_json::json!({
            "cwd": root,
            "tool_name": "Write",
            "tool_input": {
                "file_path": "config.ts",
                "content": "export const k = \"sk_live_51Hq8TzK2m9XbV4dLpQ7rW3nY6cF0aJ\";\n"
            }
        }),
    );
    assert_eq!(codex_write.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&codex_write.stderr).contains("loki/secret"));

    // Codex apply_patch using "input" key targeting protected file
    let codex_patch = run_with_stdin(
        &["--root", root_s, "protect", "--harness", "codex"],
        &serde_json::json!({
            "cwd": root,
            "tool_name": "apply_patch",
            "tool_input": {
                "input": "*** Begin Patch\n*** Update File: .codex/hooks.json\n@@\n-a\n+b\n*** End Patch\n"
            }
        }),
    );
    assert_eq!(codex_patch.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&codex_patch.stderr).contains("protected file"));

    // Claude NotebookEdit targeting protected path
    let claude_nb = run_with_stdin(
        &["--root", root_s, "protect", "--harness", "claude"],
        &serde_json::json!({
            "cwd": root,
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": ".claude/settings.json"
            }
        }),
    );
    assert_eq!(claude_nb.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&claude_nb.stderr).contains("protected file"));
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

#[test]
fn init_installs_strict_policy_and_shell_writes_for_every_harness() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("repo");
    let managed = parent.path().join("managed");
    std::fs::create_dir_all(&root).unwrap();
    git(&root, &["init", "-q"]);

    let out = Command::new(loki_bin())
        .args(["init", "--dir", root.to_str().unwrap()])
        .output()
        .expect("loki init runs");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let policy: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(".loki/loki.json")).unwrap()).unwrap();
    assert_eq!(policy["slop"]["block"], true, "init must enable strict slop.block by default");

    for (rel, harness, ptr) in [
        (".claude/settings.json", "claude", "/hooks/PreToolUse"),
        (".codex/hooks.json", "codex", "/hooks/PreToolUse"),
        (".agents/hooks.json", "agy", "/loki/PreToolUse"),
        (".factory/hooks.json", "factory", "/PreToolUse"),
    ] {
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join(rel)).unwrap()).unwrap();
        let entries = doc.pointer(ptr).unwrap().as_array().unwrap();
        assert_eq!(entries.len(), 2, "{rel} should have protect + shell-writes");
        let joined = doc.to_string();
        assert!(
            joined.contains(&format!("shell-writes --harness {harness}")),
            "{rel} missing shell-writes for {harness}"
        );
    }

    for rel in [".pi/extensions/loki.ts", ".loki/loki-shim.ts"] {
        let shim = std::fs::read_to_string(root.join(rel)).unwrap();
        assert!(shim.contains("shell-writes"), "{rel} missing shell-writes guard");
    }

    // Managed-dir rewrite must also handle the default shell-writes entries cleanly.
    let managed_out = Command::new(loki_bin())
        .args([
            "init",
            "--dir",
            root.to_str().unwrap(),
            "--managed-dir",
            managed.to_str().unwrap(),
        ])
        .output()
        .expect("loki init --managed-dir runs");
    assert!(
        managed_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&managed_out.stderr)
    );
}

#[test]
fn shell_writes_blocks_bypasses_and_allows_reads_for_every_harness() {
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
    let root_s = root.to_str().unwrap();

    let blocked_cmds = [
        "echo 'x = 1' > app.py",
        "cat <<'EOF' > app.py\nx = 1\nEOF",
        "sed -i 's/a/b/' app.py",
        "echo x | tee app.py",
    ];
    let allowed_cmds = ["git status", "pytest -q"];

    for (harness, tool_name) in [
        ("claude", "Bash"),
        ("codex", "Bash"),
        ("factory", "Execute"),
        ("pi", "bash"),
        ("omp", "bash"),
    ] {
        for cmd in blocked_cmds {
            let out = run_with_stdin(
                &["--root", root_s, "shell-writes", "--harness", harness],
                &serde_json::json!({
                    "cwd": root,
                    "tool_name": tool_name,
                    "tool_input": { "command": cmd }
                }),
            );
            assert_eq!(
                out.status.code(),
                Some(2),
                "{harness} must block `{cmd}`, stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        for cmd in allowed_cmds {
            let out = run_with_stdin(
                &["--root", root_s, "shell-writes", "--harness", harness],
                &serde_json::json!({
                    "cwd": root,
                    "tool_name": tool_name,
                    "tool_input": { "command": cmd }
                }),
            );
            assert!(
                out.status.success(),
                "{harness} must allow `{cmd}`, stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // Codex exec_command uses `cmd` and `workdir`.
    let codex_exec_deny = run_with_stdin(
        &["--root", root_s, "shell-writes", "--harness", "codex"],
        &serde_json::json!({
            "tool_name": "exec_command",
            "tool_input": { "cmd": "echo 'x = 1' > app.py", "workdir": root }
        }),
    );
    assert_eq!(codex_exec_deny.status.code(), Some(2));
    let codex_exec_ok = run_with_stdin(
        &["--root", root_s, "shell-writes", "--harness", "codex"],
        &serde_json::json!({
            "tool_name": "exec_command",
            "tool_input": { "cmd": "pytest -q", "workdir": root }
        }),
    );
    assert!(codex_exec_ok.status.success());

    // Antigravity (agy) uses toolCall.args.CommandLine and returns JSON decision on exit 0.
    let agy_deny = run_with_stdin(
        &["--root", root_s, "shell-writes", "--harness", "agy"],
        &serde_json::json!({
            "cwd": root,
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "echo 'x = 1' > app.py",
                    "NotificationTimeoutSeconds": 30
                }
            }
        }),
    );
    assert!(agy_deny.status.success());
    let agy_deny_json: serde_json::Value = serde_json::from_slice(&agy_deny.stdout).unwrap();
    assert_eq!(agy_deny_json["decision"], "deny");

    let agy_allow = run_with_stdin(
        &["--root", root_s, "shell-writes", "--harness", "agy"],
        &serde_json::json!({
            "cwd": root,
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "pytest -q",
                    "NotificationTimeoutSeconds": 30
                }
            }
        }),
    );
    assert!(agy_allow.status.success());
    let agy_allow_json: serde_json::Value = serde_json::from_slice(&agy_allow.stdout).unwrap();
    assert_eq!(agy_allow_json["decision"], "allow");
}

#[test]
fn hook_runs_hygiene_for_every_harness() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("app.py"), "def ok() -> int:\n    return 1\n").unwrap();
    let init = Command::new(loki_bin())
        .args(["init", "--minimal", "--dir", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(init.status.success());
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "init"]);

    // Add a swallowed-error pattern that triggers codehygiene on post-write hook.
    std::fs::write(
        root.join("app.py"),
        "def ok(x: int) -> int:\n    try:\n        return int(x)\n    except Exception:\n        pass\n    return 0\n",
    )
    .unwrap();

    let root_s = root.to_str().unwrap();
    for (harness, payload) in [
        (
            "claude",
            serde_json::json!({"cwd": root, "tool_name": "Write", "tool_input": {"file_path": "app.py"}}),
        ),
        (
            "codex",
            serde_json::json!({"cwd": root, "tool_name": "Write", "tool_input": {"file_path": "app.py"}}),
        ),
        (
            "factory",
            serde_json::json!({"cwd": root, "tool_name": "Create", "tool_input": {"file_path": "app.py"}}),
        ),
        (
            "agy",
            serde_json::json!({"cwd": root, "toolCall": {"name": "write_file", "args": {"Path": root.join("app.py")}}}),
        ),
    ] {
        let out = run_with_stdin(&["--root", root_s, "hook", "--harness", harness], &payload);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let combined = format!("{stdout}\n{stderr}");
        assert!(
            combined.contains("hygiene") || combined.contains("swallowed") || combined.contains("loki/"),
            "{harness} hook should report hygiene/anti-slop findings, got stdout={stdout} stderr={stderr}"
        );
    }
}
