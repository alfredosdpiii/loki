//! `loki init` without `--minimal` (loki.py `install_target`, `install_shell_guard`, `install_managed`): the engine
//! and policy in `.loki/`, the agent hooks (Claude Code, Codex, Factory, Pi, OMP), the Oxlint plugin and
//! configuration, Ruff/golangci-lint/Credo configuration and the CI workflow, all under the target repository.
//!
//! The templates, shims and the vendored anti-slop Oxlint plugin are those of the pinned engine's upstream commit
//! (alfredosdpiii/loki d7a6fa0, `init-assets/`), compiled in: the Rust engine has no template directory on disk, so
//! the "reconcile with" notices name the template by its path in the engine source (`templates/<name>`).

use crate::py;
use crate::scan::TEMPLATE;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

macro_rules! asset {
    ($path:literal) => {
        ($path, include_bytes!(concat!("../", $path)).as_slice())
    };
}

const CLAUDE_SETTINGS: &[u8] = include_bytes!("../templates/claude-settings.fragment.json");
const CODEX_HOOKS: &[u8] = include_bytes!("../templates/codex-hooks.json");
const FACTORY_HOOKS: &[u8] = include_bytes!("../templates/factory-hooks.json");
const OXLINTRC: &[u8] = include_bytes!("../templates/.oxlintrc.json");
const CREDO: &[u8] = include_bytes!("../templates/.credo.exs");
const SHIM: &[u8] = include_bytes!("../shim/loki.ts");
const OMP_SHIM: &str = include_str!("../shim/loki-omp.ts");

/// Owned configuration files written only when absent: destination, template name, template.
const OWNED_TEMPLATES: [(&str, &str, &[u8]); 3] = [
    (
        ".ruff.toml",
        ".ruff.toml",
        include_bytes!("../templates/.ruff.toml"),
    ),
    (
        ".golangci.yml",
        ".golangci.yml",
        include_bytes!("../templates/.golangci.yml"),
    ),
    (
        ".github/workflows/loki.yml",
        "loki.yml",
        include_bytes!("../templates/loki.yml"),
    ),
];

/// `vendor/anti-slop`, installed as `.loki/oxlint/anti-slop`.
const ANTI_SLOP: [(&str, &[u8]); 20] = [
    asset!("vendor/anti-slop/LICENSE"),
    asset!("vendor/anti-slop/index.ts"),
    asset!("vendor/anti-slop/rules/no-chained-type-assertions.ts"),
    asset!("vendor/anti-slop/rules/no-conditional-empty-object-spread.ts"),
    asset!("vendor/anti-slop/rules/no-known-value-widening.ts"),
    asset!("vendor/anti-slop/rules/no-module-mocking.ts"),
    asset!("vendor/anti-slop/rules/no-object-parameters.ts"),
    asset!("vendor/anti-slop/rules/no-reflect-apply.ts"),
    asset!("vendor/anti-slop/rules/no-reflect-get.ts"),
    asset!("vendor/anti-slop/rules/no-runtime-typeof.ts"),
    asset!("vendor/anti-slop/rules/no-shape-in-symbol-names.ts"),
    asset!("vendor/anti-slop/rules/no-unknown-parameters.ts"),
    asset!("vendor/anti-slop/rules/no-unknown-returns.ts"),
    asset!("vendor/anti-slop/rules/no-unknown-type-aliases.ts"),
    asset!("vendor/anti-slop/rules/no-unsafe-dictionary-type.ts"),
    asset!("vendor/anti-slop/rules/no-widen-then-assert.ts"),
    asset!("vendor/anti-slop/rules/require-safety-comment-for-type-assertion.ts"),
    asset!("vendor/anti-slop/shared/dictionary-types.ts"),
    asset!("vendor/anti-slop/shared/lexical-type-parameters.ts"),
    asset!("vendor/anti-slop/shared/reflect-method.ts"),
];

/// `vendor/landmines`, installed as `.loki/oxlint/landmines`.
const LANDMINES: [(&str, &[u8]); 18] = [
    asset!("vendor/landmines/LICENSE"),
    asset!("vendor/landmines/UPSTREAM.md"),
    asset!("vendor/landmines/lib/allowlist.ts"),
    asset!("vendor/landmines/lib/test-owner.ts"),
    asset!("vendor/landmines/plugins/structure.ts"),
    asset!("vendor/landmines/plugins/style.ts"),
    asset!("vendor/landmines/plugins/testing.ts"),
    asset!("vendor/landmines/plugins/types.ts"),
    asset!("vendor/landmines/rules/colocated-tests.ts"),
    asset!("vendor/landmines/rules/no-comments.ts"),
    asset!("vendor/landmines/rules/no-explicit-return-types.ts"),
    asset!("vendor/landmines/rules/no-fixed-sleep.ts"),
    asset!("vendor/landmines/rules/no-flake-masking.ts"),
    asset!("vendor/landmines/rules/no-test-doubles.ts"),
    asset!("vendor/landmines/rules/no-unsignaled-poll.ts"),
    asset!("vendor/landmines/rules/package-exports.ts"),
    asset!("vendor/landmines/rules/strict-msw.ts"),
    asset!("vendor/landmines/rules/test-file-names.ts"),
];

/// `vendor/codehygiene`, installed as `.loki/vendor/codehygiene`.
const CODEHYGIENE: [(&str, &[u8]); 3] = [
    asset!("vendor/codehygiene/UPSTREAM.md"),
    asset!("vendor/codehygiene/__init__.py"),
    asset!("vendor/codehygiene/weights.npz"),
];

/// An error loki.py's `init` catches (`OSError`, `ValueError`): printed as `loki: {error}`, exit 1.
pub type InitError = String;

fn os(error: std::io::Error, path: &Path) -> InitError {
    py::os_error(&error, path.to_str())
}

fn mkdir(path: &Path) -> Result<(), InitError> {
    std::fs::create_dir_all(path).map_err(|e| os(e, path))
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), InitError> {
    std::fs::write(path, bytes).map_err(|e| os(e, path))
}

/// `Path.write_text` after `parent.mkdir(parents=True, exist_ok=True)`.
fn write_in(path: &Path, bytes: &[u8]) -> Result<(), InitError> {
    if let Some(parent) = path.parent() {
        mkdir(parent)?;
    }
    write(path, bytes)
}

fn read_text(path: &Path) -> Result<String, InitError> {
    crate::proc::read_text(path)
}

/// `read_json_object`: `{}` when `path` is not a file.
fn read_json_object(path: &Path) -> Result<Map<String, Value>, InitError> {
    if !path.is_file() {
        return Ok(Map::new());
    }
    let text = read_text(path)?;
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(format!("{}: expected a JSON object", path.display())),
        Err(error) => Err(format!(
            "{}: invalid JSON: {}",
            path.display(),
            crate::pyjson::error_text(&text, &error)
        )),
    }
}

fn template(bytes: &[u8]) -> Map<String, Value> {
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(map)) => map,
        _ => unreachable!("installer templates are JSON objects"),
    }
}

/// `write_json`: `json.dumps(value, indent=2) + "\n"`.
fn write_json(path: &Path, value: Map<String, Value>) -> Result<(), InitError> {
    write_in(
        path,
        format!("{}\n", py::dumps_indent(&Value::Object(value))).as_bytes(),
    )
}

/// `merge_hook_config`: the fragment's `hooks` merged into the document's `hooks`.
pub fn merge_hook_config(
    mut existing: Map<String, Value>,
    fragment: &Map<String, Value>,
) -> Result<Map<String, Value>, InitError> {
    let hooks = existing.entry("hooks").or_insert_with(|| json!({}));
    let Value::Object(hooks) = hooks else {
        return Err("hooks must be a JSON object".into());
    };
    let Some(Value::Object(fragment_hooks)) = fragment.get("hooks") else {
        return Err("template hooks must be a JSON object".into());
    };
    merge_factory_hooks(hooks, fragment_hooks)?;
    Ok(existing)
}

fn owned_handler(handler: &Value) -> bool {
    handler
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.contains(".loki/loki.py"))
}

/// `merge_factory_hooks`: per event, previous Loki handlers are dropped (an entry left without handlers goes) and
/// the template's entries appended.
pub fn merge_factory_hooks(existing: &mut Map<String, Value>, fragment: &Map<String, Value>) -> Result<(), InitError> {
    for (event, entries) in fragment {
        let current = existing.entry(event.clone()).or_insert_with(|| json!([]));
        let (Value::Array(current), Value::Array(entries)) = (current, entries) else {
            return Err(format!("{event} must be a JSON array"));
        };
        let mut retained = Vec::new();
        for entry in current.iter() {
            match entry.get("hooks") {
                Some(Value::Array(handlers)) if entry.is_object() => {
                    let kept: Vec<Value> = handlers.iter().filter(|h| !owned_handler(h)).cloned().collect();
                    if !kept.is_empty() {
                        let mut entry = entry.clone();
                        entry["hooks"] = Value::Array(kept);
                        retained.push(entry);
                    }
                }
                _ => retained.push(entry.clone()),
            }
        }
        retained.extend(entries.iter().cloned());
        *current = retained;
    }
    Ok(())
}

/// `merge_oxlint`: list fields gain the template's missing items, object fields its keys.
pub fn merge_oxlint(
    mut existing: Map<String, Value>,
    template: &Map<String, Value>,
) -> Result<Map<String, Value>, InitError> {
    for field in ["ignorePatterns", "plugins", "jsPlugins"] {
        let Some(Value::Array(incoming)) = template.get(field) else {
            continue;
        };
        let Value::Array(current) = existing.entry(field).or_insert_with(|| json!([])) else {
            return Err(format!("{field} must be a JSON array"));
        };
        for item in incoming {
            if !current.contains(item) {
                current.push(item.clone());
            }
        }
    }
    for field in ["categories", "rules"] {
        let Some(Value::Object(incoming)) = template.get(field) else {
            continue;
        };
        let Value::Object(current) = existing.entry(field).or_insert_with(|| json!({})) else {
            return Err(format!("{field} must be a JSON object"));
        };
        for (key, value) in incoming {
            current.insert(key.clone(), value.clone());
        }
    }
    Ok(existing)
}

/// `copy_owned` of a file: kept when present unless `force`.
fn copy_owned(bytes: &[u8], target: &Path, force: bool) -> Result<(), InitError> {
    if target.exists() && !force {
        return Ok(());
    }
    write_in(target, bytes)
}

/// `copy_owned` of a directory: replaced as a whole with `force`.
fn copy_owned_tree(files: &[(&str, &[u8])], prefix: &str, target: &Path, force: bool) -> Result<(), InitError> {
    if target.exists() {
        if !force {
            return Ok(());
        }
        std::fs::remove_dir_all(target).map_err(|e| os(e, target))?;
    }
    for (path, bytes) in files {
        let relative = path.strip_prefix(prefix).unwrap_or(path);
        write_in(&target.join(relative), bytes)?;
    }
    Ok(())
}

static FEATURES_HEADER: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"(?m)^\s*\[features\][ \t]*(?:#[^\n]*)?(?:\n|$)").expect("static pattern"));

/// `enable_codex_hooks`: `features.hooks = true` in `.codex/config.toml`, only where the edit keeps the existing
/// layout and parses to exactly the intended document.
pub fn enable_codex_hooks(target: &Path) -> Result<(), InitError> {
    let path = target.join(".codex/config.toml");
    let text = if path.exists() {
        read_text(&path)?
    } else {
        String::new()
    };
    let document: toml::Table = toml::from_str(&text).map_err(|e| e.message().to_string())?;
    let features = match document.get("features") {
        None => toml::Table::new(),
        Some(toml::Value::Table(table)) => table.clone(),
        Some(_) => return Err("Codex features must be a TOML table".into()),
    };
    if features.get("hooks") == Some(&toml::Value::Boolean(true)) {
        return Ok(());
    }
    if features.contains_key("hooks") {
        println!(
            "SKIP Codex hooks activation: existing features.hooks is not true; enable it explicitly in .codex/config.toml."
        );
        return Ok(());
    }
    let mut expected = document.clone();
    let mut wanted = features;
    wanted.insert("hooks".into(), toml::Value::Boolean(true));
    expected.insert("features".into(), toml::Value::Table(wanted));
    let candidates: Vec<String> = if !document.contains_key("features") {
        vec![format!("{text}\n[features]\nhooks = true\n")]
    } else {
        FEATURES_HEADER
            .find_iter(&text)
            .map(|found| format!("{}\nhooks = true\n{}", &text[..found.end()], &text[found.end()..]))
            .collect()
    };
    let valid: Vec<&String> = candidates
        .iter()
        .filter(|candidate| toml::from_str::<toml::Table>(candidate).is_ok_and(|parsed| parsed == expected))
        .collect();
    if valid.len() != 1 {
        println!(
            "SKIP Codex hooks activation: preserve existing TOML layout; set features.hooks = true manually in .codex/config.toml."
        );
        return Ok(());
    }
    write_in(&path, valid[0].as_bytes())
}

/// `target.expanduser().resolve()`.
pub fn expand_target(target: &str) -> PathBuf {
    let expanded = match (target.strip_prefix('~'), std::env::var("HOME")) {
        (Some(rest), Ok(home)) if rest.is_empty() || rest.starts_with('/') => format!("{home}{rest}"),
        _ => target.to_string(),
    };
    crate::resolve(Path::new(&expanded))
}

/// `install_target`: everything `init` installs without `--minimal`.
pub fn install_target(target: &str, force: bool) -> Result<(), InitError> {
    let target = expand_target(target);
    mkdir(&target)?;
    copy_owned_tree(
        &ANTI_SLOP,
        "vendor/anti-slop/",
        &target.join(".loki/oxlint/anti-slop"),
        force,
    )?;
    copy_owned_tree(
        &LANDMINES,
        "vendor/landmines/",
        &target.join(".loki/oxlint/landmines"),
        force,
    )?;
    copy_owned_tree(
        &CODEHYGIENE,
        "vendor/codehygiene/",
        &target.join(".loki/vendor/codehygiene"),
        force,
    )?;
    let config_path = target.join(".loki/loki.json");
    if !config_path.exists() {
        write(&config_path, TEMPLATE)?;
    }
    for (destination, fragment) in [
        (".claude/settings.json", CLAUDE_SETTINGS),
        (".codex/hooks.json", CODEX_HOOKS),
    ] {
        let destination = target.join(destination);
        let existing = read_json_object(&destination)?;
        write_json(&destination, merge_hook_config(existing, &template(fragment))?)?;
    }
    enable_codex_hooks(&target)?;
    let factory = target.join(".factory/hooks.json");
    let mut hooks = read_json_object(&factory)?;
    merge_factory_hooks(&mut hooks, &template(FACTORY_HOOKS))?;
    write_json(&factory, hooks)?;

    copy_owned(SHIM, &target.join(".pi/extensions/loki.ts"), true)?;
    copy_owned(SHIM, &target.join(".loki/loki-shim.ts"), true)?;
    let marker = "from \"./loki.ts\"";
    if OMP_SHIM.matches(marker).count() != 1 {
        return Err("OMP shared import marker must occur exactly once".into());
    }
    write_in(
        &target.join(".omp/extensions/loki.ts"),
        OMP_SHIM.replace(marker, "from \"../../.loki/loki-shim.ts\"").as_bytes(),
    )?;

    let oxlint_json = target.join(".oxlintrc.json");
    if oxlint_json.is_file() || !target.join("oxlint.config.ts").is_file() {
        let existing = read_json_object(&oxlint_json)?;
        write_json(&oxlint_json, merge_oxlint(existing, &template(OXLINTRC))?)?;
    } else {
        println!(
            "SKIP oxlint.config.ts (merge these template fields manually: ignorePatterns, jsPlugins, plugins, categories, rules)"
        );
        println!("  template: templates/.oxlintrc.json");
    }

    for (relative, name, bytes) in OWNED_TEMPLATES {
        let destination = target.join(relative);
        if destination.exists() {
            println!("SKIP {relative} (exists; reconcile with templates/{name})");
            continue;
        }
        write_in(&destination, bytes)?;
    }

    if target.join("mix.exs").is_file() {
        let credo = target.join(".credo.exs");
        if credo.exists() {
            println!("SKIP .credo.exs (exists; reconcile with templates/.credo.exs)");
        } else {
            write(&credo, CREDO)?;
        }
    }

    if target.join("package.json").is_file() {
        let has = |name: &str| target.join(name).exists();
        let command = if has("bun.lock") || has("bun.lockb") {
            "bun add -d oxlint @oxlint/plugins"
        } else if has("pnpm-lock.yaml") {
            "pnpm add -D oxlint @oxlint/plugins"
        } else if has("yarn.lock") {
            "yarn add -D oxlint @oxlint/plugins"
        } else {
            "npm i -D oxlint @oxlint/plugins"
        };
        println!("Install JavaScript guardrail dependencies: {command}");
    }

    println!("Installed loki project guardrails.");
    println!("Codex: run /hooks and approve the project hooks.");
    println!("Factory: project hooks are installed in .factory/hooks.json.");
    println!("Pi: accept the project trust prompt.");
    println!("Claude Code and OMP: no trust action required.");
    println!(
        "Policy bootstrap or upgrade changes require independent review; scan reports them until accepted into the base."
    );
    println!("Verify: loki scan");
    Ok(())
}

const SHELL_MARKER: &str = "  for (const phase of [\"tool_call\", \"tool_result\"]) {";
const SHELL_REGISTRATION: &str = r#"  api.on("tool_call", async (event, ctx) => {
    if (!event || typeof event !== "object" || !("toolName" in event)) return;
    if (event.toolName !== "bash") return;
    try {
      const input = "input" in event ? event.input : undefined;
      const result = spawnSync(lokiBin(),
        [...checkerArgs(root), "shell", "--harness", "omp"],
        {cwd:root, encoding:"utf8", timeout:30000,
         input:JSON.stringify({cwd:ctx?.cwd, tool_name:"Bash", tool_input:input})});
      if (result.error || result.signal || result.status !== 0) {
        return {block:true,
          reason:result.stderr?.trim() || "loki: shell checker unavailable"};
      }
    } catch { return {block:true, reason:"loki: invalid shell event"}; }
  });
"#;

fn is_shell_guard_entry(entry: &Value) -> bool {
    matches!(entry.get("matcher").and_then(Value::as_str), Some("Bash" | "Execute"))
        && entry.get("hooks").and_then(Value::as_array).is_some_and(|handlers| {
            handlers.iter().any(|handler| {
                handler
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .contains(" shell --harness ")
            })
        })
}

/// `missing_engine_guard`: shell prefix for an owned hook that passes with a note on a branch without Loki, that is a
/// checkout whose HEAD has no `.loki/loki.json` while another ref does.
pub fn missing_engine_guard(root: &str) -> String {
    format!(
        "R={root}; [ -f \"$R/.loki/loki.json\" ] || git -C \"$R\" cat-file -e HEAD:.loki/loki.json 2>/dev/null || \
         [ -z \"$(git -C \"$R\" rev-list -1 --all -- .loki/loki.json 2>/dev/null)\" ] || \
         {{ printf '%s\\n' 'loki: .loki/loki.json is not on this branch; Loki did not check this' >&2; exit 0; }}; "
    )
}

/// `install_shell_guard`: a `shell` pre-tool hook for Claude Code (Bash) and Factory (Execute), replacing an earlier
/// one, and the shell registration in the Pi/OMP shims.
pub fn install_shell_guard(root: &Path) -> Result<(), InitError> {
    use crate::shell::shlex_quote as quote;
    for (relative, harness) in [(".claude/settings.json", "claude"), (".factory/hooks.json", "factory")] {
        let path = root.join(relative);
        let mut document = read_json_object(&path)?;
        let command = format!(
            "{}loki --root {} shell --harness {harness} || {{ printf '%s\\n' 'loki: shell guard failed' >&2; exit 2; }}",
            missing_engine_guard(&quote(&root.to_string_lossy())),
            quote(&root.to_string_lossy()),
        );
        let groups = if harness == "claude" {
            match document.get_mut("hooks") {
                Some(Value::Object(groups)) => groups,
                _ => return Err("hooks must be a JSON object".into()),
            }
        } else {
            &mut document
        };
        let Value::Array(entries) = groups.entry("PreToolUse").or_insert_with(|| json!([])) else {
            return Err("PreToolUse must be a JSON array".into());
        };
        entries.retain(|entry| !is_shell_guard_entry(entry));
        entries.push(json!({
            "matcher": if harness == "factory" { "Execute" } else { "Bash" },
            "hooks": [{"type": "command", "command": command, "timeout": 30}],
        }));
        write_json(&path, document)?;
    }
    for relative in [".pi/extensions/loki.ts", ".loki/loki-shim.ts"] {
        let path = root.join(relative);
        let source = read_text(&path)?;
        if source.matches(SHELL_MARKER).count() != 1 {
            return Err("shell adapter registration marker unavailable".into());
        }
        let updated = source.replace(SHELL_MARKER, &format!("{SHELL_REGISTRATION}{SHELL_MARKER}"));
        write(&path, updated.as_bytes())?;
    }
    Ok(())
}

/// `install_managed`: the `loki` binary as a read-only release outside the repository (named by its sha256), and
/// every owned hook command and shim pointed at it.
pub fn install_managed(root: &Path, destination: &Path) -> Result<(), InitError> {
    use crate::shell::shlex_quote as quote;
    if destination.starts_with(root) {
        return Err("managed engine must be outside the repository".into());
    }
    let current = std::env::current_exe().map_err(|e| os(e, Path::new("loki")))?;
    let binary = std::fs::read(&current).map_err(|e| os(e, &current))?;
    let digest = crate::compat::sha256_hex(&binary);
    let release = destination.join(digest);
    mkdir(&release)?;
    let engine = release.join("loki");
    if engine.exists() {
        if std::fs::read(&engine).map_err(|e| os(e, &engine))? != binary {
            return Err("managed release content mismatch".into());
        }
    } else {
        write(&engine, &binary)?;
    }
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o555)).map_err(|e| os(e, &engine))?;
    }
    let engine_text = engine.to_string_lossy().into_owned();
    let root_text = root.to_string_lossy().into_owned();
    for (relative, harness) in [
        (".claude/settings.json", "claude"),
        (".codex/hooks.json", "codex"),
        (".factory/hooks.json", "factory"),
    ] {
        let path = root.join(relative);
        let mut document = read_json_object(&path)?;
        let groups = if matches!(document.get("hooks"), Some(Value::Object(_))) {
            document.get_mut("hooks").and_then(Value::as_object_mut)
        } else if document.contains_key("hooks") {
            None
        } else {
            Some(&mut document)
        };
        for (event, entries) in groups.into_iter().flatten() {
            let Value::Array(entries) = entries else { continue };
            for entry in entries.iter_mut() {
                let Some(Value::Array(handlers)) = entry.get_mut("hooks") else {
                    continue;
                };
                for handler in handlers.iter_mut() {
                    let command = handler.get("command").and_then(Value::as_str).unwrap_or("");
                    if !command.contains(".loki/loki.json") {
                        continue;
                    }
                    let operations: Vec<&str> = ["context", "protect", "hook", "shell"]
                        .into_iter()
                        .filter(|name| command.contains(&format!(" {name} --")))
                        .collect();
                    let [operation] = operations[..] else {
                        return Err("unrecognized owned hook command".into());
                    };
                    let arguments = if operation == "context" {
                        format!("--event {}", quote(event))
                    } else {
                        format!("--harness {harness}")
                    };
                    handler["command"] = json!(format!(
                        "{} --root {} {operation} {arguments} || {{ printf '%s\\n' 'loki: hook command failed' >&2; exit 2; }} # .loki/loki.json managed engine",
                        quote(&engine_text),
                        quote(&root_text),
                    ));
                }
            }
        }
        write_json(&path, document)?;
    }
    for relative in [".pi/extensions/loki.ts", ".loki/loki-shim.ts"] {
        let path = root.join(relative);
        let source = read_text(&path)?;
        let marker = "process.env.LOKI_BIN || \"loki\"";
        if source.matches(marker).count() != 1 {
            return Err("shared adapter engine marker unavailable".into());
        }
        write(
            &path,
            source.replace(marker, &py::dumps(&json!(engine_text))).as_bytes(),
        )?;
    }
    println!("Managed engine: {engine_text}");
    println!("Owner-writable installation is not an OS security boundary.");
    Ok(())
}

/// `init` without `--minimal`: the target install, then the shell guard and the managed engine when asked.
pub fn init(dir: &str, force: bool, shell_guard: bool, managed_dir: Option<&str>) -> Result<(), InitError> {
    install_target(dir, force)?;
    let root = || crate::resolve(Path::new(dir));
    if shell_guard {
        install_shell_guard(&root())?;
    }
    if let Some(managed) = managed_dir {
        install_managed(&root(), &crate::resolve(Path::new(managed)))?;
    }
    Ok(())
}
