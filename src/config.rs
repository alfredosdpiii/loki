//! `.loki/loki.json`: loading and validation, with loki.py's messages.

use crate::py;
use serde_json::{Map, Value};
use std::path::Path;

pub type Config = Map<String, Value>;

const KEYS: [&str; 10] = [
    "approved_dependencies",
    "commands",
    "languages",
    "private_packages",
    "protected_extra",
    "typescript_check",
    "rule_packs",
    "elixir_security",
    "shell_commands",
    "slop",
];
pub const RULE_PACKS: [&str; 5] = ["core", "python", "typescript", "phoenix", "shell"];
const SECURITY_LEVELS: [&str; 4] = ["none", "low", "medium", "high"];
const COMMAND_GROUPS: [&str; 4] = ["contract", "property", "differential", "mutation"];
const LANGUAGES: [&str; 5] = ["python", "typescript", "go", "rust", "elixir"];
pub const PROTECTED_PATHS: [&str; 17] = [
    ".loki/**",
    ".claude/settings.json",
    ".codex/hooks.json",
    ".codex/config.toml",
    ".factory/hooks.json",
    ".pi/extensions/loki.ts",
    ".omp/extensions/loki.ts",
    ".github/workflows/loki.yml",
    ".oxlintrc.json",
    ".ruff.toml",
    ".credo.exs",
    "**/.credo.exs",
    ".golangci.yml",
    "buf.yaml",
    "buf.work.yaml",
    "oasdiff.yaml",
    "atlas.hcl",
];

/// How loading failed: loki.py reports `ValueError` and other errors differently.
#[derive(Debug, PartialEq)]
pub enum ConfigError {
    Invalid(String),
    Guard(String, String),
}

pub fn load_config(root: &Path) -> Result<Config, ConfigError> {
    let path = root.join(".loki").join("loki.json");
    if !path.is_file() {
        crate::evidence::policy("candidate", ".loki/loki.json", None, None);
        return Ok(Map::new());
    }
    let raw = std::fs::read(&path).map_err(|e| {
        let error = crate::py::os_error(&e, path.to_str());
        ConfigError::Invalid(format!("{}: invalid loki config: {error}", path.display()))
    })?;
    crate::evidence::policy("candidate", ".loki/loki.json", Some(&raw), None);
    // A UnicodeDecodeError is a ValueError, reported as invalid input.
    let text = crate::proc::decode(&raw).map_err(ConfigError::Invalid)?;
    let value: Value = serde_json::from_str(&text).map_err(|e| {
        ConfigError::Invalid(format!(
            "{}: invalid loki config: {}",
            path.display(),
            crate::pyjson::error_text(&text, &e)
        ))
    })?;
    validate_config(&value).map_err(ConfigError::Invalid)
}

fn is_nonempty_string(item: &Value) -> bool {
    item.as_str().is_some_and(|s| !s.is_empty() && !s.contains('\0'))
}

fn string_list(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(is_nonempty_string))
}

pub fn protected_patterns(config: &Config) -> Result<Vec<String>, String> {
    let extra = config.get("protected_extra").cloned().unwrap_or(Value::Array(vec![]));
    if !string_list(&extra) {
        return Err("protected_extra must be a list of nonempty strings".into());
    }
    let mut patterns: Vec<String> = PROTECTED_PATHS.iter().map(|s| s.to_string()).collect();
    patterns.extend(
        extra
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(String::from)),
    );
    Ok(patterns)
}

pub fn rule_packs(config: &Config) -> Result<Vec<String>, String> {
    let error = || "loki: rule_packs must contain known rule-pack names".to_string();
    let Some(value) = config.get("rule_packs") else {
        return Ok(RULE_PACKS.iter().map(|s| s.to_string()).collect());
    };
    let items = value.as_array().ok_or_else(error)?;
    let mut packs: Vec<String> = Vec::new();
    for item in items {
        let name = item.as_str().filter(|s| RULE_PACKS.contains(s)).ok_or_else(error)?;
        if !packs.iter().any(|p| p == name) {
            packs.push(name.to_string());
        }
    }
    Ok(packs)
}

pub fn security_policy(config: &Config) -> Result<(String, String), String> {
    let empty = Value::Object(Map::new());
    let value = config.get("elixir_security").unwrap_or(&empty);
    let value = value.as_object().ok_or("loki: elixir_security must be an object")?;
    if value.keys().any(|k| k != "sobelow") {
        return Err("loki: unknown elixir_security option".into());
    }
    let sobelow = value.get("sobelow").unwrap_or(&empty);
    let sobelow = sobelow
        .as_object()
        .ok_or("loki: elixir_security.sobelow must be an object")?;
    if sobelow.keys().any(|k| k != "block" && k != "warn") {
        return Err("loki: unknown Sobelow option".into());
    }
    let level = |key: &str, default: &str| -> Option<usize> {
        match sobelow.get(key) {
            None => SECURITY_LEVELS.iter().position(|l| *l == default),
            Some(v) => v.as_str().and_then(|s| SECURITY_LEVELS.iter().position(|l| *l == s)),
        }
    };
    let (Some(block), Some(warn)) = (level("block", "high"), level("warn", "medium")) else {
        return Err("loki: Sobelow levels must be none, low, medium or high".into());
    };
    if block != 0 && warn != 0 && warn > block {
        return Err("loki: Sobelow warn level cannot be stricter than block level".into());
    }
    Ok((SECURITY_LEVELS[block].into(), SECURITY_LEVELS[warn].into()))
}

/// `simple_shell_words`: a plain command without shell syntax.
pub fn simple_shell_words(command: &Value) -> Result<Vec<String>, String> {
    let command = match command.as_str() {
        Some(s) if !py::strip(s).is_empty() && !s.contains('\0') => s,
        _ => return Err("shell command must be a nonempty string".into()),
    };
    if command.chars().count() > 4096 || command.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return Err("shell command is too long or contains control characters".into());
    }
    if command.chars().any(|c| "><`$;|&()*?[]{}~#!".contains(c)) {
        return Err("loki: shell syntax unsupported: redirects, substitutions and compound commands or expansions require review".into());
    }
    let words = py::shlex_split(command)?;
    match words.first() {
        Some(first) if !first.contains('=') && !first.contains('/') => Ok(words),
        _ => Err("shell command requires a plain executable name".into()),
    }
}

fn canonical_relative(name: &Value) -> bool {
    let Some(name) = name.as_str() else { return false };
    if name.is_empty() || name.contains('\0') || name.contains('\\') || name.starts_with('/') {
        return false;
    }
    let parts: Vec<&str> = name.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    let posix = if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    };
    !parts.contains(&"..") && posix == name
}

pub fn shell_permissions(config: &Config) -> Result<(), String> {
    let empty = Value::Array(vec![]);
    let grants = config.get("shell_commands").unwrap_or(&empty);
    let grants = match grants.as_array() {
        Some(g) if g.len() <= 64 => g,
        _ => return Err("shell_commands must be a list of at most 64 permissions".into()),
    };
    let mut seen: Vec<(&Value, &Value)> = Vec::new();
    for grant in grants {
        let grant = match grant.as_object() {
            Some(g) if g.len() == 3 && ["command", "cwd", "inputs"].iter().all(|k| g.contains_key(*k)) => g,
            _ => return Err("shell permissions require command, cwd and inputs".into()),
        };
        let words = simple_shell_words(&grant["command"])?;
        if words[0] == "git" {
            return Err("shell permissions cannot override Git restrictions".into());
        }
        let inputs = match grant["inputs"].as_array() {
            Some(i) if (1..=64).contains(&i.len()) && i.iter().all(Value::is_string) => i,
            _ => return Err("shell permission inputs must list 1 to 64 files".into()),
        };
        if !std::iter::once(&grant["cwd"]).chain(inputs).all(canonical_relative) {
            return Err("shell permission paths must be canonical and relative".into());
        }
        if inputs.iter().any(|i| i == ".") {
            return Err("shell permission inputs must be files".into());
        }
        let key = (&grant["command"], &grant["cwd"]);
        if seen.contains(&key) {
            return Err("duplicate shell permission".into());
        }
        seen.push(key);
    }
    Ok(())
}

pub fn slop_block(config: &Config) -> Result<bool, String> {
    let empty = Value::Object(Map::new());
    let policy = config.get("slop").unwrap_or(&empty);
    let policy = match policy.as_object() {
        Some(p)
            if p.keys()
                .all(|k| ["block", "max_index", "max_index_increase"].contains(&k.as_str())) =>
        {
            p
        }
        _ => return Err("slop must be an object with block, max_index, max_index_increase".into()),
    };
    let block = match policy.get("block") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("slop.block must be a boolean".into()),
    };
    for key in ["max_index", "max_index_increase"] {
        if let Some(v) = policy.get(key)
            && !v.as_i64().is_some_and(|n| (0..=100).contains(&n))
        {
            return Err(format!("slop.{key} must be an integer from 0 to 100"));
        }
    }
    Ok(block)
}

pub fn validate_config(value: &Value) -> Result<Config, String> {
    let config = value.as_object().ok_or("loki config must be a JSON object")?;
    let mut unknown: Vec<&String> = config.keys().filter(|k| !KEYS.contains(&k.as_str())).collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(format!("loki: unknown configuration key: {key}"));
    }
    protected_patterns(config)?;
    rule_packs(config)?;
    security_policy(config)?;
    shell_permissions(config)?;
    slop_block(config)?;
    if config.get("typescript_check").is_some_and(|v| !v.is_boolean()) {
        return Err("typescript_check must be a boolean".into());
    }
    match config.get("approved_dependencies") {
        None | Some(Value::Null) => {}
        Some(items) if string_list(items) => {}
        Some(_) => return Err("loki: approved_dependencies must be a list of nonempty strings".into()),
    }
    if config.get("private_packages").is_some_and(|v| !string_list(v)) {
        return Err("loki: private_packages must be a list of nonempty strings".into());
    }
    if let Some(languages) = config.get("languages")
        && !languages
            .as_object()
            .is_some_and(|m| m.iter().all(|(k, v)| LANGUAGES.contains(&k.as_str()) && v.is_boolean()))
    {
        return Err("loki: languages must map known language names to booleans".into());
    }
    if let Some(commands) = config.get("commands") {
        let commands = commands.as_object().ok_or("loki: commands must be a JSON object")?;
        if let Some(group) = commands.keys().find(|g| !COMMAND_GROUPS.contains(&g.as_str())) {
            return Err(format!("loki: unknown command group: {group}"));
        }
        for group in COMMAND_GROUPS {
            let valid = commands.get(group).is_none_or(|values| {
                values.as_array().is_some_and(|values| {
                    values.iter().all(|v| {
                        v.as_array().is_some_and(|parts| {
                            !parts.is_empty() && parts.iter().all(|p| p.as_str().is_some_and(|s| !s.is_empty()))
                        })
                    })
                })
            });
            if !valid {
                return Err(format!(
                    "loki: commands.{group} must be a list of non-empty string arrays"
                ));
            }
        }
    }
    Ok(config.clone())
}

pub fn language_enabled(config: &Config, language: &str) -> bool {
    match config.get("languages") {
        Some(Value::Object(m)) => m.get(language) != Some(&Value::Bool(false)),
        _ => true,
    }
}
