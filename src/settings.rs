//! The `loki` settings (global only, so a repository cannot turn its own checks off): `mode` (`on`, `advise`,
//! `off`), `hygiene` (`on`, `all`, `off`), `autoInit`, `autoCommit` and `ignoreRepos`.

use serde_json::{Map, Value};

/// The global settings key the settings live under.
pub const KEY: &str = "loki";

/// The saved `loki` settings of the global settings, dropping invalid values.
pub fn saved(global: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(Value::Object(configured)) = global.get(KEY) else {
        return out;
    };
    if let Some(mode) = configured
        .get("mode")
        .and_then(Value::as_str)
        .filter(|m| ["on", "advise", "off"].contains(m))
    {
        out.insert("mode".into(), mode.into());
    }
    if let Some(hygiene) = configured
        .get("hygiene")
        .and_then(Value::as_str)
        .filter(|h| ["on", "all", "off"].contains(h))
    {
        out.insert("hygiene".into(), hygiene.into());
    }
    for key in ["autoInit", "autoCommit"] {
        if let Some(Value::Bool(b)) = configured.get(key) {
            out.insert(key.into(), (*b).into());
        }
    }
    if let Some(Value::Array(items)) = configured.get("ignoreRepos") {
        let repos: Vec<Value> = items
            .iter()
            .filter(|v| v.as_str().is_some_and(|s| !str::trim(s).is_empty()))
            .cloned()
            .collect();
        out.insert("ignoreRepos".into(), Value::Array(repos));
    }
    out
}

/// `setLokiSettings`: the saved settings with `patch` on top (`None` removes a key), as the whole new object.
pub fn patched(global: &Map<String, Value>, patch: &[(&str, Option<Value>)]) -> Value {
    let mut loki = saved(global);
    for (key, value) in patch {
        match value {
            Some(v) => loki.insert(key.to_string(), v.clone()),
            None => loki.shift_remove(*key),
        };
    }
    Value::Object(loki)
}
