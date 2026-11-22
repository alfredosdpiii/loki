//! Core rule pack: credentials, conflict markers, GitHub Actions injection.

use crate::text::Text;
use crate::{CheckError, py};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

/// `(relative path, old text, new text)` of one previewed or written file.
pub type Change = (String, String, String);

/// `(rule, message, byte offset)`.
pub type Finding = (&'static str, String, usize);

const SECRET_PATTERNS: [(&str, &str); 8] = [
    ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{60,})"),
    ("private key", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{20,}"),
    ("Stripe live key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("model provider API key", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{40,}"),
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static pattern")
}

static SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(&SECRET_PATTERNS
        .iter()
        .map(|(_, p)| format!("({p})"))
        .collect::<Vec<_>>()
        .join("|"))
});
static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)example|placeholder|dummy|fake|redacted|x{6}"));
static WORKFLOW_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?:^|/)\.github/(?:workflows/[^/]+|actions/.+/action)\.ya?ml$"));
static UNTRUSTED_CONTEXT_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\$\{\{\s*github\.(?:head_ref|event\.[\w.*\[\]'-]*?\b(?:title|body|message|head_ref|ref|label|name|email|default_branch|page_name))\s*\}\}",
    )
});
static CONFLICT_START: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^<{7} "));
static CONFLICT_END: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^>{7} "));
static CONFLICT_ANY: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^(?:<{7}|>{7}) "));
static RUN_KEY: LazyLock<Regex> = LazyLock::new(|| re(r"^(?:-\s+)?run:\s*(.*)$"));

/// Shannon entropy in bits per character.
pub fn entropy(value: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in value.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let len = value.chars().count() as f64;
    -counts
        .values()
        .map(|&n| n as f64 / len * (n as f64 / len).log2())
        .sum::<f64>()
}

/// `generic_rules`: rules for every text file. Offsets are character indices.
pub fn generic_rules(relative: &str, text: &Text) -> Vec<Finding> {
    let mut findings = Vec::new();
    for caps in SECRET_RE.captures_iter(&text.s) {
        let token = caps.get(0).expect("whole match");
        let value = token.as_str();
        if PLACEHOLDER_RE.is_match(value) || (!value.contains("PRIVATE KEY") && entropy(value) < 3.0) {
            continue;
        }
        let group = (1..=SECRET_PATTERNS.len())
            .find(|&i| caps.get(i).is_some())
            .unwrap_or(1);
        findings.push((
            "loki/secret",
            format!(
                "hardcoded credential ({}); load it from the environment or a secret store and rotate the exposed value",
                SECRET_PATTERNS[group - 1].0
            ),
            text.index(token.start()),
        ));
    }
    if CONFLICT_START.is_match(&text.s) && CONFLICT_END.is_match(&text.s) {
        for m in CONFLICT_ANY.find_iter(&text.s) {
            findings.push((
                "loki/conflict-marker",
                "unresolved merge conflict marker".into(),
                text.index(m.start()),
            ));
        }
    }
    if WORKFLOW_PATH_RE.is_match(relative) {
        findings.extend(workflow_injection(&text.s));
    }
    findings
}

/// Untrusted event fields interpolated into `run:` shell scripts.
pub fn workflow_injection(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (mut offset, mut block) = (0usize, None::<usize>);
    for line in py::splitlines(text, true) {
        let indent = line.len() - line.trim_start_matches(' ').len();
        let stripped = py::strip(line);
        if block.is_some_and(|b| !stripped.is_empty() && indent <= b) {
            block = None;
        }
        let key = RUN_KEY.captures(stripped);
        if let Some(caps) = &key {
            let rest = py::strip(caps.get(1).map_or("", |m| m.as_str()));
            block = matches!(rest.chars().next(), None | Some('|' | '>')).then_some(indent);
        }
        if key.is_some() || block.is_some() {
            for m in UNTRUSTED_CONTEXT_RE.find_iter(line) {
                findings.push((
                    "loki/actions-injection",
                    "script injection: untrusted GitHub event field interpolated into a run step; pass it through env and quote it".into(),
                    offset + line[..m.start()].chars().count(),
                ));
            }
        }
        offset += line.chars().count();
    }
    findings
}

/// The `LANGUAGE_EXTENSIONS` language of a path, by its lowercased suffix.
pub fn language(relative: &str) -> Option<&'static str> {
    Some(match suffix(relative)?.as_str() {
        ".py" => "python",
        ".ts" | ".tsx" | ".js" | ".jsx" | ".mjs" | ".cjs" | ".mts" | ".cts" => "typescript",
        ".go" => "go",
        ".rs" => "rust",
        ".ex" | ".exs" | ".heex" => "elixir",
        _ => return None,
    })
}

/// `Path(relative).suffix.lower()`, None when there is no suffix.
pub fn suffix(relative: &str) -> Option<String> {
    let name = relative.trim_end_matches('/').rsplit('/').next().unwrap_or(relative);
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() && !name.ends_with('.') => Some(name[i..].to_lowercase()),
        _ => None,
    }
}

/// `content_rule_findings`: generic rules plus the file's language pack, or
/// with `fallback` only the parser-free JavaScript rules.
pub fn content_rule_findings(relative: &str, text: &Text, fallback: bool) -> Result<Vec<Finding>, CheckError> {
    let language = language(relative);
    if fallback {
        return Ok(if language == Some("typescript") {
            crate::jsrules::javascript_fallback_rules(relative, text)
        } else {
            vec![]
        });
    }
    let mut findings = generic_rules(relative, text);
    findings.extend(match language {
        Some("typescript") => crate::jsrules::javascript_rules(text),
        Some("python") => crate::pyast::python_rules(text)?,
        Some("elixir") => crate::langrules::elixir_rules(text),
        Some("rust") => crate::langrules::rust_rules(text),
        Some("go") => crate::langrules::go_rules(text),
        _ => vec![],
    });
    Ok(findings)
}

/// `content_rule_violations`: net-new findings, matched by rule, message and line text.
pub fn content_rule_violations(
    changes: &[(String, String, String)],
    fallback: bool,
) -> Result<Vec<String>, CheckError> {
    type Key = (&'static str, String, String);
    let python: Vec<&str> = changes
        .iter()
        .filter(|(relative, _, _)| !fallback && language(relative) == Some("python"))
        .flat_map(|(_, old, new)| [old.as_str(), new.as_str()])
        .collect();
    if !python.is_empty() {
        crate::pyast::prefetch(&python)?;
    }
    let mut violations = Vec::new();
    for (relative, old, new) in changes {
        let mut old_counts: HashMap<Key, usize> = HashMap::new();
        let mut new_order: Vec<Key> = Vec::new();
        let mut new_counts: HashMap<Key, (usize, usize)> = HashMap::new();
        for (side, content) in [old, new].into_iter().enumerate() {
            let text = Text::new(content);
            let lines = py::splitlines(content, false);
            for (rule, message, offset) in content_rule_findings(relative, &text, fallback)? {
                let number = text.newlines_before(offset) + 1;
                let line = lines
                    .get(number - 1)
                    .ok_or_else(|| CheckError::Guard("IndexError".into(), "list index out of range".into()))?;
                let key = (rule, message, py::strip(line).to_string());
                if side == 0 {
                    *old_counts.entry(key).or_default() += 1;
                } else {
                    let entry = new_counts.entry(key.clone()).or_insert_with(|| {
                        new_order.push(key);
                        (0, number)
                    });
                    entry.0 += 1;
                }
            }
        }
        for key in new_order {
            let (count, line) = new_counts[&key];
            let extra = count.saturating_sub(old_counts.get(&key).copied().unwrap_or(0));
            if extra > 0 {
                crate::evidence::finding(key.0, Some(relative));
            }
            for _ in 0..extra {
                violations.push(format!("{relative}:{line}: {}: {}", key.0, key.1));
            }
        }
    }
    violations.truncate(crate::MAX_VIOLATIONS);
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loki_entropy_matches_python() {
        // python3 -c 'import math,collections;v="aabb";c=collections.Counter(v);print(-sum(n/len(v)*math.log2(n/len(v)) for n in c.values()))'
        assert_eq!(entropy("aabb"), 1.0);
        assert_eq!(entropy("abcdefgh"), 3.0);
    }

    #[test]
    fn loki_net_new_only_counts_added_findings() {
        let key = concat!("AKIA", "Q7XRJ2M4PL3ZWNVB");
        let old = format!("a = '{key}'\n");
        let new = format!("a = '{key}'\nb = 1\na = '{key}'\n");
        let found = content_rule_violations(&[("cfg.txt".into(), old, new)], false).unwrap();
        assert_eq!(
            found,
            vec![
                "cfg.txt:1: loki/secret: hardcoded credential (AWS access key); load it from the environment or a secret store and rotate the exposed value"
            ]
        );
    }
}
