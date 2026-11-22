//! TypeScript/JavaScript rule pack: `javascript_rules`, the ReDoS detector and the
//! parser-free fallback for Oxlint's preview rules.

use crate::py;
use crate::rules::Finding;
use crate::text::{Re, Text, closing_quote, expression_end, mask_javascript, matching_close, split_arguments};
use std::collections::BTreeSet;
use std::sync::LazyLock;

macro_rules! re {
    (pub $name:ident, $pattern:expr) => {
        pub static $name: LazyLock<Re> = LazyLock::new(|| Re::new($pattern));
    };
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Re> = LazyLock::new(|| Re::new($pattern));
    };
}

pub const REDOS_RULE: &str = "loki/redos";
pub const REDOS_MESSAGE: &str = "ReDoS: nested quantifier such as (a+)+ causes catastrophic backtracking on crafted input; remove the nesting or bound the repetition";
pub const OPEN_REDIRECT: &str =
    "open redirect: unvalidated navigation target; check it against an allowlist of paths or origins";
const TEST_FRAMEWORKS: [&str; 8] = [
    "vitest",
    "jest",
    "@jest/globals",
    "mocha",
    "node:test",
    "bun:test",
    "ava",
    "tap",
];
const TEST_FUNCTIONS: [&str; 6] = ["describe", "it", "test", "suite", "context", "bench"];

re!(INNER_HTML, r"\.\s*(innerHTML|outerHTML)\s*\+?=(?!=)");
re!(
    HTML_CALL,
    r"\.\s*(insertAdjacentHTML)\s*\(|(?<![\w$.])document\s*\.\s*(writeln|write)\s*\("
);
re!(DANGEROUS_HTML, r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:");
re!(
    LOCATION_SET,
    r"(?<![\w$.])(?:(?:window|document|self|top)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?!=)"
);
re!(LOCATION_CALL, r"(?<![\w$])location\s*\.\s*(?:assign|replace)\s*\(");
re!(
    TLS_OFF,
    r#"\brejectUnauthorized\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*(?:\]\s*)?=(?!=)\s*['"`]?\s*0"#
);
re!(REDIRECT_CALL, r"\bres(?:ponse)?\s*\.\s*redirect\s*\(");
re!(
    REQUEST_FIELD,
    r"\breq(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies)\b"
);
re!(
    PROMISIFY,
    r"\b([\w$]+)\s*=\s*(?:util\s*\.\s*)?promisify\s*\(\s*(?:child_process\s*\.\s*)?exec\s*\)"
);
re!(SQL_CALL, r"\.\s*(?:query|execute|raw|unsafe|prepare)\s*\(");
re!(pub SQL_WORD, r"(?i)\b(?:select|insert|update|delete)\b");
re!(SQL_CONCAT, r#"['"`]\s*\+|\+\s*['"`]"#);
// Text just before an interpolation that puts it where SQL expects a table or column name (SQL_IDENTIFIER_POSITION).
re!(
    pub SQL_IDENTIFIER_POSITION,
    r#"(?i)(?:\b(?:from|into|update|join|table|exists)|\b(?:order|group)\s+by|["`\[.])\s*$"#
);
pub const TLS_VERIFICATION: &str =
    "TLS certificate verification disabled; trust the needed CA instead of turning verification off";
pub const SQL_IDENTIFIER: &str = "SQL injection: table or column name interpolated into the query; placeholders cannot bind identifiers, so map it to a fixed set of known names before building the query";
pub const SQL_QUERY: &str =
    "SQL injection: query text built by concatenation or interpolation; use parameterized placeholders";
re!(
    COMPARE,
    r"([\w$.]+(?:\([^()]*\))?|`[^`]*`)\s*(?:===?|!==?)\s*([\w$.]+(?:\([^()]*\))?|`[^`]*`)"
);
re!(SECRET_SIDE, r"(?i)\.digest\(|(?:signature|hmac|digest)[\w$]*$");
re!(LENGTH_SIDE, r"\.length$");
re!(CONSTANT_SIDE, r"^(?:null|undefined|true|false|\d+|[\w$.]*\.length)$");
re!(LISTENER, r#"\baddEventListener\s*\(\s*(['"`])"#);
re!(ORIGIN_CHECK, r"\.\s*origin\b|\borigin\s*[,}=]");
re!(
    TAINT_ASSIGN,
    r"\b(?:const|let|var)\s+([\w$]+)\s*=([^;\n]*)\breq(?:uest)?\s*\.\s*(?:query|body|params|url)\b"
);
re!(
    TAINT_CLEAN,
    r"(?i)(?<!un)(?:safe|sanitiz|validat|allow|trusted|whitelist)\w*\s*\("
);
re!(
    TAINT_DESTRUCTURE,
    r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*\breq(?:uest)?\s*\.\s*(?:query|body|params|url)\b"
);
re!(
    FETCH_CALL,
    r"(?<![\w$.])(?:fetch|got|axios(?:\s*\.\s*(?:get|post|put|delete|head|request))?|https?\s*\.\s*(?:get|request))\s*\("
);
re!(REQUEST_SOURCE, r"\breq(?:uest)?\s*\.\s*(?:query|body|params|url)\b");
re!(BARE_WORD, r"(?<![\w$.])([\w$]+)");
re!(
    MERGE_FUNCTION,
    r"\bfunction\s+([\w$]+)\s*\(|\b(?:const|let)\s+([\w$]+)\s*=\s*(?:async\s*)?\([^)]*\)[^={]*=>\s*\{"
);
re!(
    KEY_LOOP,
    r"for\s*\(\s*(?:const|let|var)\s+\[?\s*([\w$]+)[^)]*?(?:\bof\s+Object\s*\.\s*(?:keys|entries)|\bin\b)"
);
re!(PROTO_GUARD, r"__proto__|prototype|constructor|hasOwn");
re!(SET_INTERVAL, r"(?<![\w$.])setInterval\s*\(");
re!(FOR_EACH, r"(?<![\w$.])((?:[\w$]+\s*\.\s*)*[\w$]+)\s*\.\s*forEach\s*\(");
re!(EVAL_CALL, r"(?<![\w$.])(eval|new\s+Function)\s*\(");
re!(REGEX_LITERAL, r"/( *)/[dgimsuyv]*");
re!(REGEXP_CALL, r#"\bRegExp\s*\(\s*(['"`])"#);
re!(
    SANITIZER_CALL,
    r"(?i)^\s*[\w$.]*?(?:(?<!un)safe|sanitiz|validat|allow|trusted|whitelist)[\w$]*\s*\("
);
re!(SAME_ORIGIN, r"(?i)^(?:/(?!/)|[#?]|[a-z][a-z0-9+.-]*://[^/\s]+/)");
re!(CATCH_BLOCK, r"\bcatch\s*(?:\([^()]*\))?\s*\{");
re!(ASYNC_EXECUTOR, r"\bnew\s+Promise\s*\(\s*async\b");
re!(FINALLY_BLOCK, r"\bfinally\s*\{");
re!(CONTROL, r"\b(return|throw|break|continue)\b");
re!(NESTED_SCOPE, r"=>|\bfunction\b|\bclass\b");
re!(DEBUGGER, r"(?<![\w$.])debugger\b");
re!(TEST_IMPORT, r#"\bimport\s*\{([^}]*)\}\s*from\s*(['"])"#);
re!(DECLARED, r"\b(?:const|let|var|function|class)\s+([\w$]+)");
re!(
    pub TEST_PATH,
    r"(?i)(^|/)(tests?|spec)(/|$)|(^|/)(test_[^/]+|[^/]+_(?:test|spec))\.[^.]+$|\.(?:test|spec)\.[^.]+$"
);
re!(GROUP_PREFIX, r"^\?(?:[:=!]|<[=!]|<\w+>)");
re!(OPEN_QUANTIFIER, r"^(?:[+*]|\{\d+,\})");
re!(BOUNDED_QUANTIFIER, r"^\{\d*,\d*\}");
re!(LEADING_LITERAL, r"^(?:\\[^dDwWsSbB]|[^\\\[(.|^$?*+{}])(?![?*+{])");
re!(
    TRAILING_LITERAL,
    r"(?<!\\)(?:\\[^dDwWsSbB]|[^\\\[(.|^$?*+{}])(?:\z|(?=\n\z))"
);
re!(ANY_ATOM, r"(?<!\\)\.|\\[SWD]");
re!(CHAR_CLASS, r"\[(\^?)((?:\\.|[^\]\\])*)\]");
re!(CLASS_MEMBER, r"\\.|.");

/// Constant text of a single string-literal expression, else None.
fn javascript_literal(text: &Text, masked: &Text, start: usize, end: usize) -> Option<String> {
    let value: Vec<char> = py::strip(masked.sl(start, end)).chars().collect();
    if value.len() < 2 || !"'\"`".contains(value[0]) || value[value.len() - 1] != value[0] {
        return None;
    }
    if value[1..value.len() - 1].iter().any(|&c| !py::is_space(c)) {
        return None;
    }
    let offset = (start..masked.len()).find(|&i| masked.c[i] == value[0])?;
    let literal = text.sl(offset + 1, offset + value.len() - 1).to_string();
    (!(value[0] == '`' && literal.contains("${"))).then_some(literal)
}

fn fixed_origin(text: &Text, masked: &Text, start: usize, end: usize) -> bool {
    if javascript_literal(text, masked, start, end).is_some() {
        return true;
    }
    let slice = masked.sl(start, end);
    if SANITIZER_CALL.is_match(slice) {
        return true;
    }
    let value = slice.trim_start_matches(py::is_space);
    let Some(quote) = value.chars().next().filter(|c| "'\"`".contains(*c)) else {
        return false;
    };
    let Some(offset) = (start..masked.len()).find(|&i| masked.c[i] == quote) else {
        return false;
    };
    let prefix = text.sl(offset + 1, closing_quote(&text.c, offset + 1, quote, true));
    let prefix = prefix.split("${").next().unwrap_or("");
    SAME_ORIGIN.is_match(prefix)
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `re.search(r"\b(?:const|let|var)\s*$", prefix)`.
fn declared_before(prefix: &str) -> bool {
    let trimmed = prefix.trim_end_matches(py::is_space);
    ["const", "let", "var"].iter().any(|word| {
        trimmed
            .strip_suffix(word)
            .is_some_and(|rest| !rest.chars().next_back().is_some_and(is_word))
    })
}

fn sl(text: &Text, span: (usize, usize)) -> &str {
    text.sl(span.0, span.1)
}

pub fn javascript_rules(text: &Text) -> Vec<Finding> {
    let masked = mask_javascript(text);
    let m = &masked.c;
    let mut findings: Vec<Finding> = Vec::new();
    for found in INNER_HTML.iter(&masked) {
        let end = expression_end(m, found.end());
        if javascript_literal(text, &masked, found.end(), end).is_none() {
            let sink = found.group(&masked, 1).unwrap_or("");
            findings.push((
                "loki/unsanitized-html",
                format!(
                    "cross-site scripting (XSS): non-literal HTML assigned to {sink}; use textContent or a sanitizer"
                ),
                found.start(),
            ));
        }
    }
    for found in HTML_CALL.iter(&masked) {
        let arguments = split_arguments(m, found.end() - 1);
        let position = usize::from(found.get(1).is_some());
        if arguments.len() > position
            && javascript_literal(text, &masked, arguments[position].0, arguments[position].1).is_none()
        {
            let sink = match found.group(&masked, 1) {
                Some(name) => name.to_string(),
                None => format!("document.{}", found.group(&masked, 2).unwrap_or("")),
            };
            findings.push((
                "loki/unsanitized-html",
                format!("cross-site scripting (XSS): non-literal HTML passed to {sink}"),
                found.start(),
            ));
        }
    }
    for found in DANGEROUS_HTML.iter(&masked) {
        let end = expression_end(m, found.end());
        if javascript_literal(text, &masked, found.end(), end).is_none() {
            findings.push((
                "loki/unsanitized-html",
                "cross-site scripting (XSS): non-literal dangerouslySetInnerHTML".into(),
                found.start(),
            ));
        }
    }
    for found in LOCATION_SET.iter(&masked) {
        if !declared_before(masked.sl(0, found.start()))
            && !fixed_origin(text, &masked, found.end(), expression_end(m, found.end()))
        {
            findings.push(("loki/open-redirect", OPEN_REDIRECT.into(), found.start()));
        }
    }
    for found in LOCATION_CALL.iter(&masked) {
        let arguments = split_arguments(m, found.end() - 1);
        if let Some(&(a, b)) = arguments.first()
            && !fixed_origin(text, &masked, a, b)
        {
            findings.push(("loki/open-redirect", OPEN_REDIRECT.into(), found.start()));
        }
    }
    for found in TLS_OFF.iter(text) {
        if masked.at(found.start()) != Some(' ') {
            findings.push(("loki/tls-verification", TLS_VERIFICATION.into(), found.start()));
        }
    }
    for found in REDIRECT_CALL.iter(&masked) {
        let arguments = split_arguments(m, found.end() - 1);
        if let Some(&last) = arguments.last()
            && REQUEST_FIELD.is_match(sl(&masked, last))
        {
            findings.push(("loki/open-redirect", OPEN_REDIRECT.into(), found.start()));
        }
    }
    let shell = text.s.contains("child_process");
    let aliases: Vec<String> = PROMISIFY
        .group1_strs(&masked.s)
        .iter()
        .map(|a| fancy_regex::escape(a).into_owned())
        .collect();
    let runners = ["exec".to_string(), "execSync".to_string()]
        .into_iter()
        .chain(aliases)
        .collect::<Vec<_>>()
        .join("|");
    let runner = Re::new(&format!(r"(?:(?<![\w$.])|\bchild_process\s*\.\s*)({runners})\s*\("));
    for found in runner.iter(&masked) {
        let arguments = split_arguments(m, found.end() - 1);
        if shell
            && let Some(&(a, b)) = arguments.first()
            && javascript_literal(text, &masked, a, b).is_none()
        {
            findings.push((
                "loki/command-injection",
                format!(
                    "shell command injection: non-literal command passed to {}; use execFile or spawn with an argument array",
                    found.group(&masked, 1).unwrap_or("")
                ),
                found.start(),
            ));
        }
    }
    for found in SQL_CALL.iter(&masked) {
        let arguments = split_arguments(m, found.end() - 1);
        let Some(&first) = arguments.first() else { continue };
        let argument = sl(text, first);
        if SQL_WORD.is_match(argument) && (argument.contains("${") || SQL_CONCAT.is_match(argument)) {
            let identifier = argument.contains("${")
                && !argument.contains('+')
                && argument
                    .match_indices("${")
                    .all(|(at, _)| SQL_IDENTIFIER_POSITION.is_match(&argument[..at]));
            let message = if identifier { SQL_IDENTIFIER } else { SQL_QUERY };
            findings.push(("loki/sql-injection", message.into(), found.start()));
        }
    }
    for found in COMPARE.iter(&masked) {
        let sides = [
            found.group(&masked, 1).unwrap_or(""),
            found.group(&masked, 2).unwrap_or(""),
        ];
        if sides.iter().any(|s| s.starts_with('`')) && !text.sl(found.start(), found.end()).contains("${") {
            continue;
        }
        let secret = sides
            .iter()
            .any(|side| SECRET_SIDE.is_match(side) && !LENGTH_SIDE.is_match(side));
        if secret && !sides.iter().any(|side| CONSTANT_SIDE.is_match(side)) {
            findings.push((
                "loki/timing-compare",
                "timing attack: signature or digest compared with ==; use crypto.timingSafeEqual".into(),
                found.start(),
            ));
        }
    }
    for found in LISTENER.iter(&masked) {
        let quote_char = found.group(&masked, 1).and_then(|q| q.chars().next()).unwrap_or('"');
        let Some(quote) = (found.start()..masked.len()).find(|&i| m[i] == quote_char) else {
            continue;
        };
        if !text.starts_at(quote + 1, "message") {
            continue;
        }
        let handler = masked.sl(found.end(), matching_close(m, found.end() - 2));
        if !ORIGIN_CHECK.is_match(handler) {
            findings.push((
                "loki/postmessage-origin",
                "message event handler never checks event.origin; any window can post to it".into(),
                found.start(),
            ));
        }
    }
    let mut tainted: BTreeSet<String> = BTreeSet::new();
    for found in TAINT_ASSIGN.iter(&masked) {
        if !TAINT_CLEAN.is_match(found.group(&masked, 2).unwrap_or("")) {
            tainted.insert(found.group(&masked, 1).unwrap_or("").to_string());
        }
    }
    for group in TAINT_DESTRUCTURE.group1_strs(&masked.s) {
        for item in group.split(',') {
            tainted.insert(py::strip(item.rsplit(':').next().unwrap_or("")).to_string());
        }
    }
    tainted.remove("");
    for found in FETCH_CALL.iter(&masked) {
        let arguments = split_arguments(m, found.end() - 1);
        let target = arguments.first().map_or("", |&span| sl(&masked, span));
        let words = BARE_WORD.group1_strs(target);
        if REQUEST_SOURCE.is_match(target) || words.iter().any(|w| tainted.contains(*w)) {
            findings.push((
                "loki/ssrf",
                "server-side request forgery (SSRF): outbound request URL comes from request data; validate the host against an allowlist".into(),
                found.start(),
            ));
        }
    }
    for found in MERGE_FUNCTION.iter(&masked) {
        let name = found
            .group(&masked, 1)
            .or_else(|| found.group(&masked, 2))
            .unwrap_or("");
        let Some(opening) = masked.find("{", found.end() - 1) else {
            continue;
        };
        let end = matching_close(m, opening);
        let body = Text::new(masked.sl(opening, end));
        let Some(key_loop) = KEY_LOOP.search(&body, 0) else {
            continue;
        };
        let key = key_loop.group(&body, 1).unwrap_or("");
        let calls = Re::new(&format!(r"(?<![\w$.]){}\s*\(", fancy_regex::escape(name)));
        let assigns = Re::new(&format!(r"\[\s*{}\s*\]\s*=(?!=)", fancy_regex::escape(key)));
        if calls.is_match(body.sl(1, body.len()))
            && assigns.is_match(&body.s)
            && !PROTO_GUARD.is_match(text.sl(opening, end))
        {
            findings.push((
                "loki/prototype-pollution",
                "prototype pollution: recursive merge copies arbitrary keys; skip __proto__, constructor and prototype or use Object.create(null)".into(),
                found.start(),
            ));
        }
    }
    for (pattern, offset) in javascript_regexes(text, &masked) {
        if nested_quantifier(&pattern) {
            findings.push((REDOS_RULE, REDOS_MESSAGE.into(), offset));
        }
    }
    if !masked.s.contains("clearInterval") {
        for found in SET_INTERVAL.iter(&masked) {
            findings.push((
                "loki/timer-leak",
                "setInterval without any clearInterval in this file: the timer and everything it captures are never released".into(),
                found.start(),
            ));
        }
    }
    for found in FOR_EACH.iter(&masked) {
        let callback = masked.sl(found.end() - 1, matching_close(m, found.end() - 1));
        let receiver_text = found.group(&masked, 1).unwrap_or("");
        let receiver = receiver_text
            .split('.')
            .map(|part| fancy_regex::escape(py::strip(part)).into_owned())
            .collect::<Vec<_>>()
            .join(r"\s*\.\s*");
        let splice = Re::new(&format!(r"(?<![\w$.]){receiver}\s*\.\s*splice\s*\("));
        if splice.is_match(callback) {
            findings.push((
                "loki/mutation-during-iteration",
                format!(
                    "{receiver_text} is spliced while forEach iterates it, which skips the next element; filter into a new array instead"
                ),
                found.start(),
            ));
        }
    }
    for found in EVAL_CALL.iter(&masked) {
        let arguments = split_arguments(m, found.end() - 1);
        if let Some(&(a, b)) = arguments.last()
            && javascript_literal(text, &masked, a, b).is_none()
        {
            let callee = found
                .group(&masked, 1)
                .unwrap_or("")
                .split(py::is_space)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            findings.push((
                "loki/code-eval",
                format!("dynamic code execution: non-literal source passed to {callee}"),
                found.start(),
            ));
        }
    }
    findings
}

/// Regex literal bodies and `new RegExp("...")` patterns with their offsets.
fn javascript_regexes(text: &Text, masked: &Text) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    for item in REGEX_LITERAL.iter(masked) {
        if let Some((a, b)) = item.get(1)
            && b > a
        {
            found.push((text.sl(a, b).to_string(), item.start()));
        }
    }
    for item in REGEXP_CALL.iter(masked) {
        let quote = item.group(masked, 1).and_then(|q| q.chars().next()).unwrap_or('"');
        let close = closing_quote(&text.c, item.end(), quote, false);
        found.push((text.sl(item.end(), close).replace("\\\\", "\\"), item.start()));
    }
    found
}

/// Whether a repeated group starts or ends with a literal no atom can absorb.
fn delimiter_separated(body: &str) -> bool {
    let text = Text::new(body);
    let found = LEADING_LITERAL
        .search(&text, 0)
        .or_else(|| TRAILING_LITERAL.search(&text, 0));
    let Some(found) = found else { return false };
    let Some(delimiter) = found.whole(&text).chars().last() else {
        return false;
    };
    if ANY_ATOM.is_match(body) {
        return false;
    }
    for class in CHAR_CLASS.iter(&text) {
        let members = CLASS_MEMBER.find_strs(class.group(&text, 2).unwrap_or(""));
        let last = |s: &str| s.chars().last().unwrap_or('\0');
        let mut inside = false;
        for (index, member) in members.iter().enumerate() {
            let ranged = index > 0
                && index + 1 < members.len()
                && *member == "-"
                && last(members[index - 1]) <= delimiter
                && delimiter <= last(members[index + 1]);
            if ranged || (last(member) == delimiter && *member != "-") {
                inside = true;
            }
        }
        if members.first() == Some(&"-") || members.last() == Some(&"-") {
            inside = inside || delimiter == '-';
        }
        if inside != class.get(1).is_some_and(|(a, b)| b > a) {
            return false;
        }
    }
    true
}

/// A group containing a quantifier that is itself repeated: (x+)+, (x*)*, (x+){2,}.
pub fn nested_quantifier(pattern: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let text = Text::from_chars(p.clone());
    let mut stack: Vec<(bool, usize)> = Vec::new();
    let mut index = 0;
    while index < p.len() {
        let c = p[index];
        if c == '\\' {
            index += 2;
            continue;
        }
        if c == '[' {
            index = match text.find("]", index + 2) {
                Some(close) => close + 1,
                None => p.len(),
            };
            continue;
        }
        if c == '(' {
            stack.push((false, index + 1));
        } else if ((c == '+' || c == '*') || (c == '{' && BOUNDED_QUANTIFIER.is_match(text.sl(index, p.len()))))
            && !stack.is_empty()
        {
            if let Some(top) = stack.last_mut() {
                top.0 = true;
            }
        } else if c == ')'
            && let Some((inner, start)) = stack.pop()
        {
            let group = text.sl(start, index);
            let body = match GROUP_PREFIX.search(&Text::new(group), 0) {
                Some(prefix) => group.chars().skip(prefix.end()).collect::<String>(),
                None => group.to_string(),
            };
            let delimited = !body.contains('|') && delimiter_separated(&body);
            if inner && !delimited && OPEN_QUANTIFIER.is_match(text.sl(index + 1, p.len())) {
                return true;
            }
            if inner && let Some(top) = stack.last_mut() {
                top.0 = true;
            }
        }
        index += 1;
    }
    false
}

/// Test-framework bindings in scope: imports, aliases and test-file globals.
fn javascript_test_names(relative: &str, text: &Text, masked: &Text) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = if TEST_PATH.is_match(relative) {
        TEST_FUNCTIONS.iter().map(|s| s.to_string()).collect()
    } else {
        BTreeSet::new()
    };
    for statement in TEST_IMPORT.iter(masked) {
        let quote = statement.group(masked, 2).and_then(|q| q.chars().next()).unwrap_or('"');
        let end = closing_quote(&text.c, statement.end(), quote, false);
        if TEST_FRAMEWORKS.contains(&text.sl(statement.end(), end)) {
            for item in statement.group(masked, 1).unwrap_or("").split(',') {
                let parts: Vec<&str> = item.split(py::is_space).filter(|s| !s.is_empty()).collect();
                if let (Some(first), Some(last)) = (parts.first(), parts.last())
                    && TEST_FUNCTIONS.contains(first)
                {
                    names.insert(last.to_string());
                }
            }
        }
    }
    for declared in DECLARED.group1_strs(&masked.s) {
        names.remove(declared);
    }
    names
}

/// Parser-free equivalents of the Oxlint preview rules, used only without it.
pub fn javascript_fallback_rules(relative: &str, text: &Text) -> Vec<Finding> {
    let masked = mask_javascript(text);
    let m = &masked.c;
    let mut findings: Vec<Finding> = Vec::new();
    for found in CATCH_BLOCK.iter(&masked) {
        let close = matching_close(m, found.end() - 1);
        if py::strip(text.sl(found.end(), close.saturating_sub(1))).is_empty() {
            findings.push(("no-empty", "empty catch block swallows the error".into(), found.start()));
        }
    }
    for found in ASYNC_EXECUTOR.iter(&masked) {
        findings.push((
            "no-async-promise-executor",
            "async Promise executor functions are not allowed".into(),
            found.start(),
        ));
    }
    for found in FINALLY_BLOCK.iter(&masked) {
        let close = matching_close(m, found.end() - 1);
        let body = Text::new(masked.sl(found.end(), close.saturating_sub(1)));
        if let Some(control) = CONTROL.search(&body, 0)
            && !NESTED_SCOPE.is_match(&body.s)
        {
            findings.push((
                "no-unsafe-finally",
                format!(
                    "unsafe finally: {} in finally overrides try/catch control flow",
                    control.group(&body, 1).unwrap_or("")
                ),
                found.end() + control.start(),
            ));
        }
    }
    for found in DEBUGGER.iter(&masked) {
        findings.push(("no-debugger", "debugger statement".into(), found.start()));
    }
    for name in javascript_test_names(relative, text, &masked) {
        let pattern = Re::new(&format!(
            r#"(?<![\w$.]){}\s*(?:\.\s*(only|skip)\b|\[\s*(['"`])\s*\2\s*\])\s*\("#,
            fancy_regex::escape(&name)
        ));
        for found in pattern.iter(&masked) {
            let kind = match found.group(&masked, 1) {
                Some(kind) => kind.to_string(),
                None => {
                    let quote_char = found.group(&masked, 2).and_then(|q| q.chars().next()).unwrap_or('"');
                    let Some(quote) = (found.start()..masked.len()).find(|&i| m[i] == quote_char) else {
                        continue;
                    };
                    text.sl(quote + 1, closing_quote(&text.c, quote + 1, text.c[quote], false))
                        .to_string()
                }
            };
            if kind == "only" {
                findings.push((
                    "no-focused-tests",
                    "focused test (.only) silently skips the rest of the suite".into(),
                    found.start(),
                ));
            } else if kind == "skip" {
                findings.push((
                    "no-disabled-tests",
                    "disabled test (.skip) removes coverage".into(),
                    found.start(),
                ));
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loki_js_nested_quantifier_matches_python() {
        // python3 -c 'import loki; print([loki.nested_quantifier(p) for p in ["(a+)+", "(?:-[a-z]+)*", "(\\d+,)*", "(x*){2,}", "([a-z]+|b)*", "(a{1,3})+", "[(a+)+]"]])'
        let got: Vec<bool> = [
            "(a+)+",
            "(?:-[a-z]+)*",
            r"(\d+,)*",
            "(x*){2,}",
            "([a-z]+|b)*",
            "(a{1,3})+",
            "[(a+)+]",
        ]
        .iter()
        .map(|p| nested_quantifier(p))
        .collect();
        assert_eq!(got, [true, false, false, true, true, true, false]);
    }

    /// loki.py test_sql_identifier_interpolation_gets_identifier_advice: an interpolation only where a table or
    /// column name goes gets the allowlist advice; any value position or `+` keeps the placeholder advice.
    #[test]
    fn loki_js_sql_identifier_interpolation_gets_identifier_advice() {
        let message = |source: &str| {
            let found = javascript_rules(&Text::new(source));
            let rules: Vec<&str> = found.iter().map(|f| f.0).collect();
            assert_eq!(rules, ["loki/sql-injection"], "{source}");
            found[0].1.clone()
        };
        for source in [
            "db.prepare(`SELECT * FROM ${name} ORDER BY 1`)",
            "db.query(`SELECT * FROM \"${table}\" ORDER BY ${column}`)",
            "db.query(`INSERT INTO s.${table} (a) VALUES (?)`, [a])",
        ] {
            assert_eq!(message(source), SQL_IDENTIFIER, "{source}");
        }
        for source in [
            "db.query(`SELECT * FROM ${table} WHERE id = ${id}`)",
            "db.query(`SELECT * FROM t WHERE name = '${name}'`)",
            "db.query('SELECT * FROM ' + table)",
        ] {
            assert_eq!(message(source), SQL_QUERY, "{source}");
        }
    }
}
