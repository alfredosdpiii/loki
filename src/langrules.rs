//! Rust, Go and Elixir rule packs (`rust_rules`, `go_rules`, `elixir_rules`).

use crate::jsrules::{SQL_IDENTIFIER, SQL_IDENTIFIER_POSITION, SQL_QUERY, SQL_WORD, TLS_VERIFICATION};
use crate::py;
use crate::rules::Finding;
use crate::text::{Re, Text, closing_quote, mask_elixir, mask_go, mask_rust, matching_close, split_arguments};
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

pub const SHELLS: [&str; 7] = ["sh", "bash", "zsh", "dash", "/bin/sh", "/bin/bash", "/usr/bin/env"];
pub const SHELL_COMMAND: &str = "shell command injection: command string built from variables runs through a shell with -c; pass the program and arguments separately";

re!(PLACEHOLDER, r"(?<![\w:])(todo|unimplemented)\s*!\s*[(\[{]");
re!(RUST_FN, r"\bfn\s+\w+[^{;]*\{");
re!(BUF_WRITER, r"\bBufWriter\s*::\s*(?:new|with_capacity)\s*\(");
re!(FLUSHED, r"\.flush\s*\(|\binto_inner\s*\(|->\s*[^{]*BufWriter");
re!(UNCHECKED, r"\.get_unchecked(?:_mut)?\s*\(\s*([A-Za-z_]\w*)");
re!(COMMAND_NEW, r#"\bCommand\s*::\s*new\s*\(\s*""#);
re!(DYNAMIC_ARGS, r#"format!|\.args?\s*\(\s*(?!["\[\s])"#);
re!(
    DANGER_ACCEPT,
    r"\.\s*danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)"
);
re!(
    RUST_SQL_FORMAT,
    r"(?:(?<![\w.])(?:sqlx\s*::\s*)?query(?:_as|_scalar)?(?:\s*::\s*<[^>()]*>)?|\.\s*execute|(?<![\w.])(?:diesel\s*::\s*)?sql_query)\s*\(\s*&?\s*format\s*!\s*\("
);
re!(RUST_STRING_START, r#"^r?#*""#);
re!(RUST_HOLE, r"\{(\{)?");
re!(GO_SKIP_VERIFY, r"\bInsecureSkipVerify\s*(?::|=(?!=))\s*true\b");
re!(GO_EXEC, r"\bexec\s*\.\s*Command(Context)?\s*\(");
re!(GO_SQL_CALL, r"\.\s*(?:Query|QueryRow|Exec|Prepare)(Context)?\s*\(");
re!(GO_SPRINTF, r"^\s*fmt\s*\.\s*Sprintf\s*\(");
re!(GO_VERB, r"%(?:%|[-+# 0-9.]*([sv]))");
re!(
    GO_LITERAL,
    r#"^\s*(?:"[^"\n]*"|`[^`]*`)\s*(?:\+\s*(?:"[^"\n]*"|`[^`]*`)\s*)*$"#
);
re!(GO_ARCHIVE, r#""archive/(?:zip|tar)""#);
re!(GO_FUNC, r"\bfunc\b[^{]*\{");
re!(GO_JOIN, r"\b(?:filepath|path)\.Join\s*\([^)]*\b\w+\.Name\b");
re!(
    GO_GUARD,
    r"\bIsLocal\s*\(|\bfilepath\.Rel\s*\(|\bHasPrefix\s*\(|\bValidPath\s*\(|\bContains\s*\([^)]*\.\."
);
re!(
    pub AUTHORIZATION_KEY,
    r"(?i)^(?:[a-z_]*?(?:admin|superuser|super_user|staff|role|roles|permission|permissions|privilege|privileges|scope|scopes|authorized|authorised)[a-z_?]*)$"
);
re!(
    EX_PARAM,
    r#"(?<![\w.])(?:conn\s*\.\s*)?(?:params|query_params|body_params)\s*\[\s*""#
);
re!(EX_COMPARE_AFTER, r"^\s*(?:===?|!==?|and\b|or\b|&&|\|\|)");
re!(EX_HEAD, r"\bdefp?\s+[\w?!]+\s*\(");
re!(EX_ARROW_VALUE, r"=>\s*([a-z][\w]*)");
re!(EX_PARAMS_NAME, r"\b([a-z]\w*params)\b");
re!(EX_LITERAL_FLAG, r#""\s*"\s*=>\s*(true|false)\b"#);
re!(EX_PARAMS_ASSIGN, r"(?m)^\s*([a-z]\w*)\s*=[^\n]*\bparams\b");
re!(EX_REDIRECT, r"\bredirect\s*\(");
re!(EX_EXTERNAL, r"\bexternal:\s*([^,)]+)");
re!(EX_LOCAL_WORD, r"(?<![\w.:])([a-z]\w*)");
re!(EX_PARAMS, r"\bparams\b");
re!(EX_SORT, r"\bEnum\.(?:sort_by|max_by|min_by)\s*\(");
re!(EX_DATE_FIELD, r"\.\w*(?:_at|_on|date|time|timestamp)\b");
re!(EX_DIRECTION, r"^:(?:asc|desc)$");
re!(
    EX_FILE_MATCH,
    r"\{:ok,\s*[\w_]+\}\s*=\s*File\.(read|open|stat|ls|lstat|read_link)\s*\("
);
re!(EX_FILE_OPEN, r"\{:ok,\s*([a-z]\w*)\}\s*(?:=|<-)\s*File\.open\s*\(");
re!(EX_SYSTEM_CMD, r#"\bSystem\.cmd\s*\(\s*""#);
re!(EX_VARIABLE_ARG, r#",\s*(?!["\s])[a-z_]\w*\s*[\]<]"#);
re!(EX_OS_CMD, r"(?<![\w.]):os\.cmd\s*\(");
re!(EX_CHARLIST, r#"^\s*~c?["'].*["']\s*$"#);
re!(
    EX_HTTP_CALL,
    r"(?<![\w.]):(?:httpc|hackney)\.request\s*\(|(?<![\w.])(?:HTTPoison|Req|Tesla)\.(?:get|post|put|patch|delete|head|options|request|new)!?\s*\(|(?<![\w.])Finch\.build\s*\(|(?<![\w.])Mint\.HTTP\.connect\s*\("
);
re!(EX_WORD, r"(?<![\w.:])([a-z]\w*)\b");
re!(EX_REQUEST_PARAMS, r"\b(?:query_|body_)?params\b");

pub fn rust_rules(text: &Text) -> Vec<Finding> {
    let masked = mask_rust(text);
    let m = &masked.c;
    let mut findings: Vec<Finding> = PLACEHOLDER
        .iter(&masked)
        .into_iter()
        .map(|found| {
            (
                "loki/placeholder",
                format!(
                    "{}!() placeholder left in code panics at runtime",
                    found.group(&masked, 1).unwrap_or("")
                ),
                found.start(),
            )
        })
        .collect();
    for function in RUST_FN.iter(&masked) {
        let open = function.end() - 1;
        let body = Text::new(masked.sl(open, matching_close(m, open)));
        if let Some(writer) = BUF_WRITER.search(&body, 0) {
            let head = format!("{}{}", masked.sl(function.start(), function.end()), body.s);
            if !FLUSHED.is_match(&head) {
                findings.push((
                    "loki/unflushed-writer",
                    "BufWriter dropped without flush(): write errors on drop are silently discarded; call flush()? before returning".into(),
                    open + writer.start(),
                ));
            }
        }
        for found in UNCHECKED.iter(&body) {
            let index = fancy_regex::escape(found.group(&body, 1).unwrap_or("")).into_owned();
            let checked = Re::new(&format!(
                r"\b{index}\s*(?:<|>=)|(?:>|<=)\s*{index}\b|assert!\([^;]*\b{index}\b"
            ));
            if !checked.is_match(&body.s) {
                findings.push((
                    "loki/unchecked-index",
                    "get_unchecked index is not bounds-checked in this function; an out-of-bounds index is undefined behaviour".into(),
                    open + found.start(),
                ));
            }
        }
    }
    for found in COMMAND_NEW.iter(&masked) {
        let program = text.sl(found.end(), closing_quote(&text.c, found.end(), '"', false));
        let end = masked.find(";", found.end()).unwrap_or(text.len());
        let chain = text.sl(found.end(), end);
        if SHELLS.contains(&program) && chain.contains("\"-c\"") && DYNAMIC_ARGS.is_match(chain) {
            findings.push(("loki/command-injection", SHELL_COMMAND.into(), found.start()));
        }
    }
    for found in DANGER_ACCEPT.iter(&masked) {
        findings.push(("loki/tls-verification", TLS_VERIFICATION.into(), found.start()));
    }
    for found in RUST_SQL_FORMAT.iter(&masked) {
        let arguments = split_arguments(m, found.end() - 1);
        let literal = arguments
            .first()
            .map_or("", |&(a, b)| text.sl(a, b).trim_matches(py::is_space));
        if !RUST_STRING_START.is_match(literal) {
            continue;
        }
        let literal = Text::new(literal);
        let holes: Vec<usize> = RUST_HOLE
            .iter(&literal)
            .into_iter()
            .filter(|h| h.get(1).is_none())
            .map(|h| h.start())
            .collect();
        if let Some(message) = sql_message(&literal, &holes) {
            findings.push(("loki/sql-injection", message.into(), found.start()));
        }
    }
    findings
}

/// SQL injection message for query text with non-literal values at the hole indexes.
fn sql_message(literal: &Text, holes: &[usize]) -> Option<&'static str> {
    if holes.is_empty() || !SQL_WORD.is_match(&literal.s) {
        return None;
    }
    let identifier = holes
        .iter()
        .all(|&hole| SQL_IDENTIFIER_POSITION.is_match(literal.sl(0, hole)));
    Some(if identifier { SQL_IDENTIFIER } else { SQL_QUERY })
}

fn go_literal(masked: &Text, (a, b): (usize, usize)) -> bool {
    GO_LITERAL.is_match(masked.sl(a, b))
}

/// Top-level spans of masked[start:end] separated by `+`.
fn plus_parts(masked: &[char], start: usize, end: usize) -> Vec<(usize, usize)> {
    let (mut spans, mut depth, mut begin) = (Vec::new(), 0i64, start);
    for (index, &c) in masked.iter().enumerate().take(end).skip(start) {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            '+' if depth == 0 => {
                spans.push((begin, index));
                begin = index + 1;
            }
            _ => {}
        }
    }
    spans.push((begin, end));
    spans
}

fn go_security_rules(text: &Text, masked: &Text) -> Vec<Finding> {
    let m = &masked.c;
    let mut findings: Vec<Finding> = GO_SKIP_VERIFY
        .iter(masked)
        .into_iter()
        .map(|found| ("loki/tls-verification", TLS_VERIFICATION.into(), found.start()))
        .collect();
    for call in GO_EXEC.iter(masked) {
        let all = split_arguments(m, call.end() - 1);
        let arguments = &all[usize::from(call.get(1).is_some()).min(all.len())..];
        if arguments.len() > 2 {
            let word = |(a, b): (usize, usize)| text.sl(a, b).trim_matches(py::is_space).trim_matches(['"', '`']);
            if SHELLS.contains(&word(arguments[0])) && word(arguments[1]) == "-c" && !go_literal(masked, arguments[2]) {
                findings.push(("loki/command-injection", SHELL_COMMAND.into(), call.start()));
            }
        }
    }
    for call in GO_SQL_CALL.iter(masked) {
        let all = split_arguments(m, call.end() - 1);
        let Some(&(start, end)) = all.get(usize::from(call.get(1).is_some())) else {
            continue;
        };
        let message = if let Some(sprintf) = GO_SPRINTF.search(&Text::new(masked.sl(start, end)), 0) {
            let inner = split_arguments(m, start + sprintf.end() - 1);
            let Some(&format) = inner.first() else { continue };
            if inner[1..].iter().all(|&span| go_literal(masked, span)) || !go_literal(masked, format) {
                continue;
            }
            let literal = Text::new(text.sl(format.0, format.1));
            let holes: Vec<usize> = GO_VERB
                .iter(&literal)
                .into_iter()
                .filter(|h| h.get(1).is_some())
                .map(|h| h.start())
                .collect();
            sql_message(&literal, &holes)
        } else {
            let parts = plus_parts(m, start, end);
            let literals: Vec<&str> = parts
                .iter()
                .filter(|&&part| go_literal(masked, part))
                .map(|&(a, b)| text.sl(a, b))
                .collect();
            if literals.is_empty() || literals.len() == parts.len() {
                continue;
            }
            sql_message(&Text::new(&literals.concat()), &[0])
        };
        if let Some(message) = message {
            findings.push(("loki/sql-injection", message.into(), call.start()));
        }
    }
    findings
}

/// Zip slip, SQL built with Sprintf or +, shell -c commands, TLS skip-verify.
pub fn go_rules(text: &Text) -> Vec<Finding> {
    let masked = mask_go(text);
    let mut findings = go_security_rules(text, &masked);
    if !GO_ARCHIVE.is_match(&text.s) {
        return findings;
    }
    for function in GO_FUNC.iter(&masked) {
        let open = function.end() - 1;
        let end = matching_close(&masked.c, open);
        let body = Text::new(masked.sl(open, end));
        if let Some(joined) = GO_JOIN.search(&body, 0)
            && !GO_GUARD.is_match(text.sl(open, end))
        {
            findings.push((
                "loki/zip-slip",
                "path traversal (zip slip): archive entry name joined into a path without checking it stays inside the destination; use filepath.IsLocal".into(),
                open + joined.start(),
            ));
        }
    }
    findings
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `re.search(r"(?:\bif|\bunless|\bnot|!|\bwhen|\band|\bor|&&|\|\|)\s*$", before)`.
fn decision_before(before: &str) -> bool {
    let trimmed = before.trim_end_matches(py::is_space);
    if trimmed.ends_with('!') || trimmed.ends_with("&&") || trimmed.ends_with("||") {
        return true;
    }
    ["if", "unless", "not", "when", "and", "or"].iter().any(|word| {
        trimmed
            .strip_suffix(word)
            .is_some_and(|rest| !rest.chars().next_back().is_some_and(is_word))
    })
}

fn authorization(key: &str) -> String {
    format!(
        "authorization decision trusts client-controlled request param \"{key}\"; derive privilege from the authenticated server-side identity (conn.assigns)"
    )
}

pub fn elixir_rules(text: &Text) -> Vec<Finding> {
    let masked = mask_elixir(text);
    let m = &masked.c;
    let mut findings: Vec<Finding> = Vec::new();
    for found in EX_PARAM.iter(&masked) {
        let close = closing_quote(&text.c, found.end(), '"', false);
        let key = text.sl(found.end(), close);
        let after_start = masked.find("]", close).map_or(0, |i| i + 1);
        let after = masked.sl(after_start, masked.len());
        let before = masked.sl(0, found.start());
        if AUTHORIZATION_KEY.is_match(key) && (EX_COMPARE_AFTER.is_match(after) || decision_before(before)) {
            findings.push(("loki/request-authorization", authorization(key), found.start()));
        }
    }
    let mut tainted: BTreeSet<String> = BTreeSet::new();
    for head in EX_HEAD.iter(&masked) {
        let arguments = Text::new(masked.sl(head.end(), matching_close(m, head.end() - 1) - 1));
        tainted.extend(EX_ARROW_VALUE.group1_strs(&arguments.s).iter().map(|s| s.to_string()));
        tainted.extend(EX_PARAMS_NAME.group1_strs(&arguments.s).iter().map(|s| s.to_string()));
        for pair in EX_LITERAL_FLAG.iter(&arguments) {
            let start = head.end() + pair.start();
            let key = text.sl(start + 1, closing_quote(&text.c, start + 1, '"', false));
            if AUTHORIZATION_KEY.is_match(key) {
                findings.push(("loki/request-authorization", authorization(key), start));
            }
        }
    }
    tainted.extend(EX_PARAMS_ASSIGN.group1_strs(&masked.s).iter().map(|s| s.to_string()));
    for call in EX_REDIRECT.iter(&masked) {
        let arguments = Text::new(masked.sl(call.end(), matching_close(m, call.end() - 1) - 1));
        if let Some(external) = EX_EXTERNAL.search(&arguments, 0) {
            let target = external.group(&arguments, 1).unwrap_or("");
            if EX_LOCAL_WORD.group1_strs(target).iter().any(|w| tainted.contains(*w)) || EX_PARAMS.is_match(target) {
                findings.push((
                    "loki/open-redirect",
                    "open redirect: external redirect target comes from request params; allow only known hosts or same-site paths".into(),
                    call.start(),
                ));
            }
        }
    }
    for call in EX_SORT.iter(&masked) {
        let arguments: Vec<&str> = split_arguments(m, call.end() - 1)
            .iter()
            .map(|&(a, b)| py::strip(masked.sl(a, b)))
            .collect();
        let mapper = arguments.iter().find(|item| EX_DATE_FIELD.is_match(item));
        let sorter = match arguments.last() {
            Some(last) if Some(last) != mapper => *last,
            _ => "",
        };
        if mapper.is_some() && (sorter.is_empty() || EX_DIRECTION.is_match(sorter)) {
            findings.push((
                "loki/structural-date-sort",
                "structural comparison: DateTime/Date values sorted with plain term ordering; pass DateTime (or {:desc, DateTime}) as the sorter".into(),
                call.start(),
            ));
        }
    }
    for found in EX_FILE_MATCH.iter(&masked) {
        findings.push((
            "loki/unhandled-error-tuple",
            format!(
                "{{:ok, _}} = File.{}(...) raises MatchError on {{:error, reason}}; use case/with, or the ! variant deliberately",
                found.group(&masked, 1).unwrap_or("")
            ),
            found.start(),
        ));
    }
    for found in EX_FILE_OPEN.iter(&masked) {
        let handle = found.group(&masked, 1).unwrap_or("");
        let closed = Re::new(&format!(r"\bFile\.close\s*\(\s*{handle}\b"));
        if !closed.is_match(&masked.s) {
            findings.push((
                "loki/resource-leak",
                format!(
                    "file handle {handle} from File.open is never closed; use File.open/3 with a function or File.close"
                ),
                found.start(),
            ));
        }
    }
    for call in EX_SYSTEM_CMD.iter(&masked) {
        let program = text.sl(call.end(), closing_quote(&text.c, call.end(), '"', false));
        let arguments = text.sl(call.end(), matching_close(m, call.end() - 2));
        if SHELLS.contains(&program)
            && arguments.contains("\"-c\"")
            && (arguments.contains("#{") || EX_VARIABLE_ARG.is_match(arguments))
        {
            findings.push(("loki/command-injection", SHELL_COMMAND.into(), call.start()));
        }
    }
    for call in EX_OS_CMD.iter(&masked) {
        let arguments = text.sl(call.end(), matching_close(m, call.end() - 1) - 1);
        if arguments.contains("#{") || !EX_CHARLIST.is_match(arguments) {
            findings.push(("loki/command-injection", SHELL_COMMAND.into(), call.start()));
        }
    }
    for call in EX_HTTP_CALL.iter(&masked) {
        let arguments = masked.sl(call.end(), matching_close(m, call.end() - 1) - 1);
        if EX_WORD.group1_strs(arguments).iter().any(|w| tainted.contains(*w)) || EX_REQUEST_PARAMS.is_match(arguments)
        {
            findings.push((
                "loki/ssrf",
                "server-side request forgery (SSRF): outbound request to an untrusted URL from request parameters; validate the host against an allowlist".into(),
                call.start(),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(go: bool, source: &str) -> Vec<&'static str> {
        let text = Text::new(source);
        let found = if go { go_rules(&text) } else { rust_rules(&text) };
        found.into_iter().map(|(rule, _, _)| rule).collect()
    }

    #[test]
    fn go_security_rules_match_python() {
        for (source, expected) in [
            (
                r#"func f() { db.Query(fmt.Sprintf("SELECT * FROM t WHERE n = '%s'", n)) }"#,
                vec!["loki/sql-injection"],
            ),
            (
                r#"func f() { db.QueryRowContext(ctx, "SELECT * FROM t WHERE id = " + id) }"#,
                vec!["loki/sql-injection"],
            ),
            (r#"func f() { db.Query("SELECT * FROM t WHERE id = ?", id) }"#, vec![]),
            (r#"func f() { db.Query(fmt.Sprintf("SELECT %d", id)) }"#, vec![]),
            (
                "func f() {\n\t// db.Query(fmt.Sprintf(\"SELECT %s\", x))\n\ts := `db.Exec(\"DELETE \" + x)`\n}",
                vec![],
            ),
            (
                r#"func f() { exec.Command("sh", "-c", "ls " + dir) }"#,
                vec!["loki/command-injection"],
            ),
            (r#"func f() { exec.Command("sh", "-c", "ls -la") }"#, vec![]),
            (
                "var c = &tls.Config{InsecureSkipVerify: true}",
                vec!["loki/tls-verification"],
            ),
            ("var c = &tls.Config{InsecureSkipVerify: false}", vec![]),
        ] {
            assert_eq!(rules(true, source), expected, "{source}");
        }
    }

    #[test]
    fn rust_security_rules_match_python() {
        for (source, expected) in [
            (
                "fn c() { Client::builder().danger_accept_invalid_certs(true); }",
                vec!["loki/tls-verification"],
            ),
            ("fn c() { Client::builder().danger_accept_invalid_certs(v); }", vec![]),
            (
                r#"fn q() { sqlx::query(&format!("SELECT * FROM t WHERE n = '{n}'")); }"#,
                vec!["loki/sql-injection"],
            ),
            (
                r#"fn q() { diesel::sql_query(format!("UPDATE t SET a = {}", v)); }"#,
                vec!["loki/sql-injection"],
            ),
            (r#"fn q() { sqlx::query("SELECT * FROM t WHERE n = $1"); }"#, vec![]),
            (r##"fn q() { k.execute(&format!("#{}", x)); }"##, vec![]),
        ] {
            assert_eq!(rules(false, source), expected, "{source}");
        }
    }
}
